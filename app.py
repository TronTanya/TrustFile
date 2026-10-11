"""TrustFile — веб-интерфейс на Streamlit.

Запуск: streamlit run app.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Sequence

import streamlit as st

import demo
from comparison import ComparisonResult, Status, compare_with_manifest, hashes_match
from hashing import (
    MAX_FILE_SIZE,
    MAX_FILES,
    FileRecord,
    hash_files,
    hash_stream,
    normalize_expected_hash,
    validate_batch,
)
from manifest import (
    APP_VERSION,
    MAX_MANIFEST_BYTES,
    ManifestError,
    build_manifest,
    manifest_to_bytes,
    parse_manifest,
)
from reporting import LIMITATIONS, result_to_csv, result_to_html

st.set_page_config(page_title="TrustFile — контроль целостности файлов", layout="wide")

# Только собственные классы и стабильный data-testid контейнера страницы.
st.markdown(
    """
<style>
[data-testid="stMainBlockContainer"] { max-width: 1100px; }
.tf-subtitle { color:#667085; margin:-0.6rem 0 0.2rem 0; font-size:1.05rem; }
.tf-scroll { overflow-x:auto; }
.tf-table { width:100%; border-collapse:collapse; font-size:0.875rem; background:#FFFFFF;
            border:1px solid #E4E7EC; border-radius:6px; margin:0.25rem 0 0.75rem 0; }
.tf-table th, .tf-table td { padding:6px 10px; border-bottom:1px solid #E4E7EC; text-align:left; }
.tf-table th { color:#667085; font-weight:600; background:#F7F8FA; }
.tf-table tr:last-child td { border-bottom:none; }
.tf-mono { font-family: ui-monospace, Consolas, "Courier New", monospace; font-size:0.8rem; }
.tf-num { text-align:right !important; white-space:nowrap; }
.tf-muted { color:#667085; }
.tf-status { font-weight:600; white-space:nowrap; }
.tf-ok { color:#278451; } .tf-warn { color:#B7791F; } .tf-err { color:#C43D3D; } .tf-info { color:#315EFB; }
</style>
""",
    unsafe_allow_html=True,
)

STATUS_CLASS = {
    Status.MATCH: "tf-ok",
    Status.CHANGED: "tf-err",
    Status.MISSING: "tf-warn",
    Status.ADDED: "tf-info",
}
STATUS_PLURAL = {
    Status.MATCH: "Совпадают",
    Status.CHANGED: "Изменены",
    Status.MISSING: "Отсутствуют",
    Status.ADDED: "Добавлены",
}
DASH = '<span class="tf-muted">—</span>'
MAX_FILE_MB = MAX_FILE_SIZE // (1024 * 1024)


# ---------- Вспомогательные функции отображения ----------


def short_hash(value: str | None) -> str:
    if not value:
        return DASH
    return f'<span class="tf-mono" title="{escape(value)}">{escape(value[:10])}…{escape(value[-6:])}</span>'


def fmt_size(value: int | None) -> str:
    if value is None:
        return DASH
    return f"{value:,}".replace(",", "\u202f")


def html_table(headers: Sequence[str], rows: Sequence[Sequence[str]], numeric: set[int]) -> None:
    """Рисует таблицу. Ячейки rows должны быть уже экранированы."""
    head = "".join(
        f'<th class="{"tf-num" if i in numeric else ""}">{escape(h)}</th>' for i, h in enumerate(headers)
    )
    body = "".join(
        "<tr>"
        + "".join(f'<td class="{"tf-num" if i in numeric else ""}">{c}</td>' for i, c in enumerate(row))
        + "</tr>"
        for row in rows
    )
    st.markdown(
        f'<div class="tf-scroll"><table class="tf-table"><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def full_hash_viewer(options: dict[str, str], key: str) -> None:
    """Позволяет выбрать файл и посмотреть / скопировать полный хеш."""
    if not options:
        return
    with st.expander("Полные значения SHA-256"):
        label = st.selectbox("Файл", list(options), key=key)
        st.code(options[label], language=None)
        st.caption("Кнопка копирования находится в правом верхнем углу поля.")


def uploads_signature(files) -> tuple:
    if not files:
        return ()
    if not isinstance(files, list):
        files = [files]
    return tuple((f.file_id, f.name, f.size) for f in files)


def show_errors(errors: list[str]) -> None:
    st.error("Анализ не выполнен:\n\n" + "\n".join(f"- {e}" for e in errors))


def timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def render_records(records: list[FileRecord], key: str) -> None:
    html_table(
        ["Имя файла", "Размер, байт", "SHA-256"],
        [[escape(r.name), fmt_size(r.size), short_hash(r.sha256)] for r in records],
        numeric={1},
    )
    full_hash_viewer({r.name: r.sha256 for r in records}, key=key)


def render_result(result: ComparisonResult, key: str) -> None:
    columns = st.columns(4)
    for column, status in zip(columns, (Status.MATCH, Status.CHANGED, Status.MISSING, Status.ADDED)):
        column.metric(STATUS_PLURAL[status], result.count(status))

    if result.all_match:
        st.success("Загруженные файлы совпадают с эталоном.")
    else:
        st.warning("Обнаружены расхождения с эталоном. Подробности — в таблице ниже.")

    rows = [
        [
            escape(row.name),
            f'<span class="tf-status {STATUS_CLASS[row.status]}">{escape(row.status.value)}</span>',
            fmt_size(row.reference_size),
            fmt_size(row.current_size),
            short_hash(row.reference_hash),
            short_hash(row.current_hash),
        ]
        for row in result.rows
    ]
    html_table(
        ["Имя файла", "Статус", "Размер эталона", "Текущий размер", "SHA-256 эталона", "Текущий SHA-256"],
        rows,
        numeric={2, 3},
    )
    st.caption(
        "Статус «Отсутствует» означает, что файл не представлен в загруженном наборе. "
        "Файлы сопоставляются по точному имени с учётом регистра: переименованный файл "
        "отображается как «Отсутствует» и «Добавлен»."
    )

    hashes: dict[str, str] = {}
    for row in result.rows:
        if row.reference_hash:
            hashes[f"{row.name} — эталон"] = row.reference_hash
        if row.current_hash:
            hashes[f"{row.name} — текущий"] = row.current_hash
    full_hash_viewer(hashes, key=f"{key}_hash")

    slug = timestamp_slug()
    left, right, _ = st.columns([1, 1, 2])
    left.download_button(
        "Скачать CSV",
        data=result_to_csv(result),
        file_name=f"trustfile-{key}-{slug}.csv",
        mime="text/csv",
        key=f"{key}_csv",
        width="stretch",
        on_click="ignore",
    )
    right.download_button(
        "Скачать HTML-отчёт",
        data=result_to_html(result).encode("utf-8"),
        file_name=f"trustfile-{key}-{slug}.html",
        mime="text/html",
        key=f"{key}_html",
        width="stretch",
        on_click="ignore",
    )


def clear_state(*keys: str) -> None:
    for k in keys:
        st.session_state.pop(k, None)


# ---------- Вкладка «Создать эталон» ----------


def tab_create() -> None:
    st.subheader("Создание эталонного манифеста")
    st.write(
        f"Загрузите файлы, для которых нужно сохранить цифровые отпечатки. "
        f"Ограничения: до {MAX_FILES} файлов, до 20 МБ на файл и до 100 МБ на набор. "
        "Поддерживается плоский набор файлов без каталогов и архивов."
    )
    files = st.file_uploader(
        "Файлы для эталона",
        accept_multiple_files=True,
        max_upload_size=MAX_FILE_MB,
        key="create_files",
        on_change=clear_state,
        args=("create_records", "create_manifest", "create_sig"),
    )
    if not files:
        return

    signature = uploads_signature(files)
    if st.session_state.get("create_sig") != signature:
        clear_state("create_records", "create_manifest")
        errors = validate_batch((f.name, f.size) for f in files)
        if errors:
            show_errors(errors)
            return
        with st.spinner("Вычисление SHA-256…"):
            records = hash_files((f.name, f) for f in files)
        st.session_state["create_records"] = records
        st.session_state["create_manifest"] = manifest_to_bytes(build_manifest(records))
        st.session_state["create_sig"] = signature

    records: list[FileRecord] = st.session_state["create_records"]
    total = sum(r.size for r in records)
    st.caption(f"Файлов: {len(records)}. Общий размер: {fmt_size(total)} байт.")
    render_records(records, key="create_full")

    st.download_button(
        "Скачать эталонный манифест",
        data=st.session_state["create_manifest"],
        file_name=f"trustfile-manifest-{timestamp_slug()}.json",
        mime="application/json",
        type="primary",
        on_click="ignore",
    )
    st.info(
        "Храните эталон отдельно от проверяемых файлов. Если изменить и файл, и манифест, "
        "такая проверка не обнаружит подмену эталона."
    )


# ---------- Вкладка «Проверить файлы» ----------


def section_verify() -> None:
    st.subheader("Проверка по эталону")
    col_manifest, col_files = st.columns(2)
    reset = ("verify_result", "verify_sig")
    manifest_file = col_manifest.file_uploader(
        "Эталонный манифест (JSON, до 1 МБ)",
        type=["json"],
        max_upload_size=1,
        key="verify_manifest",
        on_change=clear_state,
        args=reset,
    )
    files = col_files.file_uploader(
        "Текущий набор файлов",
        accept_multiple_files=True,
        max_upload_size=MAX_FILE_MB,
        key="verify_files",
        on_change=clear_state,
        args=reset,
    )

    signature = (uploads_signature(manifest_file), uploads_signature(files))
    if st.session_state.get("verify_sig") not in (None, signature):
        clear_state(*reset)

    ready = manifest_file is not None and bool(files)
    if st.button("Проверить", type="primary", disabled=not ready, key="verify_run"):
        clear_state(*reset)
        if manifest_file.size > MAX_MANIFEST_BYTES:
            show_errors(["Файл манифеста больше 1 МБ."])
            return
        try:
            manifest = parse_manifest(manifest_file.getvalue())
        except ManifestError as exc:
            show_errors([f"Манифест не прошёл проверку. {exc}"])
            return
        errors = validate_batch((f.name, f.size) for f in files)
        if errors:
            show_errors(errors)
            return
        with st.spinner("Вычисление SHA-256…"):
            current = hash_files((f.name, f) for f in files)
        st.session_state["verify_result"] = compare_with_manifest(manifest, current)
        st.session_state["verify_sig"] = signature

    if not ready:
        st.caption("Загрузите манифест и текущий набор файлов, затем нажмите «Проверить».")

    result: ComparisonResult | None = st.session_state.get("verify_result")
    if result is not None:
        st.caption(
            f"Эталон создан: {result.manifest_created_at} (UTC). "
            f"Проверка выполнена: {result.verified_at} (UTC)."
        )
        render_result(result, key="verify")


def section_single() -> None:
    with st.expander("Сравнить с известным SHA-256"):
        st.caption(
            "Ожидаемый отпечаток должен быть получен из надёжного независимого источника, "
            "например с официальной страницы загрузки или напрямую от отправителя. "
            "Значение, полученное вместе с самим файлом, не защищает от его подмены."
        )
        uploaded = st.file_uploader(
            "Файл", max_upload_size=MAX_FILE_MB, key="single_file", on_change=clear_state, args=("single",)
        )
        expected_text = st.text_input("Ожидаемый SHA-256", key="single_expected", placeholder="64 шестнадцатеричных символа")
        if uploaded is None or not expected_text.strip():
            return
        if uploaded.size > MAX_FILE_SIZE:
            show_errors([f"Файл больше {MAX_FILE_SIZE:,} байт (20 МБ).".replace(",", " ")])
            return
        try:
            expected = normalize_expected_hash(expected_text)
        except ValueError as exc:
            st.error(str(exc))
            return

        cached = st.session_state.get("single")
        signature = uploads_signature(uploaded)
        if not cached or cached[0] != signature:
            uploaded.seek(0)
            cached = (signature, hash_stream(uploaded)[0])
            st.session_state["single"] = cached
        calculated = cached[1]

        st.markdown("Вычисленный SHA-256")
        st.code(calculated, language=None)
        st.markdown("Ожидаемый SHA-256")
        st.code(expected, language=None)
        if hashes_match(calculated, expected):
            st.success("Совпадает: байты файла соответствуют ожидаемому отпечатку.")
        else:
            st.error("Не совпадает: байты файла отличаются от ожидаемого отпечатка.")


def section_demo() -> None:
    with st.expander("Демонстрационный режим"):
        st.write(
            "Эталонный набор содержит три текстовых файла. В изменённом наборе один файл "
            "не изменён, в одном изменена одна цифра, один файл удалён и один добавлен."
        )
        c1, c2, c3 = st.columns(3)
        downloads = (
            (c1, "Эталонный набор (ZIP)", demo.zip_files(demo.REFERENCE_FILES), "trustfile-demo-reference.zip", "application/zip"),
            (c2, "Изменённый набор (ZIP)", demo.zip_files(demo.CHANGED_FILES), "trustfile-demo-changed.zip", "application/zip"),
            (c3, "Демо-манифест (JSON)", demo.demo_manifest_bytes(), "trustfile-demo-manifest.json", "application/json"),
        )
        for column, label, data, file_name, mime in downloads:
            column.download_button(
                label, data, file_name=file_name, mime=mime, width="stretch", on_click="ignore"
            )
        st.caption(
            "Архивы нужно распаковать перед загрузкой: TrustFile не извлекает файлы из архивов."
        )

        run, hide, _ = st.columns([1, 1, 2])
        if run.button("Запустить демонстрацию", key="demo_run", width="stretch"):
            st.session_state["demo_result"] = demo.run_demo_comparison()
        if hide.button("Скрыть результат", key="demo_hide", width="stretch"):
            clear_state("demo_result")

        result = st.session_state.get("demo_result")
        if result is not None:
            st.info("ДЕМОНСТРАЦИЯ: результат получен на встроенных учебных файлах, а не на ваших данных.")
            render_result(result, key="demo")


def tab_verify() -> None:
    section_verify()
    st.divider()
    section_single()
    section_demo()


# ---------- Вкладка «О проекте» ----------


def tab_about() -> None:
    st.subheader("О проекте")
    st.markdown(
        f"""
**Назначение.** TrustFile помогает убедиться, что файлы не изменились с момента
создания эталона: после копирования, пересылки, хранения или сдачи работы.

**Для кого.** Студенты, преподаватели и все, кто передаёт файлы и хочет проверить,
что получатель видит те же самые байты.

**Что делает SHA-256.** Криптографическая хеш-функция превращает содержимое файла
любой длины в отпечаток из 64 шестнадцатеричных символов. Одинаковые байты всегда
дают одинаковый отпечаток. Для SHA-256 не известно практического способа подобрать
другие данные с тем же отпечатком, поэтому любое изменение, даже одного байта,
на практике приводит к другому значению.

**Как работает сравнение с эталоном.**
1. Для исходных файлов вычисляются отпечатки и сохраняются в манифест (JSON).
2. Позже загружаются манифест и текущий набор файлов.
3. Файлы сопоставляются по точному имени, и каждому присваивается статус:
   «Совпадает», «Изменён», «Отсутствует» или «Добавлен».

**Гипотеза исследования.** «Сравнение криптографических отпечатков позволяет
обнаруживать изменения файлов относительно сохранённого эталона.»

**Технологии.** Python 3.11+, Streamlit, стандартные модули hashlib, json, csv, io,
pathlib, datetime; тесты — pytest. Работает локально и без подключения к интернету.
Загруженные файлы хранятся только во временной памяти сеанса и не исполняются.

**Практическая польза.** Быстрая проверка копий и резервных архивов, контроль
сданных работ и материалов курса, проверка загрузок по опубликованному SHA-256,
наглядный отчёт в CSV и HTML.

**Ограничения.**
- Инструмент проверяет целостность на уровне байтов.
- Он не проверяет файлы на вредоносный код.
- Он не устанавливает авторство.
- Эталонные манифесты не имеют цифровой подписи и могут быть изменены.
- Доверие к эталону нужно обеспечивать отдельно: храните его вне проверяемого набора.
- Поддерживаются плоские наборы до {MAX_FILES} файлов; каталоги и архивы не разбираются.
- Обнаружение переименований не реализовано.

Версия приложения: {APP_VERSION}.
"""
    )
    with st.expander("Ограничения, включаемые в отчёт"):
        for item in LIMITATIONS:
            st.markdown(f"- {item}")


# ---------- Страница ----------

st.title("TrustFile")
st.markdown('<p class="tf-subtitle">Контроль целостности файлов</p>', unsafe_allow_html=True)
st.write("Создайте цифровые отпечатки файлов и сравните их при повторной проверке.")

tab1, tab2, tab3 = st.tabs(["Создать эталон", "Проверить файлы", "О проекте"])
with tab1:
    tab_create()
with tab2:
    tab_verify()
with tab3:
    tab_about()
