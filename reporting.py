"""Экспорт результатов проверки в CSV и автономный HTML-отчёт."""

from __future__ import annotations

import csv
import io
from html import escape

from comparison import STATUS_ORDER, ComparisonResult, Status
from manifest import APP_NAME, APP_VERSION, HASH_ALGORITHM

MISSING_VALUE = "—"
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠")

CSV_HEADER = (
    "Имя файла",
    "Статус",
    "Размер эталона, байт",
    "Текущий размер, байт",
    "SHA-256 эталона",
    "Текущий SHA-256",
)

LIMITATIONS = (
    "Совпадение SHA-256 означает, что загруженные байты совпадают с эталонным отпечатком. "
    "Это не доказывает, что файл безопасен, подлинен или не содержит вредоносного кода.",
    "Инструмент проверяет целостность на уровне байтов и не выполняет антивирусную проверку.",
    "Эталонный манифест не имеет цифровой подписи: его можно изменить. Доверие к эталону "
    "нужно обеспечивать отдельно, например храня его вне проверяемого набора.",
    "Инструмент не устанавливает авторство файлов.",
    "Файлы сопоставляются по точному имени. Переименованный файл отображается как "
    "«Отсутствует» и «Добавлен»; обнаружение переименований не реализовано.",
    "Статус «Отсутствует» означает, что файл не представлен в загруженном наборе.",
)


def neutralize_formula(value: str) -> str:
    """Не даёт табличным редакторам интерпретировать текст как формулу."""
    if value and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def _cell(value: object) -> str:
    if value is None:
        return MISSING_VALUE
    if isinstance(value, Status):
        return value.value
    if isinstance(value, int):
        return str(value)
    return neutralize_formula(str(value))


def result_to_csv(result: ComparisonResult) -> bytes:
    """CSV в UTF-8 с BOM (корректно открывается в Excel с русскими именами)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")
    writer.writerow(CSV_HEADER)
    for row in result.rows:
        writer.writerow(
            [
                _cell(row.name),
                _cell(row.status),
                _cell(row.reference_size),
                _cell(row.current_size),
                _cell(row.reference_hash),
                _cell(row.current_hash),
            ]
        )
    return buffer.getvalue().encode("utf-8-sig")


_STATUS_CLASS = {
    Status.MATCH: "ok",
    Status.CHANGED: "err",
    Status.MISSING: "warn",
    Status.ADDED: "info",
}

_REPORT_CSS = """
body{margin:0;background:#F7F8FA;color:#202733;font:15px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 24px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.muted{color:#667085}
section{background:#FFFFFF;border:1px solid #E4E7EC;border-radius:6px;padding:16px 20px;margin-top:16px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}dt{color:#667085}dd{margin:0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid #E4E7EC;padding:6px 8px;text-align:left;vertical-align:top}
th{color:#667085;font-weight:600}
code{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:12px;word-break:break-all}
.num{text-align:right;white-space:nowrap}
.ok{color:#278451}.warn{color:#B7791F}.err{color:#C43D3D}.info{color:#315EFB}
.status{font-weight:600;white-space:nowrap}
.summary td{font-size:15px}
"""


def _html_value(value: object, mono: bool = False) -> str:
    if value is None:
        return f'<span class="muted">{MISSING_VALUE}</span>'
    text = escape(str(value), quote=True)
    return f"<code>{text}</code>" if mono else text


def result_to_html(result: ComparisonResult) -> str:
    """Автономный HTML-отчёт без внешних ресурсов и скриптов."""
    summary_rows = "".join(
        f'<tr><td class="status {_STATUS_CLASS[s]}">{escape(s.value)}</td>'
        f'<td class="num">{result.count(s)}</td></tr>'
        for s in STATUS_ORDER
    )
    detail_rows = "".join(
        "<tr>"
        f"<td>{_html_value(row.name)}</td>"
        f'<td class="status {_STATUS_CLASS[row.status]}">{escape(row.status.value)}</td>'
        f'<td class="num">{_html_value(row.reference_size)}</td>'
        f'<td class="num">{_html_value(row.current_size)}</td>'
        f"<td>{_html_value(row.reference_hash, mono=True)}</td>"
        f"<td>{_html_value(row.current_hash, mono=True)}</td>"
        "</tr>"
        for row in result.rows
    )
    headers = "".join(f"<th>{escape(h)}</th>" for h in CSV_HEADER)
    limitations = "".join(f"<li>{escape(item)}</li>" for item in LIMITATIONS)
    conclusion = (
        "Загруженные файлы совпадают с эталоном."
        if result.all_match
        else "Обнаружены расхождения с эталоном."
    )

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME} — отчёт о проверке</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<main>
<h1>{APP_NAME} — отчёт о проверке целостности</h1>
<p class="muted">Контроль целостности файлов</p>

<section>
<dl>
<dt>Время проверки (UTC)</dt><dd>{escape(result.verified_at)}</dd>
<dt>Алгоритм</dt><dd>{HASH_ALGORITHM}</dd>
<dt>Эталон создан (UTC)</dt><dd>{escape(result.manifest_created_at)}</dd>
<dt>Версия приложения</dt><dd>{APP_VERSION}</dd>
<dt>Итог</dt><dd>{escape(conclusion)}</dd>
</dl>
</section>

<h2>Сводка</h2>
<section>
<table class="summary"><tbody>{summary_rows}</tbody></table>
</section>

<h2>Результаты по файлам</h2>
<section>
<table>
<thead><tr>{headers}</tr></thead>
<tbody>{detail_rows}</tbody>
</table>
</section>

<h2>Ограничения метода</h2>
<section><ul>{limitations}</ul></section>
</main>
</body>
</html>
"""
