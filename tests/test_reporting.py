import csv
import io

import pytest

from comparison import ComparisonResult, Status, compare_records
from hashing import FileRecord, hash_bytes
from manifest import APP_VERSION
from reporting import LIMITATIONS, neutralize_formula, result_to_csv, result_to_html


def rec(name: str, data: bytes) -> FileRecord:
    return FileRecord(name, len(data), hash_bytes(data))


def make_result(reference, current) -> ComparisonResult:
    return ComparisonResult(
        rows=tuple(compare_records(reference, current)),
        manifest_created_at="2026-10-11T10:00:00Z",
        verified_at="2026-10-11T12:00:00Z",
    )


SAMPLE = make_result(
    [rec("отчёт.txt", b"1"), rec("изменён.txt", b"a"), rec("нет.txt", b"x")],
    [rec("отчёт.txt", b"1"), rec("изменён.txt", b"b"), rec("новый файл.txt", b"y")],
)


@pytest.mark.parametrize("value", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx", "＝1"])
def test_formula_neutralized(value):
    assert neutralize_formula(value) == "'" + value


@pytest.mark.parametrize("value", ["отчёт.txt", "1+1", "a=b", ""])
def test_safe_values_unchanged(value):
    assert neutralize_formula(value) == value


def parse_csv(raw: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(raw.decode("utf-8-sig")), delimiter=";"))


def test_csv_has_bom_and_russian_header():
    raw = result_to_csv(SAMPLE)
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = parse_csv(raw)
    assert rows[0][0] == "Имя файла"
    assert len(rows) == 1 + len(SAMPLE.rows)


def test_csv_contents_and_missing_values():
    rows = {r[0]: r for r in parse_csv(result_to_csv(SAMPLE))[1:]}
    assert rows["нет.txt"][1] == "Отсутствует"
    assert rows["нет.txt"][3] == "—" and rows["нет.txt"][5] == "—"
    assert rows["новый файл.txt"][1] == "Добавлен"
    assert rows["отчёт.txt"][4] == hash_bytes(b"1")


def test_csv_formula_filename_neutralized():
    result = make_result([], [rec("=HYPERLINK(\"http://x\")", b"1"), rec("-2+3", b"2")])
    names = [r[0] for r in parse_csv(result_to_csv(result))[1:]]
    assert all(name.startswith("'") for name in names)


def test_html_escapes_user_text():
    evil = '<script>alert("x")</script>&.txt'
    result = make_result([rec(evil, b"1")], [rec(evil, b"2"), rec("<img src=x onerror=1>", b"3")])
    html = result_to_html(result)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;.txt" in html
    assert "<img src=x" not in html
    assert "<script" not in html.lower()


def test_html_report_contents():
    html = result_to_html(SAMPLE)
    assert html.startswith("<!DOCTYPE html>")
    assert "2026-10-11T12:00:00Z" in html and "2026-10-11T10:00:00Z" in html
    assert "SHA-256" in html and APP_VERSION in html
    for status in Status:
        assert status.value in html
    for row in SAMPLE.rows:
        for h in (row.reference_hash, row.current_hash):
            if h:
                assert h in html
    assert "Обнаружены расхождения" in html
    assert "http://" not in html and "https://" not in html
    from html import escape
    for item in LIMITATIONS:
        assert escape(item) in html


def test_html_all_match_message():
    result = make_result([rec("a", b"1")], [rec("a", b"1")])
    assert "Загруженные файлы совпадают с эталоном." in result_to_html(result)
    assert "безопасн" not in result_to_html(result).split("Ограничения метода")[0]
