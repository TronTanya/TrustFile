import io

from comparison import Status, compare_records, compare_with_manifest, hashes_match
from demo import CHANGED_FILES, REFERENCE_FILES, run_demo_comparison
from hashing import FileRecord, hash_bytes, hash_files
from manifest import build_manifest, manifest_to_bytes, parse_manifest


def rec(name: str, data: bytes) -> FileRecord:
    return FileRecord(name, len(data), hash_bytes(data))


def by_name(rows):
    return {row.name: row for row in rows}


def test_all_four_statuses():
    reference = [rec("same.txt", b"1"), rec("changed.txt", b"old"), rec("missing.txt", b"x")]
    current = [rec("same.txt", b"1"), rec("changed.txt", b"new"), rec("added.txt", b"y")]
    rows = by_name(compare_records(reference, current))

    assert rows["same.txt"].status is Status.MATCH
    assert rows["changed.txt"].status is Status.CHANGED
    assert rows["missing.txt"].status is Status.MISSING
    assert rows["added.txt"].status is Status.ADDED

    assert rows["missing.txt"].current_size is None and rows["missing.txt"].current_hash is None
    assert rows["added.txt"].reference_size is None and rows["added.txt"].reference_hash is None
    assert rows["changed.txt"].reference_hash != rows["changed.txt"].current_hash


def test_status_labels():
    assert [s.value for s in Status] == ["Совпадает", "Изменён", "Отсутствует", "Добавлен"]


def test_rows_ordered_problems_first():
    reference = [rec("a.txt", b"1"), rec("b.txt", b"2")]
    current = [rec("a.txt", b"1"), rec("b.txt", b"3")]
    assert [r.status for r in compare_records(reference, current)] == [Status.CHANGED, Status.MATCH]


def test_renamed_file_is_missing_plus_added():
    data = b"same content"
    rows = by_name(compare_records([rec("old name.txt", data)], [rec("new name.txt", data)]))
    assert rows["old name.txt"].status is Status.MISSING
    assert rows["new name.txt"].status is Status.ADDED
    assert len(rows) == 2


def test_case_sensitive_names():
    rows = by_name(compare_records([rec("Report.txt", b"1")], [rec("report.txt", b"1")]))
    assert rows["Report.txt"].status is Status.MISSING
    assert rows["report.txt"].status is Status.ADDED


def test_size_mismatch_with_same_hash_is_changed():
    reference = [FileRecord("a", 1, "a" * 64)]
    current = [FileRecord("a", 2, "a" * 64)]
    assert compare_records(reference, current)[0].status is Status.CHANGED


def test_full_cycle_through_manifest_all_match():
    files = {"отчёт.txt": b"text", "пустой файл": b"", "bin.dat": bytes(range(256))}
    records = hash_files((n, io.BytesIO(d)) for n, d in files.items())
    manifest = parse_manifest(manifest_to_bytes(build_manifest(records)))
    result = compare_with_manifest(manifest, hash_files((n, io.BytesIO(d)) for n, d in files.items()))
    assert result.all_match
    assert result.summary[Status.MATCH] == 3


def test_empty_comparison_is_not_all_match():
    manifest = parse_manifest(manifest_to_bytes(build_manifest([])))
    assert not compare_with_manifest(manifest, []).all_match


def test_demo_sets_cover_every_status():
    assert len(REFERENCE_FILES) == 3
    result = run_demo_comparison()
    assert {s: result.count(s) for s in Status} == {
        Status.MATCH: 1,
        Status.CHANGED: 1,
        Status.MISSING: 1,
        Status.ADDED: 1,
    }
    rows = by_name(result.rows)
    assert rows["readme.txt"].status is Status.MATCH
    assert rows["отчёт.txt"].status is Status.CHANGED
    assert rows["данные измерений.csv"].status is Status.MISSING
    assert rows["приложение.txt"].status is Status.ADDED
    assert not result.all_match


def test_demo_modified_file_differs_by_one_character():
    a = REFERENCE_FILES["отчёт.txt"].decode("utf-8")
    b = CHANGED_FILES["отчёт.txt"].decode("utf-8")
    assert len(a) == len(b)
    assert sum(x != y for x, y in zip(a, b)) == 1


def test_hashes_match_case_insensitive():
    h = hash_bytes(b"abc")
    assert hashes_match(h, h.upper())
    assert not hashes_match(h, hash_bytes(b"abd"))
