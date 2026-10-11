import json

import pytest

from hashing import MAX_FILES, FileRecord
from manifest import (
    APP_VERSION,
    MAX_MANIFEST_BYTES,
    SCHEMA_VERSION,
    ManifestError,
    build_manifest,
    manifest_to_bytes,
    parse_manifest,
)

H1 = "a" * 64
H2 = "0123456789abcdef" * 4

RECORDS = [
    FileRecord("файл с пробелом.txt", 10, H1),
    FileRecord("отчёт.docx", 0, H2),
]


def valid_dict() -> dict:
    return build_manifest(RECORDS, created_at="2026-10-11T12:00:00Z")


def encode(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def test_build_manifest_fields_and_order():
    m = valid_dict()
    assert m["schema_version"] == SCHEMA_VERSION
    assert m["app_version"] == APP_VERSION
    assert m["hash_algorithm"] == "SHA-256"
    assert m["file_count"] == 2
    assert [f["name"] for f in m["files"]] == sorted(r.name for r in RECORDS)
    assert set(m["files"][0]) == {"name", "size", "sha256"}


def test_default_timestamp_is_utc():
    assert build_manifest(RECORDS)["created_at"].endswith("Z")


def test_round_trip():
    raw = manifest_to_bytes(valid_dict())
    assert "файл с пробелом.txt" in raw.decode("utf-8")
    parsed = parse_manifest(raw)
    assert parsed.created_at == "2026-10-11T12:00:00Z"
    assert list(parsed.files) == sorted(RECORDS, key=lambda r: r.name)


def test_accepts_bom_and_normalizes_uppercase_hash():
    data = valid_dict()
    data["files"][0]["sha256"] = data["files"][0]["sha256"].upper()
    parsed = parse_manifest(b"\xef\xbb\xbf" + encode(data))
    assert all(r.sha256 == r.sha256.lower() for r in parsed.files)


def test_empty_file_list_is_valid():
    parsed = parse_manifest(manifest_to_bytes(build_manifest([], created_at="2026-01-01T00:00:00Z")))
    assert parsed.file_count == 0


@pytest.mark.parametrize("raw", [b"", b"{", b"not json", b"[1, 2]", b"null", "{}".encode("utf-16"), b"\xff\xfe"])
def test_malformed(raw):
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_too_large():
    with pytest.raises(ManifestError, match="1 МБ"):
        parse_manifest(b" " * (MAX_MANIFEST_BYTES + 1))


def test_deeply_nested_json_rejected():
    depth = 100_000
    with pytest.raises(ManifestError):
        parse_manifest(b"[" * depth + b"]" * depth)


def test_duplicate_top_level_key():
    raw = encode(valid_dict())[:-1] + b', "file_count": 2}'
    with pytest.raises(ManifestError, match="повторяется ключ"):
        parse_manifest(raw)


def test_duplicate_key_in_entry():
    raw = (
        '{"schema_version":1,"app_version":"1","hash_algorithm":"SHA-256",'
        '"created_at":"2026-01-01T00:00:00Z","file_count":1,'
        f'"files":[{{"name":"a","size":1,"sha256":"{H1}","sha256":"{H2}"}}]}}'
    ).encode()
    with pytest.raises(ManifestError, match="повторяется ключ"):
        parse_manifest(raw)


@pytest.mark.parametrize("version", [0, 2, "1", 1.0, True, None])
def test_unsupported_schema(version):
    data = valid_dict()
    data["schema_version"] = version
    with pytest.raises(ManifestError):
        parse_manifest(encode(data))


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-1", "sha512", "", 256])
def test_unsupported_algorithm(algorithm):
    data = valid_dict()
    data["hash_algorithm"] = algorithm
    with pytest.raises(ManifestError):
        parse_manifest(encode(data))


@pytest.mark.parametrize("field", ["schema_version", "app_version", "hash_algorithm", "created_at", "file_count", "files"])
def test_missing_required_field(field):
    data = valid_dict()
    del data[field]
    with pytest.raises(ManifestError, match=field):
        parse_manifest(encode(data))


@pytest.mark.parametrize(
    "field, value",
    [("app_version", 1), ("created_at", 123), ("created_at", "вчера"), ("file_count", "2"), ("files", {})],
)
def test_wrong_field_types(field, value):
    data = valid_dict()
    data[field] = value
    with pytest.raises(ManifestError):
        parse_manifest(encode(data))


def test_file_count_mismatch():
    data = valid_dict()
    data["file_count"] = 3
    with pytest.raises(ManifestError, match="file_count"):
        parse_manifest(encode(data))


def test_too_many_entries():
    files = [{"name": f"{i}.txt", "size": 1, "sha256": H1} for i in range(MAX_FILES + 1)]
    data = valid_dict() | {"files": files, "file_count": len(files)}
    with pytest.raises(ManifestError, match="Максимум"):
        parse_manifest(encode(data))


def test_duplicate_filenames():
    data = valid_dict()
    data["files"][1]["name"] = data["files"][0]["name"]
    with pytest.raises(ManifestError, match="повторяются имена"):
        parse_manifest(encode(data))


@pytest.mark.parametrize("size", [-1, 1.5, "10", None, True])
def test_invalid_sizes(size):
    data = valid_dict()
    data["files"][0]["size"] = size
    with pytest.raises(ManifestError, match="размер"):
        parse_manifest(encode(data))


@pytest.mark.parametrize("digest", ["", "a" * 63, "a" * 65, "z" * 64, " " + "a" * 63, None, 123])
def test_invalid_hash_format(digest):
    data = valid_dict()
    data["files"][0]["sha256"] = digest
    with pytest.raises(ManifestError, match="SHA-256"):
        parse_manifest(encode(data))


@pytest.mark.parametrize(
    "name",
    ["/etc/passwd", "C:\\Windows\\win.ini", "C:x", "..", "../a.txt", "sub/a.txt", "sub\\a.txt",
     "a\x00.txt", "", "x" * 300, 42],
)
def test_unsafe_names_rejected(name):
    data = valid_dict()
    data["files"][0]["name"] = name
    with pytest.raises(ManifestError, match="недопустимое имя"):
        parse_manifest(encode(data))


def test_entry_must_be_object_with_fields():
    data = valid_dict()
    data["files"][0] = ["a", 1, H1]
    with pytest.raises(ManifestError):
        parse_manifest(encode(data))
    data = valid_dict()
    del data["files"][0]["sha256"]
    with pytest.raises(ManifestError, match="sha256"):
        parse_manifest(encode(data))


def test_nan_rejected():
    raw = encode(valid_dict()).replace(b'"file_count": 2', b'"file_count": NaN')
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_manifest_contains_no_paths_or_contents():
    raw = manifest_to_bytes(valid_dict()).decode("utf-8")
    data = json.loads(raw)
    assert set(data) == {"schema_version", "app", "app_version", "hash_algorithm", "created_at", "file_count", "files"}
