import hashlib
import io

import pytest

from hashing import (
    MAX_BATCH_SIZE,
    MAX_FILE_SIZE,
    MAX_FILES,
    FileRecord,
    filename_problem,
    hash_bytes,
    hash_files,
    hash_stream,
    is_valid_sha256,
    normalize_expected_hash,
    validate_batch,
)

# Тестовые векторы FIPS 180-2 / NIST.
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
TWO_BLOCK = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
MILLION_A = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"", EMPTY),
        (b"abc", ABC),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", TWO_BLOCK),
        (b"a" * 1_000_000, MILLION_A),
    ],
    ids=["empty", "abc", "two-block", "million-a"],
)
def test_known_vectors(data, expected):
    assert hash_bytes(data) == expected
    assert hash_stream(io.BytesIO(data)) == (expected, len(data))


def test_empty_file():
    assert hash_files([("пустой.txt", io.BytesIO(b""))]) == [FileRecord("пустой.txt", 0, EMPTY)]


def test_binary_data_all_byte_values():
    data = bytes(range(256)) * 37
    assert hash_stream(io.BytesIO(data)) == (hashlib.sha256(data).hexdigest(), len(data))


@pytest.mark.parametrize("chunk_size", [1, 7, 63, 64, 65, 4096, 1 << 20])
def test_chunked_matches_one_shot(chunk_size):
    data = bytes((i * 31 + 7) % 256 for i in range(10_000))
    assert hash_stream(io.BytesIO(data), chunk_size=chunk_size)[0] == hash_bytes(data)


def test_stream_without_readinto():
    class ReadOnly:
        def __init__(self, data: bytes):
            self._buf = io.BytesIO(data)

        def read(self, n: int) -> bytes:
            return self._buf.read(n)

    data = b"x" * 200_000
    assert hash_stream(ReadOnly(data)) == (hash_bytes(data), len(data))


def test_identical_bytes_identical_hash_and_changed_byte_differs():
    data = bytearray(b"TrustFile fixture " * 100)
    first = hash_bytes(bytes(data))
    assert hash_bytes(bytes(data)) == first
    data[500] ^= 0x01
    assert hash_bytes(bytes(data)) != first


def test_hash_files_sorted_and_rewinds_stream():
    stream = io.BytesIO(b"abc")
    stream.read()
    records = hash_files([("б файл.txt", io.BytesIO(b"")), ("а файл.txt", stream)])
    assert [r.name for r in records] == ["а файл.txt", "б файл.txt"]
    assert records[0].sha256 == ABC


@pytest.mark.parametrize("name", ["отчёт.txt", "файл с пробелами.docx", "data.bin", ".hidden", "заметка: v2.txt"])
def test_accepts_flat_names(name):
    assert filename_problem(name) is None


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "../secret", "dir/file", "dir\\file", "/etc/passwd", "C:\\x", "C:x", "a:b.txt",
     "nul\x00byte", "tab\tname", "x" * 256, None, 5],
)
def test_rejects_unsafe_names(name):
    assert filename_problem(name) is not None


def test_validate_batch_ok():
    assert validate_batch([("a.txt", 0), ("b.txt", MAX_FILE_SIZE)]) == []


def test_validate_batch_duplicates():
    errors = validate_batch([("a.txt", 1), ("b.txt", 1), ("a.txt", 2)])
    assert len(errors) == 1
    assert "Повторяющиеся имена" in errors[0] and "«a.txt»" in errors[0]


def test_duplicates_are_case_sensitive():
    assert validate_batch([("A.txt", 1), ("a.txt", 1)]) == []


def test_file_count_limit():
    assert validate_batch([(f"{i}.txt", 1) for i in range(MAX_FILES)]) == []
    errors = validate_batch([(f"{i}.txt", 1) for i in range(MAX_FILES + 1)])
    assert any("Максимум — 50" in e for e in errors)


def test_file_size_limit():
    errors = validate_batch([("big.bin", MAX_FILE_SIZE + 1)])
    assert len(errors) == 1 and "big.bin" in errors[0]


def test_batch_size_limit():
    per_file = MAX_FILE_SIZE
    count = MAX_BATCH_SIZE // per_file
    assert validate_batch([(f"{i}.bin", per_file) for i in range(count)]) == []
    errors = validate_batch([(f"{i}.bin", per_file) for i in range(count)] + [("extra.bin", 1)])
    assert any("Общий размер" in e for e in errors)


def test_expected_hash_normalization():
    assert normalize_expected_hash("  " + ABC.upper() + "  ") == ABC
    assert normalize_expected_hash(f"{ABC}  file.txt") == ABC


@pytest.mark.parametrize("value", ["", "   ", ABC[:-1], ABC + "0", "g" * 64, "0x" + ABC[:62], ABC[:32] + " " + ABC[32:]])
def test_expected_hash_invalid(value):
    with pytest.raises(ValueError):
        normalize_expected_hash(value)


def test_is_valid_sha256():
    assert is_valid_sha256(ABC) and is_valid_sha256(ABC.upper())
    assert not is_valid_sha256(ABC + "\n")
    assert not is_valid_sha256(None)
