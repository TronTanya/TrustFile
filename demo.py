"""Демонстрационные наборы файлов с заранее известным содержимым."""

from __future__ import annotations

import io
import zipfile

from comparison import ComparisonResult, compare_with_manifest
from hashing import FileRecord, hash_files
from manifest import build_manifest, parse_manifest, manifest_to_bytes

REFERENCE_FILES: dict[str, bytes] = {
    "отчёт.txt": "Отчёт по лабораторной работе №1.\nРезультат: 42.\n".encode("utf-8"),
    "данные измерений.csv": "время;значение\n0;1.00\n1;1.25\n2;1.50\n".encode("utf-8"),
    "readme.txt": "Демонстрационный набор TrustFile.\n".encode("utf-8"),
}

# Один неизменённый файл, один изменённый (одна цифра), один удалён, один новый.
CHANGED_FILES: dict[str, bytes] = {
    "readme.txt": REFERENCE_FILES["readme.txt"],
    "отчёт.txt": "Отчёт по лабораторной работе №1.\nРезультат: 43.\n".encode("utf-8"),
    "приложение.txt": "Новый файл, которого нет в эталоне.\n".encode("utf-8"),
}


def records_for(files: dict[str, bytes]) -> list[FileRecord]:
    return hash_files((name, io.BytesIO(data)) for name, data in files.items())


def demo_manifest_bytes(created_at: str | None = None) -> bytes:
    return manifest_to_bytes(build_manifest(records_for(REFERENCE_FILES), created_at=created_at))


def zip_files(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return buffer.getvalue()


def run_demo_comparison() -> ComparisonResult:
    """Полный цикл на демонстрационных данных: манифест → проверка → сравнение."""
    manifest = parse_manifest(demo_manifest_bytes())
    return compare_with_manifest(manifest, records_for(CHANGED_FILES))
