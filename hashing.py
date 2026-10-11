"""Вычисление SHA-256 и проверка входных файлов.

Модуль не обращается к файловой системе: файлы передаются как потоки байтов,
а имена используются только как идентификаторы.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import BinaryIO, Iterable

CHUNK_SIZE = 64 * 1024
MAX_FILES = 50
MAX_FILE_SIZE = 20 * 1024 * 1024
MAX_BATCH_SIZE = 100 * 1024 * 1024
MAX_FILENAME_LENGTH = 255

SHA256_HEX_LENGTH = 64
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class FileRecord:
    """Цифровой отпечаток одного файла."""

    name: str
    size: int
    sha256: str


def hash_stream(stream: BinaryIO, chunk_size: int = CHUNK_SIZE) -> tuple[str, int]:
    """Вычисляет SHA-256 потока по частям и возвращает (хеш, размер в байтах).

    Используется один переиспользуемый буфер, поэтому содержимое файла
    не копируется целиком.
    """
    if chunk_size <= 0:
        raise ValueError("Размер блока должен быть положительным.")
    digest = hashlib.sha256()
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)
    total = 0
    readinto = getattr(stream, "readinto", None)
    while True:
        if readinto is not None:
            count = readinto(buffer)
            if not count:
                break
            digest.update(view[:count])
        else:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            count = len(chunk)
            digest.update(chunk)
        total += count
    return digest.hexdigest(), total


def hash_bytes(data: bytes) -> str:
    """Вычисляет SHA-256 для байтов в памяти."""
    return hashlib.sha256(data).hexdigest()


def is_valid_sha256(value: object) -> bool:
    """Проверяет, что значение — строка ровно из 64 шестнадцатеричных символов."""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def normalize_expected_hash(text: str) -> str:
    """Очищает введённый пользователем хеш и приводит его к нижнему регистру.

    Допускаются пробелы по краям и формат вывода утилит вида «<хеш>  <имя>».
    """
    candidate = (text or "").strip()
    if candidate:
        candidate = candidate.split()[0]
    if not candidate:
        raise ValueError("Введите ожидаемое значение SHA-256.")
    if not is_valid_sha256(candidate):
        raise ValueError(
            "Значение SHA-256 должно состоять ровно из 64 шестнадцатеричных "
            f"символов (0–9, a–f). Получено символов: {len(candidate)}."
        )
    return candidate.lower()


def filename_problem(name: object) -> str | None:
    """Возвращает описание проблемы с именем файла или None, если имя допустимо.

    Имя должно быть плоским: без путей, переходов в родительский каталог,
    управляющих символов и нулевых байтов.
    """
    if not isinstance(name, str):
        return "имя файла должно быть строкой"
    if not name:
        return "имя файла пустое"
    if len(name) > MAX_FILENAME_LENGTH:
        return f"имя файла длиннее {MAX_FILENAME_LENGTH} символов"
    if "\x00" in name:
        return "имя содержит нулевой байт"
    if "/" in name or "\\" in name:
        return "имя содержит разделитель пути; поддерживаются только плоские наборы файлов"
    if name in {".", ".."}:
        return "имя указывает на каталог"
    if _WINDOWS_DRIVE_RE.match(name):
        return "имя похоже на абсолютный путь Windows"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return "имя содержит управляющие символы"
    return None


def validate_batch(items: Iterable[tuple[str, int]]) -> list[str]:
    """Проверяет набор (имя, размер) до вычисления хешей.

    Возвращает список понятных сообщений об ошибках; пустой список — набор допустим.
    """
    items = list(items)
    errors: list[str] = []

    if len(items) > MAX_FILES:
        errors.append(f"Выбрано файлов: {len(items)}. Максимум — {MAX_FILES}.")

    seen: set[str] = set()
    duplicates: list[str] = []
    total = 0
    for name, size in items:
        problem = filename_problem(name)
        if problem:
            errors.append(f"Недопустимое имя «{name}»: {problem}.")
        if name in seen and name not in duplicates:
            duplicates.append(name)
        seen.add(name)
        if size > MAX_FILE_SIZE:
            errors.append(
                f"Файл «{name}» занимает {size:,} байт. Максимум — "
                f"{MAX_FILE_SIZE:,} байт (20 МБ).".replace(",", " ")
            )
        total += size

    if duplicates:
        listed = ", ".join(f"«{d}»" for d in duplicates)
        errors.append(
            f"Повторяющиеся имена файлов: {listed}. Имя служит идентификатором файла, "
            "поэтому в одном наборе оно должно быть уникальным. Переименуйте файлы "
            "или проверьте их отдельными наборами."
        )

    if total > MAX_BATCH_SIZE:
        errors.append(
            f"Общий размер набора — {total:,} байт. Максимум — "
            f"{MAX_BATCH_SIZE:,} байт (100 МБ).".replace(",", " ")
        )
    return errors


def hash_files(files: Iterable[tuple[str, BinaryIO]]) -> list[FileRecord]:
    """Вычисляет отпечатки для набора (имя, поток) и сортирует их по имени."""
    records = []
    for name, stream in files:
        if hasattr(stream, "seek"):
            stream.seek(0)
        digest, size = hash_stream(stream)
        records.append(FileRecord(name=name, size=size, sha256=digest))
    return sorted(records, key=lambda r: r.name)
