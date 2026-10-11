"""Создание и строгая проверка эталонного манифеста.

Манифест рассматривается только как данные: пути из него никогда не открываются,
а значения не интерпретируются как команды.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from hashing import MAX_FILES, FileRecord, filename_problem, is_valid_sha256

APP_NAME = "TrustFile"
APP_VERSION = "1.0.0"
SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})
HASH_ALGORITHM = "SHA-256"
MAX_MANIFEST_BYTES = 1024 * 1024


class ManifestError(ValueError):
    """Ошибка формата или содержимого манифеста (сообщение на русском)."""


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    app_version: str
    algorithm: str
    created_at: str
    files: tuple[FileRecord, ...]

    @property
    def file_count(self) -> int:
        return len(self.files)


def utc_now_iso() -> str:
    """Текущее время UTC в формате ISO 8601 с точностью до секунды."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_manifest(records: Iterable[FileRecord], created_at: str | None = None) -> dict[str, Any]:
    """Формирует словарь манифеста. Записи сортируются по имени файла."""
    ordered = sorted(records, key=lambda r: r.name)
    return {
        "schema_version": SCHEMA_VERSION,
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "created_at": created_at or utc_now_iso(),
        "file_count": len(ordered),
        "files": [{"name": r.name, "size": r.size, "sha256": r.sha256} for r in ordered],
    }


def manifest_to_bytes(manifest: dict[str, Any]) -> bytes:
    """Сериализует манифест в читаемый JSON (UTF-8, с отступами)."""
    return (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"В JSON повторяется ключ «{key}». Такой манифест неоднозначен.")
        result[key] = value
    return result


def _reject_constant(name: str) -> None:
    raise ManifestError(f"Недопустимое числовое значение в JSON: {name}.")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require(data: dict[str, Any], key: str, kind: type, label: str) -> Any:
    if key not in data:
        raise ManifestError(f"В манифесте отсутствует обязательное поле «{key}».")
    value = data[key]
    ok = _is_int(value) if kind is int else isinstance(value, kind)
    if not ok:
        raise ManifestError(f"Поле «{key}» должно быть {label}.")
    return value


def _parse_entry(index: int, entry: Any) -> FileRecord:
    position = f"Запись №{index + 1}"
    if not isinstance(entry, dict):
        raise ManifestError(f"{position} в списке файлов должна быть объектом.")
    for key in ("name", "size", "sha256"):
        if key not in entry:
            raise ManifestError(f"{position}: отсутствует поле «{key}».")

    name = entry["name"]
    problem = filename_problem(name)
    if problem:
        shown = name if isinstance(name, str) else repr(name)
        raise ManifestError(f"{position}: недопустимое имя «{shown[:80]}» — {problem}.")

    size = entry["size"]
    if not _is_int(size) or size < 0:
        raise ManifestError(f"{position} («{name}»): размер должен быть неотрицательным целым числом.")

    digest = entry["sha256"]
    if not is_valid_sha256(digest):
        raise ManifestError(
            f"{position} («{name}»): значение SHA-256 должно содержать ровно "
            "64 шестнадцатеричных символа."
        )
    return FileRecord(name=name, size=size, sha256=digest.lower())


def parse_manifest(raw: bytes) -> Manifest:
    """Разбирает и проверяет манифест. При любой ошибке выбрасывает ManifestError."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("Файл манифеста больше 1 МБ.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ManifestError("Манифест должен быть текстом в кодировке UTF-8.") from exc

    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ManifestError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        detail = f" (строка {exc.lineno}, позиция {exc.colno})" if isinstance(exc, json.JSONDecodeError) else ""
        raise ManifestError(f"Файл не является корректным JSON{detail}.") from exc

    if not isinstance(data, dict):
        raise ManifestError("Корнем манифеста должен быть JSON-объект.")

    schema = _require(data, "schema_version", int, "целым числом")
    if schema not in SUPPORTED_SCHEMA_VERSIONS:
        raise ManifestError(
            f"Версия схемы {schema} не поддерживается. Поддерживаемые версии: "
            + ", ".join(str(v) for v in sorted(SUPPORTED_SCHEMA_VERSIONS))
            + "."
        )

    algorithm = _require(data, "hash_algorithm", str, "строкой")
    if algorithm.strip().upper().replace("_", "-") not in {"SHA-256", "SHA256"}:
        raise ManifestError(f"Алгоритм «{algorithm[:40]}» не поддерживается. Ожидается SHA-256.")

    app_version = _require(data, "app_version", str, "строкой")
    created_at = _require(data, "created_at", str, "строкой")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestError("Поле «created_at» должно содержать дату в формате ISO 8601.") from exc

    file_count = _require(data, "file_count", int, "целым числом")
    entries = _require(data, "files", list, "списком")

    if len(entries) > MAX_FILES:
        raise ManifestError(f"В манифесте {len(entries)} записей. Максимум — {MAX_FILES}.")
    if file_count != len(entries):
        raise ManifestError(
            f"Поле «file_count» ({file_count}) не совпадает с числом записей ({len(entries)})."
        )

    records = [_parse_entry(i, e) for i, e in enumerate(entries)]
    names = [r.name for r in records]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ManifestError(
            "В манифесте повторяются имена файлов: " + ", ".join(f"«{d}»" for d in duplicates) + "."
        )

    return Manifest(
        schema_version=schema,
        app_version=app_version[:40],
        algorithm=HASH_ALGORITHM,
        created_at=created_at[:64],
        files=tuple(sorted(records, key=lambda r: r.name)),
    )
