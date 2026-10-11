"""Сравнение текущего набора файлов с эталонным манифестом."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from hashing import FileRecord
from manifest import Manifest, utc_now_iso


class Status(str, Enum):
    MATCH = "Совпадает"
    CHANGED = "Изменён"
    MISSING = "Отсутствует"
    ADDED = "Добавлен"


STATUS_ORDER = (Status.CHANGED, Status.MISSING, Status.ADDED, Status.MATCH)


@dataclass(frozen=True)
class ComparisonRow:
    name: str
    status: Status
    reference_size: int | None
    current_size: int | None
    reference_hash: str | None
    current_hash: str | None


@dataclass(frozen=True)
class ComparisonResult:
    rows: tuple[ComparisonRow, ...]
    manifest_created_at: str
    verified_at: str = field(default_factory=utc_now_iso)

    def count(self, status: Status) -> int:
        return sum(1 for row in self.rows if row.status is status)

    @property
    def summary(self) -> dict[Status, int]:
        return {status: self.count(status) for status in STATUS_ORDER}

    @property
    def all_match(self) -> bool:
        return bool(self.rows) and all(row.status is Status.MATCH for row in self.rows)


def compare_records(
    reference: Iterable[FileRecord], current: Iterable[FileRecord]
) -> list[ComparisonRow]:
    """Сопоставляет записи по точному имени файла (с учётом регистра).

    Переименованный файл даёт две строки: «Отсутствует» и «Добавлен».
    Сначала идут расхождения, затем совпадения; внутри группы — по имени.
    """
    ref_by_name = {r.name: r for r in reference}
    cur_by_name = {r.name: r for r in current}
    rows: list[ComparisonRow] = []

    for name in ref_by_name.keys() | cur_by_name.keys():
        ref = ref_by_name.get(name)
        cur = cur_by_name.get(name)
        if ref is None:
            status = Status.ADDED
        elif cur is None:
            status = Status.MISSING
        elif ref.sha256 == cur.sha256 and ref.size == cur.size:
            status = Status.MATCH
        else:
            status = Status.CHANGED
        rows.append(
            ComparisonRow(
                name=name,
                status=status,
                reference_size=ref.size if ref else None,
                current_size=cur.size if cur else None,
                reference_hash=ref.sha256 if ref else None,
                current_hash=cur.sha256 if cur else None,
            )
        )

    rows.sort(key=lambda row: (STATUS_ORDER.index(row.status), row.name))
    return rows


def compare_with_manifest(manifest: Manifest, current: Iterable[FileRecord]) -> ComparisonResult:
    return ComparisonResult(
        rows=tuple(compare_records(manifest.files, current)),
        manifest_created_at=manifest.created_at,
    )


def hashes_match(calculated: str, expected: str) -> bool:
    """Сравнивает два шестнадцатеричных SHA-256 без учёта регистра."""
    return calculated.strip().lower() == expected.strip().lower()
