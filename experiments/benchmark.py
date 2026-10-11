"""Учебный эксперимент: чувствительность SHA-256 к изменению одного байта и время хеширования.

Запуск из каталога проекта:
    python experiments/benchmark.py
    python experiments/benchmark.py --repeats 21 --csv experiments/results/benchmark.csv

Используется тот же движок хеширования, что и в приложении (hashing.hash_stream).
Данные синтетические и детерминированные: при одинаковом seed байты всегда одинаковы.
"""

from __future__ import annotations

import argparse
import csv
import io
import platform
import random
import statistics
import sys
from pathlib import Path
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hashing import hash_stream  # noqa: E402

SIZES = (1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024)
SEED = 2026


def make_data(size: int, seed: int = SEED) -> bytes:
    return random.Random(seed + size).randbytes(size)


def flip_one_byte(data: bytes) -> tuple[bytes, int]:
    """Инвертирует младший бит байта в середине последовательности."""
    position = len(data) // 2
    changed = bytearray(data)
    changed[position] ^= 0x01
    return bytes(changed), position


def sha256(data: bytes) -> str:
    return hash_stream(io.BytesIO(data))[0]


def differing_bits(hex_a: str, hex_b: str) -> int:
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


def median_seconds(data: bytes, repeats: int) -> float:
    timings = []
    for _ in range(repeats):
        start = perf_counter()
        sha256(data)
        timings.append(perf_counter() - start)
    return statistics.median(timings)


def human_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} МиБ"
    if size >= 1024:
        return f"{size // 1024} КиБ"
    return f"{size} Б"


def run(repeats: int) -> list[dict[str, object]]:
    rows = []
    for size in SIZES:
        original = make_data(size)
        changed, position = flip_one_byte(original)
        h1, h2 = sha256(original), sha256(changed)
        h1_again = sha256(original)
        median = median_seconds(original, repeats)
        rows.append(
            {
                "size_bytes": size,
                "changed_byte_offset": position,
                "hash_original": h1,
                "hash_changed": h2,
                "repeat_identical": h1 == h1_again,
                "hashes_differ": h1 != h2,
                "differing_bits_of_256": differing_bits(h1, h2),
                "median_seconds": median,
                "throughput_mib_s": (size / (1024 * 1024)) / median if median > 0 else float("inf"),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Эксперимент TrustFile с SHA-256")
    parser.add_argument("--repeats", type=int, default=15, help="число повторов измерения (по умолчанию 15)")
    parser.add_argument("--csv", type=Path, help="сохранить результаты в CSV")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats должен быть не меньше 1")

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    rows = run(args.repeats)

    print("TrustFile — эксперимент с SHA-256")
    print(f"Python {platform.python_version()}, {platform.system()} {platform.release()}, {platform.machine()}")
    print(f"Seed: {SEED}. Повторов на размер: {args.repeats}. Изменение: 1 бит в 1 байте посередине.\n")
    header = f"{'Размер':>9} | {'Повтор = исходный':>17} | {'Хеши различны':>13} | {'Разных бит':>10} | {'Медиана, мс':>11} | {'МиБ/с':>8}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{human_size(r['size_bytes']):>9} | {('да' if r['repeat_identical'] else 'нет'):>17} | "
            f"{('да' if r['hashes_differ'] else 'нет'):>13} | {r['differing_bits_of_256']:>6} / 256 | "
            f"{r['median_seconds'] * 1000:>11.3f} | {r['throughput_mib_s']:>8.1f}"
        )

    print("\nПример (наименьший размер):")
    print(f"  исходный:   {rows[0]['hash_original']}")
    print(f"  изменённый: {rows[0]['hash_changed']}")

    print(
        "\nКак читать результаты:\n"
        "- Время зависит от компьютера, версии Python, нагрузки системы и режима питания;\n"
        "  это измерения на конкретной машине, а не характеристика алгоритма в целом.\n"
        "- Различие хешей после изменения одного байта — наблюдение на "
        f"{len(rows)} синтетических примерах.\n"
        "  Оно согласуется с ожидаемым «лавинным эффектом» (в среднем около 128 из 256 бит),\n"
        "  но не доказывает стойкость SHA-256 к коллизиям. Эта стойкость — теоретическое\n"
        "  свойство, основанное на криптоанализе, а не на подобных экспериментах.\n"
        "- Эксперимент не моделирует все возможные атаки, например одновременную подмену\n"
        "  файла и эталонного манифеста."
    )

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nРезультаты сохранены: {args.csv}")


if __name__ == "__main__":
    main()
