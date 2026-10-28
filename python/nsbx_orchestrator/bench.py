"""Smoke samples for the benchmark method in design §15.2.

The full method is 100 warm-up runs and at least 2,000 samples on bare metal.
This module records a short sample list. It does not report a performance result.
"""

from __future__ import annotations


def summarize(samples_ms: list[int]) -> dict[str, object]:
    if len(samples_ms) < 3:
        raise ValueError("a smoke sample needs at least 3 measurements")
    ordered = sorted(samples_ms)
    return {
        "samples": len(samples_ms),
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
        "method": "smoke",
    }


def percentiles(samples_ms: list[int]) -> dict[str, object]:
    """Percentiles of one measured series.

    `method` is `measured` only at the design's 2,000-sample size. A shorter
    run is `measured-short` so it cannot be quoted as that study.
    """
    if not samples_ms:
        raise ValueError("no samples")
    ordered = sorted(samples_ms)
    count = len(ordered)

    def at(percent: float) -> int:
        index = min(count - 1, round((percent / 100) * (count - 1)))
        return ordered[index]

    return {
        "samples": count,
        "min_ms": ordered[0],
        "p50_ms": at(50),
        "p95_ms": at(95),
        "p99_ms": at(99),
        "max_ms": ordered[-1],
        "method": "measured" if count >= 2000 else "measured-short",
    }
