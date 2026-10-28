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
