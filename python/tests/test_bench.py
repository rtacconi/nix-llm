import pytest

from nsbx_orchestrator.bench import percentiles, summarize


def test_summarize_records_a_smoke_sample() -> None:
    got = summarize([12, 4, 9])
    assert got == {"samples": 3, "min_ms": 4, "max_ms": 12, "method": "smoke"}


def test_summarize_refuses_a_short_sample() -> None:
    with pytest.raises(ValueError):
        summarize([1, 2])


def test_percentiles_keep_a_short_run_out_of_the_full_study() -> None:
    short = percentiles([5, 4, 9])
    assert short["method"] == "measured-short"
    assert short["samples"] == 3
    assert short["p50_ms"] == 5
    full = percentiles([1] * 2000)
    assert full["method"] == "measured"
    assert full["samples"] == 2000
