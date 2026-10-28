import pytest

from nsbx_orchestrator.bench import summarize


def test_summarize_records_a_smoke_sample() -> None:
    got = summarize([12, 4, 9])
    assert got == {"samples": 3, "min_ms": 4, "max_ms": 12, "method": "smoke"}


def test_summarize_refuses_a_short_sample() -> None:
    with pytest.raises(ValueError):
        summarize([1, 2])
