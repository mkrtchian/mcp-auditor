import pytest

from evals.tracing import tracing_enabled


@pytest.mark.parametrize(
    "value, expected",
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        (" TRUE ", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("", False),
    ],
)
def test_tracing_enabled_parses_the_flag(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    monkeypatch.setenv("LANGSMITH_TRACING", value)
    assert tracing_enabled() is expected


def test_tracing_enabled_is_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    assert tracing_enabled() is False


def test_tracing_enabled_reads_langchain_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    assert tracing_enabled() is True
