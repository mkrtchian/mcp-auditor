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
    monkeypatch.setenv("LANGSMITH_TRACING", value)
    assert tracing_enabled() is expected


def test_tracing_enabled_is_false_when_unset() -> None:
    assert tracing_enabled() is False


@pytest.mark.parametrize(
    "name",
    ["LANGSMITH_TRACING", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING", "LANGCHAIN_TRACING_V2"],
)
def test_tracing_enabled_reads_each_variable_langsmith_reads(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv(name, "true")
    assert tracing_enabled() is True
