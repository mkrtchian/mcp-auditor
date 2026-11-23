"""Shared test fixtures.

The suite must not read the developer's `.env`. `load_settings` calls `load_dotenv`, which copies
`.env` values (LANGSMITH_TRACING among them) into `os.environ` for any key not already set. Because
that assignment is not a test's own monkeypatch, it outlives the test and leaks across the xdist
worker, so a later holdout run refuses on tracing before any other check. python-dotenv skips
loading while `PYTHON_DOTENV_DISABLED` is set, in the test process and in every subprocess a test
starts, so `load_settings` reads only the real environment.
"""

import pytest

from evals.tracing import TRACING_VARIABLES


@pytest.fixture(autouse=True)
def _no_dotenv_in_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")


@pytest.fixture(autouse=True)
def _no_tracing_in_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """`.env` loading is disabled already, but a tracing flag exported in the shell still reaches
    the tests."""
    for name in TRACING_VARIABLES:
        monkeypatch.delenv(name, raising=False)
