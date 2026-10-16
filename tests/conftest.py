"""Shared test fixtures.

The suite must not read the developer's `.env`. `load_settings` calls `load_dotenv`, which copies
`.env` values (LANGSMITH_TRACING among them) into `os.environ` for any key not already set. Because
that assignment is not a test's own monkeypatch, it outlives the test and leaks across the xdist
worker, so a later holdout run refuses on tracing before any other check. Neutralise it at the
source: no-op `load_dotenv` for every test, so `load_settings` reads only the real environment.
"""

import pytest


def _noop_load_dotenv(*_args: object, **_kwargs: object) -> bool:
    return False


@pytest.fixture(autouse=True)
def _no_dotenv_in_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mcp_auditor.config.load_dotenv", _noop_load_dotenv)
