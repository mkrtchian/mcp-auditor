"""A nuisance run stopped by an exception out of a server's runs: the pending servers are
cancelled and the finished ones are kept in a partial result. No Docker, no LLM."""

import pytest

import tests.unit.support.test_nuisance_run_given as given
from evals.nuisance_results import RunInterrupted
from evals.provider_errors import ProviderFatal


@pytest.fixture(autouse=True)
def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


async def test_a_fatal_provider_error_keeps_the_finished_server_in_a_partial_result():
    servers = [given.a_server(package) for package in ("npm:done", "npm:failing", "npm:pending")]
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit("npm:done", "npm:failing", fatal)

    with pytest.raises(RunInterrupted) as interrupted:
        await given.run(servers, given.deps_auditing(audit))

    assert interrupted.value.cause is fatal
    partial = interrupted.value.partial
    assert partial.partial
    assert [server.server_package for server in partial.servers] == ["npm:done"]


async def test_the_runs_still_in_flight_are_cancelled():
    servers = [given.a_server(package) for package in ("npm:done", "npm:failing", "npm:pending")]
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit("npm:done", "npm:failing", fatal)

    with pytest.raises(RunInterrupted):
        await given.run(servers, given.deps_auditing(audit))

    assert set(audit.cancelled) == {"npm:failing", "npm:pending"}


async def test_any_other_exception_interrupts_the_run_the_same_way():
    servers = [given.a_server(package) for package in ("npm:done", "npm:failing")]
    bug = KeyError("a bug in the run")
    audit = given.InterruptingAudit("npm:done", "npm:failing", bug)

    with pytest.raises(RunInterrupted) as interrupted:
        await given.run(servers, given.deps_auditing(audit))

    assert interrupted.value.cause is bug
    assert [server.server_package for server in interrupted.value.partial.servers] == ["npm:done"]
