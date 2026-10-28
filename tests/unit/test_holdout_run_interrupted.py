"""A holdout run stopped by an exception out of a target's runs: the pending targets are
cancelled and the finished ones are kept in a partial result. No Docker, no LLM."""

import pytest

import tests.unit.support.test_holdout_run_given as given
from evals.holdout_results import RunInterrupted
from evals.provider_errors import ProviderFatal


@pytest.fixture(autouse=True)
def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


async def test_a_fatal_provider_error_keeps_the_finished_target_in_a_partial_result():
    finished, failing, pending = (
        given.a_target(given.FILESYSTEM),
        given.a_target(given.KUBERNETES),
        given.a_target(given.GIT),
    )
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit(finished.cve_id, failing.cve_id, fatal)

    with pytest.raises(RunInterrupted) as interrupted:
        await given.run([finished, failing, pending], given.deps_auditing(audit))

    assert interrupted.value.cause is fatal
    partial = interrupted.value.partial
    assert partial.partial
    assert [target.cve_id for target in partial.targets] == [finished.cve_id]


async def test_the_runs_still_in_flight_are_cancelled():
    finished, failing, pending = (
        given.a_target(given.FILESYSTEM),
        given.a_target(given.KUBERNETES),
        given.a_target(given.GIT),
    )
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit(finished.cve_id, failing.cve_id, fatal)

    with pytest.raises(RunInterrupted):
        await given.run([finished, failing, pending], given.deps_auditing(audit))

    assert set(audit.cancelled) == {failing.cve_id, pending.cve_id}


async def test_any_other_exception_interrupts_the_run_the_same_way():
    finished, failing = given.a_target(given.FILESYSTEM), given.a_target(given.KUBERNETES)
    bug = KeyError("a bug in the run")
    audit = given.InterruptingAudit(finished.cve_id, failing.cve_id, bug)

    with pytest.raises(RunInterrupted) as interrupted:
        await given.run([finished, failing], given.deps_auditing(audit))

    assert interrupted.value.cause is bug
    assert [target.cve_id for target in interrupted.value.partial.targets] == [finished.cve_id]
