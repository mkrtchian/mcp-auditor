"""A holdout run stopped by an exception out of a target's runs: the pending targets are
cancelled and the finished ones are kept in a partial result. No Docker, no LLM."""

import pytest

import tests.unit.detection.support.test_detection_holdout_run_interrupted_given as given
from evals.cve.detection.holdout_results import RunInterrupted
from evals.cve.provider_errors import ProviderFatal
from tests.unit.support import holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, KUBERNETES


async def test_a_fatal_provider_error_keeps_the_finished_target_in_a_partial_result():
    finished, failing, pending = given.holdout_targets(FILESYSTEM, KUBERNETES, GIT)
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit(finished.flaw_id, failing.flaw_id, fatal)

    with pytest.raises(RunInterrupted) as interrupted:
        await holdout_runs.run([finished, failing, pending], holdout_runs.deps_auditing(audit))

    assert interrupted.value.cause is fatal
    partial = interrupted.value.partial
    assert partial.partial
    assert [target.flaw_id for target in partial.targets] == [finished.flaw_id]


async def test_the_runs_still_in_flight_are_cancelled():
    finished, failing, pending = given.holdout_targets(FILESYSTEM, KUBERNETES, GIT)
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit(finished.flaw_id, failing.flaw_id, fatal)

    with pytest.raises(RunInterrupted):
        await holdout_runs.run([finished, failing, pending], holdout_runs.deps_auditing(audit))

    assert set(audit.cancelled) == {failing.flaw_id, pending.flaw_id}


async def test_any_other_exception_interrupts_the_run_the_same_way():
    finished, failing = given.holdout_targets(FILESYSTEM, KUBERNETES)
    bug = KeyError("a bug in the run")
    audit = given.InterruptingAudit(finished.flaw_id, failing.flaw_id, bug)

    with pytest.raises(RunInterrupted) as interrupted:
        await holdout_runs.run([finished, failing], holdout_runs.deps_auditing(audit))

    assert interrupted.value.cause is bug
    assert [target.flaw_id for target in interrupted.value.partial.targets] == [finished.flaw_id]
