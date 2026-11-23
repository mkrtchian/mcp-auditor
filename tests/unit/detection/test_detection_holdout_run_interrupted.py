"""A detection holdout run stopped by an exception out of a target's runs: the pending targets are
cancelled and the finished ones are kept in a partial result. No Docker, no LLM."""

import pytest

import tests.unit.detection.support.test_detection_holdout_run_interrupted_given as given
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.provider_errors import ProviderFatal
from evals.cve.run_files import RunInterrupted
from tests.unit.support import detection_holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, KUBERNETES


async def test_a_fatal_provider_error_keeps_the_finished_target_in_a_partial_result():
    finished, failing, pending = (
        detection_holdout_runs.a_target(flaw_id) for flaw_id in (FILESYSTEM, KUBERNETES, GIT)
    )
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit(finished.flaw_id, failing.flaw_id, fatal)

    with pytest.raises(RunInterrupted) as interrupted:
        await detection_holdout_runs.run(
            [finished, failing, pending], detection_holdout_runs.deps_auditing(audit)
        )

    assert interrupted.value.cause is fatal
    partial = interrupted.value.partial
    assert isinstance(partial, DetectionHoldoutRunResult)
    assert partial.partial
    assert [target.flaw_id for target in partial.targets] == [finished.flaw_id]


async def test_the_runs_still_in_flight_are_cancelled():
    finished, failing, pending = (
        detection_holdout_runs.a_target(flaw_id) for flaw_id in (FILESYSTEM, KUBERNETES, GIT)
    )
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit(finished.flaw_id, failing.flaw_id, fatal)

    with pytest.raises(RunInterrupted):
        await detection_holdout_runs.run(
            [finished, failing, pending], detection_holdout_runs.deps_auditing(audit)
        )

    assert set(audit.cancelled) == {failing.flaw_id, pending.flaw_id}


async def test_any_other_exception_interrupts_the_run_the_same_way():
    finished, failing = (
        detection_holdout_runs.a_target(FILESYSTEM),
        detection_holdout_runs.a_target(KUBERNETES),
    )
    bug = KeyError("a bug in the run")
    audit = given.InterruptingAudit(finished.flaw_id, failing.flaw_id, bug)

    with pytest.raises(RunInterrupted) as interrupted:
        await detection_holdout_runs.run(
            [finished, failing], detection_holdout_runs.deps_auditing(audit)
        )

    assert interrupted.value.cause is bug
    partial = interrupted.value.partial
    assert isinstance(partial, DetectionHoldoutRunResult)
    assert [target.flaw_id for target in partial.targets] == [finished.flaw_id]
