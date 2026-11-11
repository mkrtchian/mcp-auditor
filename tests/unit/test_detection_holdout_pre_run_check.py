"""The pre-run check of a holdout run, with the calibration check and the layout observation
scripted: a target the parallel pass would drop is checked once more, alone, and runs if that pass
is clean.
No Docker, no LLM."""

import tests.unit.support.test_detection_holdout_pre_run_check_given as given
import tests.unit.support.test_detection_holdout_pre_run_check_then as then
from evals.cve.detection.holdout_pre_run_check import check_before_run
from evals.cve.detection.holdout_results import NotRunCause


async def test_a_target_out_of_calibration_on_its_first_pass_runs_when_its_second_pass_is_clean():
    flaky, *_ = given.TARGETS
    checks = given.ScriptedChecks(
        out_of_calibration={
            flaky.flaw_id: [["vulnerable: exploit 3 surfaces no nonce"], given.LIVE]
        }
    )

    outcome = await check_before_run(given.TARGETS, checks.check, checks.layout)

    assert outcome.surviving == list(given.TARGETS)
    assert outcome.not_run == []
    assert outcome.second_pass == [flaky.flaw_id]


async def test_a_target_the_layout_breaks_once_runs_when_its_second_pass_is_clean():
    flaky, *_ = given.TARGETS
    checks = given.ScriptedChecks(layouts={flaky.flaw_id: [given.BROKEN, given.SOUND]})

    outcome = await check_before_run(given.TARGETS, checks.check, checks.layout)

    assert flaky in outcome.surviving
    assert outcome.second_pass == [flaky.flaw_id]


async def test_a_target_failing_both_passes_is_dropped_with_the_second_reason():
    unfit, *healthy = given.TARGETS
    checks = given.ScriptedChecks(
        out_of_calibration={
            unfit.flaw_id: [
                ["vulnerable: exploit 3 surfaces no nonce"],
                ["patched: exploit 0 surfaces"],
            ]
        }
    )

    outcome = await check_before_run(given.TARGETS, checks.check, checks.layout)

    assert outcome.surviving == healthy
    (not_run,) = outcome.not_run
    assert (not_run.flaw_id, not_run.cause) == (unfit.flaw_id, NotRunCause.PRE_RUN_CHECK)
    assert not_run.reason == "out of calibration: patched: exploit 0 surfaces"
    assert outcome.second_pass == []


async def test_a_target_passing_its_first_pass_is_checked_once():
    checks = given.ScriptedChecks()

    outcome = await check_before_run(given.TARGETS, checks.check, checks.layout)

    assert outcome.surviving == list(given.TARGETS)
    assert [checks.passes(target.flaw_id) for target in given.TARGETS] == [1, 1, 1]
    assert outcome.second_pass == []


async def test_the_second_passes_run_one_at_a_time_after_every_first_pass():
    first, second, _ = given.TARGETS
    checks = given.ScriptedChecks(
        out_of_calibration={first.flaw_id: [["exploit 0 surfaces no nonce"], given.LIVE]},
        layouts={second.flaw_id: [given.BROKEN, given.SOUND]},
    )

    await check_before_run(given.TARGETS, checks.check, checks.layout)

    then.second_passes_ran_alone_after_every_first_pass(checks.events, len(given.TARGETS))
