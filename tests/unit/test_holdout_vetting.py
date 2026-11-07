"""The holdout pre-run check, with the dead-condition check and the layout observation scripted:
a target the parallel pass would drop is vetted once more, alone, and runs if that pass is clean.
No Docker, no LLM."""

import tests.unit.support.test_holdout_vetting_given as given
import tests.unit.support.test_holdout_vetting_then as then
from evals.holdout_results import NotRunCause
from evals.holdout_vetting import vet_all


async def test_a_target_dead_on_its_first_pass_runs_when_its_second_pass_is_clean():
    flaky, *_ = given.TARGETS
    checks = given.ScriptedChecks(dead={flaky.cve_id: [["vulnerable: exploit 3 dead"], given.LIVE]})

    outcome = await vet_all(given.TARGETS, checks.check, checks.layout)

    assert outcome.surviving == list(given.TARGETS)
    assert outcome.not_run == []
    assert outcome.second_pass == [flaky.cve_id]


async def test_a_target_the_layout_breaks_once_runs_when_its_second_pass_is_clean():
    flaky, *_ = given.TARGETS
    checks = given.ScriptedChecks(layouts={flaky.cve_id: [given.BROKEN, given.SOUND]})

    outcome = await vet_all(given.TARGETS, checks.check, checks.layout)

    assert flaky in outcome.surviving
    assert outcome.second_pass == [flaky.cve_id]


async def test_a_target_failing_both_passes_is_dropped_with_the_second_reason():
    dead, *healthy = given.TARGETS
    checks = given.ScriptedChecks(
        dead={dead.cve_id: [["vulnerable: exploit 3 dead"], ["patched: exploit 0 surfaces"]]}
    )

    outcome = await vet_all(given.TARGETS, checks.check, checks.layout)

    assert outcome.surviving == healthy
    (not_run,) = outcome.not_run
    assert (not_run.cve_id, not_run.cause) == (dead.cve_id, NotRunCause.PRE_RUN_CHECK)
    assert not_run.reason == "dead on a version: patched: exploit 0 surfaces"
    assert outcome.second_pass == []


async def test_a_target_passing_its_first_pass_is_vetted_once():
    checks = given.ScriptedChecks()

    outcome = await vet_all(given.TARGETS, checks.check, checks.layout)

    assert outcome.surviving == list(given.TARGETS)
    assert [checks.passes(target.cve_id) for target in given.TARGETS] == [1, 1, 1]
    assert outcome.second_pass == []


async def test_the_second_passes_run_one_at_a_time_after_every_first_pass():
    first, second, _ = given.TARGETS
    checks = given.ScriptedChecks(
        dead={first.cve_id: [["exploit 0 dead"], given.LIVE]},
        layouts={second.cve_id: [given.BROKEN, given.SOUND]},
    )

    await vet_all(given.TARGETS, checks.check, checks.layout)

    then.second_passes_ran_alone_after_every_first_pass(checks.events, len(given.TARGETS))
