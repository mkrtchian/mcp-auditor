"""The pre-run check inside a detection holdout run: a target out of calibration or broken by the
layout under the normal launch leaves N, a fallback target stays, a target clean on its solo second
pass runs and is named, and a run where no target survives refuses. No Docker, no LLM."""

import dataclasses

import pytest

import tests.unit.detection.support.test_detection_holdout_pre_run_check_given as pre_run_check
from evals.cve.detection.holdout_results import NotRunCause
from evals.cve.detection.targets import LaunchMode
from evals.eval_session import Refused
from tests.unit.detection.support.layouts import SOUND_LAYOUT
from tests.unit.support import detection_holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, KUBERNETES


async def test_a_target_out_of_calibration_is_not_run():
    unfit, healthy = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    audit = detection_holdout_runs.scripted(
        {unfit.flaw_id: [], healthy.flaw_id: detection_holdout_runs.three_detections()}
    )
    deps = detection_holdout_runs.deps_auditing(
        audit, check={unfit.flaw_id: ["patched: exploit 0 still surfaces etc-shadow"]}
    )

    result = await detection_holdout_runs.run([unfit, healthy], deps)

    assert [t.flaw_id for t in result.targets] == [healthy.flaw_id]
    (not_run,) = result.not_run
    assert not_run.flaw_id == unfit.flaw_id
    assert "patched: exploit 0 still surfaces etc-shadow" in not_run.reason
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_normal_target_the_layout_breaks_is_dropped():
    broken, healthy = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    audit = detection_holdout_runs.scripted(
        {broken.flaw_id: [], healthy.flaw_id: detection_holdout_runs.three_detections()}
    )
    deps = detection_holdout_runs.deps_auditing(
        audit,
        layout={broken.flaw_id: dataclasses.replace(SOUND_LAYOUT, breaks=True)},
    )

    result = await detection_holdout_runs.run([broken, healthy], deps)

    assert [t.flaw_id for t in result.targets] == [healthy.flaw_id]
    (not_run,) = result.not_run
    assert not_run.flaw_id == broken.flaw_id
    assert not_run.reason == "the layout breaks the server under the normal launch"
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_fallback_target_the_layout_breaks_is_kept():
    target = detection_holdout_runs.a_target(KUBERNETES, launch_mode=LaunchMode.FALLBACK)
    audit = detection_holdout_runs.scripted(
        {target.flaw_id: detection_holdout_runs.three_detections()}
    )
    deps = detection_holdout_runs.deps_auditing(
        audit,
        layout={target.flaw_id: dataclasses.replace(SOUND_LAYOUT, breaks=True)},
    )

    result = await detection_holdout_runs.run([target], deps)

    (assembled,) = result.targets
    assert assembled.ran_in_fallback is True
    assert result.not_run == []


async def test_a_target_clean_on_its_solo_second_pre_run_pass_runs_and_is_named():
    flaky = detection_holdout_runs.a_target(KUBERNETES)
    audit = detection_holdout_runs.scripted(
        {flaky.flaw_id: detection_holdout_runs.three_detections()}
    )
    checks = pre_run_check.ScriptedChecks(
        out_of_calibration={flaky.flaw_id: [["vulnerable: exploit 3 surfaces no nonce"], []]}
    )
    deps = dataclasses.replace(
        detection_holdout_runs.deps_auditing(audit), check=checks.check, layout=checks.layout
    )

    result = await detection_holdout_runs.run([flaky], deps)

    assert [t.flaw_id for t in result.targets] == [flaky.flaw_id]
    assert result.not_run == []
    assert result.second_pass == [flaky.flaw_id]


async def test_every_target_dropped_refuses_with_the_reasons():
    unfit, broken = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    deps = detection_holdout_runs.deps_auditing(
        detection_holdout_runs.scripted({unfit.flaw_id: [], broken.flaw_id: []}),
        check={unfit.flaw_id: ["patched: exploit 0 still surfaces etc-shadow"]},
        layout={broken.flaw_id: dataclasses.replace(SOUND_LAYOUT, breaks=True)},
    )

    with pytest.raises(Refused, match="no target survived") as caught:
        await detection_holdout_runs.run([unfit, broken], deps)

    reasons = caught.value.reasons
    assert any("etc-shadow" in reason for reason in reasons)
    assert any("the layout breaks" in reason for reason in reasons)
