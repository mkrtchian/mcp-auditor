from pathlib import Path

import pytest

import tests.unit.evals.support.judge_baselines as judge_baselines
import tests.unit.evals.support.judge_sessions as judge_sessions
from evals.eval_session import Refused, TreeState
from evals.gate import Observation
from evals.judge.session import run_judge_gate
from evals.judge.session_model import JudgeHarness, JudgeOptions

FAIL_ID, PASS_ID = judge_baselines.FAIL_ID, judge_baselines.PASS_ID


async def test_recording_without_a_baseline_is_refused_before_any_judge_call(tmp_path: Path):
    judge = judge_sessions.ScriptedJudge()

    refusal = await _refused(
        judge_sessions.options(record_baseline=True, no_baseline=True),
        judge_sessions.a_harness(judge, tmp_path / "absent.json"),
    )

    assert "--no-baseline" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def _refused(options: JudgeOptions, harness: JudgeHarness) -> Refused:
    with pytest.raises(Refused) as refusal:
        await run_judge_gate(options, judge_baselines.a_judge_fixture(), harness)
    return refusal.value


async def test_a_broken_baseline_is_refused_before_any_judge_call(tmp_path: Path):
    judge = judge_sessions.ScriptedJudge()

    refusal = await _refused(
        judge_sessions.options(),
        judge_sessions.a_harness(judge, judge_sessions.a_broken_baseline_file(tmp_path)),
    )

    assert "not a valid baseline" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_a_baseline_holding_fewer_runs_than_it_claims_is_refused_before_any_judge_call(
    tmp_path: Path,
):
    judge = judge_sessions.ScriptedJudge()
    baseline = judge_baselines.a_baseline(
        runs=judge_baselines.runs_where(PASS_ID, Observation.PASS)
    )

    refusal = await _refused(
        judge_sessions.options(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path, baseline)),
    )

    assert refusal.reasons == ["the baseline holds 1 runs, its conditions claim 3"]
    assert judge.total_calls() == 0


async def test_a_relabel_leaving_the_fail_side_blind_is_refused_before_any_judge_call(
    tmp_path: Path,
):
    judge = judge_sessions.ScriptedJudge()
    never_detected = judge_baselines.runs_where(FAIL_ID, *[Observation.PASS] * 3)
    path = judge_sessions.a_baseline_file(tmp_path, judge_baselines.a_baseline(runs=never_detected))

    refusal = await _refused(judge_sessions.options(), judge_sessions.a_harness(judge, path))

    assert len(refusal.reasons) == 1
    assert "no stable and correct FAIL case" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_recording_off_the_ci_conditions_is_refused_before_any_judge_call(tmp_path: Path):
    judge = judge_sessions.ScriptedJudge()

    refusal = await _refused(
        judge_sessions.options(runs=5, record_baseline=True),
        judge_sessions.a_harness(judge, tmp_path / "absent.json"),
    )

    assert refusal.reasons == [
        "a baseline records the conditions CI runs at, runs: CI runs 3, this run 5"
    ]
    assert judge.total_calls() == 0


async def test_recording_on_a_dirty_tree_is_refused_before_any_judge_call(tmp_path: Path):
    judge = judge_sessions.ScriptedJudge()
    dirty = TreeState(commit=judge_baselines.RECORDED_COMMIT, dirty=True)

    refusal = await _refused(
        judge_sessions.options(record_baseline=True),
        judge_sessions.a_harness(judge, tmp_path / "absent.json", trees=[dirty]),
    )

    assert len(refusal.reasons) == 1
    assert "clean tree" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_recording_over_an_unconfirmed_baseline_of_another_commit_is_refused_early(
    tmp_path: Path,
):
    judge = judge_sessions.ScriptedJudge()
    path = judge_sessions.an_unconfirmed_baseline_file(tmp_path)

    refusal = await _refused(
        judge_sessions.options(record_baseline=True),
        judge_sessions.a_harness(judge, path, trees=[judge_sessions.a_clean_tree("4567def")]),
    )

    assert len(refusal.reasons) == 1
    assert "4567def" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_a_declaration_naming_a_case_outside_the_fixture_is_refused_early(
    tmp_path: Path,
):
    judge = judge_sessions.ScriptedJudge()
    declarations = [judge_sessions.a_declaration(judge_baselines.UNSPECIFIED_ID)]

    refusal = await _refused(
        judge_sessions.options(),
        judge_sessions.a_harness(judge, tmp_path / "absent.json", declarations=declarations),
    )

    assert refusal.reasons == [
        f"declared flip {judge_baselines.UNSPECIFIED_ID} names no judge case of the fixture"
    ]
    assert judge.total_calls() == 0
