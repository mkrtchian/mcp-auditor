from pathlib import Path

import pytest

import tests.unit.support.test_judge_session_given as given
from evals.baseline import BaselineStatus
from evals.eval_session import Refused, TreeState
from evals.gate import CellOutcome, Observation
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_baseline import load_judge_baseline
from evals.judge_session import JudgeHarness, JudgeOptions, run_judge_gate
from evals.run_judge_eval import judge_one_case
from mcp_auditor.domain.ports import ProviderRefusal, ProviderUsage, UnparseableOutput

FAIL, PASS = given.FAIL, given.PASS
FAIL_ID, PASS_ID = given.FAIL_ID, given.PASS_ID


async def _refused(options: JudgeOptions, harness: JudgeHarness) -> Refused:
    with pytest.raises(Refused) as refusal:
        await run_judge_gate(options, given.a_judge_fixture(), harness)
    return refusal.value


async def test_recording_ungated_is_refused_before_any_judge_call(tmp_path: Path):
    judge = given.ScriptedJudge()

    refusal = await _refused(
        given.options(record_baseline=True, ungated=True),
        given.a_harness(judge, tmp_path / "absent.json"),
    )

    assert "--ungated" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_a_broken_baseline_is_refused_before_any_judge_call(tmp_path: Path):
    judge = given.ScriptedJudge()

    refusal = await _refused(
        given.options(), given.a_harness(judge, given.a_broken_baseline_file(tmp_path))
    )

    assert "not a valid baseline" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_a_baseline_holding_fewer_runs_than_it_claims_is_refused_before_any_judge_call(
    tmp_path: Path,
):
    judge = given.ScriptedJudge()
    baseline = given.a_baseline(runs=given.runs_where(PASS_ID, Observation.PASS))

    refusal = await _refused(
        given.options(), given.a_harness(judge, given.a_baseline_file(tmp_path, baseline))
    )

    assert refusal.reasons == ["the baseline holds 1 runs, its conditions claim 3"]
    assert judge.total_calls() == 0


async def test_a_relabel_leaving_the_fail_side_blind_is_refused_before_any_judge_call(
    tmp_path: Path,
):
    judge = given.ScriptedJudge()
    never_detected = given.runs_where(FAIL_ID, *[Observation.PASS] * 3)
    path = given.a_baseline_file(tmp_path, given.a_baseline(runs=never_detected))

    refusal = await _refused(given.options(), given.a_harness(judge, path))

    assert len(refusal.reasons) == 1
    assert "no stable and correct FAIL case" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_recording_off_the_ci_conditions_is_refused_before_any_judge_call(tmp_path: Path):
    judge = given.ScriptedJudge()

    refusal = await _refused(
        given.options(runs=5, record_baseline=True),
        given.a_harness(judge, tmp_path / "absent.json"),
    )

    assert refusal.reasons == [
        "a baseline records the conditions CI runs at, runs: CI runs 3, this run 5"
    ]
    assert judge.total_calls() == 0


async def test_recording_on_a_dirty_tree_is_refused_before_any_judge_call(tmp_path: Path):
    judge = given.ScriptedJudge()
    dirty = TreeState(commit=given.RECORDED_COMMIT, dirty=True)

    refusal = await _refused(
        given.options(record_baseline=True),
        given.a_harness(judge, tmp_path / "absent.json", trees=[dirty]),
    )

    assert len(refusal.reasons) == 1
    assert "clean tree" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_recording_over_an_exploratory_baseline_of_another_commit_is_refused_early(
    tmp_path: Path,
):
    judge = given.ScriptedJudge()
    path = given.an_exploratory_baseline_file(tmp_path)

    refusal = await _refused(
        given.options(record_baseline=True),
        given.a_harness(judge, path, trees=[given.a_clean_tree("4567def")]),
    )

    assert len(refusal.reasons) == 1
    assert "4567def" in refusal.reasons[0]
    assert judge.total_calls() == 0


async def test_a_declaration_naming_a_case_outside_the_ground_truth_is_refused_early(
    tmp_path: Path,
):
    judge = given.ScriptedJudge()
    declarations = [given.a_declaration(given.UNSPECIFIED_ID)]

    refusal = await _refused(
        given.options(),
        given.a_harness(judge, tmp_path / "absent.json", declarations=declarations),
    )

    assert refusal.reasons == [
        f"declared flip {given.UNSPECIFIED_ID} names no cell of the ground truth"
    ]
    assert judge.total_calls() == 0


async def test_every_case_is_judged_once_per_run_and_the_gate_is_green(tmp_path: Path):
    judge = given.ScriptedJudge()

    result = await run_judge_gate(
        given.options(),
        given.a_judge_fixture(),
        given.a_harness(judge, given.a_baseline_file(tmp_path)),
    )

    assert set(judge.calls.values()) == {3}
    assert len(judge.calls) == 4
    assert result.gate.mode == GateMode.PAIRED
    assert result.gate.verdict == GateVerdict.GREEN
    assert result.exit_code == 0


async def test_a_flipped_case_is_replayed_until_it_reproduces_and_the_others_are_not(
    tmp_path: Path,
):
    judge = given.a_judge_flipping(PASS_ID, FAIL, PASS, PASS, FAIL, FAIL, FAIL, FAIL)

    result = await run_judge_gate(
        given.options(),
        given.a_judge_fixture(),
        given.a_harness(judge, given.a_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 3 + 4
    assert {case: count for case, count in judge.calls.items() if case != PASS_ID} == {
        case: 3 for case in judge.calls if case != PASS_ID
    }
    assert result.gate.cases[PASS_ID].outcome == CellOutcome.REGRESSION
    assert result.gate.verdict == GateVerdict.RED
    assert result.exit_code == 1


async def test_a_flip_cleared_twice_stops_its_replays_and_keeps_the_gate_green(tmp_path: Path):
    judge = given.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        given.options(),
        given.a_judge_fixture(),
        given.a_harness(judge, given.a_baseline_file(tmp_path)),
    )

    assert result.gate.cases[PASS_ID].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert result.gate.cases[PASS_ID].replays == [False, False]
    assert result.exit_code == 0


async def test_a_replay_whose_judge_call_raised_counts_as_reproduced(tmp_path: Path):
    judge = given.a_judge_flipping(PASS_ID, None, PASS, PASS, None, None, None, None)

    result = await run_judge_gate(
        given.options(),
        given.a_judge_fixture(),
        given.a_harness(judge, given.a_baseline_file(tmp_path)),
    )

    assert Observation.UNCOVERED in [run[PASS_ID] for run in result.runs]
    assert result.gate.cases[PASS_ID].replays == [True, True, True, True]
    assert result.gate.cases[PASS_ID].outcome == CellOutcome.REGRESSION


async def test_a_declared_flip_is_not_replayed(tmp_path: Path):
    judge = given.a_judge_flipping(PASS_ID, FAIL, FAIL, FAIL)

    result = await run_judge_gate(
        given.options(),
        given.a_judge_fixture(),
        given.a_harness(
            judge, given.a_baseline_file(tmp_path), declarations=[given.a_declaration(PASS_ID)]
        ),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.gate.cases[PASS_ID].outcome == CellOutcome.DECLARED
    assert result.exit_code == 0


async def test_no_flip_is_replayed_against_an_exploratory_baseline(tmp_path: Path):
    judge = given.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        given.options(),
        given.a_judge_fixture(),
        given.a_harness(judge, given.an_exploratory_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.gate.mode == GateMode.FLOORS_ONLY
    assert result.exit_code == 0


async def test_no_flip_is_replayed_under_ungated(tmp_path: Path):
    judge = given.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        given.options(ungated=True),
        given.a_judge_fixture(),
        given.a_harness(judge, given.a_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.gate.mode == GateMode.FLOORS_ONLY
    assert result.gate.cases == {}


async def test_other_conditions_than_the_baseline_are_not_comparable_and_replay_nothing(
    tmp_path: Path,
):
    judge = given.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        given.options(runs=4),
        given.a_judge_fixture(),
        given.a_harness(judge, given.a_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 4
    assert result.gate.verdict == GateVerdict.NOT_COMPARABLE
    assert result.exit_code == 3


async def test_a_first_recording_writes_an_exploratory_baseline(tmp_path: Path):
    path = tmp_path / "judge_isolation.json"

    result = await run_judge_gate(
        given.options(record_baseline=True),
        given.a_judge_fixture(),
        given.a_harness(given.ScriptedJudge(), path),
    )

    written = load_judge_baseline(path)
    assert written is not None
    assert written.status == BaselineStatus.EXPLORATORY
    assert written.commit == given.RECORDED_COMMIT
    assert written.recorded_at == "2026-09-28T14:00:00+00:00"
    assert result.written == written
    assert result.exit_code == 0


async def test_a_recording_is_refused_when_the_tree_drifted_during_the_runs(tmp_path: Path):
    path = tmp_path / "judge_isolation.json"
    trees = [given.a_clean_tree(), given.a_clean_tree("4567def")]

    result = await run_judge_gate(
        given.options(record_baseline=True),
        given.a_judge_fixture(),
        given.a_harness(given.ScriptedJudge(), path, trees=trees),
    )

    assert not path.exists()
    assert result.written is None
    assert len(result.recording_refused) == 1
    assert "HEAD moved" in result.recording_refused[0]
    assert result.exit_code == 3


async def test_a_recording_refused_by_its_decision_writes_nothing(tmp_path: Path):
    path = tmp_path / "judge_isolation.json"
    judge = given.a_judge_flipping(PASS_ID, None)

    result = await run_judge_gate(
        given.options(record_baseline=True),
        given.a_judge_fixture(),
        given.a_harness(judge, path),
    )

    assert not path.exists()
    assert "a judge call failed on case" in result.recording_refused[0]
    assert result.exit_code == 3


@pytest.mark.parametrize(
    "error",
    [
        UnparseableOutput(attempts=3, truncated_attempts=0, usage=ProviderUsage()),
        ProviderRefusal("blocked by policy", ProviderUsage()),
    ],
)
async def test_a_judge_call_that_fails_to_answer_is_uncovered(error: Exception):
    [case, *_] = given.a_judge_fixture().cases

    assert await judge_one_case(given.RaisingLLM(error), case) is None


async def test_any_other_judge_call_failure_propagates():
    [case, *_] = given.a_judge_fixture().cases

    with pytest.raises(ConnectionError):
        await judge_one_case(given.RaisingLLM(ConnectionError("network down")), case)
