from pathlib import Path

import pytest

import tests.unit.evals.support.judge_baselines as judge_baselines
import tests.unit.evals.support.judge_sessions as judge_sessions
from evals.baseline import BaselineStatus
from evals.gate import CellOutcome, Observation
from evals.gate_outcome import GateMode, GateOutcome
from evals.judge.baseline import load_judge_baseline
from evals.judge.session import run_judge_gate

FAIL, PASS = judge_sessions.FAIL, judge_sessions.PASS
FAIL_ID, PASS_ID = judge_baselines.FAIL_ID, judge_baselines.PASS_ID


async def test_every_case_is_judged_once_per_run_and_the_gate_is_green(tmp_path: Path):
    judge = judge_sessions.ScriptedJudge()

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert set(judge.calls.values()) == {3}
    assert len(judge.calls) == 4
    assert result.gate.mode == GateMode.PAIRED
    assert result.gate.outcome == GateOutcome.GREEN
    assert result.retest_observations == {}
    assert result.exit_code == 0


async def test_a_run_returns_the_baseline_it_compared_to(tmp_path: Path):
    path = judge_sessions.a_baseline_file(tmp_path)

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge_sessions.ScriptedJudge(), path),
    )

    assert result.baseline == load_judge_baseline(path)


async def test_a_run_with_no_baseline_file_returns_none_for_it(tmp_path: Path):
    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge_sessions.ScriptedJudge(), tmp_path / "absent.json"),
    )

    assert result.baseline is None


async def test_a_flipped_case_is_retested_until_it_reproduces_and_the_others_are_not(
    tmp_path: Path,
):
    judge = judge_sessions.a_judge_flipping(PASS_ID, FAIL, PASS, PASS, FAIL, FAIL, FAIL, FAIL)
    announced: list[int] = []

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(
            judge, judge_sessions.a_baseline_file(tmp_path), on_retests=announced.append
        ),
    )

    assert announced == [1]
    assert result.retest_observations == {PASS_ID: [Observation.FAIL] * 4}
    assert judge.calls[PASS_ID] == 3 + 4
    assert {case: count for case, count in judge.calls.items() if case != PASS_ID} == {
        case: 3 for case in judge.calls if case != PASS_ID
    }
    assert result.gate.cases[PASS_ID].outcome == CellOutcome.REGRESSION
    assert result.gate.outcome == GateOutcome.RED
    assert result.exit_code == 1


async def test_a_flip_cleared_twice_stops_its_retests_and_keeps_the_gate_green(tmp_path: Path):
    judge = judge_sessions.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert result.gate.cases[PASS_ID].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert result.gate.cases[PASS_ID].retests == [False, False]
    assert result.retest_observations == {PASS_ID: [Observation.PASS] * 2}
    assert result.exit_code == 0


async def test_a_retest_whose_judge_call_raised_counts_as_reproduced(tmp_path: Path):
    judge = judge_sessions.a_judge_flipping(PASS_ID, None, PASS, PASS, None, None, None, None)

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert Observation.UNCOVERED in [run[PASS_ID] for run in result.runs]
    assert result.gate.cases[PASS_ID].retests == [True, True, True, True]
    assert result.retest_observations == {PASS_ID: [Observation.UNCOVERED] * 4}
    assert result.gate.cases[PASS_ID].outcome == CellOutcome.REGRESSION


async def test_nothing_is_announced_when_no_case_flipped(tmp_path: Path):
    announced: list[int] = []

    await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(
            judge_sessions.ScriptedJudge(),
            judge_sessions.a_baseline_file(tmp_path),
            on_retests=announced.append,
        ),
    )

    assert announced == []


async def test_a_declared_flip_is_not_retested(tmp_path: Path):
    judge = judge_sessions.a_judge_flipping(PASS_ID, FAIL, FAIL, FAIL)

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(
            judge,
            judge_sessions.a_baseline_file(tmp_path),
            declarations=[judge_sessions.a_declaration(PASS_ID)],
        ),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.gate.cases[PASS_ID].outcome == CellOutcome.DECLARED
    assert result.exit_code == 0


async def test_no_flip_is_retested_against_an_unconfirmed_baseline(tmp_path: Path):
    judge = judge_sessions.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.an_unconfirmed_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.gate.mode == GateMode.FLOORS_ONLY
    assert result.exit_code == 0


async def test_no_flip_is_retested_in_a_no_baseline_run(tmp_path: Path):
    judge = judge_sessions.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        judge_sessions.options(no_baseline=True),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.gate.mode == GateMode.FLOORS_ONLY
    assert result.gate.cases == {}
    assert result.baseline is None


async def test_other_conditions_than_the_baseline_are_not_comparable_and_retest_nothing(
    tmp_path: Path,
):
    judge = judge_sessions.a_judge_flipping(PASS_ID, FAIL)

    result = await run_judge_gate(
        judge_sessions.options(runs=4),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 4
    assert result.gate.outcome == GateOutcome.NOT_COMPARABLE
    assert result.exit_code == 3


@pytest.mark.parametrize("no_baseline", [False, True])
async def test_a_throttled_run_judgment_is_not_comparable_and_retests_nothing(
    tmp_path: Path, no_baseline: bool
):
    judge = judge_sessions.a_judge_flipping(PASS_ID, judge_sessions.THROTTLED_JUDGMENT)

    result = await run_judge_gate(
        judge_sessions.options(no_baseline=no_baseline),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert judge.calls[PASS_ID] == 3
    assert result.retest_observations == {}
    assert result.gate.outcome == GateOutcome.NOT_COMPARABLE
    assert result.gate.reasons == [_throttle_mismatch(1)]
    assert result.throttled_judgments == [PASS_ID]
    assert result.exit_code == 3


def _throttle_mismatch(count: int) -> str:
    return (
        f"{count} judgment(s) throttled by the model provider past every retry:"
        " the run cannot be compared"
    )


async def test_a_throttled_retest_cannot_read_as_a_reproduced_flip(tmp_path: Path):
    judge = judge_sessions.a_judge_flipping(
        PASS_ID, FAIL, PASS, PASS, *(judge_sessions.THROTTLED_JUDGMENT,) * 4
    )

    result = await run_judge_gate(
        judge_sessions.options(),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, judge_sessions.a_baseline_file(tmp_path)),
    )

    assert result.retest_observations == {PASS_ID: [Observation.UNCOVERED] * 4}
    assert result.gate.outcome == GateOutcome.NOT_COMPARABLE
    assert result.gate.reasons == [_throttle_mismatch(4)]
    assert result.exit_code == 3


async def test_a_first_recording_writes_an_unconfirmed_baseline(tmp_path: Path):
    path = tmp_path / "judge.json"

    result = await run_judge_gate(
        judge_sessions.options(record_baseline=True),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge_sessions.ScriptedJudge(), path),
    )

    written = load_judge_baseline(path)
    assert written is not None
    assert written.status == BaselineStatus.UNCONFIRMED
    assert written.commit == judge_baselines.RECORDED_COMMIT
    assert written.recorded_at == "2026-09-28T14:00:00+00:00"
    assert result.written == written
    assert result.exit_code == 0


async def test_a_recording_is_refused_when_the_tree_drifted_during_the_runs(tmp_path: Path):
    path = tmp_path / "judge.json"
    trees = [judge_sessions.a_clean_tree(), judge_sessions.a_clean_tree("4567def")]

    result = await run_judge_gate(
        judge_sessions.options(record_baseline=True),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge_sessions.ScriptedJudge(), path, trees=trees),
    )

    assert not path.exists()
    assert result.written is None
    assert len(result.recording_refused) == 1
    assert "HEAD moved" in result.recording_refused[0]
    assert result.exit_code == 3


async def test_a_recording_refused_by_its_decision_writes_nothing(tmp_path: Path):
    path = tmp_path / "judge.json"
    judge = judge_sessions.a_judge_flipping(PASS_ID, None)

    result = await run_judge_gate(
        judge_sessions.options(record_baseline=True),
        judge_baselines.a_judge_fixture(),
        judge_sessions.a_harness(judge, path),
    )

    assert not path.exists()
    assert "a judge call failed on case" in result.recording_refused[0]
    assert result.exit_code == 3
