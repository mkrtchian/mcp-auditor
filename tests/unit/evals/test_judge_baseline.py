import json
from pathlib import Path

import tests.unit.evals.support.judge_baselines as judge_baselines
import tests.unit.evals.support.test_judge_baseline_given as given
from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import RetestRule
from evals.judge.baseline import (
    judge_baseline_integrity,
    judge_condition_mismatches,
    load_judge_baseline,
    write_judge_baseline,
)
from tests.unit.evals.support.judge_cases import a_case, a_fixture

PASS_ID = judge_baselines.PASS_ID


def test_a_baseline_holding_every_case_of_the_fixture_has_no_integrity_problem():
    assert (
        judge_baseline_integrity(judge_baselines.a_baseline(), judge_baselines.a_judge_fixture())
        == []
    )


def test_a_baseline_with_fewer_runs_than_its_conditions_claim_names_the_run_count():
    baseline = judge_baselines.a_baseline(runs=judge_baselines.correct_runs(2))

    problems = judge_baseline_integrity(baseline, judge_baselines.a_judge_fixture())

    assert problems == ["the baseline holds 2 runs, its conditions claim 3"]


def test_a_confirmed_baseline_holds_the_runs_of_both_recordings():
    confirms = RecordingRef(
        commit=judge_baselines.RECORDED_COMMIT, recorded_at="2026-09-28T11:00:00+00:00"
    )
    baseline = judge_baselines.a_baseline(runs=judge_baselines.correct_runs(3), confirms=confirms)

    problems = judge_baseline_integrity(baseline, judge_baselines.a_judge_fixture())

    assert problems == ["the baseline holds 3 runs, its conditions and its confirmation claim 6"]


def test_a_baseline_with_no_run_is_refused():
    problems = judge_baseline_integrity(
        judge_baselines.a_baseline(runs=[]), judge_baselines.a_judge_fixture()
    )

    assert problems == ["the baseline holds no run"]


def test_a_run_missing_a_case_of_the_fixture_names_it():
    runs = judge_baselines.correct_runs()
    del runs[1][PASS_ID]

    problems = judge_baseline_integrity(
        judge_baselines.a_baseline(runs=runs), judge_baselines.a_judge_fixture()
    )

    assert problems == [f"run 1: cases ['{PASS_ID}'] missing"]


def test_a_run_with_a_case_outside_the_fixture_names_it():
    runs = judge_baselines.correct_runs()
    runs[2]["0000000000000000"] = runs[2][PASS_ID]

    problems = judge_baseline_integrity(
        judge_baselines.a_baseline(runs=runs), judge_baselines.a_judge_fixture()
    )

    assert problems == ["run 2: cases ['0000000000000000'] unknown"]


def test_a_baseline_of_another_draw_is_not_checked_case_by_case():
    redrawn = a_fixture(a_case(description="A case of another draw"))

    assert judge_baseline_integrity(judge_baselines.a_baseline(), redrawn) == []


def test_identical_conditions_do_not_mismatch():
    assert (
        judge_condition_mismatches(judge_baselines.conditions(), judge_baselines.conditions()) == []
    )


def test_a_condition_mismatch_names_the_field():
    mismatches = judge_condition_mismatches(
        judge_baselines.conditions(runs=3), judge_baselines.conditions(runs=5)
    )

    assert mismatches == ["runs: baseline 3, candidate 5"]


def test_a_redraw_mismatches_on_the_inputs_fingerprint():
    redrawn = a_fixture(a_case(description="A case of another draw"))

    mismatches = judge_condition_mismatches(
        judge_baselines.conditions(), judge_baselines.conditions(fixture=redrawn)
    )

    assert len(mismatches) == 1
    assert mismatches[0].startswith("inputs_fingerprint: ")


def test_a_baseline_written_then_loaded_is_equal(tmp_path: Path):
    path = tmp_path / "baselines" / "judge.json"
    baseline = judge_baselines.a_baseline()

    write_judge_baseline(path, baseline)

    assert load_judge_baseline(path) == baseline


def test_a_baseline_written_over_another_replaces_it_and_leaves_no_temporary(tmp_path: Path):
    path = tmp_path / "judge.json"
    write_judge_baseline(path, judge_baselines.a_baseline())
    second = judge_baselines.a_baseline(status=BaselineStatus.UNCONFIRMED)

    write_judge_baseline(path, second)

    assert load_judge_baseline(path) == second
    assert list(tmp_path.glob("*.tmp")) == []


def test_loading_an_absent_baseline_gives_none(tmp_path: Path):
    assert load_judge_baseline(tmp_path / "missing.json") is None


def test_a_baseline_file_still_keyed_replay_rule_loads_its_retest_rule(tmp_path: Path):
    path = given.a_baseline_file_keyed_replay_rule(tmp_path)

    baseline = load_judge_baseline(path)

    assert baseline is not None and baseline.retest_rule == RetestRule()


def test_a_written_baseline_carries_the_retest_keys_only(tmp_path: Path):
    path = tmp_path / "judge.json"

    write_judge_baseline(path, judge_baselines.a_baseline())

    written = json.loads(path.read_text())
    assert written["retest_rule"] == RetestRule().model_dump()
    assert "replay_rule" not in written
