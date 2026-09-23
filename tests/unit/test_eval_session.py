import tests.unit.support.test_eval_session_given as given
from evals.baseline import BaselineStatus
from evals.eval_session import (
    TreeState,
    baseline_changed,
    ci_condition_mismatches,
    pre_run_refusals,
    select_mode,
    tree_drift,
)
from evals.gate_verdict import GateMode
from evals.recording import exploratory_commit_refusal
from mcp_auditor.config import Settings

OTHER_COMMIT = "4567def"


def test_ungated_gates_on_floors_only_even_with_a_confirmed_baseline():
    baseline = given.a_baseline_at_ci_conditions(BaselineStatus.CONFIRMED)

    assert select_mode(baseline, ungated=True) == GateMode.FLOORS_ONLY


def test_no_baseline_gates_on_the_legacy_thresholds():
    assert select_mode(None, ungated=False) == GateMode.LEGACY_THRESHOLDS


def test_an_exploratory_baseline_gates_on_floors_only():
    baseline = given.a_baseline_at_ci_conditions(BaselineStatus.EXPLORATORY)

    assert select_mode(baseline, ungated=False) == GateMode.FLOORS_ONLY


def test_a_confirmed_baseline_gates_paired():
    baseline = given.a_baseline_at_ci_conditions(BaselineStatus.CONFIRMED)

    assert select_mode(baseline, ungated=False) == GateMode.PAIRED


def test_a_run_without_baseline_nor_recording_is_not_refused():
    assert pre_run_refusals(given.a_session()) == []


def test_a_baseline_at_other_conditions_names_the_mismatch():
    session = given.a_session(
        baseline=given.a_baseline_at_ci_conditions(), conditions=given.ci_conditions(budget=7)
    )

    reasons = pre_run_refusals(session)

    assert reasons == ["budget: baseline 10, candidate 7"]


def test_recording_on_a_dirty_tree_is_refused():
    session = given.a_session(tree=TreeState(commit=given.HEAD, dirty=True))

    reasons = pre_run_refusals(session)

    assert len(reasons) == 1
    assert "clean tree" in reasons[0]


def test_recording_at_other_ci_conditions_is_refused():
    session = given.a_session(tree=given.a_clean_tree(), conditions=given.ci_conditions(budget=7))

    reasons = pre_run_refusals(session)

    assert reasons == [
        "a baseline records the conditions CI runs at, budget: CI runs 10, this run 7"
    ]


def test_recording_over_an_exploratory_baseline_at_another_commit_is_refused():
    baseline = given.a_baseline_at_ci_conditions(BaselineStatus.EXPLORATORY)
    session = given.a_session(baseline=baseline, tree=given.a_clean_tree(OTHER_COMMIT))

    reasons = pre_run_refusals(session)

    assert reasons == exploratory_commit_refusal(baseline, OTHER_COMMIT)
    assert reasons != []


def test_an_unchanged_tree_has_no_drift():
    tree = given.a_clean_tree()

    assert tree_drift(tree, tree) == []


def test_a_tree_dirtied_during_the_runs_is_named():
    drift = tree_drift(given.a_clean_tree(), TreeState(commit=given.HEAD, dirty=True))

    assert len(drift) == 1
    assert "tracked files changed" in drift[0]


def test_a_moved_commit_names_both_commits():
    drift = tree_drift(given.a_clean_tree(), given.a_clean_tree(OTHER_COMMIT))

    assert len(drift) == 1
    assert given.HEAD in drift[0]
    assert OTHER_COMMIT in drift[0]


def test_no_baseline_before_nor_after_has_not_changed():
    assert baseline_changed(None, None) == []


def test_an_unchanged_baseline_has_not_changed():
    baseline = given.a_baseline_at_ci_conditions()

    assert baseline_changed(baseline, baseline.model_copy()) == []


def test_a_baseline_appearing_during_the_runs_is_named():
    changed = baseline_changed(None, given.a_baseline_at_ci_conditions())

    assert changed == ["the baseline file changed during the runs: record again"]


def test_a_baseline_recorded_again_during_the_runs_is_named():
    loaded = given.a_baseline_at_ci_conditions()
    current = loaded.model_copy(update={"recorded_at": "2026-09-23T11:00:00+00:00"})

    assert baseline_changed(loaded, current) == [
        "the baseline file changed during the runs: record again"
    ]


def test_the_ci_conditions_have_no_mismatch():
    assert ci_condition_mismatches(given.ci_conditions()) == []


def test_a_budget_other_than_the_ci_one_is_named():
    mismatches = ci_condition_mismatches(given.ci_conditions(budget=7))

    assert mismatches == ["budget: CI runs 10, this run 7"]


def test_a_model_override_is_named():
    conditions = given.ci_conditions().model_copy(update={"judge_model": "another-judge"})

    mismatches = ci_condition_mismatches(conditions)

    ci_judge = Settings.model_construct().resolve_judge_model()
    assert mismatches == [f"judge_model: CI runs {ci_judge}, this run another-judge"]
