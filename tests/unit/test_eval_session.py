from pathlib import Path

import pytest

import tests.unit.support.test_eval_session_given as given
from evals import eval_session
from evals.baseline import BaselineStatus
from evals.declared_flips import ActiveDeclarations
from evals.eval_session import (
    REFUSED_BEFORE_ANY_LLM_CALL,
    Refused,
    TreeState,
    baseline_changed,
    candidate_conditions,
    ci_condition_mismatches,
    open_session,
    pre_run_refusals,
    select_mode,
    tree_drift,
)
from evals.gate_verdict import GateMode
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
    assert pre_run_refusals(given.a_session(), given.LABELS) == []


def test_a_baseline_at_other_conditions_names_the_mismatch():
    session = given.a_session(
        baseline=given.a_baseline_at_ci_conditions(), conditions=given.ci_conditions(budget=7)
    )

    reasons = pre_run_refusals(session, given.LABELS)

    assert len(reasons) == 1
    assert "budget: baseline 10, candidate 7" in reasons[0]
    assert "reset the baseline under ADR 020" in reasons[0]


def test_a_baseline_of_another_ground_truth_is_not_refused():
    baseline = given.a_baseline_at_ci_conditions()
    baseline.conditions.ground_truth_fingerprint = "another"

    assert pre_run_refusals(given.a_session(baseline=baseline), given.LABELS) == []


@pytest.mark.parametrize("status", list(BaselineStatus))
def test_a_label_revision_leaving_no_stable_and_correct_fail_cell_names_the_reset(
    status: BaselineStatus,
):
    session = given.a_session(baseline=given.a_baseline_at_ci_conditions(status))

    reasons = pre_run_refusals(session, given.LABELS_WITH_THE_FLAW_RELABELED_PASS)

    assert reasons == [
        "under the current labels the baseline holds no stable and correct planted FAIL cell: "
        "delete the baseline file in a commit of its own and record twice at that commit "
        "(ADR 022)"
    ]


def test_a_label_revision_leaving_no_stable_and_correct_pass_cell_names_the_reset():
    session = given.a_session(baseline=given.a_baseline_at_ci_conditions())

    reasons = pre_run_refusals(session, given.LABELS_WITH_THE_SAFE_CELL_RELABELED_FAIL)

    assert len(reasons) == 1
    assert "no stable and correct PASS cell" in reasons[0]


def test_recording_over_a_baseline_a_label_revision_left_blind_is_refused():
    session = given.a_session(
        baseline=given.a_baseline_at_ci_conditions(), tree=given.a_clean_tree()
    )

    reasons = pre_run_refusals(session, given.LABELS_WITH_THE_FLAW_RELABELED_PASS)

    assert len(reasons) == 1
    assert "no stable and correct planted FAIL cell" in reasons[0]


def test_recording_on_a_dirty_tree_is_refused():
    session = given.a_session(tree=TreeState(commit=given.HEAD, dirty=True))

    reasons = pre_run_refusals(session, given.LABELS)

    assert len(reasons) == 1
    assert "clean tree" in reasons[0]


def test_recording_at_other_ci_conditions_is_refused():
    session = given.a_session(tree=given.a_clean_tree(), conditions=given.ci_conditions(budget=7))

    reasons = pre_run_refusals(session, given.LABELS)

    assert reasons == [
        "a baseline records the conditions CI runs at, budget: CI runs 10, this run 7"
    ]


def test_recording_over_an_exploratory_baseline_at_another_commit_is_refused():
    baseline = given.a_baseline_at_ci_conditions(BaselineStatus.EXPLORATORY)
    session = given.a_session(baseline=baseline, tree=given.a_clean_tree(OTHER_COMMIT))

    reasons = pre_run_refusals(session, given.LABELS)

    assert len(reasons) == 1
    assert OTHER_COMMIT in reasons[0]


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


def test_a_budget_other_than_the_ci_one_is_named():
    mismatches = ci_condition_mismatches(given.ci_conditions(budget=7))

    assert mismatches == ["budget: CI runs 10, this run 7"]


def test_a_model_override_is_named():
    conditions = given.ci_conditions().model_copy(update={"judge_model": "another-judge"})

    mismatches = ci_condition_mismatches(conditions)

    ci_judge = Settings.model_construct().resolve_judge_model()
    assert mismatches == [f"judge_model: CI runs {ci_judge}, this run another-judge"]


def test_a_reasoning_override_is_named():
    conditions = given.ci_conditions().model_copy(update={"reasoning": "high"})

    mismatches = ci_condition_mismatches(conditions)

    ci_reasoning = Settings.model_construct().resolve_reasoning(
        Settings.model_construct().resolve_model()
    )
    assert mismatches == [f"reasoning: CI runs {ci_reasoning}, this run high"]


def test_candidate_conditions_carry_the_resolved_reasoning_of_both_models():
    conditions = candidate_conditions(Settings.model_construct(provider="google"), given.options())

    assert conditions.reasoning == "minimal"
    assert conditions.judge_reasoning == "minimal"


def test_a_judge_override_leaves_the_judge_reasoning_unset():
    settings = Settings.model_construct(provider="google", judge_model="gemini-3.1-pro-preview")

    conditions = candidate_conditions(settings, given.options())

    assert conditions.reasoning == "minimal"
    assert conditions.judge_reasoning is None


def test_an_invalid_reasoning_setting_is_refused_before_any_llm_call(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "google")
    monkeypatch.setenv("MCP_AUDITOR_REASONING", "hgih")

    with pytest.raises(Refused) as refusal:
        open_session(given.options())

    assert refusal.value.title == REFUSED_BEFORE_ANY_LLM_CALL
    assert "'hgih'" in refusal.value.reasons[0]


def test_an_invalid_declaration_file_is_refused_before_any_git_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    declarations = tmp_path / "declared_flips.json"
    declarations.write_text('{"entries": [{"suite": "honeypot"}]}')
    monkeypatch.setattr(eval_session, "DECLARED_FLIPS_PATH", declarations)
    monkeypatch.setattr(eval_session.subprocess, "run", given.a_git_that_must_not_run)

    with pytest.raises(Refused) as refusal:
        open_session(given.options())

    assert refusal.value.title == REFUSED_BEFORE_ANY_LLM_CALL
    assert f"{declarations} is not a valid declaration file" in refusal.value.reasons[0]


def test_an_empty_declaration_file_reads_nothing_from_git(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setattr(eval_session, "BASELINE_PATH", tmp_path / "no_baseline.json")
    monkeypatch.setattr(eval_session, "DECLARED_FLIPS_PATH", given.a_declaration_file(tmp_path))
    monkeypatch.setattr(eval_session.subprocess, "run", given.a_git_that_must_not_run)

    session = open_session(given.options())

    assert session.declarations == ActiveDeclarations()


def test_an_active_declaration_of_an_unknown_cell_is_refused_before_any_llm_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    declarations = given.a_declaration_file(tmp_path, "no_such_tool/injection")
    monkeypatch.setattr(eval_session, "BASELINE_PATH", tmp_path / "no_baseline.json")
    monkeypatch.setattr(eval_session, "DECLARED_FLIPS_PATH", declarations)
    monkeypatch.setattr(
        eval_session.subprocess, "run", given.a_git_whose_parent_is_declared(dirty=False)
    )

    with pytest.raises(Refused) as refusal:
        open_session(given.options())

    assert refusal.value.title == REFUSED_BEFORE_ANY_LLM_CALL
    assert refusal.value.reasons == [
        "declared flip no_such_tool/injection names no cell of the ground truth"
    ]


@pytest.mark.parametrize(
    ("dirty", "expected"),
    [
        (False, ActiveDeclarations(keys=frozenset({given.A_GATED_CELL}))),
        (True, ActiveDeclarations(ignored=frozenset({given.A_GATED_CELL}))),
    ],
)
def test_the_declarations_of_head_apply_only_on_a_clean_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, dirty: bool, expected: ActiveDeclarations
):
    declarations = given.a_declaration_file(tmp_path, given.A_GATED_CELL)
    monkeypatch.setattr(eval_session, "BASELINE_PATH", tmp_path / "no_baseline.json")
    monkeypatch.setattr(eval_session, "DECLARED_FLIPS_PATH", declarations)
    monkeypatch.setattr(eval_session.subprocess, "run", given.a_git_whose_parent_is_declared(dirty))

    session = open_session(given.options())

    assert session.declarations == expected
