from pathlib import Path

import pytest

import tests.unit.evals.support.honeypot_sessions as honeypot_sessions
import tests.unit.evals.support.test_honeypot_session_given as given
import tests.unit.evals.support.working_trees as working_trees
from evals.baseline import BaselineStatus
from evals.declared_flips import ActiveDeclarations
from evals.eval_session import REFUSED_BEFORE_ANY_LLM_CALL, Refused, TreeState
from evals.gate_outcome import GateMode
from evals.ground_truth import parse_cell_key
from evals.honeypot.session import (
    DEFAULT_RUNS,
    GateBasis,
    candidate_conditions,
    ci_condition_mismatches,
    open_session,
    pre_run_refusals,
    select_mode,
)
from mcp_auditor.config import Settings

OTHER_COMMIT = "4567def"


def test_a_no_baseline_run_gates_on_floors_only_even_with_a_confirmed_baseline():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions(BaselineStatus.CONFIRMED)

    assert select_mode(baseline, no_baseline=True) == GateMode.FLOORS_ONLY


def test_no_baseline_gates_on_the_legacy_thresholds():
    assert select_mode(None, no_baseline=False) == GateMode.LEGACY_THRESHOLDS


def test_an_unconfirmed_baseline_gates_on_floors_only():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions(BaselineStatus.UNCONFIRMED)

    assert select_mode(baseline, no_baseline=False) == GateMode.FLOORS_ONLY


def test_a_confirmed_baseline_gates_paired():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions(BaselineStatus.CONFIRMED)

    assert select_mode(baseline, no_baseline=False) == GateMode.PAIRED


def test_a_session_gate_basis_carries_its_mode_baseline_declared_cells_and_runs():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions(BaselineStatus.CONFIRMED)
    session = honeypot_sessions.a_session(
        baseline=baseline,
        declarations=ActiveDeclarations(keys=frozenset({given.A_GATED_CELL})),
    )

    assert session.gate_basis == GateBasis(
        mode=GateMode.PAIRED,
        baseline=baseline,
        declared=frozenset({parse_cell_key(given.A_GATED_CELL)}),
        requested_runs=DEFAULT_RUNS,
    )


def test_a_run_without_baseline_nor_recording_is_not_refused():
    assert pre_run_refusals(honeypot_sessions.a_session(), given.LABELS) == []


def test_a_baseline_at_other_conditions_names_the_mismatch():
    session = honeypot_sessions.a_session(
        baseline=honeypot_sessions.a_baseline_at_ci_conditions(),
        conditions=honeypot_sessions.ci_conditions(test_budget=7),
    )

    reasons = pre_run_refusals(session, given.LABELS)

    assert len(reasons) == 1
    assert "budget: baseline 10, candidate 7" in reasons[0]
    assert "reset the baseline under ADR 020" in reasons[0]


def test_a_baseline_of_another_ground_truth_is_not_refused():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions()
    baseline.conditions.ground_truth_fingerprint = "another"

    assert pre_run_refusals(honeypot_sessions.a_session(baseline=baseline), given.LABELS) == []


@pytest.mark.parametrize("status", list(BaselineStatus))
def test_a_label_revision_leaving_no_stable_and_correct_fail_cell_names_the_reset(
    status: BaselineStatus,
):
    session = honeypot_sessions.a_session(
        baseline=honeypot_sessions.a_baseline_at_ci_conditions(status)
    )

    reasons = pre_run_refusals(session, given.LABELS_WITH_THE_FLAW_RELABELED_PASS)

    assert reasons == [
        "under the current labels the baseline holds no stable and correct planted FAIL cell: "
        "delete the baseline file in a commit of its own and record twice at that commit "
        "(ADR 022)"
    ]


def test_a_label_revision_leaving_no_stable_and_correct_pass_cell_names_the_reset():
    session = honeypot_sessions.a_session(baseline=honeypot_sessions.a_baseline_at_ci_conditions())

    reasons = pre_run_refusals(session, given.LABELS_WITH_THE_SAFE_CELL_RELABELED_FAIL)

    assert len(reasons) == 1
    assert "no stable and correct PASS cell" in reasons[0]


def test_recording_over_a_baseline_a_label_revision_left_blind_is_refused():
    session = honeypot_sessions.a_session(
        baseline=honeypot_sessions.a_baseline_at_ci_conditions(),
        tree=working_trees.a_clean_tree(),
    )

    reasons = pre_run_refusals(session, given.LABELS_WITH_THE_FLAW_RELABELED_PASS)

    assert len(reasons) == 1
    assert "no stable and correct planted FAIL cell" in reasons[0]


def test_recording_on_a_dirty_tree_is_refused():
    session = honeypot_sessions.a_session(tree=TreeState(commit=working_trees.HEAD, dirty=True))

    reasons = pre_run_refusals(session, given.LABELS)

    assert len(reasons) == 1
    assert "clean tree" in reasons[0]


def test_recording_at_other_ci_conditions_is_refused():
    session = honeypot_sessions.a_session(
        tree=working_trees.a_clean_tree(), conditions=honeypot_sessions.ci_conditions(test_budget=7)
    )

    reasons = pre_run_refusals(session, given.LABELS)

    assert reasons == [
        "a baseline records the conditions CI runs at, budget: CI runs 10, this run 7"
    ]


def test_recording_over_an_unconfirmed_baseline_at_another_commit_is_refused():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions(BaselineStatus.UNCONFIRMED)
    session = honeypot_sessions.a_session(
        baseline=baseline, tree=working_trees.a_clean_tree(OTHER_COMMIT)
    )

    reasons = pre_run_refusals(session, given.LABELS)

    assert len(reasons) == 1
    assert OTHER_COMMIT in reasons[0]


def test_a_budget_other_than_the_ci_one_is_named():
    mismatches = ci_condition_mismatches(honeypot_sessions.ci_conditions(test_budget=7))

    assert mismatches == ["budget: CI runs 10, this run 7"]


def test_a_model_override_is_named():
    conditions = honeypot_sessions.ci_conditions().model_copy(
        update={"judge_model": "another-judge"}
    )

    mismatches = ci_condition_mismatches(conditions)

    ci_judge = Settings.model_construct().resolve_judge_model()
    assert mismatches == [f"judge_model: CI runs {ci_judge}, this run another-judge"]


def test_a_reasoning_override_is_named():
    conditions = honeypot_sessions.ci_conditions().model_copy(update={"reasoning": "high"})

    mismatches = ci_condition_mismatches(conditions)

    ci_reasoning = Settings.model_construct().resolve_reasoning(
        Settings.model_construct().resolve_model()
    )
    assert mismatches == [f"reasoning: CI runs {ci_reasoning}, this run high"]


def test_candidate_conditions_carry_the_resolved_reasoning_of_both_models():
    conditions = candidate_conditions(given.options(Settings.model_construct(provider="google")))

    assert conditions.reasoning == "minimal"
    assert conditions.judge_reasoning == "minimal"


def test_a_judge_override_leaves_the_judge_reasoning_unset():
    settings = Settings.model_construct(provider="google", judge_model="gemini-3.1-pro-preview")

    conditions = candidate_conditions(given.options(settings))

    assert conditions.reasoning == "minimal"
    assert conditions.judge_reasoning is None


def test_an_invalid_reasoning_setting_is_refused_before_any_llm_call(tmp_path: Path):
    settings = Settings.model_construct(provider="google", reasoning="hgih")
    working_tree = working_trees.a_working_tree_that_must_not_read_git(
        working_trees.a_declaration_file(tmp_path)
    )

    with pytest.raises(Refused) as refusal:
        open_session(given.options(settings), working_tree, tmp_path / "no_baseline.json")

    assert refusal.value.title == REFUSED_BEFORE_ANY_LLM_CALL
    assert "'hgih'" in refusal.value.reasons[0]


def test_an_active_declaration_of_an_unknown_cell_is_refused_before_any_llm_call(
    tmp_path: Path,
):
    declarations = working_trees.a_declaration_file(tmp_path, "no_such_tool/injection")

    with pytest.raises(Refused) as refusal:
        open_session(
            given.options(), given.a_working_tree(declarations), tmp_path / "no_baseline.json"
        )

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
    tmp_path: Path, dirty: bool, expected: ActiveDeclarations
):
    declarations = working_trees.a_declaration_file(tmp_path, given.A_GATED_CELL)

    session = open_session(
        given.options(), given.a_working_tree(declarations, dirty), tmp_path / "no_baseline.json"
    )

    assert session.declarations == expected
