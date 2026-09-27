import ast
from pathlib import Path

import tests.unit.support.test_eval_baseline_given as given
from evals.baseline import (
    Baseline,
    BaselineStatus,
    RecordingRef,
    baseline_integrity,
    condition_mismatches,
    fingerprint_ground_truth,
    fingerprint_source,
    load_baseline,
    rescore,
    write_baseline,
)
from evals.gate import CellOutcome, Observation, ReplayRule, cell_key
from evals.gate_verdict import GateMode, GateVerdict
from evals.ground_truth import GroundTruth
from evals.honeypots import HONEYPOTS
from evals.recording import (
    GatedSetChange,
    RecordingRefused,
    decide_recording,
    gated_set_changes,
)
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

VULNERABLE_CELL = given.VULNERABLE_CELL
SAFE_CELL = given.SAFE_CELL


def test_ground_truth_fingerprint_changes_with_one_verdict_flipped():
    ground_truth: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}
    flipped: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.FAIL}

    assert fingerprint_ground_truth(ground_truth) != fingerprint_ground_truth(flipped)


def test_ground_truth_fingerprint_ignores_insertion_order():
    ground_truth: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}
    reordered: GroundTruth = {SAFE_CELL: EvalVerdict.PASS, VULNERABLE_CELL: EvalVerdict.FAIL}

    assert fingerprint_ground_truth(ground_truth) == fingerprint_ground_truth(reordered)


def test_source_fingerprint_ignores_an_added_comment_line():
    commented = given.SERVER_SOURCE.replace(
        "def get_user", "# Planted flaw: no validation of user_id.\ndef get_user"
    )

    assert fingerprint_source(commented) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_ignores_blank_lines():
    spaced = given.SERVER_SOURCE.replace("import json\n", "import json\n\n\n\n")

    assert fingerprint_source(spaced) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_changes_with_a_changed_string_literal():
    changed = given.SERVER_SOURCE.replace('"id"', '"user_id"')

    assert fingerprint_source(changed) != fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_ignores_the_module_docstring():
    edited = given.SERVER_SOURCE.replace("A server with one tool.", "The planted flaws, explained.")

    assert fingerprint_source(edited) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_ignores_quotes_trailing_commas_and_parentheses():
    reformatted = given.SERVER_SOURCE.replace(
        'def get_user(user_id: str) -> str:\n    """Return the user."""\n'
        '    return json.dumps({"id": user_id})\n',
        'def get_user(\n    user_id: str,\n) -> str:\n    """Return the user."""\n'
        "    return (\n        json.dumps({'id': user_id})\n    )\n",
    )
    assert reformatted != given.SERVER_SOURCE

    assert fingerprint_source(reformatted) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_changes_with_a_tool_docstring():
    changed = given.SERVER_SOURCE.replace("Return the user.", "Return any user.")

    assert fingerprint_source(changed) != fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_changes_with_a_changed_argument_type():
    changed = given.SERVER_SOURCE.replace("user_id: str", "user_id: int")

    assert fingerprint_source(changed) != fingerprint_source(given.SERVER_SOURCE)


def test_no_honeypot_passes_instructions_to_its_server():
    for honeypot in HONEYPOTS:
        module = ast.parse(honeypot.server.read_text())

        assert not any(
            isinstance(node, ast.keyword) and node.arg == "instructions"
            for node in ast.walk(module)
        ), honeypot.name


def test_no_tool_name_appears_in_two_honeypots():
    tool_names = [{tool for tool, _ in honeypot.ground_truth} for honeypot in HONEYPOTS]

    assert len(set[str]().union(*tool_names)) == sum(len(names) for names in tool_names)


def test_equal_conditions_have_no_mismatch():
    assert condition_mismatches(given.conditions(), given.conditions()) == []


def test_a_differing_budget_names_both_values():
    mismatches = condition_mismatches(given.conditions(budget=10), given.conditions(budget=7))

    assert len(mismatches) == 1
    assert "budget" in mismatches[0]
    assert "10" in mismatches[0]
    assert "7" in mismatches[0]


def test_a_baseline_recorded_at_another_reasoning_setting_names_it():
    recorded = given.conditions()
    candidate = recorded.model_copy(update={"reasoning": "high"})

    mismatches = condition_mismatches(recorded, candidate)

    assert mismatches == ["reasoning: baseline minimal, candidate high"]


def test_a_differing_ground_truth_fingerprint_is_no_mismatch():
    recorded = given.conditions()
    candidate = recorded.model_copy(update={"ground_truth_fingerprint": "another"})

    assert condition_mismatches(recorded, candidate) == []


def test_a_differing_fixture_fingerprint_names_the_honeypot():
    mismatches = condition_mismatches(
        given.conditions(source_fingerprint="abc"), given.conditions(source_fingerprint="xyz")
    )

    assert len(mismatches) == 1
    assert "honeypot" in mismatches[0]
    assert "source_fingerprint" in mismatches[0]


def test_a_baseline_written_then_loaded_is_equal(tmp_path: Path):
    path = tmp_path / "baselines" / "honeypot_e2e.json"
    baseline = given.a_baseline()

    write_baseline(path, baseline)

    assert load_baseline(path) == baseline


def test_a_baseline_written_over_another_replaces_it_and_leaves_no_temporary(tmp_path: Path):
    path = tmp_path / "honeypot_e2e.json"
    write_baseline(path, given.a_baseline())
    second = given.a_baseline(status=BaselineStatus.CONFIRMED)

    write_baseline(path, second)

    assert load_baseline(path) == second
    assert list(tmp_path.glob("*.tmp")) == []


def test_observation_runs_parse_the_keys_back_to_cells():
    runs = given.a_baseline().observation_runs()

    assert runs[1] == {VULNERABLE_CELL: Observation.UNCOVERED, SAFE_CELL: Observation.PASS}


def test_loading_an_absent_baseline_gives_none(tmp_path: Path):
    assert load_baseline(tmp_path / "missing.json") is None


def test_a_baseline_consistent_with_the_ground_truth_has_no_integrity_problem():
    assert baseline_integrity(given.a_baseline(), given.a_ground_truth()) == []


def test_a_run_missing_a_ground_truth_cell_names_it():
    runs = given.all_correct_runs()
    del runs[1][SAFE_CELL]

    problems = baseline_integrity(given.a_baseline(runs=runs), given.a_ground_truth())

    assert problems == [f"run 1: cells ['{cell_key(SAFE_CELL)}'] missing"]


def test_a_run_with_a_cell_outside_the_ground_truth_names_it():
    unknown_cell = ("get_user", AuditCategory.ERROR_HANDLING)
    runs = given.all_correct_runs()
    runs[2][unknown_cell] = Observation.PASS

    problems = baseline_integrity(given.a_baseline(runs=runs), given.a_ground_truth())

    assert problems == [f"run 2: cells ['{cell_key(unknown_cell)}'] unknown"]


def test_a_baseline_with_no_run_is_refused():
    problems = baseline_integrity(given.a_baseline(runs=[]), given.a_ground_truth())

    assert problems == ["the baseline holds no run"]


def test_a_baseline_with_no_run_is_refused_even_when_its_conditions_claim_none():
    baseline = given.a_baseline(runs=[])
    baseline.conditions.runs = 0

    problems = baseline_integrity(baseline, given.a_ground_truth())

    assert problems == ["the baseline holds no run"]


def test_a_baseline_with_fewer_runs_than_its_conditions_claim_names_the_run_count():
    runs = given.runs_where_vulnerable_cell_is(Observation.FAIL, Observation.FAIL)

    problems = baseline_integrity(given.a_baseline(runs=runs), given.a_ground_truth())

    assert problems == ["the baseline holds 2 runs, its conditions claim 3"]


def test_a_key_without_a_category_is_reported_not_raised():
    baseline = given.a_baseline()
    baseline.runs[0]["get_user"] = Observation.PASS

    problems = baseline_integrity(baseline, given.a_ground_truth())

    assert problems == ["run 0: unreadable cell key 'get_user'"]


def test_a_key_with_an_unknown_category_is_reported_not_raised():
    baseline = given.a_baseline()
    baseline.runs[1]["get_user/unknown"] = Observation.PASS

    problems = baseline_integrity(baseline, given.a_ground_truth())

    assert problems == ["run 1: unreadable cell key 'get_user/unknown'"]


def test_a_baseline_missing_a_cell_the_ground_truth_added_has_no_integrity_problem():
    other_ground_truth: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL}
    runs = given.all_correct_runs()
    del runs[0][SAFE_CELL]
    baseline = given.a_baseline(runs=runs, ground_truth=other_ground_truth)

    assert baseline_integrity(baseline, given.a_ground_truth()) == []


def test_a_baseline_holding_a_cell_the_ground_truth_removed_has_no_integrity_problem():
    removed_cell = ("get_user", AuditCategory.ERROR_HANDLING)
    recorded_ground_truth: GroundTruth = {**given.a_ground_truth(), removed_cell: EvalVerdict.PASS}
    runs = [{**run, removed_cell: Observation.PASS} for run in given.all_correct_runs()]
    baseline = given.a_baseline(runs=runs, ground_truth=recorded_ground_truth)

    assert baseline_integrity(baseline, given.a_ground_truth()) == []


def test_rescoring_under_a_revised_label_recomputes_recall_and_precision():
    baseline = given.a_baseline(runs=given.all_correct_runs())
    revised: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.FAIL}

    rescored = rescore(baseline, revised)

    assert (rescored.metrics.recall, rescored.metrics.precision) == (0.5, 1.0)


def test_rescoring_leaves_out_a_cell_the_baseline_did_not_record():
    added_cell = ("get_user", AuditCategory.ERROR_HANDLING)
    baseline = given.a_baseline(runs=given.all_correct_runs())
    revised: GroundTruth = {**given.a_ground_truth(), added_cell: EvalVerdict.FAIL}

    rescored = rescore(baseline, revised)

    assert added_cell not in rescored.ground_truth
    assert rescored.metrics.recall == 1.0


def test_rescoring_keeps_the_recorded_distribution_coverage():
    baseline = given.a_baseline(runs=given.all_correct_runs())

    rescored = rescore(baseline, given.a_ground_truth())

    assert rescored.metrics.distribution_coverage == baseline.metrics.distribution_coverage


def test_a_first_recording_is_exploratory():
    result = decide_recording(
        None, given.a_recording(), given.a_gate(mode=GateMode.LEGACY_THRESHOLDS)
    )

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.replay_rule == ReplayRule()
    assert result.observation_runs() == given.all_correct_runs()


def test_a_first_recording_missing_legacy_thresholds_with_floors_met_is_written():
    gate = given.a_gate(verdict=GateVerdict.RED, mode=GateMode.LEGACY_THRESHOLDS)

    result = decide_recording(None, given.a_recording(), gate)

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY


def test_a_first_recording_breaching_a_floor_is_refused():
    gate = given.a_gate(floor_breaches=["precision"], mode=GateMode.LEGACY_THRESHOLDS)

    result = decide_recording(None, given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any("precision" in reason for reason in result.reasons)


def test_a_recording_with_no_stable_and_correct_fail_cell_is_refused():
    recording = given.a_recording(protected=given.no_stable_and_correct_fail_cell())

    result = decide_recording(None, recording, given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no planted FAIL cell is stable and correct: the gate could not see a lost detection"
    ]


def test_a_recording_with_no_stable_and_correct_pass_cell_is_refused():
    recording = given.a_recording(protected=given.no_stable_and_correct_pass_cell())

    result = decide_recording(None, recording, given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no PASS cell is stable and correct: the gate could not see a new false positive"
    ]


def test_a_recording_with_one_stable_and_correct_cell_on_each_side_is_written():
    recording = given.a_recording(protected=given.protected_on_both_sides())

    result = decide_recording(None, recording, given.a_gate())

    assert isinstance(result, Baseline)


def test_a_recording_with_a_failed_run_is_refused():
    result = decide_recording(None, given.a_recording(completed_all=False), given.a_gate())

    assert isinstance(result, RecordingRefused)


def test_a_second_recording_agreeing_on_stable_cells_confirms_the_first():
    existing = given.a_baseline(runs=given.all_correct_runs())

    result = decide_recording(existing, given.a_recording(), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.confirms == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replaces is None


def test_a_second_recording_disagreeing_on_a_stable_cell_stays_exploratory():
    existing = given.a_baseline(runs=given.all_correct_runs())
    unstable = given.runs_where_vulnerable_cell_is(
        Observation.FAIL, Observation.PASS, Observation.FAIL
    )

    result = decide_recording(existing, given.a_recording(runs=unstable), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.disagreements == [cell_key(VULNERABLE_CELL)]


def test_a_cell_unstable_in_the_exploratory_baseline_is_no_disagreement():
    existing = given.a_baseline(
        runs=given.runs_where_vulnerable_cell_is(
            Observation.FAIL, Observation.UNCOVERED, Observation.FAIL
        )
    )

    result = decide_recording(existing, given.a_recording(), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.disagreements == []


def test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees():
    existing = given.a_baseline(runs=given.runs_where_safe_cell_is(Observation.FAIL))
    uncovered = given.runs_where_safe_cell_is(Observation.UNCOVERED)

    result = decide_recording(existing, given.a_recording(runs=uncovered), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.disagreements == [cell_key(SAFE_CELL)]


def test_a_second_recording_at_another_commit_is_refused():
    existing = given.a_baseline(runs=given.all_correct_runs())

    result = decide_recording(existing, given.a_recording(commit="4567def"), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(given.RECORDED_COMMIT in reason for reason in result.reasons)


def test_a_second_recording_at_other_conditions_is_refused():
    existing = given.a_baseline(runs=given.all_correct_runs())

    result = decide_recording(existing, given.a_recording(budget=7), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(
        "exploratory baseline" in reason and "reset the baseline under ADR 020" in reason
        for reason in result.reasons
    )


def test_recording_over_a_confirmed_baseline_under_a_green_gate_replaces_it():
    rule = ReplayRule(replays=7, required=5)
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED, replay_rule=rule)

    result = decide_recording(existing, given.a_recording(commit="4567def"), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replay_rule == rule


def test_recording_over_a_confirmed_baseline_with_a_gated_flip_not_reproduced_is_refused():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)
    gate = given.a_gate(vulnerable_cell_outcome=CellOutcome.FLIP_NOT_REPRODUCED)

    result = decide_recording(existing, given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any(cell_key(VULNERABLE_CELL) in reason for reason in result.reasons)


def test_recording_over_a_confirmed_baseline_under_a_red_gate_is_refused():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)

    result = decide_recording(existing, given.a_recording(), given.a_gate(GateVerdict.RED))

    assert isinstance(result, RecordingRefused)


def test_recording_over_a_confirmed_baseline_at_other_conditions_points_at_the_reset_procedure():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)

    result = decide_recording(existing, given.a_recording(budget=7), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(
        "confirmed baseline" in reason and "reset the baseline under ADR 020" in reason
        for reason in result.reasons
    )


def test_a_gated_cell_becoming_unstable_leaves_the_gated_set():
    old = given.a_baseline(runs=given.all_correct_runs())
    new = given.a_baseline(
        runs=given.runs_where_vulnerable_cell_is(
            Observation.FAIL, Observation.UNCOVERED, Observation.FAIL
        )
    )

    changes = gated_set_changes(old, new, given.a_ground_truth())

    assert changes == GatedSetChange(entering=[], leaving=[cell_key(VULNERABLE_CELL)])


def test_a_stable_incorrect_cell_becoming_correct_enters_the_gated_set():
    old = given.a_baseline(
        runs=given.runs_where_vulnerable_cell_is(Observation.PASS, Observation.PASS)
    )
    new = given.a_baseline(runs=given.all_correct_runs())

    changes = gated_set_changes(old, new, given.a_ground_truth())

    assert changes == GatedSetChange(entering=[cell_key(VULNERABLE_CELL)], leaving=[])


def test_with_no_previous_baseline_every_gated_cell_enters():
    new = given.a_baseline(runs=given.all_correct_runs())

    changes = gated_set_changes(None, new, given.a_ground_truth())

    assert changes == GatedSetChange(
        entering=sorted([cell_key(VULNERABLE_CELL), cell_key(SAFE_CELL)]), leaving=[]
    )
