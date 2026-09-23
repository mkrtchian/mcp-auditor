from pathlib import Path

import tests.unit.support.test_eval_baseline_given as given
from evals.baseline import (
    condition_mismatches,
    fingerprint_ground_truth,
    fingerprint_source,
    load_baseline,
    write_baseline,
)
from evals.gate import Observation
from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import EvalVerdict

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


def test_equal_conditions_have_no_mismatch():
    assert condition_mismatches(given.conditions(), given.conditions()) == []


def test_a_differing_budget_names_both_values():
    mismatches = condition_mismatches(given.conditions(budget=10), given.conditions(budget=7))

    assert len(mismatches) == 1
    assert "budget" in mismatches[0]
    assert "10" in mismatches[0]
    assert "7" in mismatches[0]


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


def test_observation_runs_parse_the_keys_back_to_cells():
    runs = given.a_baseline().observation_runs()

    assert runs[1] == {VULNERABLE_CELL: Observation.UNCOVERED, SAFE_CELL: Observation.PASS}


def test_loading_an_absent_baseline_gives_none(tmp_path: Path):
    assert load_baseline(tmp_path / "missing.json") is None
