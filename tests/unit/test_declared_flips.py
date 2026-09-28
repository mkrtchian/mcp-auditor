from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import tests.unit.support.test_declared_flips_given as given
from evals.declared_flips import (
    Suite,
    active_declarations,
    apply_declarations,
    declaration_problems,
    entries_of_commit,
    load_declared_flips,
)
from evals.gate import Cell, CellComparison, CellOutcome, FlipCause
from mcp_auditor.domain.models import AuditCategory

DECLARED_CELL: Cell = ("get_user", AuditCategory.INPUT_VALIDATION)
OTHER_CELL: Cell = ("get_user", AuditCategory.ERROR_HANDLING)


def test_a_missing_file_loads_as_no_entry(tmp_path: Path):
    assert load_declared_flips(tmp_path / "absent.json") == []


def test_a_valid_file_round_trips(tmp_path: Path):
    path = given.a_file_holding(tmp_path, given.a_raw_entry(runs_seen=["run-1"]))

    entries = load_declared_flips(path)

    assert entries == [given.an_entry().model_copy(update={"runs_seen": ["run-1"]})]


@pytest.mark.parametrize(
    "invalid",
    [
        {"mechanism": ""},
        {"mechanism": "   "},
        {"base": "0123456"},
        {"base": given.BASE.upper()},
    ],
)
def test_an_invalid_entry_fails_to_load(tmp_path: Path, invalid: dict[str, Any]):
    path = given.a_file_holding(tmp_path, given.a_raw_entry(**invalid))

    with pytest.raises(ValidationError):
        load_declared_flips(path)


def test_an_entry_without_runs_seen_fails_to_load(tmp_path: Path):
    raw = given.a_raw_entry()
    del raw["runs_seen"]
    path = given.a_file_holding(tmp_path, raw)

    with pytest.raises(ValidationError):
        load_declared_flips(path)


def test_the_entries_of_a_commit_are_those_based_on_its_parent():
    current = given.an_entry(base=given.BASE)
    history = given.an_entry(base=given.OTHER_BASE)

    assert entries_of_commit([current, history], Suite.HONEYPOT, given.BASE) == [current]


def test_a_commit_without_a_parent_has_no_entry():
    assert entries_of_commit([given.an_entry()], Suite.HONEYPOT, None) == []


def test_a_clean_tree_activates_the_declared_keys():
    declarations = active_declarations([given.an_entry()], dirty=False)

    assert declarations.keys == {"get_user/input_validation"}
    assert declarations.ignored == frozenset()


def test_a_dirty_tree_ignores_the_declared_keys():
    declarations = active_declarations([given.an_entry()], dirty=True)

    assert declarations.keys == frozenset()
    assert declarations.ignored == {"get_user/input_validation"}


def test_valid_entries_have_no_problem():
    entries = [given.an_entry(), given.an_entry(key="get_user/error_handling")]

    assert declaration_problems(entries, given.KNOWN_KEYS) == []


def test_a_key_outside_the_ground_truth_is_a_problem():
    problems = declaration_problems([given.an_entry(key="nope/input_validation")], given.KNOWN_KEYS)

    assert len(problems) == 1
    assert "nope/input_validation" in problems[0]


def test_a_key_named_twice_is_a_problem():
    problems = declaration_problems([given.an_entry(), given.an_entry()], given.KNOWN_KEYS)

    assert len(problems) == 1
    assert "get_user/input_validation" in problems[0]


def test_an_entry_of_another_commit_naming_an_unknown_key_is_no_problem():
    old = given.an_entry(key="removed/input_validation", base=given.OTHER_BASE)

    entries = entries_of_commit([old, given.an_entry()], Suite.HONEYPOT, given.BASE)

    assert declaration_problems(entries, given.KNOWN_KEYS) == []


def test_a_declared_flip_reads_declared_and_keeps_its_cause():
    cells = {
        DECLARED_CELL: CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.UNCOVERED),
        OTHER_CELL: CellComparison(outcome=CellOutcome.FLIP),
    }

    result = apply_declarations(cells, frozenset({DECLARED_CELL}))

    assert result[DECLARED_CELL] == CellComparison(
        outcome=CellOutcome.DECLARED, cause=FlipCause.UNCOVERED
    )
    assert result[OTHER_CELL] == CellComparison(outcome=CellOutcome.FLIP)


def test_a_declared_cell_that_did_not_flip_is_unchanged():
    cells = {DECLARED_CELL: CellComparison(outcome=CellOutcome.UNCHANGED)}

    result = apply_declarations(cells, frozenset({DECLARED_CELL}))

    assert result == cells
