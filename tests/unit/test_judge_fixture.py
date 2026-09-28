from pathlib import Path
from typing import Any

import pytest

import tests.unit.support.test_judge_fixture_given as given
from evals.judge_fixture import (
    CaseLabel,
    case_id,
    ground_truth_of,
    inputs_fingerprint,
    load_drawn,
    load_fixture,
)
from evals.run_judge_eval import FIXTURES_PATH
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


def test_a_case_id_ignores_the_key_order_of_the_arguments():
    first = given.some_inputs(arguments={"user_id": -1, "verbose": True})
    second = given.some_inputs(arguments={"verbose": True, "user_id": -1})

    assert case_id(first) == case_id(second)


@pytest.mark.parametrize(
    "change",
    [
        {"tool_name": "list_items"},
        {"tool_description": None},
        {"category": AuditCategory.ERROR_HANDLING},
        {"description": "Huge user_id"},
        {"arguments": {"user_id": -2, "verbose": True}},
        {"response": {"rows": 0}},
        {"error": None},
    ],
)
def test_a_case_id_changes_with_any_input(change: dict[str, Any]):
    assert case_id(given.some_inputs(**change)) != case_id(given.some_inputs())


def test_a_case_id_is_sixteen_hex_characters():
    identifier = case_id(given.some_inputs())

    assert len(identifier) == 16
    int(identifier, 16)


def test_a_fixture_round_trips(tmp_path: Path):
    cases = (given.a_case(), given.a_case(CaseLabel.FAIL, description="Other"))

    fixture = load_fixture(given.a_file_holding(tmp_path, *cases))

    assert fixture.cases == list(cases)


def test_a_case_whose_id_does_not_match_its_inputs_is_refused(tmp_path: Path):
    raw = {**given.a_case().model_dump(mode="json"), "id": "0000000000000000"}
    path = given.a_file_with_raw_cases(tmp_path, raw)

    with pytest.raises(ValueError, match="0000000000000000"):
        load_fixture(path)
    with pytest.raises(ValueError, match="0000000000000000"):
        load_drawn(path)


def test_a_duplicate_id_is_refused(tmp_path: Path):
    case = given.a_case()
    path = given.a_file_holding(tmp_path, case, case.model_copy(update={"label": CaseLabel.FAIL}))

    with pytest.raises(ValueError, match=case.id):
        load_fixture(path)
    with pytest.raises(ValueError, match=case.id):
        load_drawn(path)


def test_an_unlabeled_case_is_refused_by_the_fixture_and_accepted_by_the_draw(tmp_path: Path):
    unlabeled = given.a_case(label=None)
    path = given.a_file_holding(tmp_path, unlabeled)

    with pytest.raises(ValueError, match=unlabeled.id):
        load_fixture(path)
    assert load_drawn(path).cases == [unlabeled]


def test_the_ground_truth_leaves_unspecified_cases_out():
    passing = given.a_case(CaseLabel.PASS, description="passing")
    failing = given.a_case(CaseLabel.FAIL, description="failing")
    unspecified = given.a_case(CaseLabel.UNSPECIFIED, description="unspecified")

    ground_truth = ground_truth_of(given.a_fixture(passing, failing, unspecified))

    assert ground_truth == {passing.id: EvalVerdict.PASS, failing.id: EvalVerdict.FAIL}


def test_the_fingerprint_ignores_labels_clauses_and_order():
    first = given.a_case(CaseLabel.PASS, description="first")
    second = given.a_case(CaseLabel.FAIL, description="second")
    relabeled = second.model_copy(update={"label": CaseLabel.PASS, "clause": "J1"})

    assert inputs_fingerprint(given.a_fixture(first, second)) == inputs_fingerprint(
        given.a_fixture(relabeled, first)
    )


def test_the_fingerprint_changes_when_a_case_is_added():
    first = given.a_case(description="first")
    second = given.a_case(description="second")

    assert inputs_fingerprint(given.a_fixture(first)) != inputs_fingerprint(
        given.a_fixture(first, second)
    )


def test_the_fingerprint_changes_when_the_inputs_of_a_case_change():
    before = given.a_case(description="before")
    after = given.a_case(description="after")

    assert inputs_fingerprint(given.a_fixture(before)) != inputs_fingerprint(given.a_fixture(after))


def test_the_legacy_fixture_loads_with_its_32_cases():
    fixture = load_fixture(FIXTURES_PATH)

    assert fixture.draw is None
    assert len(fixture.cases) == 32
    assert sum(case.label == CaseLabel.FAIL for case in fixture.cases) == 8
