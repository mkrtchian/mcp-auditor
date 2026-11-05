from collections.abc import Callable

import pytest

import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_records_given as given
from evals.nuisance_admission import NuisanceAdmission

_MUTATIONS: list[tuple[Callable[[NuisanceAdmission], NuisanceAdmission], str]] = [
    (
        given.with_a_removed_tool_carrying_a_real_software_record,
        "is removed but carries a real_software record",
    ),
    (
        given.with_a_removed_tool_carrying_a_declared_function_record,
        "is removed but carries a declared_function_is_effect record",
    ),
    (given.with_a_software_release_without_its_source, "release of PostgreSQL records no source"),
    (
        given.with_a_fix_check_record_carrying_a_holdout_fingerprint,
        "runs its own fix check but carries a holdout_fingerprint",
    ),
    (given.with_a_silent_tool_without_a_cause, "does not answer and lacks its cause or evidence"),
    (given.with_a_silent_tool_without_evidence, "does not answer and lacks its cause or evidence"),
    (given.with_an_answering_tool_carrying_a_cause, "answers but records a cause or evidence"),
    (given.with_a_tool_recorded_on_one_flaw_only, "has differing real_software verdicts"),
    (given.with_a_tool_given_two_verdicts, "has differing real_software verdicts"),
    (given.with_an_empty_expected_text, "expects an empty text"),
    (
        given.with_an_expected_text_quoting_the_arguments,
        "expects 'README', which its arguments or its prerequisite calls already contain",
    ),
    (
        given.with_an_expected_text_quoting_a_prerequisite_call,
        "expects 'app', which its arguments or its prerequisite calls already contain",
    ),
    (given.with_two_benign_calls_for_one_tool, "has 2 different benign calls"),
    (
        given.with_a_published_sample_without_pin,
        "published sample '/agents.yaml' lacks its citation or pin",
    ),
    (
        given.with_a_project_document_without_citation,
        "project document '/rules/python.md' lacks its citation",
    ),
    (given.with_an_invented_stand_in_output_without_form_source, "names no form source"),
]


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    _MUTATIONS,
    ids=[mutate.__name__ for mutate, _ in _MUTATIONS],
)
def test_each_mutation_yields_exactly_one_problem_naming_the_server_and_its_detail(
    mutate: Callable[[NuisanceAdmission], NuisanceAdmission], fragment: str
):
    [problem] = admission_given.problems_of(mutate(admission_given.an_admission()))

    assert admission_given.SERVER_PACKAGE in problem
    assert fragment in problem


def test_two_benign_calls_for_one_tool_load_clean_when_only_one_flaw_counts():
    admission = given.with_the_second_flaw_not_counting(
        given.with_two_benign_calls_for_one_tool(admission_given.an_admission())
    )

    assert admission_given.problems_of(admission) == []


def test_an_admission_predating_the_new_fields_loads_clean():
    admission = given.with_every_new_field_unrecorded(admission_given.an_admission())

    assert admission_given.problems_of(admission) == []
