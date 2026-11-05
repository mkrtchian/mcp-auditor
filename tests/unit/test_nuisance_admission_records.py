from collections.abc import Callable

import pytest

import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_records_given as given
from evals.nuisance_admission import NuisanceAdmission

_MUTATORS: list[Callable[[NuisanceAdmission], NuisanceAdmission]] = [
    given.with_a_removed_tool_carrying_a_real_software_record,
    given.with_a_removed_tool_carrying_a_declared_function_record,
    given.with_a_software_release_without_its_source,
    given.with_a_fix_check_record_carrying_a_holdout_fingerprint,
    given.with_a_silent_tool_without_a_cause,
    given.with_a_silent_tool_without_evidence,
    given.with_an_answering_tool_carrying_a_cause,
    given.with_a_tool_recorded_on_one_flaw_only,
    given.with_a_tool_given_two_verdicts,
    given.with_an_empty_expected_text,
    given.with_an_expected_text_quoting_the_arguments,
    given.with_an_expected_text_quoting_a_prerequisite_call,
    given.with_two_benign_calls_for_one_tool,
    given.with_a_published_sample_without_pin,
    given.with_a_project_document_without_citation,
    given.with_an_invented_stand_in_output_without_form_source,
]


@pytest.mark.parametrize("mutate", _MUTATORS)
def test_each_mutation_yields_exactly_one_problem_naming_the_server(
    mutate: Callable[[NuisanceAdmission], NuisanceAdmission],
):
    problems = admission_given.problems_of(mutate(admission_given.an_admission()))

    assert len(problems) == 1, problems
    assert admission_given.SERVER_PACKAGE in problems[0]


def test_two_benign_calls_for_one_tool_load_clean_when_only_one_flaw_counts():
    admission = given.with_the_second_flaw_not_counting(
        given.with_two_benign_calls_for_one_tool(admission_given.an_admission())
    )

    assert admission_given.problems_of(admission) == []


def test_an_admission_predating_the_new_fields_loads_clean():
    admission = given.with_every_new_field_unrecorded(admission_given.an_admission())

    assert admission_given.problems_of(admission) == []
