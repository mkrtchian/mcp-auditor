import re

from evals.cve.census.classification import (
    GRAMMAR_CLASS_DEFINITIONS,
    GRAMMAR_CLASSES,
    Criterion,
    SoftwareKind,
    Transport,
    criteria_met,
    in_grammar,
    is_consistent,
)
from tests.unit.support.censuses import a_classification


def test_failing_stdio_tools_call_with_stdio_and_tools_is_inconsistent():
    classification = a_classification(first_failed_criterion=Criterion.STDIO_TOOLS_CALL)

    assert not is_consistent(classification)


def test_failing_mcp_server_with_a_server_kind_is_consistent():
    classification = a_classification(first_failed_criterion=Criterion.MCP_SERVER)

    assert is_consistent(classification)
    assert not criteria_met(classification)[Criterion.MCP_SERVER]


def test_meeting_all_five_with_an_effect_class_outside_the_grammar_is_inconsistent():
    classification = a_classification(effect_class="denial_of_service")

    assert not is_consistent(classification)


def test_failing_the_grammar_class_after_a_non_server_kind_is_inconsistent():
    classification = a_classification(
        software_kind=SoftwareKind.CLIENT,
        effect_class="denial_of_service",
        first_failed_criterion=Criterion.GRAMMAR_CLASS,
    )

    assert not is_consistent(classification)


def test_failing_the_grammar_class_with_a_class_outside_it_is_consistent():
    classification = a_classification(
        effect_class="denial_of_service", first_failed_criterion=Criterion.GRAMMAR_CLASS
    )

    assert is_consistent(classification)


def test_stdio_and_http_with_tools_meets_the_stdio_tools_call():
    classification = a_classification(transport=Transport.STDIO_AND_HTTP)

    assert criteria_met(classification)[Criterion.STDIO_TOOLS_CALL]


def test_grammar_membership_ignores_case_and_surrounding_whitespace():
    assert in_grammar("  Command_Execution ")
    assert not in_grammar("command execution")


def test_the_census_classes_are_the_classes_its_definitions_define():
    """The definitions also ship in the calibration and admission dossiers, so a class they gain
    fails this test, which is the moment to split the census's text from the dossiers'."""
    defined = re.findall(r"^- `(\w+)`:", GRAMMAR_CLASS_DEFINITIONS, flags=re.MULTILINE)

    assert tuple(defined) == GRAMMAR_CLASSES
