from datetime import date
from typing import Any

from evals.census_classification import (
    Classification,
    Criterion,
    Primitive,
    SoftwareKind,
    Transport,
    criteria_met,
    in_grammar,
    is_consistent,
)


def a_classification(**overrides: Any) -> Classification:
    fields: dict[str, Any] = {
        "flaw": "CVE-2025-1234",
        "software_kind": SoftwareKind.SERVER,
        "server_package": "npm:@acme/files",
        "affected_versions": "< 1.2.0",
        "vulnerable_version": "1.1.0",
        "first_patched_version": "1.2.0",
        "pinnable": True,
        "disclosure_date": date(2025, 6, 10),
        "transport": Transport.STDIO,
        "primitive": Primitive.TOOLS,
        "effect_in_tool_response": True,
        "runs_in_container": True,
        "effect_class": "read_outside_scope",
        "first_failed_criterion": None,
        **overrides,
    }
    return Classification(**fields)


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
