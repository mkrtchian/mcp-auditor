from datetime import date

import tests.unit.support.test_census_figures_given as given
from evals.census_classification import Criterion, SoftwareKind, Transport
from evals.census_figures import Share, compute_figures

HTTP_ONLY = {"transport": Transport.HTTP, "first_failed_criterion": Criterion.STDIO_TOOLS_CALL}
A_CLIENT = {"software_kind": SoftwareKind.CLIENT, "first_failed_criterion": Criterion.MCP_SERVER}
OUTSIDE_THE_GRAMMAR = {
    "effect_class": "denial_of_service",
    "first_failed_criterion": Criterion.GRAMMAR_CLASS,
}


def test_agreement_is_the_share_of_flaws_on_which_both_classifiers_give_the_same_value():
    census = given.a_census(
        given.agreed("CVE-2025-0001"),
        given.the_same_flaw_seen_as("CVE-2025-0002", {}, HTTP_ONLY),
        given.the_same_flaw_seen_as("CVE-2025-0003", {"pinnable": False}, HTTP_ONLY),
    )

    figures = compute_figures(*census)

    assert figures.agreement["transport"] == Share(count=1, denominator=3)
    assert figures.agreement["pinnable"] == Share(count=2, denominator=3)
    assert figures.agreement["primitive"] == Share(count=3, denominator=3)


def test_two_free_names_outside_the_grammar_disagree_on_the_name_and_agree_on_membership():
    census = given.a_census(
        given.the_same_flaw_seen_as(
            "CVE-2025-0001",
            OUTSIDE_THE_GRAMMAR,
            OUTSIDE_THE_GRAMMAR | {"effect_class": "resource_exhaustion"},
        )
    )

    figures = compute_figures(*census)

    assert figures.effect_class_name_agreement == Share(count=0, denominator=1)
    assert figures.effect_class_membership_agreement == Share(count=1, denominator=1)


def test_a_flaw_only_one_classifier_finds_on_stdio_is_reachable():
    census = given.a_census(given.the_same_flaw_seen_as("CVE-2025-0001", {}, HTTP_ONLY))

    figures = compute_figures(*census)

    assert figures.reachable == Share(count=1, denominator=1)


def test_a_flaw_is_outside_the_grammar_only_when_both_classifiers_place_it_there():
    census = given.a_census(
        given.the_same_flaw_seen_as("CVE-2025-0001", {}, OUTSIDE_THE_GRAMMAR),
        given.agreed("CVE-2025-0002", **OUTSIDE_THE_GRAMMAR),
    )

    figures = compute_figures(*census)

    assert figures.grammar_covered == Share(count=1, denominator=2)


def test_breakdowns_are_per_classifier_over_the_flaws_it_finds_to_be_mcp_servers():
    census = given.a_census(
        given.the_same_flaw_seen_as("CVE-2025-0001", {}, HTTP_ONLY),
        given.the_same_flaw_seen_as("CVE-2025-0002", {"effect_in_tool_response": False}, A_CLIENT),
    )

    figures = compute_figures(*census)

    first, second = figures.breakdowns[given.FIRST], figures.breakdowns[given.SECOND]
    assert first.by_transport == {"stdio": Share(count=2, denominator=2)}
    assert first.effect_not_in_tool_response == Share(count=1, denominator=2)
    assert second.by_transport == {"http": Share(count=1, denominator=1)}
    assert second.effect_not_in_tool_response == Share(count=0, denominator=1)


def test_monthly_counts_follow_the_computed_disclosure_date():
    census = given.a_census(
        given.agreed("CVE-2025-0001", disclosure_date=date(2025, 6, 30)),
        given.agreed("CVE-2025-0002", **A_CLIENT),
        disclosed={"CVE-2025-0001": date(2025, 7, 2), "CVE-2025-0002": date(2025, 7, 3)},
    )

    figures = compute_figures(*census)

    assert figures.monthly_counts == {"2025-07": 1}


def test_a_withdrawn_flaw_counts_only_in_the_agreement():
    census = given.a_census(
        given.agreed("CVE-2025-0001"),
        given.the_same_flaw_seen_as("CVE-2025-0002", {}, HTTP_ONLY),
        withdrawn={"CVE-2025-0002"},
    )

    figures = compute_figures(*census)

    assert figures.agreement["transport"] == Share(count=1, denominator=2)
    assert figures.reachable == Share(count=1, denominator=1)
    assert figures.grammar_covered == Share(count=1, denominator=1)
    assert figures.breakdowns[given.SECOND].by_transport == {"stdio": Share(count=1, denominator=1)}
    assert figures.monthly_counts == {"2025-06": 1}
