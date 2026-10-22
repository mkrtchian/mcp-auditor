import pytest

import tests.unit.support.test_nuisance_walk_given as given
from evals.census_classification import Criterion
from evals.nuisance_walk import (
    ServerMark,
    acceptance_servers,
    current_acceptance_servers,
    normalized_package,
    nuisance_population,
    reached_identifiers,
    server_of,
    version_setting_flaws,
)


def test_reached_identifiers_raises_without_a_draw():
    census = given.a_census_walking([("a1", "drawn", "npm:srv1")])
    census = census.model_copy(update={"draw": None})

    with pytest.raises(ValueError, match="no draw walk"):
        reached_identifiers(census)


def test_reached_identifiers_follows_the_walk_order():
    census = given.a_census_walking(
        [("a1", "drawn", "npm:srv1"), ("b1", "skipped", "npm:srv2"), ("a2", "given_up", "npm:srv1")]
    )

    assert reached_identifiers(census) == ["a1", "b1", "a2"]


def test_population_is_one_server_per_package_in_first_reaching_order():
    census = given.a_census_walking(
        [
            ("a1", "drawn", "npm:srv1"),
            ("a2", "given_up", "npm:srv1"),
            ("b1", "skipped", "npm:srv2"),
            ("b1", "excluded", "npm:srv2"),
        ],
        a3={"server_package": "npm:srv1"},
    )

    population = nuisance_population(census)

    assert [server.server_package for server in population] == ["npm:srv1", "npm:srv2"]
    assert population[0].reaching_flaw == "a1"
    assert population[1].reaching_flaw == "b1"
    assert population[0].flaws == ("a1", "a2", "a3")
    assert population[1].flaws == ("b1",)


def test_pypi_names_collapse_by_pep503_other_prefixes_stay_verbatim():
    assert normalized_package("PyPI:PraisonAI") == "PyPI:praisonai"
    assert normalized_package("npm:Foo") == "npm:Foo"

    census = given.a_census_walking(
        [
            ("p1", "drawn", "PyPI:PraisonAI"),
            ("p2", "drawn", "PyPI:praisonai"),
            ("f1", "drawn", "npm:Foo"),
        ]
    )

    assert server_of("p1", census) == "PyPI:praisonai"
    assert server_of("p2", census) == "PyPI:praisonai"
    assert [server.server_package for server in nuisance_population(census)] == [
        "PyPI:praisonai",
        "npm:Foo",
    ]


def test_server_of_raises_when_the_flaw_has_no_classification():
    census = given.a_census_walking([("a1", "drawn", "npm:srv1")])

    with pytest.raises(ValueError, match="unknown"):
        server_of("unknown", census)


def test_version_setting_keeps_only_the_four_criteria():
    census = given.a_census_walking(
        [
            ("good", "drawn", "npm:srv"),
            ("good_http", "drawn", "npm:srv"),
            ("no_grammar", "drawn", "npm:srv"),
            ("hidden", "drawn", "npm:srv"),
            ("unpinnable", "drawn", "npm:srv"),
            ("resources", "drawn", "npm:srv"),
        ],
        good_http=given.OVER_HTTP,
        no_grammar=given.OUTSIDE_THE_GRAMMAR,
        hidden=given.EFFECT_HIDDEN,
        unpinnable=given.NOT_PINNABLE,
        resources=given.ON_RESOURCES,
    )

    assert version_setting_flaws("npm:srv", census) == ["good", "good_http"]


def test_settlements_override_the_classifiers_per_criterion():
    census = given.a_census_walking([("g", "drawn", "npm:srv")], g=given.OUTSIDE_THE_GRAMMAR)
    assert version_setting_flaws("npm:srv", census) == []
    brought_in = given.with_a_settlement(census, "g", Criterion.GRAMMAR_CLASS, True)
    assert version_setting_flaws("npm:srv", brought_in) == ["g"]

    census = given.a_census_walking([("p", "drawn", "npm:srv")])
    taken_out = given.with_a_settlement(census, "p", Criterion.PINNABLE, False)
    assert version_setting_flaws("npm:srv", taken_out) == []

    census = given.a_census_walking([("t", "drawn", "npm:srv")])
    left_in = given.with_a_settlement(census, "t", Criterion.STDIO_TOOLS_CALL, False)
    assert version_setting_flaws("npm:srv", left_in) == ["t"]


def test_a_flaw_only_the_second_classifier_places_in_grammar_still_sets_version():
    census = given.a_census_walking([("g", "drawn", "npm:srv")], g=given.OUTSIDE_THE_GRAMMAR)
    assert version_setting_flaws("npm:srv", census) == []

    brought_in = given.with_the_second_classifier_overriding(
        census, "g", {"effect_class": "read_outside_scope"}
    )

    assert version_setting_flaws("npm:srv", brought_in) == ["g"]


def test_a_server_whose_every_flaw_fails_leaves_the_population():
    census = given.a_census_walking(
        [("bad", "drawn", "npm:bad"), ("ok", "drawn", "npm:ok")],
        bad=given.OUTSIDE_THE_GRAMMAR,
    )

    assert [server.server_package for server in nuisance_population(census)] == ["npm:ok"]


def test_a_benchmark_flaw_marks_its_server_acceptance():
    census = given.a_census_walking([("CVE-2025-53109", "excluded", "npm:accsrv")])

    [server] = nuisance_population(census)

    assert server.mark == ServerMark.ACCEPTANCE


def test_an_excluded_server_is_marked_excluded():
    census = given.a_census_walking(
        [("exc1", "drawn", "npm:@modelcontextprotocol/server-filesystem")]
    )

    [server] = nuisance_population(census)

    assert server.mark == ServerMark.EXCLUDED


def test_acceptance_wins_over_excluded():
    census = given.a_census_walking(
        [("CVE-2025-53110", "drawn", "npm:@modelcontextprotocol/server-filesystem")]
    )

    [server] = nuisance_population(census)

    assert server.mark == ServerMark.ACCEPTANCE


def test_only_a_current_target_makes_its_server_a_current_acceptance_server():
    census = given.a_census_walking(
        [
            ("CVE-2025-53355", "excluded", "npm:mcp-server-kubernetes"),
            ("CVE-2026-0755", "excluded", "npm:gemini-mcp-tool"),
        ]
    )

    assert current_acceptance_servers(census) == {"npm:mcp-server-kubernetes"}
    assert acceptance_servers(census) == {"npm:mcp-server-kubernetes", "npm:gemini-mcp-tool"}
