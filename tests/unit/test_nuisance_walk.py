import pytest

import tests.unit.support.test_nuisance_walk_given as given
from evals.cve.census.classification import Criterion
from evals.cve.census.draw_order import draw_order
from evals.cve.nuisance.walk import (
    ServerMark,
    acceptance_target_servers,
    candidate_counted_flaws,
    nuisance_acceptance_servers,
    nuisance_population,
    server_of,
)
from evals.cve.nuisance.walk_record import normalized_package, reached_identifiers


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


def test_reached_identifiers_lists_a_re_walked_flaw_once_at_its_first_reach():
    census = given.a_census_walking(
        [("a1", "given_up", "npm:srv1"), ("b1", "skipped", "npm:srv2"), ("a1", "drawn", "npm:srv1")]
    )

    assert reached_identifiers(census) == ["a1", "b1"]


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

    population = nuisance_population(given.walk_inputs_of(census))

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

    assert server_of("p1", given.walk_inputs_of(census)) == "PyPI:praisonai"
    assert server_of("p2", given.walk_inputs_of(census)) == "PyPI:praisonai"
    assert [
        server.server_package for server in nuisance_population(given.walk_inputs_of(census))
    ] == [
        "PyPI:praisonai",
        "npm:Foo",
    ]


def test_server_of_raises_when_the_flaw_has_no_classification():
    census = given.a_census_walking([("a1", "drawn", "npm:srv1")])

    with pytest.raises(ValueError, match="unknown"):
        server_of("unknown", given.walk_inputs_of(census))


def test_candidate_counted_flaws_leave_the_class_to_the_admission():
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

    assert candidate_counted_flaws("npm:srv", given.walk_inputs_of(census)) == [
        "good",
        "good_http",
        "no_grammar",
    ]


def test_settlements_override_the_classifiers_per_criterion():
    census = given.a_census_walking([("u", "drawn", "npm:srv")], u=given.NOT_PINNABLE)
    assert candidate_counted_flaws("npm:srv", given.walk_inputs_of(census)) == []
    brought_in = given.with_a_settlement(census, "u", Criterion.PINNABLE, True)
    assert candidate_counted_flaws("npm:srv", given.walk_inputs_of(brought_in)) == ["u"]

    census = given.a_census_walking([("p", "drawn", "npm:srv")])
    taken_out = given.with_a_settlement(census, "p", Criterion.PINNABLE, False)
    assert candidate_counted_flaws("npm:srv", given.walk_inputs_of(taken_out)) == []

    census = given.a_census_walking([("t", "drawn", "npm:srv")])
    left_in = given.with_a_settlement(census, "t", Criterion.STDIO_TOOLS_CALL, False)
    assert candidate_counted_flaws("npm:srv", given.walk_inputs_of(left_in)) == ["t"]


def test_a_server_whose_only_flaw_both_classifiers_file_outside_the_grammar_stays():
    census = given.a_census_walking(
        [("ok", "drawn", "npm:ok"), ("outside", "drawn", "npm:outside")],
        outside=given.OUTSIDE_THE_GRAMMAR,
    )

    assert [
        server.server_package for server in nuisance_population(given.walk_inputs_of(census))
    ] == ["npm:ok", "npm:outside"]


def test_a_server_whose_every_flaw_fails_leaves_the_population():
    census = given.a_census_walking([("bad", "drawn", "npm:bad"), ("ok", "drawn", "npm:ok")])
    settled = given.with_a_record_settlement(
        given.walk_inputs_of(census), "bad", Criterion.PINNABLE, False
    )

    assert [server.server_package for server in nuisance_population(settled)] == ["npm:ok"]


def test_a_benchmark_flaw_marks_its_server_acceptance():
    census = given.a_census_walking(
        [("a1", "drawn", "npm:accsrv")],
        **{given.A_CURRENT_TARGET_FLAW: {"server_package": "npm:accsrv"}},
    )

    [server] = nuisance_population(given.walk_inputs_of(census))

    assert server.mark == ServerMark.ACCEPTANCE_TARGET_SERVER


def test_an_excluded_server_is_marked_excluded():
    census = given.a_census_walking([("exc1", "drawn", given.AN_EXCLUDED_SERVER)])
    census = given.with_the_second_classifier_overriding(
        census, "exc1", {"server_package": "npm:another-label"}
    )

    [server] = nuisance_population(given.walk_inputs_of(census))

    assert server.mark == ServerMark.EXCLUDED


def test_acceptance_wins_over_excluded():
    census = given.a_census_walking(
        [("exc1", "drawn", given.AN_EXCLUDED_SERVER)],
        **{given.A_CURRENT_TARGET_FLAW: {"server_package": given.AN_EXCLUDED_SERVER}},
    )
    census = given.with_the_second_classifier_overriding(
        census, "exc1", {"server_package": "npm:another-label"}
    )

    [server] = nuisance_population(given.walk_inputs_of(census))

    assert server.mark == ServerMark.ACCEPTANCE_TARGET_SERVER


def test_a_dropped_target_s_server_is_an_acceptance_target_server_only():
    census = given.a_census_walking(
        [
            (given.A_CURRENT_TARGET_FLAW, "excluded", "npm:current"),
            (given.A_DROPPED_ACCEPTANCE_TARGET_FLAW, "excluded", "npm:dropped"),
        ]
    )

    assert nuisance_acceptance_servers(given.walk_inputs_of(census)) == {"npm:current"}
    assert acceptance_target_servers(given.walk_inputs_of(census)) == {
        "npm:current",
        "npm:dropped",
    }


def test_the_walk_resumes_past_the_detection_walk_in_draw_order():
    census = given.a_census_walking_the_first(2, of=["q1", "q2", "q3", "q4"])
    order = [entry.identifier for entry in draw_order(census)]

    population = nuisance_population(given.walk_inputs_of(census))

    assert [
        (server.server_package, server.reaching_flaw, server.reaching_position, server.in_addition)
        for server in population
    ] == [
        (f"npm:{order[0]}", order[0], 1, False),
        (f"npm:{order[1]}", order[1], 2, False),
        (f"npm:{order[2]}", order[2], 3, True),
        (f"npm:{order[3]}", order[3], 4, True),
    ]


def test_a_queue_flaw_settled_against_a_draw_order_criterion_is_skipped():
    census = given.a_census_walking([("a", "drawn", "npm:a")], q={"server_package": "npm:q"})
    census = given.with_the_second_classifier_overriding(
        census, "q", {"effect_in_tool_response": False}
    )

    settled_false = given.with_a_record_settlement(
        given.walk_inputs_of(census), "q", Criterion.EFFECT_IN_TOOL_RESPONSE, False
    )
    settled_true = given.with_a_record_settlement(
        given.walk_inputs_of(census), "q", Criterion.EFFECT_IN_TOOL_RESPONSE, True
    )

    assert [server.server_package for server in nuisance_population(settled_false)] == ["npm:a"]
    assert [server.server_package for server in nuisance_population(settled_true)] == [
        "npm:a",
        "npm:q",
    ]


def test_an_identity_merges_two_labels_into_one_server():
    census = given.a_census_walking(
        [("go", "drawn", "Go:github.com/acme/toolbox")],
        https={"server_package": "https://github.com/acme/toolbox"},
    )
    identified = given.with_an_identity(
        given.walk_inputs_of(census), "https", "Go:github.com/acme/toolbox"
    )

    [server] = nuisance_population(identified)

    assert server.server_package == "Go:github.com/acme/toolbox"
    assert server.flaws == ("go", "https")
    assert server.candidate_counted_flaws == ("go", "https")


def test_an_identity_package_is_normalized():
    census = given.a_census_walking([("k", "drawn", "PyPI:kubectl-mcp-tool")])
    identified = given.with_an_identity(
        given.walk_inputs_of(census), "k", "PyPI:Kubectl_MCP.Server"
    )

    assert server_of("k", identified) == "PyPI:kubectl-mcp-server"


def test_a_record_settlement_takes_a_flaw_out_of_the_candidate_counted_flaws():
    census = given.a_census_walking([("p", "drawn", "npm:srv")])
    settled = given.with_a_record_settlement(
        given.walk_inputs_of(census), "p", Criterion.PINNABLE, False
    )

    assert candidate_counted_flaws("npm:srv", settled) == []


def test_a_grammar_class_settlement_false_does_not_take_a_server_out():
    census = given.a_census_walking([("g", "drawn", "npm:srv")])
    in_the_census = given.with_a_settlement(census, "g", Criterion.GRAMMAR_CLASS, False)
    in_the_record = given.with_a_record_settlement(
        given.walk_inputs_of(census), "g", Criterion.GRAMMAR_CLASS, False
    )

    for settled in (given.walk_inputs_of(in_the_census), in_the_record):
        assert [server.server_package for server in nuisance_population(settled)] == ["npm:srv"]
    assert candidate_counted_flaws("npm:srv", in_the_record) == ["g"]


def test_a_detection_walk_flaw_outside_the_draw_order_is_refused():
    census = given.a_census_walking([("r", "drawn", "npm:srv")], r=given.ON_RESOURCES)

    with pytest.raises(ValueError, match="outside the draw order"):
        nuisance_population(given.walk_inputs_of(census))
