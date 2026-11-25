import pytest

import tests.unit.nuisance.admission.support.test_nuisance_walk_given as given
import tests.unit.nuisance.admission.support.test_nuisance_walk_then as then
import tests.unit.support.nuisance_walks as walks
from evals.cve.census.classification import Criterion
from evals.cve.census.draw_order import draw_order
from evals.cve.nuisance.admission.walk import (
    acceptance_target_servers,
    candidate_counted_flaws,
    nuisance_acceptance_servers,
    nuisance_population,
    reached_servers,
    server_of,
)
from evals.cve.nuisance.admission.walk_record import normalized_package, reached_identifiers
from evals.cve.nuisance.exits import ExitReason
from tests.unit.support import censuses


def test_reached_identifiers_raises_without_a_draw():
    census = walks.a_census_walking([("a1", "drawn", "npm:srv1")])
    census = census.model_copy(update={"draw": None})

    with pytest.raises(ValueError, match="no draw walk"):
        reached_identifiers(census)


def test_reached_identifiers_follows_the_detection_walk_order():
    census = walks.a_census_walking(
        [("a1", "drawn", "npm:srv1"), ("b1", "skipped", "npm:srv2"), ("a2", "given_up", "npm:srv1")]
    )

    assert reached_identifiers(census) == ["a1", "b1", "a2"]


def test_reached_identifiers_lists_a_re_walked_flaw_once_at_its_first_reach():
    census = walks.a_census_walking(
        [("a1", "given_up", "npm:srv1"), ("b1", "skipped", "npm:srv2"), ("a1", "drawn", "npm:srv1")]
    )

    assert reached_identifiers(census) == ["a1", "b1"]


def test_population_is_one_server_per_package_in_first_reaching_order():
    census = walks.a_census_walking(
        [
            ("a1", "drawn", "npm:srv1"),
            ("a2", "given_up", "npm:srv1"),
            ("b1", "skipped", "npm:srv2"),
            ("b1", "excluded", "npm:srv2"),
        ],
        a3={"server_package": "npm:srv1"},
    )

    population = nuisance_population(walks.walk_inputs_of(census))

    assert [server.server_package for server in population] == ["npm:srv1", "npm:srv2"]
    assert population[0].reaching_flaw == "a1"
    assert population[1].reaching_flaw == "b1"
    assert population[0].flaws == ("a1", "a2", "a3")
    assert population[1].flaws == ("b1",)


def test_pypi_names_collapse_by_pep503_other_prefixes_stay_verbatim():
    assert normalized_package("PyPI:PraisonAI") == "PyPI:praisonai"
    assert normalized_package("npm:Foo") == "npm:Foo"

    census = walks.a_census_walking(
        [
            ("p1", "drawn", "PyPI:PraisonAI"),
            ("p2", "drawn", "PyPI:praisonai"),
            ("f1", "drawn", "npm:Foo"),
        ]
    )

    assert server_of("p1", walks.walk_inputs_of(census)) == "PyPI:praisonai"
    assert server_of("p2", walks.walk_inputs_of(census)) == "PyPI:praisonai"
    then.the_population_is(walks.walk_inputs_of(census), "PyPI:praisonai", "npm:Foo")


def test_server_of_raises_when_the_flaw_has_no_classification():
    census = walks.a_census_walking([("a1", "drawn", "npm:srv1")])

    with pytest.raises(ValueError, match="unknown"):
        server_of("unknown", walks.walk_inputs_of(census))


def test_candidate_counted_flaws_leave_the_class_to_the_admission():
    census = walks.a_census_walking(
        [
            ("good", "drawn", "npm:srv"),
            ("good_http", "drawn", "npm:srv"),
            ("no_grammar", "drawn", "npm:srv"),
            ("hidden", "drawn", "npm:srv"),
            ("unpinnable", "drawn", "npm:srv"),
            ("resources", "drawn", "npm:srv"),
        ],
        good_http=given.OVER_HTTP,
        no_grammar=censuses.OUTSIDE_THE_GRAMMAR,
        hidden=walks.EFFECT_HIDDEN,
        unpinnable=censuses.NOT_PINNABLE,
        resources=given.ON_RESOURCES,
    )

    assert candidate_counted_flaws("npm:srv", walks.walk_inputs_of(census)) == [
        "good",
        "good_http",
        "no_grammar",
    ]


def test_a_pinnable_settlement_brings_a_flaw_in():
    census = walks.a_census_walking([("u", "drawn", "npm:srv")], u=censuses.NOT_PINNABLE)
    brought_in = walks.with_a_settlement(census, "u", Criterion.PINNABLE, True)

    before = candidate_counted_flaws("npm:srv", walks.walk_inputs_of(census))
    after = candidate_counted_flaws("npm:srv", walks.walk_inputs_of(brought_in))

    assert (before, after) == ([], ["u"])


def test_a_pinnable_settlement_takes_a_flaw_out():
    census = walks.a_census_walking([("p", "drawn", "npm:srv")])
    taken_out = walks.with_a_settlement(census, "p", Criterion.PINNABLE, False)

    assert candidate_counted_flaws("npm:srv", walks.walk_inputs_of(taken_out)) == []


def test_a_false_stdio_tools_call_settlement_leaves_a_flaw_reached_through_tools():
    census = walks.a_census_walking([("t", "drawn", "npm:srv")])
    left_in = walks.with_a_settlement(census, "t", Criterion.STDIO_TOOLS_CALL, False)

    assert candidate_counted_flaws("npm:srv", walks.walk_inputs_of(left_in)) == ["t"]


def test_a_server_whose_only_flaw_both_classifiers_file_outside_the_grammar_stays():
    census = walks.a_census_walking(
        [("ok", "drawn", "npm:ok"), ("outside", "drawn", "npm:outside")],
        outside=censuses.OUTSIDE_THE_GRAMMAR,
    )

    then.the_population_is(walks.walk_inputs_of(census), "npm:ok", "npm:outside")


def test_a_server_whose_every_flaw_fails_leaves_the_population():
    census = walks.a_census_walking([("bad", "drawn", "npm:bad"), ("ok", "drawn", "npm:ok")])
    settled = walks.with_a_record_settlement(
        walks.walk_inputs_of(census), "bad", Criterion.PINNABLE, False
    )

    then.the_population_is(settled, "npm:ok")


def test_reached_servers_keep_apart_a_server_with_no_flaw_that_may_count():
    reached = reached_servers(walks.a_walk_reaching_a_server_with_no_flaw_that_may_count())

    assert [server.server_package for server in reached.listed] == ["npm:ok"]
    assert reached.without_candidates == ["npm:bad"]


def test_a_current_target_flaw_marks_its_server():
    census = walks.a_census_walking(
        [("a1", "drawn", "npm:accsrv")],
        **{walks.A_CURRENT_TARGET_FLAW: {"server_package": "npm:accsrv"}},
    )

    [server] = nuisance_population(walks.walk_inputs_of(census))

    assert server.mark == ExitReason.ACCEPTANCE_TARGET_SERVER


def test_an_excluded_server_is_marked_excluded():
    census = walks.a_census_walking([("exc1", "drawn", walks.AN_EXCLUDED_SERVER)])
    census = walks.with_the_second_classifier_overriding(
        census, "exc1", {"server_package": "npm:another-label"}
    )

    [server] = nuisance_population(walks.walk_inputs_of(census))

    assert server.mark == ExitReason.EXCLUDED_SERVER


def test_acceptance_wins_over_excluded():
    census = walks.a_census_walking(
        [("exc1", "drawn", walks.AN_EXCLUDED_SERVER)],
        **{walks.A_CURRENT_TARGET_FLAW: {"server_package": walks.AN_EXCLUDED_SERVER}},
    )
    census = walks.with_the_second_classifier_overriding(
        census, "exc1", {"server_package": "npm:another-label"}
    )

    [server] = nuisance_population(walks.walk_inputs_of(census))

    assert server.mark == ExitReason.ACCEPTANCE_TARGET_SERVER


def test_a_dropped_target_s_server_is_an_acceptance_target_server_only():
    census = walks.a_census_walking(
        [
            (walks.A_CURRENT_TARGET_FLAW, "excluded", "npm:current"),
            (given.A_DROPPED_ACCEPTANCE_TARGET_FLAW, "excluded", "npm:dropped"),
        ]
    )

    assert nuisance_acceptance_servers(walks.walk_inputs_of(census)) == {"npm:current"}
    assert acceptance_target_servers(walks.walk_inputs_of(census)) == {
        "npm:current",
        "npm:dropped",
    }


def test_the_nuisance_walk_resumes_past_the_detection_walk_in_draw_order():
    census = walks.a_census_walking_the_first(2, of=["q1", "q2", "q3", "q4"])
    order = [entry.identifier for entry in draw_order(census)]

    population = nuisance_population(walks.walk_inputs_of(census))

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
    census = walks.a_census_walking([("a", "drawn", "npm:a")], q={"server_package": "npm:q"})
    census = walks.with_the_second_classifier_overriding(
        census, "q", {"effect_in_tool_response": False}
    )

    settled_false = walks.with_a_record_settlement(
        walks.walk_inputs_of(census), "q", Criterion.EFFECT_IN_TOOL_RESPONSE, False
    )
    settled_true = walks.with_a_record_settlement(
        walks.walk_inputs_of(census), "q", Criterion.EFFECT_IN_TOOL_RESPONSE, True
    )

    then.the_population_is(settled_false, "npm:a")
    then.the_population_is(settled_true, "npm:a", "npm:q")


def test_an_identity_merges_two_labels_into_one_server():
    census = walks.a_census_walking(
        [("go", "drawn", "Go:github.com/acme/toolbox")],
        https={"server_package": "https://github.com/acme/toolbox"},
    )
    identified = given.with_an_identity(
        walks.walk_inputs_of(census), "https", "Go:github.com/acme/toolbox"
    )

    [server] = nuisance_population(identified)

    assert server.server_package == "Go:github.com/acme/toolbox"
    assert server.flaws == ("go", "https")
    assert server.candidate_counted_flaws == ("go", "https")


def test_an_identity_package_is_normalized():
    census = walks.a_census_walking([("k", "drawn", "PyPI:kubectl-mcp-tool")])
    identified = given.with_an_identity(
        walks.walk_inputs_of(census), "k", "PyPI:Kubectl_MCP.Server"
    )

    assert server_of("k", identified) == "PyPI:kubectl-mcp-server"


def test_a_record_settlement_takes_a_flaw_out_of_the_candidate_counted_flaws():
    census = walks.a_census_walking([("p", "drawn", "npm:srv")])
    settled = walks.with_a_record_settlement(
        walks.walk_inputs_of(census), "p", Criterion.PINNABLE, False
    )

    assert candidate_counted_flaws("npm:srv", settled) == []


def test_a_grammar_class_settlement_false_does_not_take_a_server_out():
    census = walks.a_census_walking([("g", "drawn", "npm:srv")])
    in_the_census = walks.with_a_settlement(census, "g", Criterion.GRAMMAR_CLASS, False)
    in_the_record = walks.with_a_record_settlement(
        walks.walk_inputs_of(census), "g", Criterion.GRAMMAR_CLASS, False
    )

    for settled in (walks.walk_inputs_of(in_the_census), in_the_record):
        then.the_population_is(settled, "npm:srv")
    assert candidate_counted_flaws("npm:srv", in_the_record) == ["g"]


def test_a_detection_walk_flaw_outside_the_draw_order_is_refused():
    census = walks.a_census_walking([("r", "drawn", "npm:srv")], r=given.ON_RESOURCES)

    with pytest.raises(ValueError, match="outside the draw order"):
        nuisance_population(walks.walk_inputs_of(census))
