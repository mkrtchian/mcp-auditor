import dataclasses

import tests.unit.support.fictional_planting as planting
from evals.cve.detection.survey import (
    PlaceFacts,
    TargetSurvey,
    candidates_for,
    survey_groups,
    survey_lines,
)


def test_candidates_for_returns_exactly_the_places_whose_reach_meets_the_target():
    places = {
        "read": planting.file_place("read", path="/a"),
        "fetch": dataclasses.replace(
            planting.file_place("fetch", path="/b"), reaches=frozenset({"internal_fetch"})
        ),
        "both": dataclasses.replace(
            planting.file_place("both", path="/c"),
            reaches=frozenset({"arbitrary_read", "internal_fetch"}),
        ),
    }

    result = candidates_for(places, frozenset({"arbitrary_read"}))

    assert [place.id for place in result] == ["both", "read"]


def test_candidates_for_includes_an_unplaceable_place_whose_reach_meets():
    place = planting.unplaceable_place("up")

    result = candidates_for({"up": place}, frozenset({"arbitrary_read"}))

    assert result == [place]


def test_an_unplaceable_candidate_is_listed_as_not_plantable():
    place = planting.unplaceable_place("up")

    grouped = survey_groups([place], planting.unprivileged_host(), planting.FakeNonces())

    assert grouped.groups == []
    assert grouped.not_plantable == [place]


def test_an_account_place_is_grouped_alone():
    account = planting.account_place("acct")

    grouped = survey_groups([account], planting.unprivileged_host(), planting.FakeNonces())

    assert grouped.groups == [(account,)]
    assert grouped.not_plantable == []


def test_an_ip_literal_inside_the_reserved_block_is_not_plantable():
    endpoint = planting.endpoint_place("ep", host="10.255.255.5")

    grouped = survey_groups(
        [endpoint], planting.unprivileged_host(has_network=True), planting.FakeNonces()
    )

    assert grouped.not_plantable == [endpoint]


def test_an_ip_literal_that_cannot_be_a_unicast_host_address_is_not_plantable():
    endpoint = planting.endpoint_place("ep", host="240.0.0.1")

    grouped = survey_groups([endpoint], planting.unprivileged_host(), planting.FakeNonces())

    assert grouped.not_plantable == [endpoint]


def test_each_hostname_place_is_grouped_alone():
    first, second = planting.hostname_place("h1"), planting.hostname_place("h2")

    grouped = survey_groups([first, second], planting.unprivileged_host(), planting.FakeNonces())

    assert grouped.groups == [(first,), (second,)]


def test_nested_file_places_go_to_separate_groups():
    parent = planting.file_place("parent", path="/data")
    child = planting.file_place("child", path="/data/secret")

    grouped = survey_groups([parent, child], planting.unprivileged_host(), planting.FakeNonces())

    assert {frozenset(group) for group in grouped.groups} == {
        frozenset({parent}),
        frozenset({child}),
    }


def test_two_endpoints_with_the_same_host_go_to_separate_groups():
    first = planting.endpoint_place("e1", host="internal.test", path="/a")
    second = planting.endpoint_place("e2", host="internal.test", path="/b")

    grouped = survey_groups(
        [first, second], planting.unprivileged_host(has_network=True), planting.FakeNonces()
    )

    assert len(grouped.groups) == 2
    assert all(len(group) == 1 for group in grouped.groups)


def test_ip_literal_loopback_and_name_endpoints_share_one_group():
    literal = planting.endpoint_place("lit", host="203.0.113.5", path="/a")
    loopback = planting.endpoint_place("lo", host="127.0.0.5", path="/b")
    name = planting.endpoint_place("name", host="internal.test", path="/c")

    grouped = survey_groups(
        [literal, loopback, name], planting.unprivileged_host(), planting.FakeNonces()
    )

    assert len(grouped.groups) == 1
    assert set(grouped.groups[0]) == {literal, loopback, name}


def test_an_endpoint_groups_with_files_and_env_on_a_host_without_network():
    file_place = planting.file_place("f", path="/a")
    env_place = planting.env_place("e")
    endpoint = planting.endpoint_place("ep", host="127.0.0.5", path="/x")

    grouped = survey_groups(
        [file_place, env_place, endpoint], planting.unprivileged_host(), planting.FakeNonces()
    )

    assert len(grouped.groups) == 1
    assert set(grouped.groups[0]) == {file_place, env_place, endpoint}


def test_survey_lines_report_the_three_facts_the_not_plantable_and_the_not_surveyed():
    leaky = planting.file_place("leaky", path="/a")
    clean = planting.file_place("clean", path="/b")
    result = TargetSurvey(
        "CVE-X",
        facts=[
            PlaceFacts(
                leaky,
                surfaced_by_exploit=True,
                surfaced_by_benign_call=False,
                surfaced_on_patched=True,
            ),
            PlaceFacts(
                clean,
                surfaced_by_exploit=False,
                surfaced_by_benign_call=True,
                surfaced_on_patched=False,
            ),
        ],
        not_plantable=[planting.unplaceable_place("up")],
        not_surveyed=[planting.file_place("broken", path="/c")],
    )

    assert survey_lines(result) == [
        "  leaky (fictional-family): exploit yes, benign no, patched yes",
        "  clean (fictional-family): exploit no, benign yes, patched no",
        "  up (fictional-family): not plantable",
        "  broken (fictional-family): launch failed, not surveyed",
    ]
