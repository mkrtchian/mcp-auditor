import dataclasses

import tests.unit.support.test_cve_planting_given as given
from evals.cve_survey import PlaceFacts, TargetSurvey, candidates_for, survey_groups, survey_lines


def test_candidates_for_returns_exactly_the_places_whose_reach_meets_the_target():
    places = {
        "read": given.file_place("read", path="/a"),
        "fetch": dataclasses.replace(
            given.file_place("fetch", path="/b"), reachable_by=frozenset({"internal_fetch"})
        ),
        "both": dataclasses.replace(
            given.file_place("both", path="/c"),
            reachable_by=frozenset({"arbitrary_read", "internal_fetch"}),
        ),
    }

    result = candidates_for(places, frozenset({"arbitrary_read"}))

    assert [place.id for place in result] == ["both", "read"]


def test_candidates_for_includes_an_unplaceable_place_whose_reach_meets():
    place = given.unplaceable_place("up")

    result = candidates_for({"up": place}, frozenset({"arbitrary_read"}))

    assert result == [place]


def test_an_unplaceable_candidate_is_listed_as_not_plantable():
    place = given.unplaceable_place("up")

    grouped = survey_groups([place], given.unprivileged_host(), given.FakeNonces())

    assert grouped.groups == []
    assert grouped.not_plantable == [place]


def test_an_account_place_is_grouped_alone():
    account = given.account_place("acct")

    grouped = survey_groups([account], given.unprivileged_host(), given.FakeNonces())

    assert grouped.groups == [(account,)]
    assert grouped.not_plantable == []


def test_an_account_place_on_a_host_user_launch_is_not_plantable():
    account = given.account_place("acct")

    grouped = survey_groups([account], given.host_user_host(), given.FakeNonces())

    assert grouped.groups == []
    assert grouped.not_plantable == [account]


def test_an_ip_literal_inside_the_reserved_block_is_not_plantable():
    endpoint = given.endpoint_place("ep", host="10.255.255.5")

    grouped = survey_groups(
        [endpoint], given.unprivileged_host(has_network=True), given.FakeNonces()
    )

    assert grouped.not_plantable == [endpoint]


def test_an_ip_literal_that_cannot_be_a_unicast_host_address_is_not_plantable():
    endpoint = given.endpoint_place("ep", host="240.0.0.1")

    grouped = survey_groups([endpoint], given.unprivileged_host(), given.FakeNonces())

    assert grouped.not_plantable == [endpoint]


def test_each_hostname_place_is_grouped_alone():
    first, second = given.hostname_place("h1"), given.hostname_place("h2")

    grouped = survey_groups([first, second], given.unprivileged_host(), given.FakeNonces())

    assert grouped.groups == [(first,), (second,)]


def test_nested_file_places_go_to_separate_groups():
    parent = given.file_place("parent", path="/data")
    child = given.file_place("child", path="/data/secret")

    grouped = survey_groups([parent, child], given.unprivileged_host(), given.FakeNonces())

    assert {frozenset(group) for group in grouped.groups} == {
        frozenset({parent}),
        frozenset({child}),
    }


def test_two_endpoints_with_the_same_host_go_to_separate_groups():
    first = given.endpoint_place("e1", host="internal.test", path="/a")
    second = given.endpoint_place("e2", host="internal.test", path="/b")

    grouped = survey_groups(
        [first, second], given.unprivileged_host(has_network=True), given.FakeNonces()
    )

    assert len(grouped.groups) == 2
    assert all(len(group) == 1 for group in grouped.groups)


def test_ip_literal_loopback_and_name_endpoints_share_one_group():
    literal = given.endpoint_place("lit", host="203.0.113.5", path="/a")
    loopback = given.endpoint_place("lo", host="127.0.0.5", path="/b")
    name = given.endpoint_place("name", host="internal.test", path="/c")

    grouped = survey_groups(
        [literal, loopback, name], given.unprivileged_host(), given.FakeNonces()
    )

    assert len(grouped.groups) == 1
    assert set(grouped.groups[0]) == {literal, loopback, name}


def test_an_endpoint_groups_with_files_and_env_on_a_host_without_network():
    file_place = given.file_place("f", path="/a")
    env_place = given.env_place("e")
    endpoint = given.endpoint_place("ep", host="127.0.0.5", path="/x")

    grouped = survey_groups(
        [file_place, env_place, endpoint], given.unprivileged_host(), given.FakeNonces()
    )

    assert len(grouped.groups) == 1
    assert set(grouped.groups[0]) == {file_place, env_place, endpoint}


def test_survey_lines_report_the_three_facts_the_not_plantable_and_the_not_surveyed():
    leaky = given.file_place("leaky", path="/a")
    clean = given.file_place("clean", path="/b")
    result = TargetSurvey(
        "CVE-X",
        facts=[
            PlaceFacts(leaky, exploit=True, benign=False, patched=True),
            PlaceFacts(clean, exploit=False, benign=True, patched=False),
        ],
        not_plantable=[given.unplaceable_place("up")],
        not_surveyed=[given.file_place("broken", path="/c")],
    )

    assert survey_lines(result) == [
        "  leaky (fictional-family): exploit yes, benign no, patched yes",
        "  clean (fictional-family): exploit no, benign yes, patched no",
        "  up (fictional-family): not plantable",
        "  broken (fictional-family): launch failed, not surveyed",
    ]
