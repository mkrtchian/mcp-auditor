import tests.unit.support.test_cve_survey_given as given
from evals.cve_survey import PlaceFacts, TargetSurvey, candidates_for, survey_groups, survey_lines


def test_candidates_for_returns_exactly_the_places_whose_reach_meets_the_target():
    places = {
        "read": given.a_file_place("read", "/a", reaches=frozenset({"arbitrary_read"})),
        "fetch": given.a_file_place("fetch", "/b", reaches=frozenset({"internal_fetch"})),
        "both": given.a_file_place(
            "both", "/c", reaches=frozenset({"arbitrary_read", "internal_fetch"})
        ),
    }

    result = candidates_for(places, frozenset({"arbitrary_read"}))

    assert [place.id for place in result] == ["both", "read"]


def test_candidates_for_includes_an_unplaceable_place_whose_reach_meets():
    place = given.an_unplaceable_place("up")

    result = candidates_for({"up": place}, frozenset({"arbitrary_read"}))

    assert result == [place]


def test_an_unplaceable_candidate_is_listed_as_not_plantable():
    place = given.an_unplaceable_place("up")

    grouped = survey_groups([place], given.NO_NETWORK, given.FakeNonces())

    assert grouped.groups == []
    assert grouped.not_plantable == [place]


def test_an_account_place_is_grouped_alone():
    account = given.an_account_place("acct")

    grouped = survey_groups([account], given.NO_NETWORK, given.FakeNonces())

    assert grouped.groups == [(account,)]
    assert grouped.not_plantable == []


def test_an_account_place_on_a_host_user_launch_is_not_plantable():
    account = given.an_account_place("acct")

    grouped = survey_groups([account], given.HOST_USER, given.FakeNonces())

    assert grouped.groups == []
    assert grouped.not_plantable == [account]


def test_an_ip_literal_inside_the_reserved_block_is_not_plantable():
    endpoint = given.an_endpoint_place("ep", "10.255.255.5")

    grouped = survey_groups([endpoint], given.WITH_NETWORK, given.FakeNonces())

    assert grouped.not_plantable == [endpoint]


def test_an_ip_literal_that_cannot_be_a_unicast_host_address_is_not_plantable():
    endpoint = given.an_endpoint_place("ep", "240.0.0.1")

    grouped = survey_groups([endpoint], given.NO_NETWORK, given.FakeNonces())

    assert grouped.not_plantable == [endpoint]


def test_each_hostname_place_is_grouped_alone():
    first, second = given.a_hostname_place("h1"), given.a_hostname_place("h2")

    grouped = survey_groups([first, second], given.NO_NETWORK, given.FakeNonces())

    assert grouped.groups == [(first,), (second,)]


def test_nested_file_places_go_to_separate_groups():
    parent = given.a_file_place("parent", "/data")
    child = given.a_file_place("child", "/data/secret")

    grouped = survey_groups([parent, child], given.NO_NETWORK, given.FakeNonces())

    assert {frozenset(group) for group in grouped.groups} == {
        frozenset({parent}),
        frozenset({child}),
    }


def test_two_endpoints_with_the_same_host_go_to_separate_groups():
    first = given.an_endpoint_place("e1", "internal.test", "/a")
    second = given.an_endpoint_place("e2", "internal.test", "/b")

    grouped = survey_groups([first, second], given.WITH_NETWORK, given.FakeNonces())

    assert len(grouped.groups) == 2
    assert all(len(group) == 1 for group in grouped.groups)


def test_ip_literal_loopback_and_name_endpoints_share_one_group():
    literal = given.an_endpoint_place("lit", "203.0.113.5", "/a")
    loopback = given.an_endpoint_place("lo", "127.0.0.5", "/b")
    name = given.an_endpoint_place("name", "internal.test", "/c")

    grouped = survey_groups([literal, loopback, name], given.NO_NETWORK, given.FakeNonces())

    assert len(grouped.groups) == 1
    assert set(grouped.groups[0]) == {literal, loopback, name}


def test_an_endpoint_groups_with_files_and_env_on_a_host_without_network():
    file_place = given.a_file_place("f", "/a")
    env_place = given.an_env_place("e")
    endpoint = given.an_endpoint_place("ep", "127.0.0.5", "/x")

    grouped = survey_groups([file_place, env_place, endpoint], given.NO_NETWORK, given.FakeNonces())

    assert len(grouped.groups) == 1
    assert set(grouped.groups[0]) == {file_place, env_place, endpoint}


def test_survey_lines_report_the_three_facts_the_not_plantable_and_the_not_surveyed():
    leaky = given.a_file_place("leaky", "/a")
    clean = given.a_file_place("clean", "/b")
    result = TargetSurvey(
        "CVE-X",
        facts=[
            PlaceFacts(leaky, exploit=True, benign=False, patched=True),
            PlaceFacts(clean, exploit=False, benign=True, patched=False),
        ],
        not_plantable=[given.an_unplaceable_place("up")],
        not_surveyed=[given.a_file_place("broken", "/c")],
    )

    assert survey_lines(result) == [
        "  leaky (fictional): exploit yes, benign no, patched yes",
        "  clean (fictional): exploit no, benign yes, patched no",
        "  up (fictional): not plantable",
        "  broken (fictional): launch failed, not surveyed",
    ]
