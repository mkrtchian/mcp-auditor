import json

import pytest

import tests.unit.cve.backends.support.test_atlassian_backend_given as given
from evals.cve.backends.atlassian import atlassian_env_args
from tests.unit.support.docker_argv import environment

JIRA_ERROR: dict[str, object] = {"errorMessages": [], "errors": {}}


def test_the_environment_points_at_the_responder_address_it_is_given():
    variables = environment(atlassian_env_args("198.18.0.77"))

    assert variables["JIRA_URL"] == "http://198.18.0.77"
    assert variables["CONFLUENCE_URL"] == "http://198.18.0.77"


def test_both_clients_are_scoped_to_the_project_and_space_of_the_server_examples():
    variables = environment(atlassian_env_args("198.18.0.77"))

    assert variables["JIRA_PROJECTS_FILTER"] == "PROJ"
    assert variables["CONFLUENCE_SPACES_FILTER"] == "TEAM"


@pytest.mark.parametrize("jql", given.PROJ_JQLS)
def test_each_jql_the_server_builds_for_the_project_answers_its_issues(
    jql: str, monkeypatch: pytest.MonkeyPatch
):
    answer = given.a_jira_search(given.the_responder(monkeypatch), jql)

    assert answer.status == 200
    assert answer.body["issues"][0]["key"] == "PROJ-19"


@pytest.mark.parametrize(
    "jql",
    [
        "project = PROJ AND summary ~ report",
        "(sprint = 7) AND project = PROJ",
        "((issuetype = Task) AND project = PROJ) AND project = DEMO",
        "project = PROJ OR project = DEMO",
    ],
)
def test_any_other_jql_answers_the_bare_error_collection(jql: str, monkeypatch: pytest.MonkeyPatch):
    answer = given.a_jira_search(given.the_responder(monkeypatch), jql)

    assert (answer.status, answer.body) == (400, JIRA_ERROR)


@pytest.mark.parametrize("jql", given.DEMO_JQLS)
def test_a_fix_checks_responder_gives_the_out_of_allowlist_issues_its_witness(
    jql: str, monkeypatch: pytest.MonkeyPatch
):
    answer = given.a_jira_search(
        given.the_responder(monkeypatch, demo_summary="MCPAUDIT-ab12"), jql
    )

    assert answer.status == 200
    assert {issue["fields"]["summary"] for issue in answer.body["issues"]} == {"MCPAUDIT-ab12"}


@pytest.mark.parametrize(("key", "identifier"), [("PROJ-19", "10050"), ("PROJ-35", "10389")])
def test_each_issue_a_project_search_returns_answers_the_servers_issue_fixture_under_its_key(
    key: str, identifier: str, monkeypatch: pytest.MonkeyPatch
):
    answer = given.a_jira_issue(given.the_responder(monkeypatch), key)

    assert answer.status == 200
    assert (answer.body["key"], answer.body["id"]) == (key, identifier)
    assert answer.body["self"] == f"http://localhost:8080/rest/api/2/issue/{identifier}"
    assert answer.body["fields"]["summary"] == "Test Issue Summary"
    assert answer.body["fields"]["project"]["key"] == "PROJ"
    assert "example.atlassian.net" not in json.dumps(answer.body)


def test_an_issue_of_the_demo_search_answers_under_the_demo_project(
    monkeypatch: pytest.MonkeyPatch,
):
    answer = given.a_jira_issue(given.the_responder(monkeypatch), "DEMO-19")

    assert (answer.status, answer.body["key"]) == (200, "DEMO-19")
    assert answer.body["fields"]["project"]["key"] == "DEMO"


@pytest.mark.parametrize("key", ["PROJ-123", "PROJ-21", "OTHER-1"])
def test_an_issue_no_search_returns_answers_jiras_404(key: str, monkeypatch: pytest.MonkeyPatch):
    answer = given.a_jira_issue(given.the_responder(monkeypatch), key)

    assert (answer.status, answer.body) == (404, JIRA_ERROR)


@pytest.mark.parametrize("cql", given.TEAM_CQLS)
def test_each_cql_the_server_builds_for_the_space_answers_its_page(
    cql: str, monkeypatch: pytest.MonkeyPatch
):
    answer = given.a_confluence_search(given.the_responder(monkeypatch), cql)

    assert answer.status == 200
    assert [result["title"] for result in answer.body["results"]] == [
        "2024-01-01: Team Progress Meeting 01"
    ]


def test_a_fix_checks_responder_gives_the_out_of_allowlist_page_its_witness(
    monkeypatch: pytest.MonkeyPatch,
):
    answer = given.a_confluence_search(
        given.the_responder(monkeypatch, demo_summary="MCPAUDIT-ab12"), given.DEMO_CQL
    )

    assert [result["title"] for result in answer.body["results"]] == ["MCPAUDIT-ab12"]


@pytest.mark.parametrize(
    "cql", ["((type = page) AND (space = TEAM)) AND (space = DEMO)", 'siteSearch ~ "meeting"']
)
def test_any_other_cql_answers_the_bare_rest_error_without_the_query(
    cql: str, monkeypatch: pytest.MonkeyPatch
):
    answer = given.a_confluence_search(given.the_responder(monkeypatch), cql)

    assert (answer.status, answer.body) == (400, {"statusCode": 400})


@pytest.mark.parametrize(
    ("method", "request_target"),
    [
        ("GET", "/rest/api/2/project"),
        ("POST", "/rest/api/2/issue"),
        ("PUT", "/rest/api/2/issue/PROJ-19"),
        ("DELETE", "/rest/api/content/123456789"),
        ("POST", "/rest/api/2/search"),
    ],
)
def test_every_other_method_and_path_answers_jiras_404_with_no_server_header(
    method: str, request_target: str, monkeypatch: pytest.MonkeyPatch
):
    with given.serving(given.the_responder(monkeypatch)) as server:
        served = given.a_request(server, method, request_target)

    assert served.status == 404
    assert json.loads(served.body) == JIRA_ERROR
    assert "server" not in served.headers


def test_a_served_search_carries_no_server_header_of_its_own(monkeypatch: pytest.MonkeyPatch):
    with given.serving(given.the_responder(monkeypatch)) as server:
        served = given.a_request(server, "GET", "/rest/api/search?cql=space+%3D+TEAM")

    assert served.status == 200
    assert "server" not in served.headers
