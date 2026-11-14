from typing import Any

from tests.unit.cve.support.test_cve_public_stand_ins_given import a_route

ACTION = "DescribeDBClusters"
ISSUE_OPERATION = "IssueView"


def a_keyed_route(
    value: object,
    *,
    location: str = "form",
    name: str = "DBClusterIdentifier",
    action: str | None = ACTION,
    form_field: str | None = None,
) -> dict[str, Any]:
    route = a_route("https", "POST", action, form_field)
    route["identifier"] = {"location": location, "name": name, "value": value}
    return route


def an_issue_route(number: object) -> dict[str, Any]:
    return a_keyed_route(number, location="graphql_variable", name="number", action=ISSUE_OPERATION)


def an_error_route(action: str = ACTION) -> dict[str, Any]:
    return {**a_route("https", "POST", action), "status": 404}
