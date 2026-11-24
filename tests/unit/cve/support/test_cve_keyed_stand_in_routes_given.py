from typing import Any

from tests.unit.support.fictional_stand_ins import a_route

ACTION = "DescribeDBClusters"
ISSUE_OPERATION = "IssueView"


def an_issue_route(number: object) -> dict[str, Any]:
    return a_keyed_route(number, location="graphql_variable", name="number", action=ISSUE_OPERATION)


def a_keyed_route(
    value: object,
    *,
    location: str = "form",
    name: str = "DBClusterIdentifier",
    action: str | None = ACTION,
) -> dict[str, Any]:
    route = a_route("https", "POST", action)
    route["identifier"] = {"location": location, "name": name, "value": value}
    return route


def an_error_route(action: str = ACTION) -> dict[str, Any]:
    return {**a_route("https", "POST", action), "status": 404}
