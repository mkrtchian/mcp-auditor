import json
from collections.abc import Sequence
from pathlib import Path

from tests.integration.support.test_cve_planting_stand_ins_given import (
    GRAPHQL_TARGET,
    Sent,
    a_stand_ins_directory,
)

_AMZ_JSON = (("Content-Type", "application/x-amz-json-1.1"),)
_FORM = (("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),)
_GRAPHQL = (("Content-Type", "application/json; charset=utf-8"),)

# A JSON-protocol action keyed on a top-level member, the X-Amz-Target naming the action.
SECRET_DESCRIBED = "secretsmanager.DescribeSecret"
SECRET_ID = "MyTestDatabaseSecret"
DESCRIBED_BODY = '{"Name": "MyTestDatabaseSecret"}'
DESCRIBED_HEADERS = _AMZ_JSON
SECRET_NOT_FOUND = (400, '{"__type":"ResourceNotFoundException"}')
# A query-protocol action keyed on a form field.
CLUSTERS_ACTION = "DescribeDBClusters"
CLUSTER_ID = "app-cluster"
CLUSTERS_BODY = "<DescribeDBClustersResponse>app-cluster</DescribeDBClustersResponse>"
CLUSTERS_HEADERS = (("Content-Type", "text/xml"),)
CLUSTER_NOT_FOUND = (404, "<ErrorResponse><Error><Code>DBClusterNotFoundFault</Code></Error>")
# A GraphQL operation keyed on an integer variable, as gh sends an issue number.
ISSUE_OPERATION = "IssueView"
ISSUE_BODY = '{"data": {"repository": {"issue": {"number": 1}}}}'
ISSUE_HEADERS = (("Content-Type", "application/json"),)
ISSUE_NOT_FOUND = (200, '{"errors": [{"message": "no issue"}]}')


def a_keyed_stand_ins_directory(directory: Path) -> Path:
    return a_stand_ins_directory(
        directory,
        more_routes=[
            {
                **_route("/", SECRET_DESCRIBED, (DESCRIBED_HEADERS, DESCRIBED_BODY)),
                "identifier": _identifier("json_member", "SecretId", SECRET_ID),
            },
            _error("/", SECRET_DESCRIBED, SECRET_NOT_FOUND),
            {
                **_route("/", CLUSTERS_ACTION, (CLUSTERS_HEADERS, CLUSTERS_BODY)),
                "identifier": _identifier("form", "DBClusterIdentifier", CLUSTER_ID),
            },
            _error("/", CLUSTERS_ACTION, CLUSTER_NOT_FOUND),
            {
                **_route(GRAPHQL_TARGET, ISSUE_OPERATION, (ISSUE_HEADERS, ISSUE_BODY)),
                "identifier": _identifier("graphql_variable", "number", 1),
            },
            _error(GRAPHQL_TARGET, ISSUE_OPERATION, ISSUE_NOT_FOUND),
        ],
    )


def _identifier(location: str, name: str, value: str | int) -> dict[str, object]:
    return {"location": location, "name": name, "value": value}


def _route(
    target: str, action: str, answer: tuple[Sequence[tuple[str, str]], str]
) -> dict[str, object]:
    headers, body = answer
    return {
        "scheme": "https",
        "method": "POST",
        "request_target": target,
        "action": action,
        "status": 200,
        "headers": [list(header) for header in headers],
        "body": body,
    }


def _error(target: str, action: str, answer: tuple[int, str]) -> dict[str, object]:
    status, body = answer
    return {**_route(target, action, ((), body)), "status": status}


def a_secret_request(body: str, action: str = SECRET_DESCRIBED) -> Sent:
    return Sent((("X-Amz-Target", action), *_AMZ_JSON), body)


def a_clusters_request(fields: str) -> Sent:
    return Sent(_FORM, f"Action={CLUSTERS_ACTION}&Version=2014-10-31{fields}")


def an_issue_request(number: object) -> Sent:
    query = f"query {ISSUE_OPERATION}($number: Int!) {{ repository {{ issue(number: $number) }} }}"
    return Sent(_GRAPHQL, json.dumps({"query": query, "variables": {"number": number}}))
