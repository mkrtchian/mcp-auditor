from pathlib import Path

from tests.integration.support.stand_in_capture import (
    GRAPHQL_REQUEST_TARGET,
    StandInAnswer,
    a_post_route,
    a_stand_ins_directory,
)
from tests.integration.support.stand_in_fetches import (
    Sent,
    a_graphql_request,
    an_aws_json_request,
    an_aws_query_request,
)

# A JSON-protocol action keyed on a top-level member, the X-Amz-Target naming the action.
SECRET_DESCRIBED = "secretsmanager.DescribeSecret"
SECRET_ID = "MyTestDatabaseSecret"
DESCRIBED_ANSWER = StandInAnswer(
    '{"Name": "MyTestDatabaseSecret"}', (("Content-Type", "application/x-amz-json-1.1"),)
)
SECRET_NOT_FOUND = StandInAnswer('{"__type":"ResourceNotFoundException"}', status=400)
# A query-protocol action keyed on a form field.
CLUSTERS_ACTION = "DescribeDBClusters"
CLUSTER_ID = "app-cluster"
CLUSTERS_ANSWER = StandInAnswer(
    "<DescribeDBClustersResponse>app-cluster</DescribeDBClustersResponse>",
    (("Content-Type", "text/xml"),),
)
CLUSTER_NOT_FOUND = StandInAnswer(
    "<ErrorResponse><Error><Code>DBClusterNotFoundFault</Code></Error>", status=404
)
# A GraphQL operation keyed on an integer variable, as gh sends an issue number.
ISSUE_OPERATION = "IssueView"
ISSUE_ANSWER = StandInAnswer(
    '{"data": {"repository": {"issue": {"number": 1}}}}', (("Content-Type", "application/json"),)
)
ISSUE_NOT_FOUND = StandInAnswer('{"errors": [{"message": "no issue"}]}')


def a_keyed_stand_ins_directory(directory: Path) -> Path:
    return a_stand_ins_directory(
        directory,
        more_routes=[
            {
                **a_post_route("/", SECRET_DESCRIBED, DESCRIBED_ANSWER),
                "identifier": _identifier("json_member", "SecretId", SECRET_ID),
            },
            a_post_route("/", SECRET_DESCRIBED, SECRET_NOT_FOUND),
            {
                **a_post_route("/", CLUSTERS_ACTION, CLUSTERS_ANSWER),
                "identifier": _identifier("form", "DBClusterIdentifier", CLUSTER_ID),
            },
            a_post_route("/", CLUSTERS_ACTION, CLUSTER_NOT_FOUND),
            {
                **a_post_route(GRAPHQL_REQUEST_TARGET, ISSUE_OPERATION, ISSUE_ANSWER),
                "identifier": _identifier("graphql_variable", "number", 1),
            },
            a_post_route(GRAPHQL_REQUEST_TARGET, ISSUE_OPERATION, ISSUE_NOT_FOUND),
        ],
    )


def _identifier(location: str, name: str, value: str | int) -> dict[str, object]:
    return {"location": location, "name": name, "value": value}


def a_secret_request(body: str, action: str = SECRET_DESCRIBED) -> Sent:
    return an_aws_json_request(action, body)


def a_clusters_request(fields: str) -> Sent:
    return an_aws_query_request(CLUSTERS_ACTION, fields)


def an_issue_request(number: object) -> Sent:
    query = f"query {ISSUE_OPERATION}($number: Int!) {{ repository {{ issue(number: $number) }} }}"
    return a_graphql_request(query, {"number": number})
