from tests.integration.support.stand_in_capture import (
    FORM_FIELD,
    INSTANCES_ACTION,
    ISSUES_OPERATION,
    SECRET_ACTION,
)
from tests.integration.support.stand_in_fetches import (
    Sent,
    a_graphql_request,
    an_aws_json_request,
    an_aws_query_request,
)

JSON_PROTOCOL_REQUEST = an_aws_json_request(SECRET_ACTION, '{"SecretId": "fict"}')
QUERY_PROTOCOL_REQUEST = an_aws_query_request(INSTANCES_ACTION)
UNKNOWN_ACTION_REQUEST = an_aws_json_request("secretsmanager.ListSecrets", "{}")
_FORM_CONTENT = (("Content-Type", "application/x-www-form-urlencoded"),)
SEARCH_REQUEST = Sent(_FORM_CONTENT, f"{FORM_FIELD}=wikipedia&kl=fr-fr")
FIELDLESS_SEARCH_REQUEST = Sent(_FORM_CONTENT, "kl=fr-fr")
# Shaped like gh's: the fragments come before the operation.
ISSUES_REQUEST = a_graphql_request(
    "fragment issue on Issue {\n\tnumber\n}\n\t"
    f"query {ISSUES_OPERATION}($owner: String!) {{ repository(owner: $owner) {{ name }} }}"
)
OTHER_OPERATION_REQUEST = a_graphql_request("query ViewerLogin { viewer { login } }")
ANONYMOUS_OPERATION_REQUEST = a_graphql_request("query { viewer { login } }")
