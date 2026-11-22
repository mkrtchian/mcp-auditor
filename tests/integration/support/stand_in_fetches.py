import json
from dataclasses import dataclass

from evals.cve.planting import PlantedArgs
from evals.cve.planting_base import STAND_IN_IMAGE
from tests.integration.support.stand_in_capture import INSTANCES_ACTION, SECRET_ACTION
from tests.integration.support.target_commands import TargetCommand, run_as_target


@dataclass(frozen=True)
class Sent:
    headers: tuple[tuple[str, str], ...]
    body: str


JSON_PROTOCOL_REQUEST = Sent(
    (("X-Amz-Target", SECRET_ACTION), ("Content-Type", "application/x-amz-json-1.1")),
    '{"SecretId": "fict"}',
)
QUERY_PROTOCOL_REQUEST = Sent(
    (("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),),
    f"Action={INSTANCES_ACTION}&Version=2014-10-31",
)
UNKNOWN_ACTION_REQUEST = Sent(
    (
        ("X-Amz-Target", "secretsmanager.ListSecrets"),
        ("Content-Type", "application/x-amz-json-1.1"),
    ),
    "{}",
)
_FORM_CONTENT = (("Content-Type", "application/x-www-form-urlencoded"),)
SEARCH_REQUEST = Sent(_FORM_CONTENT, "q=wikipedia&kl=fr-fr")
FIELDLESS_SEARCH_REQUEST = Sent(_FORM_CONTENT, "kl=fr-fr")
_JSON_CONTENT = (("Content-Type", "application/json; charset=utf-8"),)
# Shaped like gh's: the fragments come before the operation.
ISSUES_REQUEST = Sent(
    _JSON_CONTENT,
    json.dumps(
        {
            "query": "fragment issue on Issue {\n\tnumber\n}\n\t"
            "query IssueList($owner: String!) { repository(owner: $owner) { name } }"
        }
    ),
)
OTHER_OPERATION_REQUEST = Sent(
    _JSON_CONTENT, json.dumps({"query": "query ViewerLogin { viewer { login } }"})
)
ANONYMOUS_OPERATION_REQUEST = Sent(
    _JSON_CONTENT, json.dumps({"query": "query { viewer { login } }"})
)
# The stand-in image's Python as the target: http.client sends the target as given and follows
# no redirect, and the default context verifies TLS against the default paths, which
# `SSL_CERT_FILE` points at the fixture authority.
_FETCH = (
    "import http.client,json,ssl,sys,urllib.parse\n"
    "method,url=sys.argv[1],sys.argv[2]\n"
    "parts=urllib.parse.urlsplit(url)\n"
    "connection=(http.client.HTTPSConnection(parts.hostname,timeout=5,"
    "context=ssl.create_default_context()) if parts.scheme=='https'"
    " else http.client.HTTPConnection(parts.hostname,timeout=5))\n"
    "sent=json.loads(sys.argv[3]) if len(sys.argv)>3 else {'headers':[],'body':None}\n"
    "connection.request(method,parts.path,body=sent['body'],headers=dict(sent['headers']))\n"
    "response=connection.getresponse()\n"
    "header_list=response.getheaders()\n"
    "headers={name.lower():value for name,value in header_list}\n"
    "body=response.read().decode()\n"
    "print(json.dumps({'status':response.status,'headers':headers,'header_list':header_list,"
    "'body':body}),end='')"
)


@dataclass(frozen=True)
class Fetched:
    status: int
    headers: dict[str, str]
    header_list: list[tuple[str, str]]
    body: str


def fetch_as_target(
    args: PlantedArgs, url: str, method: str = "GET", sent: Sent | None = None
) -> Fetched:
    request = [] if sent is None else [json.dumps({"headers": sent.headers, "body": sent.body})]
    command = TargetCommand(STAND_IN_IMAGE, "python", ("-c", _FETCH, method, url, *request))
    result = run_as_target(args, command)
    fetched = json.loads(result.stdout)
    header_list = [(name, value) for name, value in fetched.pop("header_list")]
    return Fetched(**fetched, header_list=header_list)
