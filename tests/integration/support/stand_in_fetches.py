import json
from dataclasses import dataclass

from evals.cve.planting import PlantedArgs
from evals.cve.planting_base import STAND_IN_IMAGE
from tests.integration.support.target_commands import TargetCommand, run_as_target


@dataclass(frozen=True)
class Sent:
    headers: tuple[tuple[str, str], ...]
    body: str


def an_aws_json_request(action: str, body: str) -> Sent:
    return Sent((("X-Amz-Target", action), ("Content-Type", "application/x-amz-json-1.1")), body)


def an_aws_query_request(action: str, fields: str = "") -> Sent:
    return Sent(
        (("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),),
        f"Action={action}&Version=2014-10-31{fields}",
    )


def a_graphql_request(query: str, variables: dict[str, object] | None = None) -> Sent:
    body: dict[str, object] = {"query": query}
    if variables is not None:
        body["variables"] = variables
    return Sent((("Content-Type", "application/json; charset=utf-8"),), json.dumps(body))


# The stand-in image's Python as the target: http.client sends the request target as given and
# follows no redirect, and the default context verifies TLS against the default paths, which
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
