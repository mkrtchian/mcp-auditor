import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve.planting import (
    RANDOM_NONCES,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from evals.cve.planting_base import PublicNames

STAND_IN_HOST = "public.fict"
STAND_IN_ADDRESS = "93.184.215.14"  # a global unicast address, as the capture loader requires
PROBED_TARGET = "/0123456789abcdef"
PLAIN_BODY = "the plain stand-in body"
# A captured route is replayed verbatim, so the probed target in it stays as captured.
SECURE_BODY = f"the secure stand-in body, {PROBED_TARGET} as captured"
MISSING_BODY = "the secure stand-in's answer to an unknown path"
# A request target a client sends percent-encoded, every character the escapings rewrite in it.
QUOTED_REQUEST = "/a%3Cb%3E%22%27"
CAPTURED_DATE = "Wed, 04 Nov 2026 07:36:50 GMT"
# The secure route's headers as a host sends them: duplicates, a lowercase name, and the
# connection and framing headers of the capture's own connection, with a length that is wrong
# for the replayed body.
SECURE_HEADERS = (
    ("Date", CAPTURED_DATE),
    ("Content-Type", "text/plain"),
    ("Transfer-Encoding", "chunked"),
    ("Connection", "keep-alive"),
    ("Server", "cloudflare"),
    ("Set-Cookie", "first=1; Path=/"),
    ("Set-Cookie", "second=2; Path=/"),
    ("strict-transport-security", "max-age=31536000"),
    ("Content-Length", "999"),
)
SECURE_REPLAYED = (
    ("Date", CAPTURED_DATE),
    ("Content-Type", "text/plain"),
    ("Server", "cloudflare"),
    ("Set-Cookie", "first=1; Path=/"),
    ("Set-Cookie", "second=2; Path=/"),
    ("strict-transport-security", "max-age=31536000"),
)
HEAD_ONLY_TARGET = "/checked"
# A HEAD route's captured length is the host's length for the body it did not send, kept as is.
HEAD_ONLY_HEADERS = (
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
    ("keep-alive", "timeout=5"),
    ("Date", CAPTURED_DATE),
)
HEAD_ONLY_REPLAYED = (
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
    ("Date", CAPTURED_DATE),
)
REDIRECT_SERVER = ("Server", "cloudflare")
# Two AWS routes on one `POST /`, written as the services' published examples are: the JSON
# protocol keys on the full `X-Amz-Target` value, the query protocol on the bare `Action` value.
SECRET_ACTION = "secretsmanager.GetSecretValue"
SECRET_BODY = '{"Name": "fict", "SecretString": "the secret"}'
SECRET_HEADERS = (("Content-Type", "application/x-amz-json-1.1"),)
INSTANCES_ACTION = "DescribeDBInstances"
INSTANCES_BODY = "<DescribeDBInstancesResponse></DescribeDBInstancesResponse>"
INSTANCES_HEADERS = (("Content-Type", "text/xml"),)
# A search form's route, chosen by the field the form body carries.
FORM_TARGET = "/html/"
FORM_FIELD = "q"
RESULTS_BODY = "<html>the results for wikipedia</html>"
RESULTS_HEADERS = (("Content-Type", "text/html"),)
# A GraphQL API's routes, chosen by the operation name the JSON body's query declares.
GRAPHQL_TARGET = "/graphql"
ISSUES_OPERATION = "IssueList"
ISSUES_BODY = '{"data": {"repository": {"name": "fict"}}}'
ISSUES_HEADERS = (("Content-Type", "application/json; charset=utf-8"),)
GRAPHQL_FALLBACK_BODY = '{"data": {"viewer": {"login": "fict"}}}'
GRAPHQL_FALLBACK_HEADERS = (("Content-Type", "application/json"), ("X-Fallback", "graphql"))
_GENERATE_TLS = Path(__file__).parents[3] / "evals" / "stand_ins" / "tls" / "generate.sh"


def a_stand_in_spec() -> PlantingSpec:
    names = PublicNames(stand_ins=(STAND_IN_HOST,), trust=("SSL_CERT_FILE",))
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", True, names)
    return planting_spec([], planting_host, RANDOM_NONCES)


@dataclass(frozen=True)
class QuotingCase:
    content_type: str
    path_form: str
    body: str
    quoted_request: str

    def answer(self, target: str) -> str:
        return self.body.replace(PROBED_TARGET, target)


QUOTING_CASES = {
    "decoded_html": QuotingCase(
        "text/html; charset=utf-8",
        "decoded",
        f'<option value="/fr{PROBED_TARGET}">fr</option><p>No page at {PROBED_TARGET}.</p>',
        "/a&lt;b&gt;&#34;&#39;",
    ),
    "decoded_json": QuotingCase(
        "application/json",
        "decoded",
        f'{{"path": "{PROBED_TARGET}", "error": "no route for {PROBED_TARGET}"}}',
        "/a<b>\\\"'",
    ),
    "raw_html": QuotingCase(
        "text/html",
        "raw",
        f'<option value="/fr{PROBED_TARGET}">fr</option><p>No page at {PROBED_TARGET}.</p>',
        QUOTED_REQUEST,
    ),
}


def a_stand_ins_directory(
    directory: Path,
    quoting: QuotingCase | None = None,
    more_routes: Sequence[dict[str, object]] = (),
) -> Path:
    secure_default = _not_found() if quoting is None else _quoting_not_found(quoting)
    capture = {
        "host": STAND_IN_HOST,
        "address": STAND_IN_ADDRESS,
        "source": "capture",
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json http://public.fict/",
        "request_headers": list[list[str]](),
        "routes": [
            _route("http", PLAIN_BODY, [["Content-Type", "text/plain"]]),
            _route("https", SECURE_BODY, [list(header) for header in SECURE_HEADERS]),
            _head_only_route(),
            _post_route("/", SECRET_ACTION, SECRET_BODY, SECRET_HEADERS),
            _post_route("/", INSTANCES_ACTION, INSTANCES_BODY, INSTANCES_HEADERS),
            _form_route(),
            _post_route(GRAPHQL_TARGET, ISSUES_OPERATION, ISSUES_BODY, ISSUES_HEADERS),
            _post_route(GRAPHQL_TARGET, None, GRAPHQL_FALLBACK_BODY, GRAPHQL_FALLBACK_HEADERS),
            *more_routes,
        ],
        "defaults": [_redirect_to_https(), secure_default],
    }
    (directory / f"{STAND_IN_HOST}.json").write_text(json.dumps(capture))
    subprocess.run(
        [str(_GENERATE_TLS), "--out", str(directory / "tls"), STAND_IN_HOST],
        check=True,
        capture_output=True,
    )
    return directory


def _route(scheme: str, body: str, headers: list[list[str]]) -> dict[str, object]:
    return {
        "scheme": scheme,
        "method": "GET",
        "request_target": "/",
        "status": 200,
        "headers": headers,
        "body": body,
    }


def _head_only_route() -> dict[str, object]:
    return {
        "scheme": "https",
        "method": "HEAD",
        "request_target": HEAD_ONLY_TARGET,
        "status": 200,
        "headers": [list(header) for header in HEAD_ONLY_HEADERS],
        "body": "",
    }


def _post_route(
    request_target: str, action: str | None, body: str, headers: Sequence[tuple[str, str]]
) -> dict[str, object]:
    route: dict[str, object] = {
        "scheme": "https",
        "method": "POST",
        "request_target": request_target,
        "status": 200,
        "headers": [list(header) for header in headers],
        "body": body,
    }
    if action is not None:
        route["action"] = action
    return route


def _form_route() -> dict[str, object]:
    return {
        "scheme": "https",
        "method": "POST",
        "request_target": FORM_TARGET,
        "form_field": FORM_FIELD,
        "status": 200,
        "headers": [list(header) for header in RESULTS_HEADERS],
        "body": RESULTS_BODY,
    }


def _redirect_to_https() -> dict[str, object]:
    return {
        "scheme": "http",
        "probed_request_target": PROBED_TARGET,
        "status": 301,
        "headers": [
            ["Location", f"https://{STAND_IN_HOST}{PROBED_TARGET}"],
            list(REDIRECT_SERVER),
        ],
        "body": "",
        "path_form": None,
    }


def _not_found() -> dict[str, object]:
    return {
        "scheme": "https",
        "probed_request_target": PROBED_TARGET,
        "status": 404,
        "headers": [["Content-Type", "text/plain"]],
        "body": MISSING_BODY,
        "path_form": None,
    }


def _quoting_not_found(case: QuotingCase) -> dict[str, object]:
    return {
        "scheme": "https",
        "probed_request_target": PROBED_TARGET,
        "status": 404,
        "headers": [["Content-Type", case.content_type]],
        "body": case.body,
        "path_form": case.path_form,
    }
