import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import tests.unit.support.fictional_planting as fictional_planting
from evals.cve.planting import RANDOM_NONCES, PlantingSpec
from evals.cve.planting_base import PublicNames
from tests.unit.support.fictional_stand_ins import (
    HOST,
    PROBED_REQUEST_TARGET,
    a_capture,
    a_default,
    a_route,
)


@dataclass(frozen=True)
class StandInAnswer:
    body: str
    headers: tuple[tuple[str, str], ...] = ()
    status: int = 200


PLAIN_BODY = "the plain stand-in body"
# A captured route is served verbatim, so the probed request target in it stays as captured.
SECURE_BODY = f"the secure stand-in body, {PROBED_REQUEST_TARGET} as captured"
MISSING_BODY = "the secure stand-in's answer to an unknown path"
# A request target a client sends percent-encoded, every character the escapings rewrite in it.
QUOTED_REQUEST = "/a%3Cb%3E%22%27"
_CAPTURED_DATE = "Wed, 04 Nov 2026 07:36:50 GMT"
# The secure route's headers as a host sends them: duplicates, a lowercase name, and the
# connection and framing headers of the capture's own connection, with a length that is wrong
# for the served body.
_SECURE_HEADERS = (
    ("Date", _CAPTURED_DATE),
    ("Content-Type", "text/plain"),
    ("Transfer-Encoding", "chunked"),
    ("Connection", "keep-alive"),
    ("Server", "cloudflare"),
    ("Set-Cookie", "first=1; Path=/"),
    ("Set-Cookie", "second=2; Path=/"),
    ("strict-transport-security", "max-age=31536000"),
    ("Content-Length", "999"),
)
SECURE_SERVED = (
    ("Date", _CAPTURED_DATE),
    ("Content-Type", "text/plain"),
    ("Server", "cloudflare"),
    ("Set-Cookie", "first=1; Path=/"),
    ("Set-Cookie", "second=2; Path=/"),
    ("strict-transport-security", "max-age=31536000"),
)
HEAD_ONLY_REQUEST_TARGET = "/checked"
# A HEAD route's captured length is the host's length for the body it did not send, kept as is.
_HEAD_ONLY_HEADERS = (
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
    ("keep-alive", "timeout=5"),
    ("Date", _CAPTURED_DATE),
)
HEAD_ONLY_SERVED = (
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
    ("Date", _CAPTURED_DATE),
)
REDIRECT_SERVER = ("Server", "cloudflare")
# Two AWS routes on one `POST /`, written as the services' published examples are: the JSON
# protocol keys on the full `X-Amz-Target` value, the query protocol on the bare `Action` value.
SECRET_ACTION = "secretsmanager.GetSecretValue"
SECRET_ANSWER = StandInAnswer(
    '{"Name": "fict", "SecretString": "the secret"}',
    (("Content-Type", "application/x-amz-json-1.1"),),
)
INSTANCES_ACTION = "DescribeDBInstances"
INSTANCES_ANSWER = StandInAnswer(
    "<DescribeDBInstancesResponse></DescribeDBInstancesResponse>", (("Content-Type", "text/xml"),)
)
# A search form's route, chosen by the field the form body carries.
FORM_REQUEST_TARGET = "/html/"
FORM_FIELD = "q"
RESULTS_ANSWER = StandInAnswer(
    "<html>the results for wikipedia</html>", (("Content-Type", "text/html"),)
)
# A GraphQL API's routes, chosen by the operation name the JSON body's query declares.
GRAPHQL_REQUEST_TARGET = "/graphql"
ISSUES_OPERATION = "IssueList"
ISSUES_ANSWER = StandInAnswer(
    '{"data": {"repository": {"name": "fict"}}}',
    (("Content-Type", "application/json; charset=utf-8"),),
)
GRAPHQL_FALLBACK_ANSWER = StandInAnswer(
    '{"data": {"viewer": {"login": "fict"}}}',
    (("Content-Type", "application/json"), ("X-Fallback", "graphql")),
)
MISSING_ANSWER = StandInAnswer(MISSING_BODY, (("Content-Type", "text/plain"),), 404)
_GENERATE_TLS = Path(__file__).parents[3] / "evals" / "stand_ins" / "tls" / "generate.sh"


def a_stand_in_spec() -> PlantingSpec:
    names = PublicNames(stand_ins=(HOST,), trust=("SSL_CERT_FILE",))
    host = fictional_planting.unprivileged_host(has_network=True, public_names=names)
    return fictional_planting.spec_of([], host, RANDOM_NONCES)


@dataclass(frozen=True)
class QuotingCase:
    content_type: str
    path_form: str
    body: str
    quoted_request: str

    def answer(self, request_target: str) -> str:
        return self.body.replace(PROBED_REQUEST_TARGET, request_target)


QUOTING_CASES = {
    "decoded_html": QuotingCase(
        "text/html; charset=utf-8",
        "decoded",
        f'<option value="/fr{PROBED_REQUEST_TARGET}">fr</option>'
        f"<p>No page at {PROBED_REQUEST_TARGET}.</p>",
        "/a&lt;b&gt;&#34;&#39;",
    ),
    "decoded_json": QuotingCase(
        "application/json",
        "decoded",
        f'{{"path": "{PROBED_REQUEST_TARGET}", "error": "no route for {PROBED_REQUEST_TARGET}"}}',
        "/a<b>\\\"'",
    ),
    "raw_html": QuotingCase(
        "text/html",
        "raw",
        f'<option value="/fr{PROBED_REQUEST_TARGET}">fr</option>'
        f"<p>No page at {PROBED_REQUEST_TARGET}.</p>",
        QUOTED_REQUEST,
    ),
}


def a_stand_ins_directory(
    directory: Path,
    quoting: QuotingCase | None = None,
    more_routes: Sequence[dict[str, object]] = (),
) -> Path:
    capture = a_capture(
        routes=_routes(more_routes), defaults=[_redirect_to_https(), _secure_default(quoting)]
    )
    (directory / f"{HOST}.json").write_text(json.dumps(capture))
    subprocess.run(
        [str(_GENERATE_TLS), "--out", str(directory / "tls"), HOST],
        check=True,
        capture_output=True,
    )
    return directory


def _routes(more_routes: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    plain = StandInAnswer(PLAIN_BODY, (("Content-Type", "text/plain"),))
    head_only = {
        **a_route("https", "HEAD"),
        "request_target": HEAD_ONLY_REQUEST_TARGET,
        **_answered(StandInAnswer("", _HEAD_ONLY_HEADERS)),
    }
    form = {
        **a_route("https", "POST", form_field=FORM_FIELD),
        "request_target": FORM_REQUEST_TARGET,
        **_answered(RESULTS_ANSWER),
    }
    return [
        {**a_route("http"), **_answered(plain)},
        {**a_route("https"), **_answered(StandInAnswer(SECURE_BODY, _SECURE_HEADERS))},
        head_only,
        a_post_route("/", SECRET_ACTION, SECRET_ANSWER),
        a_post_route("/", INSTANCES_ACTION, INSTANCES_ANSWER),
        form,
        a_post_route(GRAPHQL_REQUEST_TARGET, ISSUES_OPERATION, ISSUES_ANSWER),
        a_post_route(GRAPHQL_REQUEST_TARGET, None, GRAPHQL_FALLBACK_ANSWER),
        *more_routes,
    ]


def a_post_route(
    request_target: str, action: str | None, answer: StandInAnswer
) -> dict[str, object]:
    return {
        **a_route("https", "POST", action),
        "request_target": request_target,
        **_answered(answer),
    }


def _answered(answer: StandInAnswer) -> dict[str, object]:
    return {
        "status": answer.status,
        "headers": [list(header) for header in answer.headers],
        "body": answer.body,
    }


def _redirect_to_https() -> dict[str, object]:
    headers = [["Location", f"https://{HOST}{PROBED_REQUEST_TARGET}"], list(REDIRECT_SERVER)]
    return {**a_default("http", headers=headers, body=""), "status": 301}


def _secure_default(quoting: QuotingCase | None) -> dict[str, object]:
    if quoting is None:
        headers = [list(header) for header in MISSING_ANSWER.headers]
        return a_default("https", headers=headers, body=MISSING_ANSWER.body)
    return a_default(
        "https",
        headers=[["Content-Type", quoting.content_type]],
        body=quoting.body,
        path_form=quoting.path_form,
    )
