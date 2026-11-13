import json
from pathlib import Path
from typing import Any

import httpx

from evals.capture_defaults import FORM_SUFFIX
from evals.capture_stand_in import CapturedResponse, CaptureProvenance, ProbedDefault
from tests.unit.support.test_cve_public_stand_ins_given import (
    HOST,
    PROBED_TARGET,
    a_stand_in_directory,
)

A_PROVENANCE = CaptureProvenance(
    host="example.com",
    address="93.184.215.14",
    captured_at="2026-11-02T10:00:00Z",
    command="uv run python -m evals.capture_stand_in --out x.json https://example.com/",
    request_headers=(("Authorization", "Bearer calib-token"),),
)
FORM_TARGET = PROBED_TARGET + FORM_SUFFIX
HTML_DECODED = f"{PROBED_TARGET}&lt;x&gt;&#34;&#39;"

_HTML = ("Content-Type", "text/html; charset=utf-8")
_JSON = ("Content-Type", "application/json")


def a_route(
    status: int = 200, body: bytes = b"<html>hi</html>", method: str = "GET"
) -> CapturedResponse:
    return CapturedResponse(
        scheme="https",
        method=method,
        request_target="/robots.txt?a=1",
        status=status,
        headers=(("Content-Type", "text/html; charset=UTF-8"), ("Alt-Svc", 'h3=":443"')),
        body=body,
    )


def a_not_found_answer(
    scheme: str,
    request_target: str,
    headers: tuple[tuple[str, str], ...] = (),
    body: str = "not found",
) -> CapturedResponse:
    return CapturedResponse(
        scheme=scheme,
        method="GET",
        request_target=request_target,
        status=404,
        headers=headers,
        body=body.encode(),
    )


def a_probed_default(
    headers: tuple[tuple[str, str], ...], plain_body: str, form_body: str
) -> ProbedDefault:
    return ProbedDefault(
        plain=a_not_found_answer("https", PROBED_TARGET, headers, plain_body),
        form=a_not_found_answer("https", FORM_TARGET, headers, form_body),
    )


def a_not_found_default(scheme: str) -> ProbedDefault:
    return ProbedDefault(
        plain=a_not_found_answer(scheme, PROBED_TARGET),
        form=a_not_found_answer(scheme, FORM_TARGET),
    )


NOT_FOUND_DEFAULTS = (a_not_found_default("http"), a_not_found_default("https"))
AN_HTML_PROBE = a_probed_default(
    (_HTML,),
    f"<a href='{PROBED_TARGET}'>{PROBED_TARGET}</a>",
    f"<a href='{HTML_DECODED}'>{HTML_DECODED}</a>",
)


AN_ADDRESS_HOST_URL = "https://127.0.0.1/core/v2/rest/product/A"
OLD_HTTP_DEFAULT: dict[str, Any] = {
    "path_form": None,
    "body": "",
    "headers": [["Location", f"https://example.com{PROBED_TARGET}"], ["Server", "awselb/2.0"]],
    "status": 301,
    "probed_request_target": PROBED_TARGET,
    "scheme": "http",
}


def an_old_capture(directory: Path) -> Path:
    """A committed capture whose http default lists its keys in an order no model writes."""
    a_stand_in_directory(directory)
    out = directory / f"{HOST}.json"
    capture = json.loads(out.read_text())
    capture["defaults"][0] = OLD_HTTP_DEFAULT
    out.write_text(json.dumps(capture))
    return out


def a_recording_host(seen: list[httpx.URL]) -> httpx.MockTransport:
    """Answers 200 on its one route and a plain 404 elsewhere, recording each request's URL."""

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        if request.url.path == "/core/v2/rest/product/A":
            return httpx.Response(200, headers=[_JSON], text='{"items":[]}')
        return httpx.Response(404, headers=[("Content-Type", "text/plain")], text="not found")

    return httpx.MockTransport(answer)
