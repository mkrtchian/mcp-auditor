from evals.capture_stand_in import (
    FORM_SUFFIX,
    CapturedResponse,
    CaptureProvenance,
    ProbedDefault,
)
from tests.unit.support.test_public_stand_ins_given import PROBED_TARGET

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


def a_route(
    status: int = 200, body: bytes = b"<html>hi</html>", method: str = "GET"
) -> CapturedResponse:
    return CapturedResponse(
        scheme="https",
        method=method,
        target="/robots.txt?a=1",
        status=status,
        headers=(("Content-Type", "text/html; charset=UTF-8"), ("Alt-Svc", 'h3=":443"')),
        body=body,
    )


def a_not_found_answer(
    scheme: str, target: str, headers: tuple[tuple[str, str], ...] = (), body: str = "not found"
) -> CapturedResponse:
    return CapturedResponse(
        scheme=scheme, method="GET", target=target, status=404, headers=headers, body=body.encode()
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
