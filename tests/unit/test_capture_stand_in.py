from dataclasses import replace

import httpx
import pytest

import tests.unit.support.test_capture_stand_in_given as given
from evals.capture_stand_in import (
    CaptureRequest,
    ProbedDefault,
    capture_record,
    default_requests,
    parse_request,
    path_form,
)
from evals.public_stand_ins import StandInCapture
from tests.unit.support.test_public_stand_ins_given import PROBED_TARGET

_HTML = ("Content-Type", "text/html; charset=utf-8")
_JSON = ("Content-Type", "application/json")


def test_a_route_keeps_its_status_headers_and_body_verbatim():
    record = capture_record(given.A_PROVENANCE, [given.a_route()], given.NOT_FOUND_DEFAULTS)

    assert record["routes"] == [
        {
            "scheme": "https",
            "method": "GET",
            "target": "/robots.txt?a=1",
            "status": 200,
            "headers": [["Content-Type", "text/html; charset=UTF-8"], ["Alt-Svc", 'h3=":443"']],
            "body": "<html>hi</html>",
        }
    ]
    assert record["host"] == "example.com"
    assert record["address"] == "93.184.215.14"
    assert record["captured_at"] == "2026-11-02T10:00:00Z"
    assert record["command"] == given.A_PROVENANCE.command


def test_an_error_status_is_recorded_like_a_success():
    record = capture_record(
        given.A_PROVENANCE,
        [given.a_route(status=401, body=b'{"error":"x"}')],
        given.NOT_FOUND_DEFAULTS,
    )

    assert record["routes"][0]["status"] == 401
    assert record["routes"][0]["body"] == '{"error":"x"}'


def test_each_sent_request_header_is_recorded_with_its_name_and_value():
    record = capture_record(given.A_PROVENANCE, [given.a_route()], given.NOT_FOUND_DEFAULTS)

    assert record["request_headers"] == [["Authorization", "Bearer calib-token"]]


def test_a_body_that_is_not_utf8_is_refused():
    with pytest.raises(ValueError, match="UTF-8"):
        capture_record(
            given.A_PROVENANCE, [given.a_route(body=b"\xff\xfe")], given.NOT_FOUND_DEFAULTS
        )


_GZIP = ("Content-Encoding", "gzip")


def test_a_route_with_a_content_coding_is_refused():
    coded = replace(given.a_route(), headers=(_HTML, _GZIP))

    with pytest.raises(ValueError, match="Content-Encoding gzip"):
        capture_record(given.A_PROVENANCE, [coded], given.NOT_FOUND_DEFAULTS)


def test_a_default_with_a_content_coding_is_refused():
    plain = replace(given.a_not_found_answer("https", PROBED_TARGET), headers=(_GZIP,))
    coded = ProbedDefault(plain=plain, form=given.a_not_found_answer("https", given.FORM_TARGET))

    with pytest.raises(ValueError, match="Content-Encoding gzip"):
        capture_record(given.A_PROVENANCE, [], (given.a_not_found_default("http"), coded))


def test_an_identity_content_coding_is_recorded_as_sent():
    identity = replace(given.a_route(), headers=(_HTML, ("content-encoding", "identity")))

    record = capture_record(given.A_PROVENANCE, [identity], given.NOT_FOUND_DEFAULTS)

    assert record["routes"][0]["headers"] == [list(_HTML), ["content-encoding", "identity"]]


def test_a_head_route_keeps_its_method_status_and_headers_with_an_empty_body():
    record = capture_record(
        given.A_PROVENANCE, [given.a_route(method="HEAD", body=b"")], given.NOT_FOUND_DEFAULTS
    )
    route = record["routes"][0]

    assert route["method"] == "HEAD"
    assert route["status"] == 200
    assert route["headers"] == [
        ["Content-Type", "text/html; charset=UTF-8"],
        ["Alt-Svc", 'h3=":443"'],
    ]
    assert route["body"] == ""


def test_a_bare_url_is_a_get():
    assert parse_request("https://example.com/a?b=1") == CaptureRequest(
        "GET", httpx.URL("https://example.com/a?b=1")
    )


def test_a_url_prefixed_head_is_a_head():
    assert parse_request("HEAD https://example.com/") == CaptureRequest(
        "HEAD", httpx.URL("https://example.com/")
    )


def test_a_url_prefixed_post_and_followed_by_a_form_body_is_a_post_of_that_field():
    assert parse_request("POST https://example.com/html/ q=wikipedia") == CaptureRequest(
        "POST", httpx.URL("https://example.com/html/"), body="q=wikipedia", form_field="q"
    )


@pytest.mark.parametrize(
    "text",
    [
        "PUT https://example.com/",
        "POST https://example.com/",
        "POST https://example.com/ q=wikipedia&kl=fr-fr",
        "POST https://example.com/ =wikipedia",
        "HEAD https://example.com/ q=wikipedia",
    ],
    ids=["another_method", "post_without_body", "two_fields", "unnamed_field", "head_with_body"],
)
def test_a_request_other_than_a_get_a_head_or_a_post_of_one_form_field_is_refused(text: str):
    with pytest.raises(SystemExit, match="HEAD"):
        parse_request(text)


def test_a_post_route_records_the_form_field_its_request_carried():
    posted = replace(given.a_route(), method="POST", form_field="q")

    record = capture_record(given.A_PROVENANCE, [posted], given.NOT_FOUND_DEFAULTS)

    assert record["routes"][0]["method"] == "POST"
    assert record["routes"][0]["form_field"] == "q"


def test_the_record_says_it_was_captured():
    record = capture_record(given.A_PROVENANCE, [given.a_route()], given.NOT_FOUND_DEFAULTS)

    assert record["source"] == "capture"
    StandInCapture.model_validate(record)


def test_each_default_keeps_its_scheme_probed_target_status_headers_body_and_path_form():
    location = ("Location", f"https://example.com{PROBED_TARGET}")
    redirect = ProbedDefault(
        plain=replace(
            given.a_not_found_answer(
                "http", PROBED_TARGET, (location, ("Server", "cloudflare")), ""
            ),
            status=301,
        ),
        form=replace(given.a_not_found_answer("http", given.FORM_TARGET), status=301),
    )

    record = capture_record(given.A_PROVENANCE, [given.a_route()], [redirect, given.AN_HTML_PROBE])

    assert record["defaults"] == [
        {
            "scheme": "http",
            "probed_target": PROBED_TARGET,
            "status": 301,
            "headers": [list(location), ["Server", "cloudflare"]],
            "body": "",
            "path_form": None,
        },
        {
            "scheme": "https",
            "probed_target": PROBED_TARGET,
            "status": 404,
            "headers": [list(_HTML)],
            "body": given.AN_HTML_PROBE.plain.body.decode(),
            "path_form": "decoded",
        },
    ]
    assert len(record["routes"]) == 1


@pytest.mark.parametrize(
    ("probe", "expected"),
    [
        (given.AN_HTML_PROBE, "decoded"),
        (
            given.a_probed_default(
                (_JSON,),
                f'{{"path": "{PROBED_TARGET}"}}',
                f'{{"path": "{PROBED_TARGET}<x>\\"\'"}}',
            ),
            "decoded",
        ),
        (
            given.a_probed_default(
                (_HTML,),
                f"<p>{PROBED_TARGET}</p><p>{PROBED_TARGET}</p>",
                f"<p>{given.FORM_TARGET}</p><p>{given.FORM_TARGET}</p>",
            ),
            "raw",
        ),
        (given.a_not_found_default("https"), None),
    ],
    ids=["html_decoded", "json_decoded", "html_raw", "no_quote"],
)
def test_the_path_form_is_the_form_in_which_the_form_probe_quotes_its_target(
    probe: ProbedDefault, expected: str | None
):
    assert path_form(probe) == expected


_PYTHON_ESCAPED = f"{PROBED_TARGET}&lt;x&gt;&quot;&#x27;"


@pytest.mark.parametrize(
    ("probe", "reason"),
    [
        (
            given.a_probed_default(
                (("Content-Type", "text/plain"),), PROBED_TARGET, given.FORM_TARGET
            ),
            "neither HTML nor JSON",
        ),
        (
            given.a_probed_default(
                (_HTML,),
                f"{PROBED_TARGET} {PROBED_TARGET}",
                f"{_PYTHON_ESCAPED} {_PYTHON_ESCAPED}",
            ),
            "form probe",
        ),
        (
            given.a_probed_default(
                (_HTML,),
                f"{PROBED_TARGET} {PROBED_TARGET}",
                f"{given.HTML_DECODED} {given.FORM_TARGET}",
            ),
            "form probe",
        ),
        (
            given.a_probed_default(
                (_HTML,), f"{PROBED_TARGET} {PROBED_TARGET}", given.HTML_DECODED
            ),
            "form probe",
        ),
        (
            replace(given.AN_HTML_PROBE, form=replace(given.AN_HTML_PROBE.form, status=400)),
            "status",
        ),
        (
            replace(given.AN_HTML_PROBE, form=replace(given.AN_HTML_PROBE.form, headers=(_JSON,))),
            "media type",
        ),
    ],
    ids=[
        "plain_text_body",
        "another_escaping",
        "mixed_forms",
        "another_count",
        "another_status",
        "another_media_type",
    ],
)
def test_a_default_whose_quote_the_stand_in_cannot_reproduce_is_refused(
    probe: ProbedDefault, reason: str
):
    with pytest.raises(ValueError, match=reason):
        capture_record(
            given.A_PROVENANCE, [given.a_route()], [given.a_not_found_default("http"), probe]
        )


def test_the_default_requests_are_the_plain_then_the_form_probe_on_each_scheme():
    requests = default_requests("example.com", PROBED_TARGET)

    assert [(request.method, str(request.url)) for request in requests] == [
        ("GET", "http://example.com/0123456789abcdef"),
        ("GET", "https://example.com/0123456789abcdef"),
        ("GET", "http://example.com/0123456789abcdef%3Cx%3E%22%27"),
        ("GET", "https://example.com/0123456789abcdef%3Cx%3E%22%27"),
    ]
    assert {request.url.raw_path for request in requests[2:]} == {b"/0123456789abcdef%3Cx%3E%22%27"}
