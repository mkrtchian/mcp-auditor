from dataclasses import replace

import pytest

from evals.capture_stand_in import (
    FORM_SUFFIX,
    CapturedResponse,
    CaptureProvenance,
    ProbedDefault,
    capture_record,
    default_requests,
    parse_request,
    path_form,
)

_PROVENANCE = CaptureProvenance(
    host="example.com",
    address="93.184.215.14",
    captured_at="2026-11-02T10:00:00Z",
    command="uv run python -m evals.capture_stand_in --out x.json https://example.com/",
    request_headers=(("Authorization", "Bearer calib-token"),),
)
_PROBED_TARGET = "/0123456789abcdef"


def _response(
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


_FORM_TARGET = _PROBED_TARGET + FORM_SUFFIX
_HTML = ("Content-Type", "text/html; charset=utf-8")
_JSON = ("Content-Type", "application/json")


def _answer(
    scheme: str, target: str, headers: tuple[tuple[str, str], ...] = (), body: str = "not found"
) -> CapturedResponse:
    return CapturedResponse(
        scheme=scheme, method="GET", target=target, status=404, headers=headers, body=body.encode()
    )


def _probe(headers: tuple[tuple[str, str], ...], plain_body: str, form_body: str) -> ProbedDefault:
    return ProbedDefault(
        plain=_answer("https", _PROBED_TARGET, headers, plain_body),
        form=_answer("https", _FORM_TARGET, headers, form_body),
    )


def _not_found(scheme: str) -> ProbedDefault:
    return ProbedDefault(plain=_answer(scheme, _PROBED_TARGET), form=_answer(scheme, _FORM_TARGET))


_DEFAULTS = (_not_found("http"), _not_found("https"))
_HTML_DECODED = f"{_PROBED_TARGET}&lt;x&gt;&#34;&#39;"
_HTML_PROBE = _probe(
    (_HTML,),
    f"<a href='{_PROBED_TARGET}'>{_PROBED_TARGET}</a>",
    f"<a href='{_HTML_DECODED}'>{_HTML_DECODED}</a>",
)


def test_a_route_keeps_its_status_headers_and_body_verbatim():
    record = capture_record(_PROVENANCE, [_response()], _DEFAULTS)

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
    assert record["command"] == _PROVENANCE.command


def test_an_error_status_is_recorded_like_a_success():
    record = capture_record(_PROVENANCE, [_response(status=401, body=b'{"error":"x"}')], _DEFAULTS)

    assert record["routes"][0]["status"] == 401
    assert record["routes"][0]["body"] == '{"error":"x"}'


def test_each_sent_request_header_is_recorded_with_its_name_and_value():
    record = capture_record(_PROVENANCE, [_response()], _DEFAULTS)

    assert record["request_headers"] == [["Authorization", "Bearer calib-token"]]


def test_a_body_that_is_not_utf8_is_refused():
    with pytest.raises(ValueError, match="UTF-8"):
        capture_record(_PROVENANCE, [_response(body=b"\xff\xfe")], _DEFAULTS)


_GZIP = ("Content-Encoding", "gzip")


def test_a_route_with_a_content_coding_is_refused():
    coded = replace(_response(), headers=(_HTML, _GZIP))

    with pytest.raises(ValueError, match="Content-Encoding gzip"):
        capture_record(_PROVENANCE, [coded], _DEFAULTS)


def test_a_default_with_a_content_coding_is_refused():
    plain = replace(_answer("https", _PROBED_TARGET), headers=(_GZIP,))
    coded = ProbedDefault(plain=plain, form=_answer("https", _FORM_TARGET))

    with pytest.raises(ValueError, match="Content-Encoding gzip"):
        capture_record(_PROVENANCE, [], (_not_found("http"), coded))


def test_an_identity_content_coding_is_recorded_as_sent():
    identity = replace(_response(), headers=(_HTML, ("content-encoding", "identity")))

    record = capture_record(_PROVENANCE, [identity], _DEFAULTS)

    assert record["routes"][0]["headers"] == [list(_HTML), ["content-encoding", "identity"]]


def test_a_head_route_keeps_its_method_status_and_headers_with_an_empty_body():
    record = capture_record(_PROVENANCE, [_response(method="HEAD", body=b"")], _DEFAULTS)
    route = record["routes"][0]

    assert route["method"] == "HEAD"
    assert route["status"] == 200
    assert route["headers"] == [
        ["Content-Type", "text/html; charset=UTF-8"],
        ["Alt-Svc", 'h3=":443"'],
    ]
    assert route["body"] == ""


def test_a_bare_url_is_a_get():
    assert parse_request("https://example.com/a?b=1") == ("GET", "https://example.com/a?b=1")


def test_a_url_prefixed_head_is_a_head():
    assert parse_request("HEAD https://example.com/") == ("HEAD", "https://example.com/")


def test_another_method_prefix_is_refused():
    with pytest.raises(SystemExit, match="HEAD"):
        parse_request("POST https://example.com/")


def test_each_default_keeps_its_scheme_probed_target_status_headers_body_and_path_form():
    location = ("Location", f"https://example.com{_PROBED_TARGET}")
    redirect = ProbedDefault(
        plain=replace(
            _answer("http", _PROBED_TARGET, (location, ("Server", "cloudflare")), ""), status=301
        ),
        form=replace(_answer("http", _FORM_TARGET), status=301),
    )

    record = capture_record(_PROVENANCE, [_response()], [redirect, _HTML_PROBE])

    assert record["defaults"] == [
        {
            "scheme": "http",
            "probed_target": _PROBED_TARGET,
            "status": 301,
            "headers": [list(location), ["Server", "cloudflare"]],
            "body": "",
            "path_form": None,
        },
        {
            "scheme": "https",
            "probed_target": _PROBED_TARGET,
            "status": 404,
            "headers": [list(_HTML)],
            "body": _HTML_PROBE.plain.body.decode(),
            "path_form": "decoded",
        },
    ]
    assert len(record["routes"]) == 1


@pytest.mark.parametrize(
    ("probe", "expected"),
    [
        (_HTML_PROBE, "decoded"),
        (
            _probe(
                (_JSON,),
                f'{{"path": "{_PROBED_TARGET}"}}',
                f'{{"path": "{_PROBED_TARGET}<x>\\"\'"}}',
            ),
            "decoded",
        ),
        (
            _probe(
                (_HTML,),
                f"<p>{_PROBED_TARGET}</p><p>{_PROBED_TARGET}</p>",
                f"<p>{_FORM_TARGET}</p><p>{_FORM_TARGET}</p>",
            ),
            "raw",
        ),
        (_not_found("https"), None),
    ],
    ids=["html_decoded", "json_decoded", "html_raw", "no_quote"],
)
def test_the_path_form_is_the_form_in_which_the_form_probe_quotes_its_target(
    probe: ProbedDefault, expected: str | None
):
    assert path_form(probe) == expected


_PYTHON_ESCAPED = f"{_PROBED_TARGET}&lt;x&gt;&quot;&#x27;"


@pytest.mark.parametrize(
    ("probe", "reason"),
    [
        (
            _probe((("Content-Type", "text/plain"),), _PROBED_TARGET, _FORM_TARGET),
            "neither HTML nor JSON",
        ),
        (
            _probe(
                (_HTML,),
                f"{_PROBED_TARGET} {_PROBED_TARGET}",
                f"{_PYTHON_ESCAPED} {_PYTHON_ESCAPED}",
            ),
            "form probe",
        ),
        (
            _probe(
                (_HTML,), f"{_PROBED_TARGET} {_PROBED_TARGET}", f"{_HTML_DECODED} {_FORM_TARGET}"
            ),
            "form probe",
        ),
        (_probe((_HTML,), f"{_PROBED_TARGET} {_PROBED_TARGET}", _HTML_DECODED), "form probe"),
        (
            replace(_HTML_PROBE, form=replace(_HTML_PROBE.form, status=400)),
            "status",
        ),
        (
            replace(_HTML_PROBE, form=replace(_HTML_PROBE.form, headers=(_JSON,))),
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
        capture_record(_PROVENANCE, [_response()], [_not_found("http"), probe])


def test_the_default_requests_are_the_plain_then_the_form_probe_on_each_scheme():
    requests = default_requests("example.com", _PROBED_TARGET)

    assert [(method, str(url)) for method, url in requests] == [
        ("GET", "http://example.com/0123456789abcdef"),
        ("GET", "https://example.com/0123456789abcdef"),
        ("GET", "http://example.com/0123456789abcdef%3Cx%3E%22%27"),
        ("GET", "https://example.com/0123456789abcdef%3Cx%3E%22%27"),
    ]
    assert {url.raw_path for _, url in requests[2:]} == {b"/0123456789abcdef%3Cx%3E%22%27"}
