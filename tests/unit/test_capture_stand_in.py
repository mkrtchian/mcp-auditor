import pytest

from evals.capture_stand_in import (
    CapturedResponse,
    CaptureProvenance,
    capture_record,
    parse_request,
)

_PROVENANCE = CaptureProvenance(
    host="example.com",
    address="93.184.215.14",
    captured_at="2026-11-02T10:00:00Z",
    command="uv run python -m evals.capture_stand_in --out x.json https://example.com/",
    request_headers=(("Authorization", "Bearer calib-token"),),
)


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


def test_a_route_keeps_its_status_headers_and_body_verbatim():
    record = capture_record(_PROVENANCE, [_response()])

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
    record = capture_record(_PROVENANCE, [_response(status=401, body=b'{"error":"x"}')])

    assert record["routes"][0]["status"] == 401
    assert record["routes"][0]["body"] == '{"error":"x"}'


def test_each_sent_request_header_is_recorded_with_its_name_and_value():
    record = capture_record(_PROVENANCE, [_response()])

    assert record["request_headers"] == [["Authorization", "Bearer calib-token"]]


def test_a_body_that_is_not_utf8_is_refused():
    with pytest.raises(ValueError, match="UTF-8"):
        capture_record(_PROVENANCE, [_response(body=b"\xff\xfe")])


def test_a_head_route_keeps_its_method_status_and_headers_with_an_empty_body():
    route = capture_record(_PROVENANCE, [_response(method="HEAD", body=b"")])["routes"][0]

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
