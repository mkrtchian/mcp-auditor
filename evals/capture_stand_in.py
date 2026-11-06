"""Capture what a public service answers, for its stand-in (`evals/stand_ins/<host>.json`).

    uv run python -m evals.capture_stand_in --out PATH URL [URL ...] [--header 'NAME: VALUE']

Every URL shares one host. A URL is fetched with GET, or with HEAD when prefixed `HEAD `
(one argument, `'HEAD https://example.com/'`), for a server that checks a page before reading
it: a HEAD route is recorded with the status and headers the service gave and an empty body.
A URL prefixed `POST ` and followed by a form body of one field (one argument,
`'POST https://html.duckduckgo.com/html/ q=wikipedia'`) is posted as
`application/x-www-form-urlencoded`, and its route records the field's name as `form_field`,
the body staying in `command`.
Each is fetched once with no redirect following and no content
coding, and its status, every response header (in the order received, duplicates kept, names in
the host's case) and its body are recorded whatever the status, so a 401 or a 404 is replayed as
the real service gave it. An answer that carries a content coding anyway is refused, since the
body is stored decoded and its replayed headers would label it coded. A `--header` is sent and
recorded verbatim, name and value, in `request_headers` and in `command`: it carries only the
dummy credential the fixture's server itself sends, so nothing here reads the environment. Each
capture also records, on both schemes, the host's answer to a generated path that does not
exist (`/` and 16 random hex digits, fetched with GET and the same headers) and, from a second
probe of that path followed by percent-encoded `<x>"'`, the form in which its body quotes the
path (`path_form`, decoded or raw). The stand-in replays that answer for any request its routes
lack, quoting the request where the host quoted the probed path; an answer quoting it in another
header than `Location`, in a body that is neither HTML nor JSON, or in an escaping the stand-in
does not reproduce, is refused. A capture is written whole, never appended, so one file carries
one date, and says so with `source` `capture`.
"""

import argparse
import json
import secrets
import shlex
import socket
import sys
import urllib.parse
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx

from evals.public_stand_ins import QUOTING_MEDIA_TYPES, StandInDefault, body_quoting, media_type

_COMMAND = "uv run python -m evals.capture_stand_in"
FORM_SUFFIX = "%3Cx%3E%22%27"


@dataclass(frozen=True)
class CaptureProvenance:
    host: str
    address: str
    captured_at: str
    command: str
    request_headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class CaptureRequest:
    method: str
    url: httpx.URL
    body: str | None = None
    form_field: str | None = None


@dataclass(frozen=True)
class CapturedResponse:
    scheme: str
    method: str
    target: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    form_field: str | None = None


@dataclass(frozen=True)
class ProbedDefault:
    plain: CapturedResponse
    form: CapturedResponse


def capture_record(
    provenance: CaptureProvenance,
    responses: Iterable[CapturedResponse],
    defaults: Iterable[ProbedDefault],
) -> dict[str, Any]:
    return {
        "host": provenance.host,
        "address": provenance.address,
        "source": "capture",
        "captured_at": provenance.captured_at,
        "command": provenance.command,
        "request_headers": [list(header) for header in provenance.request_headers],
        "routes": [_route(response) for response in responses],
        "defaults": [_default(probe) for probe in defaults],
    }


def _route(response: CapturedResponse) -> dict[str, Any]:
    route: dict[str, Any] = {
        "scheme": response.scheme,
        "method": response.method,
        "target": response.target,
        "status": response.status,
        "headers": [list(header) for header in response.headers],
        "body": _text(response),
    }
    if response.form_field is not None:
        route["form_field"] = response.form_field
    return route


def _default(probe: ProbedDefault) -> dict[str, Any]:
    plain = probe.plain
    record = {
        "scheme": plain.scheme,
        "probed_target": plain.target,
        "status": plain.status,
        "headers": [list(header) for header in plain.headers],
        "body": _text(plain),
        "path_form": path_form(probe),
    }
    StandInDefault.model_validate(record)
    return record


def path_form(probe: ProbedDefault) -> Literal["decoded", "raw"] | None:
    plain, form = probe.plain, probe.form
    quotes = _text(plain).count(plain.target)
    form_body = _text(form)
    digits = form_body.count(plain.target[1:])
    if quotes == 0 and digits == 0:
        return None
    media = _same_answer(probe)
    decoded = form_body.count(body_quoting(urllib.parse.unquote(form.target), media))
    raw = form_body.count(body_quoting(form.target, media))
    if (decoded, raw, digits) == (quotes, 0, quotes):
        return "decoded"
    if (decoded, raw, digits) == (0, quotes, quotes):
        return "raw"
    raise ValueError(
        f"{plain.scheme}: the form probe quotes its target {decoded} times decoded and {raw}"
        f" times raw, its path {digits} times in all, where the plain probe quotes it {quotes}"
        " times"
    )


def _same_answer(probe: ProbedDefault) -> str:
    plain, form = probe.plain, probe.form
    media = media_type(plain.headers)
    if media not in QUOTING_MEDIA_TYPES:
        raise ValueError(
            f"{plain.scheme}: the default answer quotes the request in a body that is neither"
            " HTML nor JSON, whose escaping the stand-in does not know"
        )
    if form.status != plain.status:
        raise ValueError(
            f"{plain.scheme}: the form probe's status is {form.status},"
            f" the plain one's {plain.status}"
        )
    if media_type(form.headers) != media:
        raise ValueError(
            f"{plain.scheme}: the form probe's media type is {media_type(form.headers)},"
            f" the plain one's {media}"
        )
    return media


def _text(response: CapturedResponse) -> str:
    for name, value in response.headers:
        if name.lower() == "content-encoding" and value.strip().lower() != "identity":
            raise ValueError(
                f"{response.scheme} {response.target}: the answer carries Content-Encoding"
                f" {value}, and the capture stores the body decoded"
            )
    try:
        return response.body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            f"{response.scheme} {response.target}: the body is not UTF-8 text"
        ) from error


def default_requests(host: str, probed_target: str) -> list[CaptureRequest]:
    targets = (probed_target, probed_target + FORM_SUFFIX)
    return [
        CaptureRequest("GET", httpx.URL(f"{scheme}://{host}{target}"))
        for target in targets
        for scheme in ("http", "https")
    ]


def parse_request(text: str) -> CaptureRequest:
    words = text.split()
    match words:
        case [url]:
            return CaptureRequest("GET", httpx.URL(url))
        case ["HEAD", url]:
            return CaptureRequest("HEAD", httpx.URL(url))
        case ["POST", url, body] if (field := _single_form_field(body)) is not None:
            return CaptureRequest("POST", httpx.URL(url), body=body, form_field=field)
        case _:
            raise SystemExit(
                f"{text!r}: a URL is bare (GET), prefixed 'HEAD ',"
                " or prefixed 'POST ' and followed by a form body of one field"
            )


def _single_form_field(body: str) -> str | None:
    try:
        fields = urllib.parse.parse_qsl(body, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return None
    if len(fields) != 1 or not fields[0][0]:
        return None
    return fields[0][0]


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parsed = _parser().parse_args(arguments)
    requests = [parse_request(text) for text in parsed.urls]
    hosts = {request.url.host for request in requests}
    if len(hosts) != 1:
        raise SystemExit(f"every URL must share one host, got {sorted(hosts)}")
    headers = tuple(_header(text) for text in parsed.header)
    provenance = _provenance(hosts.pop(), arguments, headers)
    probed_target = f"/{secrets.token_hex(8)}"
    fetched = _fetch_all([*requests, *default_requests(provenance.host, probed_target)], headers)
    plain, form = fetched[len(requests) : -2], fetched[-2:]
    defaults = [ProbedDefault(*pair) for pair in zip(plain, form, strict=True)]
    record = capture_record(provenance, fetched[: len(requests)], defaults)
    Path(parsed.out).write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    return 0


def _provenance(
    host: str, arguments: Sequence[str], headers: tuple[tuple[str, str], ...]
) -> CaptureProvenance:
    return CaptureProvenance(
        host=host,
        address=_first_ipv4(host),
        captured_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        command=f"{_COMMAND} {shlex.join(arguments)}",
        request_headers=headers,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=_COMMAND)
    parser.add_argument("--out", required=True)
    parser.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'")
    parser.add_argument("urls", nargs="+", metavar="[HEAD |POST ]URL[ BODY]")
    return parser


def _header(text: str) -> tuple[str, str]:
    name, separator, value = text.partition(":")
    if not separator or not name.strip():
        raise SystemExit(f"--header {text!r} is not 'NAME: VALUE'")
    return name.strip(), value.strip()


def _first_ipv4(host: str) -> str:
    return str(socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0])


def _fetch_all(
    requests: Sequence[CaptureRequest], headers: tuple[tuple[str, str], ...]
) -> list[CapturedResponse]:
    sent = [("Accept-Encoding", "identity"), *headers]
    with httpx.Client(follow_redirects=False, headers=sent) as client:
        return [_fetch(client, request) for request in requests]


def _fetch(client: httpx.Client, request: CaptureRequest) -> CapturedResponse:
    form = {} if request.body is None else {"Content-Type": "application/x-www-form-urlencoded"}
    response = client.request(request.method, request.url, content=request.body, headers=form)
    url = request.url
    return CapturedResponse(
        scheme=url.scheme,
        method=request.method,
        target=url.raw_path.decode("ascii"),
        status=response.status_code,
        headers=tuple(
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in response.headers.raw
        ),
        body=response.content,
        form_field=request.form_field,
    )


if __name__ == "__main__":
    sys.exit(main())
