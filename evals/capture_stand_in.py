"""Capture what a public service answers, for its stand-in (`evals/stand_ins/<host>.json`).

    uv run python -m evals.capture_stand_in --out PATH URL [URL ...] [--header 'NAME: VALUE']

Every URL shares one host. A URL is fetched with GET, or with HEAD when prefixed `HEAD `
(one argument, `'HEAD https://example.com/'`), for a server that checks a page before reading
it: a HEAD route is recorded with the status and headers the service gave and an empty body.
Each is fetched once with no redirect following and no content
coding, and its status, every response header and its body are recorded whatever the status,
so a 401 or a 404 is replayed as the real service gave it. A `--header` is sent and recorded
verbatim, name and value, in `request_headers` and in `command`: it carries only the dummy
credential the fixture's server itself sends, so nothing here reads the environment. A capture
is written whole, never appended, so one file carries one date.
"""

import argparse
import json
import shlex
import socket
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

_COMMAND = "uv run python -m evals.capture_stand_in"


@dataclass(frozen=True)
class CaptureProvenance:
    host: str
    address: str
    captured_at: str
    command: str
    request_headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class CapturedResponse:
    scheme: str
    method: str
    target: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def capture_record(
    provenance: CaptureProvenance, responses: Iterable[CapturedResponse]
) -> dict[str, Any]:
    return {
        "host": provenance.host,
        "address": provenance.address,
        "captured_at": provenance.captured_at,
        "command": provenance.command,
        "request_headers": [list(header) for header in provenance.request_headers],
        "routes": [_route(response) for response in responses],
    }


def _route(response: CapturedResponse) -> dict[str, Any]:
    try:
        body = response.body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            f"{response.scheme} {response.target}: the body is not UTF-8 text"
        ) from error
    return {
        "scheme": response.scheme,
        "method": response.method,
        "target": response.target,
        "status": response.status,
        "headers": [list(header) for header in response.headers],
        "body": body,
    }


def parse_request(text: str) -> tuple[str, str]:
    method, separator, url = text.partition(" ")
    if not separator:
        return "GET", text
    if method != "HEAD":
        raise SystemExit(f"{text!r}: a URL is bare (GET) or prefixed 'HEAD '")
    return method, url.strip()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parsed = _parser().parse_args(arguments)
    requests = [(method, httpx.URL(url)) for method, url in map(parse_request, parsed.urls)]
    urls = [url for _, url in requests]
    hosts = {url.host for url in urls}
    if len(hosts) != 1:
        raise SystemExit(f"every URL must share one host, got {sorted(hosts)}")
    headers = tuple(_header(text) for text in parsed.header)
    provenance = CaptureProvenance(
        host=hosts.pop(),
        address=_first_ipv4(urls[0].host),
        captured_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        command=f"{_COMMAND} {shlex.join(arguments)}",
        request_headers=headers,
    )
    responses = _fetch_all(requests, headers)
    text = json.dumps(capture_record(provenance, responses), indent=2, ensure_ascii=False)
    Path(parsed.out).write_text(text + "\n")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=_COMMAND)
    parser.add_argument("--out", required=True)
    parser.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'")
    parser.add_argument("urls", nargs="+", metavar="[HEAD ]URL")
    return parser


def _header(text: str) -> tuple[str, str]:
    name, separator, value = text.partition(":")
    if not separator or not name.strip():
        raise SystemExit(f"--header {text!r} is not 'NAME: VALUE'")
    return name.strip(), value.strip()


def _first_ipv4(host: str) -> str:
    return str(socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0])


def _fetch_all(
    requests: Sequence[tuple[str, httpx.URL]], headers: tuple[tuple[str, str], ...]
) -> list[CapturedResponse]:
    sent = [("Accept-Encoding", "identity"), *headers]
    with httpx.Client(follow_redirects=False, headers=sent) as client:
        return [_fetch(client, method, url) for method, url in requests]


def _fetch(client: httpx.Client, method: str, url: httpx.URL) -> CapturedResponse:
    response = client.request(method, url)
    return CapturedResponse(
        scheme=url.scheme,
        method=method,
        target=url.raw_path.decode("ascii"),
        status=response.status_code,
        headers=tuple(
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in response.headers.raw
        ),
        body=response.content,
    )


if __name__ == "__main__":
    sys.exit(main())
