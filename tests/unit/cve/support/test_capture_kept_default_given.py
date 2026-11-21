import json
from pathlib import Path
from typing import Any

import httpx

from tests.unit.cve.support.stand_in_captures import (
    HOST,
    PROBED_TARGET,
    a_stand_in_directory,
)

_JSON = ("Content-Type", "application/json")
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
