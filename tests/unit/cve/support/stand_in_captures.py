import json
from pathlib import Path
from typing import Any

HOST = "example.com"
PROBED_TARGET = "/0123456789abcdef"


def a_stand_in_directory(directory: Path, **capture_overrides: Any) -> Path:
    """A capture for HOST and dummy TLS text, the capture's fields overridable."""
    capture: dict[str, Any] = {
        "host": HOST,
        "address": "93.184.215.14",
        "source": "capture",
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json https://example.com/",
        "request_headers": [],
        "routes": [
            {
                "scheme": "https",
                "method": "GET",
                "request_target": "/",
                "status": 200,
                "headers": [["Content-Type", "text/html"]],
                "body": "<html></html>",
            }
        ],
        "defaults": [a_default("http"), a_default("https")],
    }
    capture.update(capture_overrides)
    (directory / f"{HOST}.json").write_text(json.dumps(capture))
    tls = directory / "tls"
    tls.mkdir()
    (tls / f"{HOST}.pem").write_text("leaf")
    (tls / f"{HOST}-key.pem").write_text("key")
    (tls / "fixture-authority.pem").write_text("authority")
    return directory


def a_route(
    scheme: str,
    method: str = "GET",
    action: str | None = None,
    form_field: str | None = None,
) -> dict[str, Any]:
    route: dict[str, Any] = {
        "scheme": scheme,
        "method": method,
        "request_target": "/",
        "status": 200,
        "headers": [],
        "body": "",
    }
    if action is not None:
        route["action"] = action
    if form_field is not None:
        route["form_field"] = form_field
    return route


def a_default(
    scheme: str,
    *,
    probed_request_target: str = PROBED_TARGET,
    headers: list[list[str]] | None = None,
    body: str = "<html>not found</html>",
    path_form: str | None = None,
) -> dict[str, Any]:
    return {
        "scheme": scheme,
        "probed_request_target": probed_request_target,
        "status": 404,
        "headers": [["Content-Type", "text/html"]] if headers is None else headers,
        "body": body,
        "path_form": path_form,
    }
