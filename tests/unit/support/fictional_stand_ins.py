import json
from pathlib import Path

HOST = "public.fict"
ADDRESS = "93.184.215.14"  # a global unicast address, as the loader requires
CERTIFICATE = "fictional leaf"
KEY = "fictional key"
AUTHORITY = "fictional authority"


def a_stand_ins_directory(directory: Path) -> Path:
    capture = {
        "host": HOST,
        "address": ADDRESS,
        "source": "capture",
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json http://public.fict/",
        "request_headers": list[list[str]](),
        "routes": [
            {
                "scheme": "http",
                "method": "GET",
                "request_target": "/",
                "status": 200,
                "headers": [["Content-Type", "text/html"]],
                "body": "<html></html>",
            }
        ],
        "defaults": [_default("http"), _default("https")],
    }
    (directory / f"{HOST}.json").write_text(json.dumps(capture))
    tls = directory / "tls"
    tls.mkdir()
    (tls / f"{HOST}.pem").write_text(CERTIFICATE)
    (tls / f"{HOST}-key.pem").write_text(KEY)
    (tls / "fixture-authority.pem").write_text(AUTHORITY)
    return directory


def _default(scheme: str) -> dict[str, object]:
    return {
        "scheme": scheme,
        "probed_request_target": "/0123456789abcdef",
        "status": 404,
        "headers": [["Content-Type", "text/html"]],
        "body": "<html>not found</html>",
        "path_form": None,
    }
