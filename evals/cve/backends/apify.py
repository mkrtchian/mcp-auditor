"""The stand-ins the @apify/actors-mcp-server CVE-2026-46341 fix check reaches.

The run no longer drives this module: its two public hosts are served by the holder under their real
names (the server's admission records them in `host.public_names.stand_ins`). What stays is what the
fix check (`evals/cve/nuisance/fix_checks/cve_2026_46341_apify.py`) imports: two singletons on one
closed bridge, each the generic stand-in image serving a committed capture under the host's real
name, with its leaf and key from the fixture authority, mounted read-only:

- `docs.apify.com` (`DOCS_HOST`), the documentation site the `fetch-apify-docs` tool fetches
  Markdown pages from (`evals/stand_ins/docs.apify.com.json`).
- `api.apify.com` (`API_HOST`), the Apify API the server calls at start to load its default
  Actor tools (`evals/stand_ins/api.apify.com.json`).

Only the paths are named here, Docker reads them at `docker run`, so importing this module reads
no file. The singletons are stood once and reused across concurrent fix check launches, reaped by
the generic orphan sweep, so no lock is held across the yield.

The server reaches both as outbound HTTPS fetches. Each name is pinned to its stand-in with
`--add-host`, and the server trusts the fixture authority through `NODE_EXTRA_CA_CERTS`, the one
setting Node.js documents for an extra trusted root, mounted read-only. The fix check's launch, the
only one that reads these arguments, also sets NODE_TLS_REJECT_UNAUTHORIZED=0 for its self-signed
suffix-host responder, which turns off certificate checking for the whole process, these stand-ins
included. `APIFY_TOKEN`, without which the server refuses to start with its default Actor tools,
takes the placeholder the server's README gives.
"""

import threading

from evals.cve.backends.responder import Responder, remove
from evals.cve.docker_paths import image_dockerfile
from evals.cve.planting_base import STAND_IN_IMAGE, STAND_IN_SERVICE
from evals.cve.public_stand_ins import stand_in_files

APIFY_BRIDGE = "mcp-auditor-cve-apify-bridge"
APIFY_SUBNET = "198.18.1.0/24"  # RFC 2544: overlaps no other responder's subnet
DOCS_HOST = "docs.apify.com"
API_HOST = "api.apify.com"
# .2 was the retired inline responder's singleton; a fix check's own responders sit at .100-.250.
_DOCS_STAND_IN_IP = "198.18.1.4"
_API_STAND_IN_IP = "198.18.1.3"
_AUTHORITY_PATH = "/etc/ssl/extra-ca.pem"

APIFY_LAUNCH_LOCK = threading.Lock()


def _stand_in(host: str, container: str, ip: str) -> Responder:
    return Responder(
        image=STAND_IN_IMAGE,
        container=container,
        bridge=APIFY_BRIDGE,
        subnet=APIFY_SUBNET,
        ip=ip,
        dockerfile=image_dockerfile(STAND_IN_SERVICE),
        run_args=_read_only_mounts(host),
    )


def _read_only_mounts(host: str) -> tuple[str, ...]:
    files = stand_in_files(host)
    mounts = (
        (files.capture, "capture.json"),
        (files.certificate, "cert.pem"),
        (files.key, "key.pem"),
    )
    return tuple(arg for path, name in mounts for arg in ("-v", f"{path}:/stand-in/{name}:ro"))


_DOCS_STAND_IN = _stand_in(DOCS_HOST, "mcp-auditor-cve-apify-docs-stand-in", _DOCS_STAND_IN_IP)
_API_STAND_IN = _stand_in(API_HOST, "mcp-auditor-cve-apify-api-stand-in", _API_STAND_IN_IP)


def apify_network_args() -> list[str]:
    authority = stand_in_files(DOCS_HOST).authority
    return [
        "--add-host", f"{DOCS_HOST}:{_DOCS_STAND_IN_IP}",
        "--add-host", f"{API_HOST}:{_API_STAND_IN_IP}",
        "-v", f"{authority}:{_AUTHORITY_PATH}:ro",
        "-e", f"NODE_EXTRA_CA_CERTS={_AUTHORITY_PATH}",
        "-e", "APIFY_TOKEN=your-apify-token",
    ]  # fmt: skip


def ensure_apify_stand_ins() -> None:
    _DOCS_STAND_IN.ensure()
    _API_STAND_IN.ensure()


def apify_rm(name: str) -> None:
    remove(name)
