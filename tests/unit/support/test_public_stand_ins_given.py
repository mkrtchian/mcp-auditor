import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography import x509

from evals.apify_backend import API_HOST
from evals.cve_targets import CVE_TARGETS
from evals.holdout_targets import HOLDOUT_TARGETS

HOST = "example.com"


def a_stand_in_directory(directory: Path, **capture_overrides: Any) -> Path:
    """A capture for HOST and dummy TLS text, the capture's fields overridable."""
    capture: dict[str, Any] = {
        "host": HOST,
        "address": "93.184.215.14",
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json https://example.com/",
        "request_headers": [],
        "routes": [
            {
                "scheme": "https",
                "method": "GET",
                "target": "/",
                "status": 200,
                "headers": [["Content-Type", "text/html"]],
                "body": "<html></html>",
            }
        ],
    }
    capture.update(capture_overrides)
    (directory / f"{HOST}.json").write_text(json.dumps(capture))
    tls = directory / "tls"
    tls.mkdir()
    (tls / f"{HOST}.pem").write_text("leaf")
    (tls / f"{HOST}-key.pem").write_text("key")
    (tls / "fixture-authority.pem").write_text("authority")
    return directory


def a_route(scheme: str) -> dict[str, Any]:
    return {
        "scheme": scheme,
        "method": "GET",
        "target": "/",
        "status": 200,
        "headers": [],
        "body": "",
    }


def declared_stand_in_hosts() -> set[str]:
    targets = (*CVE_TARGETS, *HOLDOUT_TARGETS)
    declared = {host for target in targets for host in target.planting_host.public_names.stand_ins}
    return declared | {API_HOST}


def committed_https_hosts(directory: Path) -> set[str]:
    hosts: set[str] = set()
    for capture in directory.glob("*.json"):
        routes = json.loads(capture.read_text())["routes"]
        if any(route["scheme"] == "https" for route in routes):
            hosts.add(capture.stem)
    return hosts


def committed_authority_constraints(directory: Path) -> tuple[bool, set[str], set[str]]:
    """Critical flag, permitted and excluded DNS subtrees; an absent authority gives none."""
    authority = directory / "tls" / "fixture-authority.pem"
    if not authority.exists():
        return True, set(), set()
    certificate = x509.load_pem_x509_certificate(authority.read_bytes())
    extension = certificate.extensions.get_extension_for_class(x509.NameConstraints)
    return (
        extension.critical,
        _dns_names(extension.value.permitted_subtrees),
        _dns_names(extension.value.excluded_subtrees),
    )


def committed_leaf_names(directory: Path) -> dict[str, set[str]]:
    leaves: dict[str, set[str]] = {}
    for path in (directory / "tls").glob("*.pem"):
        if path.name == "fixture-authority.pem" or path.name.endswith("-key.pem"):
            continue
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        leaves[path.name] = set(names.value.get_values_for_type(x509.DNSName))
    return leaves


def _dns_names(subtrees: Iterable[x509.GeneralName] | None) -> set[str]:
    return {subtree.value for subtree in subtrees or () if isinstance(subtree, x509.DNSName)}
