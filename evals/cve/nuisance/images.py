"""The patched images of the nuisance suite: their own namespace, disjoint from the acceptance
and kit namespaces, which keeps a nuisance build from overwriting an acceptance or a kit image.
The fixture fingerprint of an admitted server lives in `fingerprint`.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from typing import TYPE_CHECKING

from evals.cve.detection import calibration_dossier

if TYPE_CHECKING:
    from evals.nuisance_admission import NuisanceAdmission


def image_tag(service: str) -> str:
    return f"mcp-auditor-nuisance-{service}:local"


def backend_image_ids(tags: Sequence[str]) -> dict[str, str]:
    # check=False, keeping the tags that resolve: a provenance lookup never raises. A server
    # dropped before launch never reaches this code, so its backend image is never looked up.
    ids: dict[str, str] = {}
    for tag in tags:
        inspected = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
            check=False,
            capture_output=True,
            text=True,
        )
        if inspected.returncode == 0:
            ids[tag] = inspected.stdout.strip()
    return ids


def namespace_problems(admission: NuisanceAdmission) -> list[str]:
    acceptance = calibration_dossier.acceptance_services()
    return [
        f"{server.server_package}: patched service {server.service!r} is an acceptance service"
        for server in admission.servers
        if server.service in acceptance
    ]
