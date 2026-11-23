"""The patched images of the nuisance suite: their own namespace, disjoint from the acceptance
and kit namespaces, which keeps a nuisance build from overwriting an acceptance or a kit image.
The fixture fingerprint of an admitted server lives in `fingerprint`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from evals.cve.detection.targets import acceptance_services

if TYPE_CHECKING:
    from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission


def image_tag(service: str) -> str:
    return f"mcp-auditor-nuisance-{service}:local"


def backend_images(servers: Sequence[AdmittedServer]) -> list[str]:
    images = (
        image for server in servers if server.backend is not None for image in server.backend.images
    )
    return list(dict.fromkeys(images))


def namespace_problems(admission: NuisanceAdmission) -> list[str]:
    acceptance = acceptance_services()
    return [
        f"{server.server_package}: patched service {server.service!r} is an acceptance service"
        for server in admission.servers
        if server.service in acceptance
    ]
