"""The patched images of the nuisance suite: their own namespace, disjoint from the acceptance
and kit namespaces, and the fixture fingerprint of an admitted server.

The namespace keeps a nuisance build from overwriting an acceptance or a kit image, and the
fingerprint resets a run when what the server is built, launched and judged on moves, built on
the Dockerfile identity machinery of `cve_images`.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from evals import calibration_dossier
from evals.cve_baseline import planting_host_parts
from evals.cve_images import dockerfile_instructions
from evals.cve_targets import DOCKER_DIRECTORY, image_dockerfile
from evals.nuisance_counting import counted_flaws, counted_tools

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, NuisanceAdmission


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


def nuisance_fixture_fingerprint(
    server: AdmittedServer, docker_directory: Path = DOCKER_DIRECTORY
) -> str:
    """What the admitted server is built, launched and judged on, so a run resets when any of it
    moves (the rule's Run conditions section).

    In: the patched Dockerfile's instructions (comments and blank lines out), the launch, the
    host's user, working directory and network stance, the backend fixture (provisioner, pinned
    image, network), the counted tools with the valid judge categories of their classes, and the
    benign calls of those counted tools in record order.
    Out: the vulnerable Dockerfile, the exploits, the agents, the agreement, the settlements and
    the fix-check records.
    """
    counted = counted_tools(server)
    parts: list[object] = [
        dockerfile_instructions(image_dockerfile(server.service, docker_directory)),
        server.launch,
        planting_host_parts(server.host),
        None if server.backend is None else server.backend.model_dump(),
        sorted((name, sorted(categories)) for name, categories in counted.items()),
        [
            (call.tool, call.arguments)
            for flaw in counted_flaws(server)
            for call in flaw.benign_calls
            if call.tool in counted
        ],
    ]
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()
