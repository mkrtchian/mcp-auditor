"""The patched images of the nuisance suite: their own namespace, disjoint from the acceptance
and kit namespaces, and the fixture fingerprint of an admitted server.

The namespace keeps a nuisance build from overwriting an acceptance or a kit image, and the
fingerprint resets a run when what the server is built, launched and judged on moves, built on
the Dockerfile identity machinery of `cve_images`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from evals import calibration_dossier
from evals.cve_images import dockerfile_instructions
from evals.cve_targets import DOCKER_DIRECTORY, image_dockerfile
from evals.nuisance_counting import counted_flaws, counted_tools

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, NuisanceAdmission


def image_tag(service: str) -> str:
    return f"mcp-auditor-nuisance-{service}:local"


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
    counted tools with the valid judge categories of their classes, and the benign calls of every
    counted flaw in record order. Out: the vulnerable Dockerfile, the exploits, the agents, the
    agreement, the settlements and the fix-check records.
    """
    parts: list[object] = [
        dockerfile_instructions(image_dockerfile(server.service, docker_directory)),
        server.launch,
        sorted((name, sorted(categories)) for name, categories in counted_tools(server).items()),
        [
            (call.tool, call.arguments)
            for flaw in counted_flaws(server)
            for call in flaw.benign_calls
        ],
    ]
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()
