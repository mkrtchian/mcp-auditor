"""The fixture fingerprint of an admitted nuisance server, built on the Dockerfile identity
machinery of `cve_images`.

It lives apart from `nuisance_images` because it reads the backend registry, whose provisioners
import `nuisance_images`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from evals import nuisance_confinement
from evals.baseline import fingerprint_sources
from evals.cve_baseline import planting_host_parts
from evals.cve_images import dockerfile_instructions
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.nuisance_backends import BACKENDS, RegisteredBackend
from evals.nuisance_counting import counted_flaws, counted_tools

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, BenignCall

CONFINEMENT_SOURCE = Path(nuisance_confinement.__file__)


def nuisance_fixture_fingerprint(
    server: AdmittedServer,
    docker_directory: Path = DOCKER_DIRECTORY,
    backends: Mapping[str, RegisteredBackend] = BACKENDS,
) -> str:
    """What the admitted server is built, launched and judged on, so a run resets when any of it
    moves (the rule's Run conditions section).

    In: the patched Dockerfile's instructions (comments and blank lines out), the launch, the
    host's user, working directory and network stance, the confinement module (the bound, the
    user arguments and the single-container argv, AST fingerprint), the backend fixture
    (provisioner, pinned image, network), what its backend serves (each Dockerfile by its
    instructions, each Python module by its code, any other file by its bytes), the counted tools
    with the valid judge categories of their classes, and the benign calls of those counted tools
    in record order, with their expected texts and their prerequisite calls.
    Out: the vulnerable Dockerfile, the exploits, the agents, the agreement, the settlements, the
    fix-check records, and the provenance records (`stand_ins`, `seeds`), whose content is covered
    through the Dockerfile and the backend's served files.
    """
    counted = counted_tools(server)
    backend = server.backend
    parts: list[object] = [
        dockerfile_instructions(image_dockerfile(server.service, docker_directory)),
        server.launch,
        planting_host_parts(server.host),
        fingerprint_sources([CONFINEMENT_SOURCE.read_text()]),
        None if backend is None else backend.model_dump(),
        None if backend is None else backend_content(backends[backend.provisioner].served),
        sorted((name, sorted(categories)) for name, categories in counted.items()),
        [
            _benign_call_parts(call)
            for flaw in counted_flaws(server)
            for call in flaw.benign_calls
            if call.tool in counted
        ],
    ]
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def _benign_call_parts(call: BenignCall) -> tuple[object, ...]:
    before = (
        None if call.before is None else [(prior.tool, prior.arguments) for prior in call.before]
    )
    return (call.tool, call.arguments, call.expect, before)


def backend_content(served: Sequence[Path]) -> list[object]:
    return [_file_content(path) for path in served]


def _file_content(path: Path) -> object:
    if path.name.startswith("Dockerfile."):
        return dockerfile_instructions(path)
    if path.suffix == ".py":
        return fingerprint_sources([path.read_text()])
    return hashlib.sha256(path.read_bytes()).hexdigest()
