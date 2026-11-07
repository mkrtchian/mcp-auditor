"""The fixture fingerprint of an admitted nuisance server, built on the Dockerfile identity
machinery of `cve_images`.

It lives apart from `nuisance_images` because it reads the backend registry, which
`nuisance_images` stays free of.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from evals import (
    closed_network,
    cve_endpoint_address,
    cve_planting,
    cve_planting_base,
    cve_planting_docker,
    cve_planting_spec,
    cve_planting_stand_ins,
    nuisance_confinement,
    public_stand_ins,
)
from evals.baseline import fingerprint_sources
from evals.cve_baseline import host_stand_in_files, planting_host_parts
from evals.cve_images import dockerfile_instructions
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.nuisance_backends import BACKENDS, RegisteredBackend
from evals.nuisance_counting import counted_flaws, counted_tools

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, BenignCall

CONFINEMENT_SOURCE = Path(nuisance_confinement.__file__)
# What a backend-less server with public names is launched through besides the confinement: the
# holder's and the stand-in's images, the planting code that stands them, the capture loader it
# reads them through and the closed network it puts them on.
_SHARED_SERVICES = (cve_planting_base.SENTINEL_SERVICE, cve_planting_base.STAND_IN_SERVICE)
_PUBLIC_NAME_SOURCES = (
    Path(cve_planting.__file__),
    Path(cve_planting_base.__file__),
    Path(cve_planting_spec.__file__),
    Path(cve_planting_stand_ins.__file__),
    Path(cve_planting_docker.__file__),
    Path(cve_endpoint_address.__file__),
    Path(public_stand_ins.__file__),
    Path(closed_network.__file__),
)


def nuisance_fixture_fingerprint(
    server: AdmittedServer,
    docker_directory: Path = DOCKER_DIRECTORY,
    backends: Mapping[str, RegisteredBackend] = BACKENDS,
) -> str:
    """What the admitted server is built, launched and judged on, so a run resets when any of it
    moves (the rule's Run conditions section).

    In: the patched Dockerfile's instructions (comments and blank lines out), the launch, the
    host's user, working directory and network stance, the confinement module (the bound, the
    user arguments and the single-container argv, AST fingerprint), the confinement's options
    (`nuisance_confinement_args()`, the acceptance confinement included), the resolver option
    (`resolver_args()`), the backend fixture
    (provisioner, pinned image, network), what its backend serves (each Dockerfile by its
    instructions, each Python module by its code, any other file by its bytes), for a server
    with no backend and public names the holder's and the stand-in's Dockerfiles and the planting
    modules that stand them, the counted tools
    with the valid judge categories of their classes, and the benign calls of those counted tools
    in record order, with their expected texts and their prerequisite calls.
    Out: the vulnerable Dockerfile, the exploits, the agents, the agreement, the settlements, the
    fix-check records, the provenance records (`stand_ins`, `seeds`), whose content is covered
    through the Dockerfile and the backend's served files, and the recorded `software_releases`.
    """
    counted = counted_tools(server)
    backend = server.backend
    parts: list[object] = [
        dockerfile_instructions(image_dockerfile(server.service, docker_directory)),
        server.launch,
        planting_host_parts(server.host),
        fingerprint_sources([CONFINEMENT_SOURCE.read_text()]),
        nuisance_confinement.nuisance_confinement_args(),
        cve_planting_base.resolver_args(),
        None if backend is None else backend.model_dump(),
        None if backend is None else backend_content(_served(server, backends)),
        sorted((name, sorted(categories)) for name, categories in counted.items()),
        [
            _benign_call_parts(call)
            for flaw in counted_flaws(server)
            for call in flaw.benign_calls
            if call.tool in counted
        ],
    ]
    if _serves_public_names(server):
        parts.append(backend_content(_public_name_launch(docker_directory)))
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def fingerprinted_files(
    server: AdmittedServer,
    docker_directory: Path = DOCKER_DIRECTORY,
    backends: Mapping[str, RegisteredBackend] = BACKENDS,
) -> list[Path]:
    """The fixture files whose content the fingerprint reads: the patched Dockerfile, what the
    backend serves, the host's stand-in files and, for a server with no backend and public
    names, the holder's and the stand-in's Dockerfiles and the planting modules that stand them."""
    return [
        image_dockerfile(server.service, docker_directory),
        *_served(server, backends),
        *host_stand_in_files(server.host),
        *(_public_name_launch(docker_directory) if _serves_public_names(server) else ()),
    ]


def _serves_public_names(server: AdmittedServer) -> bool:
    return server.backend is None and bool(server.host.public_names.stand_ins)


def _public_name_launch(docker_directory: Path) -> tuple[Path, ...]:
    dockerfiles = (image_dockerfile(service, docker_directory) for service in _SHARED_SERVICES)
    return (*dockerfiles, *_PUBLIC_NAME_SOURCES)


def _served(server: AdmittedServer, backends: Mapping[str, RegisteredBackend]) -> tuple[Path, ...]:
    return () if server.backend is None else backends[server.backend.provisioner].served


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
