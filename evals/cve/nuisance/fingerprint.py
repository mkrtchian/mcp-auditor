"""The fixture fingerprint of an admitted nuisance server, built on the Dockerfile identity
machinery of `evals.cve.images`.

It lives apart from `images` because it reads the backend registry, which `images` stays free
of.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from evals.baseline import fingerprint_sources
from evals.cve import (
    closed_network,
    endpoint_address,
    planting,
    planting_base,
    planting_docker,
    planting_spec,
    planting_stand_ins,
    public_stand_ins,
    stand_in_defaults,
)
from evals.cve.detection.baseline import host_stand_in_files, planting_host_parts
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.images import dockerfile_instructions
from evals.cve.nuisance import confinement
from evals.cve.nuisance.backend_registry import BACKENDS, RegisteredBackend
from evals.cve.nuisance.counting import counted_flaws, counted_tools

if TYPE_CHECKING:
    from evals.cve.nuisance.admission.admission import AdmittedServer, BenignCall

CONFINEMENT_SOURCE = Path(confinement.__file__)
# What a backend-less server with public names is launched through besides the confinement: the
# holder's and the stand-in's images, the planting code that stands them, the capture loader it
# reads them through and the closed network it puts them on.
_SHARED_SERVICES = (planting_base.SENTINEL_SERVICE, planting_base.STAND_IN_SERVICE)
PUBLIC_NAME_SOURCES = (
    Path(planting.__file__),
    Path(planting_base.__file__),
    Path(planting_spec.__file__),
    Path(planting_stand_ins.__file__),
    Path(planting_docker.__file__),
    Path(endpoint_address.__file__),
    Path(public_stand_ins.__file__),
    Path(stand_in_defaults.__file__),
    Path(closed_network.__file__),
)


@dataclass(frozen=True)
class SuiteConfinement:
    """What the suite confines every server with: the module's source and the options it sets."""

    source: Path = CONFINEMENT_SOURCE
    options: Callable[[], list[str]] = planting_base.confinement_args
    resolver: Callable[[], list[str]] = planting_base.resolver_args


@dataclass(frozen=True)
class NuisanceFixtureSources:
    docker_directory: Path = DOCKER_DIRECTORY
    backends: Mapping[str, RegisteredBackend] = field(default_factory=lambda: BACKENDS)
    confinement: SuiteConfinement = field(default_factory=SuiteConfinement)


def nuisance_fixture_fingerprint(
    server: AdmittedServer, sources: NuisanceFixtureSources | None = None
) -> str:
    """What the admitted server is built, launched and judged on, so a run resets when any of it
    moves (the rule's Run conditions section).

    In: the patched Dockerfile's instructions (comments and blank lines out), the launch, the
    host's user, working directory and network stance, the confinement module (the launch
    digest, the user arguments and the single-container argv, AST fingerprint), the confinement's
    options (`confinement_args()`, the memory bound included), the resolver option
    (`resolver_args()`), the backend fixture
    (provisioner, pinned images, network), what its backend serves (each Dockerfile by its
    instructions, each Python module by its code, any other file by its bytes), for a server
    with no backend and public names the holder's and the stand-in's Dockerfiles and the planting
    modules that stand them, the counted tools
    with the valid judge categories of their classes, and the benign calls of those counted tools
    in record order, with their expected texts and their prerequisite calls.
    Out: the vulnerable Dockerfile, the exploits, the agents, the agreement, the settlements, the
    fix-check records, the provenance records (`stand_ins`, `seeds`), whose content is covered
    through the Dockerfile and the backend's served files, and the recorded `software_releases`.
    """
    sources = NuisanceFixtureSources() if sources is None else sources
    counted = counted_tools(server)
    backend = server.backend
    parts: list[object] = [
        dockerfile_instructions(image_dockerfile(server.service, sources.docker_directory)),
        server.launch,
        planting_host_parts(server.host),
        fingerprint_sources([sources.confinement.source.read_text()]),
        sources.confinement.options(),
        sources.confinement.resolver(),
        None if backend is None else backend.model_dump(),
        None if backend is None else backend_content(_served(server, sources.backends)),
        sorted((name, sorted(categories)) for name, categories in counted.items()),
        [
            _benign_call_parts(call)
            for flaw in counted_flaws(server)
            for call in flaw.benign_calls
            if call.tool in counted
        ],
    ]
    if _serves_public_names(server):
        parts.append(backend_content(_public_name_launch(sources.docker_directory)))
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def fingerprinted_files(
    server: AdmittedServer, sources: NuisanceFixtureSources | None = None
) -> list[Path]:
    """The fixture files whose content the fingerprint reads: the patched Dockerfile, what the
    backend serves, the host's stand-in files and, for a server with no backend and public
    names, the holder's and the stand-in's Dockerfiles and the planting modules that stand them."""
    sources = NuisanceFixtureSources() if sources is None else sources
    directory = sources.docker_directory
    return [
        image_dockerfile(server.service, directory),
        *_served(server, sources.backends),
        *host_stand_in_files(server.host),
        *(_public_name_launch(directory) if _serves_public_names(server) else ()),
    ]


def _serves_public_names(server: AdmittedServer) -> bool:
    return server.backend is None and bool(server.host.public_names.stand_ins)


def _public_name_launch(docker_directory: Path) -> tuple[Path, ...]:
    dockerfiles = (image_dockerfile(service, docker_directory) for service in _SHARED_SERVICES)
    return (*dockerfiles, *PUBLIC_NAME_SOURCES)


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
