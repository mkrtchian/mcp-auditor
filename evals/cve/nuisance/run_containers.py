"""The images of a nuisance run and their containers. A running server container is refused, as
it may be an audit in progress. A running built backend container is removed at the start of a run,
a vet and a gate, before any rebuild: every built backend starts again from its image and its seed,
which its provisioner sends again, so no state an earlier command wrote reaches the next. Both are
swept at the end. Both removals run `docker rm -f -v`, so a container's anonymous volumes go with
it. The pulled backend (the Doris cluster) is removed by its container name at that start too, since
the counted SQL tools can write its state, and its provisioner stands it again from its image and
its seed; the end sweep leaves it running, as the calibration check of a holdout target shares it. A
backend-less server with public names launches a holder and stand-ins, whose images the run rebuilds
but never sweeps by tag: the launch removes its own containers, and a calibration check may run
containers of the same images."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.backend_registry import (
    backend_reset_containers,
    built_backend_services,
    built_backend_tags,
)
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.cve.run_images import refuse_running_containers, sweep_containers

if TYPE_CHECKING:
    from evals.cve.nuisance.admission import AdmittedServer


class ContainerHost(Protocol):
    @property
    def running_containers(self) -> Callable[[Sequence[str]], list[str]]: ...

    @property
    def remove_containers(self) -> Callable[[Sequence[str]], None]: ...


@dataclass(frozen=True)
class RunImages:
    server_services: list[str]
    backend_services: list[str]
    server_tags: list[str]
    backend_tags: list[str]
    reset_containers: list[str]

    @property
    def services(self) -> list[str]:
        return [*self.server_services, *self.backend_services]


def run_images(servers: Sequence[AdmittedServer]) -> RunImages:
    services = server_services(servers)
    return RunImages(
        server_services=services,
        backend_services=list(
            dict.fromkeys([*built_backend_services(servers), *_public_name_services(servers)])
        ),
        server_tags=[nuisance_images.image_tag(service) for service in services],
        backend_tags=built_backend_tags(servers),
        reset_containers=backend_reset_containers(servers),
    )


def _public_name_services(servers: Sequence[AdmittedServer]) -> list[str]:
    serves = any(
        server.backend is None and server.host.public_names.stand_ins for server in servers
    )
    return [SENTINEL_SERVICE, STAND_IN_SERVICE] if serves else []


def server_services(servers: Sequence[AdmittedServer]) -> list[str]:
    return list(dict.fromkeys(server.service for server in servers))


def refuse_server_containers(host: ContainerHost, images: RunImages, refusal: str) -> None:
    refuse_running_containers(host.running_containers(images.server_tags), refusal)


def remove_backend_containers(host: ContainerHost, images: RunImages) -> None:
    """Before the rebuild: after it, the tag names the new image and no longer matches a
    container started from the previous build. A reset container is removed whether it runs or
    not, the removal being unchecked."""
    running = host.running_containers(images.backend_tags) if images.backend_tags else []
    removed = [*running, *images.reset_containers]
    if removed:  # `docker rm -f` with no name fails
        host.remove_containers(removed)


def sweep_run_containers(host: ContainerHost, images: RunImages) -> None:
    sweep_containers(
        [*images.server_tags, *images.backend_tags],
        host.running_containers,
        host.remove_containers,
    )
