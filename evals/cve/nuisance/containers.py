"""The images of a nuisance command and their containers. A running server container is refused, as
it may be an audit in progress. A running built backend container is removed at the start of a run,
a vet and a gate, before any rebuild: every built backend starts again from its image and its seed,
which its provisioner sends again, so no state an earlier command wrote reaches the next. Both are
swept at the end. Both removals run `docker rm -f -v`, so a container's anonymous volumes go with
it. The pulled backend (the Doris cluster) is removed by its container name at that start too, since
the counted SQL tools can write its state, and its provisioner stands it again from its image and
its seed; the end sweep leaves it running, as the calibration check of a holdout target shares it.
A server's own backend containers, the Doris cluster by name included, are removed again before
that server's second pass of the vet (`vetting.drop_failing_servers`), so its provisioner stands
them again for that pass. A backend-less server with public names launches a holder and
stand-ins, whose images a run, a vet and a gate rebuild but never sweep by tag: the launch removes
its own containers, and a calibration check may run containers of the same images."""

from __future__ import annotations

from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.backend_registry import (
    backend_containers_removed_by_name,
    built_backend_services,
    built_backend_tags,
)
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.cve.run_images import (
    ContainerSweep,
    refuse_running_containers,
    refuse_without_closed_networks,
    sweep_containers,
)

if TYPE_CHECKING:
    from evals.cve.nuisance.admission.admission import AdmittedServer


@dataclass(frozen=True)
class RunImages:
    server_services: list[str]
    backend_services: list[str]
    server_tags: list[str]
    backend_tags: list[str]
    containers_removed_by_name: list[str]

    @property
    def services(self) -> list[str]:
        return [*self.server_services, *self.backend_services]


class RunContainerDeps(Protocol):
    @property
    def check_networks(self) -> Callable[[], None]: ...

    @property
    def rebuild(self) -> Callable[[Sequence[str]], None]: ...

    @property
    def sweep(self) -> ContainerSweep: ...


@contextmanager
def rebuilt_run_images(
    servers: Sequence[AdmittedServer], deps: RunContainerDeps, refusal: str
) -> Generator[None]:
    """The one container sequence of a run and a vet, so a vet proves the launch a run makes. A
    refusal raised before the yield sweeps nothing, since what it refuses may be an audit in
    progress."""
    refuse_without_closed_networks(deps.check_networks)
    images = run_images(servers)
    _refuse_server_containers(deps.sweep, images, refusal)
    remove_backend_containers(deps.sweep, images)
    deps.rebuild(images.services)
    _refuse_server_containers(deps.sweep, images, refusal)
    try:
        yield
    finally:
        sweep_run_containers(deps.sweep, images)


def run_images(servers: Sequence[AdmittedServer]) -> RunImages:
    services = server_services(servers)
    return RunImages(
        server_services=services,
        backend_services=list(
            dict.fromkeys([*built_backend_services(servers), *_public_name_services(servers)])
        ),
        server_tags=[nuisance_images.image_tag(service) for service in services],
        backend_tags=built_backend_tags(servers),
        containers_removed_by_name=backend_containers_removed_by_name(servers),
    )


def _public_name_services(servers: Sequence[AdmittedServer]) -> list[str]:
    serves = any(
        server.backend is None and server.host.public_names.stand_ins for server in servers
    )
    return [SENTINEL_SERVICE, STAND_IN_SERVICE] if serves else []


def server_services(servers: Sequence[AdmittedServer]) -> list[str]:
    return list(dict.fromkeys(server.service for server in servers))


def _refuse_server_containers(sweep: ContainerSweep, images: RunImages, refusal: str) -> None:
    refuse_running_containers(sweep.running_containers(images.server_tags), refusal)


def remove_backend_containers(sweep: ContainerSweep, images: RunImages) -> None:
    """Before the rebuild: after it, the tag names the new image and no longer matches a
    container started from the previous build. A removal after the rebuild (the vet's second pass)
    finds the containers by tag, since they were started from the rebuilt image. A container named
    by its backend's registry entry is removed whether it runs or not, the removal being
    unchecked."""
    running = sweep.running_containers(images.backend_tags) if images.backend_tags else []
    removed = [*running, *images.containers_removed_by_name]
    if removed:  # `docker rm -f` with no name fails
        sweep.remove_containers(removed)


def sweep_run_containers(sweep: ContainerSweep, images: RunImages) -> None:
    sweep_containers(
        [*images.server_tags, *images.backend_tags],
        sweep.running_containers,
        sweep.remove_containers,
    )
