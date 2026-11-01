"""The images of a nuisance run and their containers. A running server container is refused, as
it may be an audit in progress. A running built backend container is removed before the rebuild,
since a responder is a stateless stand-in its provisioner starts again from the fresh image. Both
are swept at the end. The pulled backends (Doris, the `mysql` backend's) are persistent by design
and left alone."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from evals import nuisance_images
from evals.nuisance_backends import built_backend_services, built_backend_tags
from evals.run_images import refuse_running_containers, sweep_containers

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer


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

    @property
    def services(self) -> list[str]:
        return [*self.server_services, *self.backend_services]


def run_images(servers: Sequence[AdmittedServer]) -> RunImages:
    services = server_services(servers)
    return RunImages(
        server_services=services,
        backend_services=built_backend_services(servers),
        server_tags=[nuisance_images.image_tag(service) for service in services],
        backend_tags=built_backend_tags(servers),
    )


def server_services(servers: Sequence[AdmittedServer]) -> list[str]:
    return list(dict.fromkeys(server.service for server in servers))


def refuse_server_containers(host: ContainerHost, images: RunImages, refusal: str) -> None:
    refuse_running_containers(host.running_containers(images.server_tags), refusal)


def remove_backend_containers(host: ContainerHost, images: RunImages) -> None:
    """Before the rebuild: after it, the tag names the new image and no longer matches a
    container started from the previous build."""
    if not images.backend_tags:
        return
    running = host.running_containers(images.backend_tags)
    if running:  # `docker rm -f` with no name fails
        host.remove_containers(running)


def sweep_run_containers(host: ContainerHost, images: RunImages) -> None:
    sweep_containers(
        [*images.server_tags, *images.backend_tags],
        host.running_containers,
        host.remove_containers,
    )
