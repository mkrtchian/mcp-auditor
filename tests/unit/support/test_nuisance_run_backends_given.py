import dataclasses
from collections.abc import Sequence

import tests.unit.support.test_nuisance_run_given as given
from evals import nuisance_images
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_backends import BACKENDS
from evals.nuisance_run import NuisanceDeps

SERVER_TAG = nuisance_images.image_tag("filesystem-patched")
CKAN_TAG = BACKENDS["ckan"].image
CKAN_SERVICES = list(BACKENDS["ckan"].built_services)
DORIS_TAG = BACKENDS["doris"].image


class DockerHost:
    """The containers running per image tag. The benign call of a server on a backend starts the
    backend's container when none runs, as its provisioner does."""

    def __init__(self, running: dict[str, list[str]] | None = None) -> None:
        self.containers = {tag: list(names) for tag, names in (running or {}).items()}
        self.rebuilt: list[str] = []
        self.running_at_rebuild: list[str] = []
        self.removed: list[str] = []

    def running(self, tags: Sequence[str]) -> list[str]:
        return [name for tag in tags for name in self.containers.get(tag, [])]

    def remove(self, names: Sequence[str]) -> None:
        self.removed.extend(names)
        for tag, running in self.containers.items():
            self.containers[tag] = [name for name in running if name not in names]

    def rebuild(self, services: Sequence[str]) -> None:
        self.rebuilt.extend(services)
        self.running_at_rebuild = [name for names in self.containers.values() for name in names]

    async def benign_call(self, server: AdmittedServer) -> str | None:
        if server.backend is not None and not self.containers.get(server.backend.image):
            self.containers[server.backend.image] = [f"{server.backend.provisioner}_started"]
        return None


def deps_on(host: DockerHost, server: AdmittedServer) -> NuisanceDeps:
    audit = given.scripted({server.server_package: [given.an_audit(False) for _ in range(3)]})
    return dataclasses.replace(
        given.deps_auditing(audit),
        benign_call=host.benign_call,
        rebuild=host.rebuild,
        running_containers=host.running,
        remove_containers=host.remove,
    )
