import dataclasses
from collections.abc import Sequence

import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.holdout_run import NuisanceDeps
from evals.cve.run_images import ContainerSweep

SERVER_TAG = nuisance_images.image_tag("filesystem-patched")
(CKAN_TAG,) = BACKENDS["ckan"].images
CKAN_SERVICES = list(BACKENDS["ckan"].built_services)
(DORIS_TAG,) = BACKENDS["doris"].images


class DockerHost:
    """The containers running per image tag. The benign call of a server on a backend starts the
    backend's container when none runs, as its provisioner does."""

    def __init__(self, running: dict[str, list[str]] | None = None) -> None:
        self.containers = {tag: list(names) for tag, names in (running or {}).items()}
        self.rebuilt: list[str] = []
        self.running_at_rebuild: list[str] = []
        self.removed: list[str] = []

    @property
    def sweep(self) -> ContainerSweep:
        return ContainerSweep(self.running, self.remove)

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
        if server.backend is None:
            return None
        for image in server.backend.images:
            if not self.containers.get(image):
                self.containers[image] = [f"{server.backend.provisioner}_started"]
        return None


def deps_on(host: DockerHost, server: AdmittedServer) -> NuisanceDeps:
    audit = holdout_runs.scripted(
        {server.server_package: [holdout_runs.an_audit(False) for _ in range(3)]}
    )
    return dataclasses.replace(
        holdout_runs.deps_auditing(audit),
        benign_call=host.benign_call,
        rebuild=host.rebuild,
        sweep=host.sweep,
    )
