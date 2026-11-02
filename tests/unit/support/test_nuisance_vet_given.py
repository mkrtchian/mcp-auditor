from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals import nuisance_images, nuisance_vet_command
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_vet_command import VetDeps
from tests.unit.support.test_nuisance_run_backends_given import DockerHost

SERVER = admission_given.SERVER_PACKAGE
SERVER_TAG = nuisance_images.image_tag("filesystem-nuisance")
ACCEPTANCE = admission_given.ACCEPTANCE_PACKAGE


def deps_on(host: DockerHost, failures: Mapping[str, str] | None = None) -> VetDeps:
    """Each benign call leaves its server's container running, as a server outliving its call
    does, and fails with the reason `failures` gives its server."""

    async def benign_call(server: AdmittedServer) -> str | None:
        await host.benign_call(server)
        tag = nuisance_images.image_tag(server.service)
        host.containers.setdefault(tag, []).append(f"{server.service}_left")
        return (failures or {}).get(server.server_package)

    return VetDeps(
        rebuild=host.rebuild,
        running_containers=host.running,
        remove_containers=host.remove,
        benign_call=benign_call,
        check_networks=lambda: None,
    )


class VetHarness:
    """Hands the vet command `deps` in place of the live ones, recording the tool-call timeout
    and the concurrency it built them with."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, deps: VetDeps) -> None:
        self.built_with: tuple[int, int] | None = None

        def default_vet_deps(tool_call_timeout: int, concurrency: int) -> VetDeps:
            self.built_with = (tool_call_timeout, concurrency)
            return deps

        monkeypatch.setattr(nuisance_vet_command, "default_vet_deps", default_vet_deps)


def a_failing_rebuild(services: Sequence[str]) -> None:
    raise RuntimeError(f"docker compose build failed for {', '.join(services)}")


def a_vet_of_one_server_beside_the_acceptance_one(tmp_path: Path) -> list[str]:
    """The `vet` arguments of an admission of SERVER and of the acceptance server ACCEPTANCE."""
    census = admission_given.a_census_with_an_acceptance_server()
    one = admission_given.an_admission()
    acceptance = admission_given.admitting_the_acceptance_server()
    both = one.model_copy(update={"servers": [*one.servers, *acceptance.servers]})
    return [
        "vet",
        "--census",
        str(census_given.written(tmp_path, census)),
        "--walk-record",
        str(walk_given.a_written_empty_record(tmp_path)),
        "--admission",
        str(admission_given.written(tmp_path, both)),
    ]
