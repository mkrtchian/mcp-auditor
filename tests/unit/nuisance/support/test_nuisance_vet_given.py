import dataclasses
from collections.abc import Mapping, Sequence
from pathlib import Path

import tests.unit.census.support.test_census_given as census_given
import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
import tests.unit.nuisance.admission.support.test_nuisance_walk_given as walk_given
import tests.unit.nuisance.support.test_nuisance_holdout_run_given as nuisance_run_given
from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.vet_command import VetCommandDeps, VetDeps
from evals.run_nuisance import NuisanceCommandDeps
from tests.fakes import ScriptedBenignCall
from tests.unit.nuisance.support.test_nuisance_holdout_run_backends_given import DockerHost

SERVER = admission_given.SERVER_PACKAGE
SERVER_TAG = nuisance_images.image_tag("filesystem-nuisance")
ACCEPTANCE = admission_given.ACCEPTANCE_PACKAGE


def deps_on(
    host: DockerHost,
    failures: Mapping[str, str | Sequence[str | None]] | None = None,
    ping_answers: Mapping[str, bool] | None = None,
) -> VetDeps:
    """Each benign call leaves its server's container running, as a server outliving its call
    does, fails with the reason `failures` scripts for its server as `ScriptedBenignCall` reads
    it, and records the ping answer `ping_answers` gives it, a server it does not name never
    connecting to a ping."""
    recorded: dict[str, bool] = {}
    scripted = ScriptedBenignCall(failures)

    async def benign_call(server: AdmittedServer) -> str | None:
        await host.benign_call(server)
        package = server.server_package
        tag = nuisance_images.image_tag(server.service)
        host.containers.setdefault(tag, []).append(f"{server.service}_left")
        if package in (ping_answers or {}):
            recorded[package] = (ping_answers or {})[package]
        return await scripted(server)

    return VetDeps(
        rebuild=host.rebuild,
        running_containers=host.running,
        remove_containers=host.remove,
        benign_call=benign_call,
        check_networks=lambda: None,
        ping_answers=recorded,
    )


class VetHarness:
    """The vet command's `deps`, handing it `vet_deps` in place of the live ones and run conditions
    whose tool-call timeout is `run_conditions_timeout`, recording the tool-call timeout and the
    concurrency it built the deps with."""

    def __init__(self, vet_deps: VetDeps, run_conditions_timeout: int | None = None) -> None:
        self.built_with: tuple[int, int] | None = None
        self._vet_deps = vet_deps
        conditions = dataclasses.replace(
            nuisance_run_given.conditions(), tool_call_timeout=run_conditions_timeout
        )
        self.deps = NuisanceCommandDeps(
            vet=VetCommandDeps(conditions=lambda: conditions, vet_deps=self._built)
        )

    def _built(self, tool_call_timeout: int, concurrency: int) -> VetDeps:
        self.built_with = (tool_call_timeout, concurrency)
        return self._vet_deps


def a_failing_rebuild(services: Sequence[str]) -> None:
    raise RuntimeError(f"docker compose build failed for {', '.join(services)}")


def a_vet_of_one_server_beside_the_acceptance_one(tmp_path: Path) -> list[str]:
    """The `vet` arguments of an admission of SERVER and of the nuisance acceptance server
    ACCEPTANCE."""
    census = admission_given.a_census_with_an_acceptance_server()
    one = admission_given.an_admission()
    acceptance = admission_given.admitting_the_acceptance_server()
    both = one.model_copy(update={"servers": [*one.servers, *acceptance.servers]})
    return [
        "vet",
        *walk_given.committed_census_arguments(tmp_path, census_given.written(tmp_path, census)),
        "--admission",
        str(admission_given.written(tmp_path, both)),
    ]
