from dataclasses import replace

from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.gate.gate_session_model import NuisanceGateHarness
from tests.unit.support.nuisance_docker_hosts import DockerHost


def watching_removals_at_each_benign_call(
    harness: NuisanceGateHarness, containers: DockerHost
) -> tuple[NuisanceGateHarness, list[list[str]]]:
    """The harness, and what `containers` had removed at each benign call."""
    removed: list[list[str]] = []
    benign_call = harness.benign_call

    async def call(server: AdmittedServer) -> str | None:
        removed.append(list(containers.removed))
        return await benign_call(server)

    return replace(harness, benign_call=call), removed
