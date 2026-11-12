import asyncio
import dataclasses
from collections.abc import Awaitable, Callable
from pathlib import Path

import tests.unit.support.test_nuisance_gate_session_given as gate_given
import tests.unit.support.test_nuisance_run_given as run_given
import tests.unit.support.test_nuisance_vet_given as vet_given
from evals.concurrency import bounded
from evals.cve.nuisance.admission import AdmittedServer
from evals.cve.nuisance.audit import GateRun
from evals.cve.nuisance.gate_session_model import NuisanceGateHarness
from evals.cve.nuisance.run import NuisanceDeps
from evals.cve.nuisance.vet_command import VetDeps
from tests.unit.support.test_nuisance_run_backends_given import DockerHost

MAGENTO2 = run_given.a_server("npm:@elgentos/magento2-dev-mcp")
BOUND = 2


def others(count: int) -> list[AdmittedServer]:
    return [run_given.a_server(f"npm:other-{index}") for index in range(count)]


class InFlight:
    """Records, at the start of each tracked call, the packages whose calls are then in flight,
    its own included. A tracked call yields to the loop before it answers, so calls free to run
    together overlap."""

    def __init__(self) -> None:
        self.starts: list[tuple[str, list[str]]] = []
        self._now: list[str] = []

    def tracking[R](
        self, call: Callable[[AdmittedServer], Awaitable[R]]
    ) -> Callable[[AdmittedServer], Awaitable[R]]:
        async def tracked(server: AdmittedServer) -> R:
            self._now.append(server.server_package)
            self.starts.append((server.server_package, list(self._now)))
            try:
                for _ in range(3):
                    await asyncio.sleep(0)
                return await call(server)
            finally:
                self._now.remove(server.server_package)

        return tracked

    def bounded[R](
        self, call: Callable[[AdmittedServer], Awaitable[R]]
    ) -> Callable[[AdmittedServer], Awaitable[R]]:
        """Tracked behind the concurrency bound, as the live commands bound their calls."""
        return bounded(self.tracking(call), BOUND)


async def _answering(_server: AdmittedServer) -> str | None:
    return None


def vet_deps(in_flight: InFlight) -> VetDeps:
    return dataclasses.replace(
        vet_given.deps_on(DockerHost()), benign_call=in_flight.bounded(_answering)
    )


def run_deps(in_flight: InFlight, servers: list[AdmittedServer]) -> NuisanceDeps:
    audit = run_given.scripted(
        {server.server_package: [run_given.an_audit(False) for _ in range(3)] for server in servers}
    )
    return dataclasses.replace(
        run_given.deps_auditing(audit),
        audit=in_flight.bounded(audit),
        benign_call=in_flight.bounded(_answering),
    )


def gate_harness_with_alarms(
    directory: Path, in_flight: InFlight, servers: list[AdmittedServer]
) -> NuisanceGateHarness:
    """Every server gated, each raising an alarm on its first run that its replays do not
    reproduce."""
    for server in servers:
        gate_given.a_gated_file(directory, server)
    script: list[GateRun | None] = [gate_given.a_gate_run(True), *gate_given.clean_runs(4)]
    audit = gate_given.scripted({server.server_package: list(script) for server in servers})
    harness = gate_given.a_harness(directory, in_flight.bounded(audit))
    return dataclasses.replace(harness, benign_call=in_flight.bounded(_answering))
