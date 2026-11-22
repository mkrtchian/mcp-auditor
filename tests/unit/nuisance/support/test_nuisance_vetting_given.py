from collections.abc import Callable, Mapping, Sequence

from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.solo import SOLO_SERVERS
from evals.cve.nuisance.vetting import LaunchedBenignCall
from tests.fakes import ScriptedBenignCall
from tests.unit.nuisance.support.flaky_launches import FlakyLaunches
from tests.unit.support.nuisance_docker_hosts import DockerHost, RemovalHost

(SOLO_SERVER,) = SOLO_SERVERS


class ScriptedVet:
    """A `ScriptedBenignCall` answering each package's successive calls with the reasons
    `scripted` gives it, beside a container host running `running` per image tag. Both write to
    one event list, `("call", package)` per call and `("removed", name)` per container removed,
    so the order of removals and calls reads off it."""

    def __init__(
        self,
        scripted: Mapping[str, Sequence[str | None]],
        running: dict[str, list[str]] | None = None,
    ) -> None:
        self.events: list[tuple[str, str]] = []
        self._benign_call = ScriptedBenignCall(scripted)
        self._docker = DockerHost(running)
        self.host = RemovalHost(self._docker.running, self._remove)

    async def benign_call(self, server: AdmittedServer) -> str | None:
        self.events.append(("call", server.server_package))
        return await self._benign_call(server)

    @property
    def calls(self) -> list[str]:
        return [package for kind, package in self.events if kind == "call"]

    @property
    def removed(self) -> list[str]:
        return [name for kind, name in self.events if kind == "removed"]

    def _remove(self, names: Sequence[str]) -> None:
        self.events.extend(("removed", name) for name in names)
        self._docker.remove(names)


def a_benign_call_on(
    launches: FlakyLaunches, on_ping: Callable[[AdmittedServer, bool], None] | None = None
) -> LaunchedBenignCall:
    return LaunchedBenignCall(timeout=30, on_ping=on_ping, launcher=launches.launcher)
