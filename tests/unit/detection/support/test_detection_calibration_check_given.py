import re
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Mapping
from contextlib import asynccontextmanager, contextmanager
from typing import IO

from evals.cve.detection.targets import Target, TargetVersion
from evals.cve.environments import Launch, LaunchShape
from evals.cve.grammar import FlawClass
from evals.cve.images import image_tag
from evals.cve.places import Coordinates, Place, PlaceKind, Places
from evals.cve.planting import PlantingHost, PlantingSpec, SymbolicUser
from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient

FLAW_ID = "CVE-FAKE"
_KEPT_ID = "fict-flag"
_PATCHED_IMAGE = "fake-patched"


def a_places_mapping() -> Places:
    return {
        _KEPT_ID: Place(
            id=_KEPT_ID,
            family="fictional",
            reaches=frozenset({"arbitrary_read"}),
            kind=PlaceKind.FILE,
            coordinates=Coordinates(PlaceKind.FILE, path="/outside/flag"),
        )
    }


def a_target() -> Target:
    """A target whose exploit reads `/outside/flag` and whose benign call reads `/inside/file`,
    its launch carrying its image and the planted nonces for `FakeLaunches` to answer from."""
    return Target(
        flaw_id=FLAW_ID,
        severity="CVSS 0.0",
        classes=frozenset({FlawClass.READ_OUTSIDE_SCOPE}),
        aim=re.compile(r"^/outside/"),
        reaches=frozenset({"arbitrary_read"}),
        kept_places=(_KEPT_ID,),
        images=(),
        server_image="fake",
        patched_image=_PATCHED_IMAGE,
        planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False),
        builder=_carrying_the_nonces,
        exploits=(_reading("/outside/flag"),),
        benign=_reading("/inside/file"),
        awaited_capability=None,
        note="",
        tools_filter=None,
    )


class FakeLaunches:
    """Stands in for the server's connection: each version answers the benign call cleanly and the
    exploit with the planted nonce on the vulnerable version when `exploit_surfaces_the_nonce`,
    and answers the ping with its entry of `ping_answers`."""

    def __init__(
        self, ping_answers: Mapping[TargetVersion, bool], exploit_surfaces_the_nonce: bool
    ) -> None:
        self.pings = 0
        self._ping_answers = ping_answers
        self._exploit_surfaces_the_nonce = exploit_surfaces_the_nonce

    @asynccontextmanager
    async def connect(self, launch: Launch, _stderr: IO[str]) -> AsyncGenerator[MCPClientPort]:
        image, *nonces = launch.args
        version = (
            TargetVersion.PATCHED
            if image == image_tag(_PATCHED_IMAGE)
            else TargetVersion.VULNERABLE
        )
        surfaces = self._exploit_surfaces_the_nonce and version is TargetVersion.VULNERABLE
        exploit_answer = " ".join(nonces) if surfaces else "no such file"
        answers = [ToolResponse(content="inside"), ToolResponse(content=exploit_answer)]
        client = FakeMCPClient([], {"read": answers}, ping_answers=(self._ping_answers[version],))
        yield client
        self.pings += client.pings


def launches(
    ping_answers: Mapping[TargetVersion, bool] | None = None,
    exploit_surfaces_the_nonce: bool = True,
) -> FakeLaunches:
    answers = ping_answers or {TargetVersion.VULNERABLE: True, TargetVersion.PATCHED: True}
    return FakeLaunches(answers, exploit_surfaces_the_nonce)


@contextmanager
def _carrying_the_nonces(image: str, spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
    yield Launch("docker", [image, *spec.nonces.values()])


def _reading(path: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def read(_places: Places, client: MCPClientPort) -> None:
        await client.call_tool("read", {"path": path})

    return read
