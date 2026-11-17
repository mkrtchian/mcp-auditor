from collections.abc import AsyncGenerator, Generator, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from typing import IO

import pytest

from evals.cve.environments import Launch
from evals.cve.nuisance import vetting as nuisance_vetting
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.solo import SOLO_SERVERS
from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.nuisance.support.test_nuisance_run_backends_given import (
    CKAN_TAG,
    DockerHost,
    RemovalHost,
)
from tests.unit.nuisance.support.test_nuisance_run_given import COUNTED_TOOL, a_server

__all__ = ["CKAN_TAG", "COUNTED_TOOL", "a_server"]

(SOLO_SERVER,) = SOLO_SERVERS


class ScriptedVet:
    """A benign call answering each package's successive calls with the reasons `scripted` gives
    it, a package it does not name answering None on every call, beside a container host running
    `running` per image tag. Both write to one event list, `("call", package)` per call and
    `("removed", name)` per container removed, so the order of removals and calls reads off it."""

    def __init__(
        self,
        scripted: Mapping[str, Sequence[str | None]],
        running: dict[str, list[str]] | None = None,
    ) -> None:
        self.events: list[tuple[str, str]] = []
        self._reasons: dict[str, Iterator[str | None]] = {
            package: iter(reasons) for package, reasons in scripted.items()
        }
        self._docker = DockerHost(running)
        self.host = RemovalHost(self._docker.running, self._remove)

    async def benign_call(self, server: AdmittedServer) -> str | None:
        self.events.append(("call", server.server_package))
        return next(self._reasons.get(server.server_package, iter(())), None)

    @property
    def calls(self) -> list[str]:
        return [package for kind, package in self.events if kind == "call"]

    @property
    def removed(self) -> list[str]:
        return [name for kind, name in self.events if kind == "removed"]

    def _remove(self, names: Sequence[str]) -> None:
        self.events.extend(("removed", name) for name in names)
        self._docker.remove(names)


class FlakyLaunches:
    """Stands in for the server's launch and connection: the first `failing` connections fail,
    the last of them on a timeout, and the next ones list the counted tool and answer its benign
    call with `answer` and the ping with `ping_answer`, then fail their teardown when
    `teardown_fails`."""

    def __init__(
        self, failing: int, answer: ToolResponse, teardown_fails: bool, ping_answer: bool
    ) -> None:
        self.launches = 0
        self._failing = failing
        self._answer = answer
        self._teardown_fails = teardown_fails
        self._ping_answer = ping_answer

    @contextmanager
    def environment(self, _server: AdmittedServer) -> Generator[Launch]:
        self.launches += 1
        yield Launch("docker", [])

    @asynccontextmanager
    async def connect(
        self, _launch: Launch, _stderr: IO[str], *, tool_call_timeout: int
    ) -> AsyncGenerator[MCPClientPort]:
        if self.launches == self._failing:
            raise TimeoutError("initialize timed out")
        if self.launches < self._failing:
            raise ConnectionError("Connection closed")
        listed = [ToolDefinition(name=COUNTED_TOOL, input_schema={})]
        yield FakeMCPClient(listed, {COUNTED_TOOL: self._answer}, ping_answers=(self._ping_answer,))
        if self._teardown_fails:
            raise OSError("container removal failed")


def launches_failing(
    monkeypatch: pytest.MonkeyPatch,
    failing: int,
    answer: ToolResponse | None = None,
    teardown_fails: bool = False,
    ping_answer: bool = True,
) -> FlakyLaunches:
    expected = ToolResponse(content=f"{COUNTED_TOOL} answered")
    flaky = FlakyLaunches(failing, answer or expected, teardown_fails, ping_answer)
    monkeypatch.setattr(nuisance_vetting, "nuisance_environment", flaky.environment)
    monkeypatch.setattr(nuisance_vetting, "connect", flaky.connect)
    return flaky
