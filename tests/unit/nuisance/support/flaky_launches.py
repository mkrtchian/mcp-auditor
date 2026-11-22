from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from typing import IO

import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.environments import Launch
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.vetting import ServerLauncher
from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes import FakeMCPClient


class FlakyLaunches:
    """Stands in for the server's launch and connection: the first `failing` connections fail,
    the last of them on a timeout, and the next ones list the counted tool and answer its benign
    call with `answer` and the ping with `ping_answer`, then fail their teardown when
    `teardown_fails`. `connected` keeps every launch it was asked to connect, and `launcher`
    launches and connects through it."""

    def __init__(
        self, failing: int, answer: ToolResponse, teardown_fails: bool, ping_answer: bool
    ) -> None:
        self.launches = 0
        self.connected: list[Launch] = []
        self._failing = failing
        self._answer = answer
        self._teardown_fails = teardown_fails
        self._ping_answer = ping_answer
        self.launcher = ServerLauncher(self.environment, self.connect)

    @contextmanager
    def environment(self, _server: AdmittedServer) -> Generator[Launch]:
        self.launches += 1
        yield Launch("docker", ["run", "server-image"])

    @asynccontextmanager
    async def connect(
        self, launch: Launch, _stderr: IO[str], *, tool_call_timeout: int
    ) -> AsyncGenerator[MCPClientPort]:
        self.connected.append(launch)
        if self.launches == self._failing:
            raise TimeoutError("initialize timed out")
        if self.launches < self._failing:
            raise ConnectionError("Connection closed")
        listed = [ToolDefinition(name=holdout_runs.COUNTED_TOOL, input_schema={})]
        yield FakeMCPClient(
            listed, {holdout_runs.COUNTED_TOOL: self._answer}, ping_answers=(self._ping_answer,)
        )
        if self._teardown_fails:
            raise OSError("container removal failed")


def launches_failing(
    failing: int,
    answer: ToolResponse | None = None,
    teardown_fails: bool = False,
    ping_answer: bool = True,
) -> FlakyLaunches:
    expected = ToolResponse(content=f"{holdout_runs.COUNTED_TOOL} answered")
    return FlakyLaunches(failing, answer or expected, teardown_fails, ping_answer)
