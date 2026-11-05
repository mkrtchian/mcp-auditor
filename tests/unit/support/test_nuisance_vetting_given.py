from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from typing import IO

import pytest

from evals import nuisance_vetting
from evals.cve_environments import Launch
from evals.nuisance_admission import AdmittedServer
from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.support.test_nuisance_run_given import COUNTED_TOOL, a_server

__all__ = ["COUNTED_TOOL", "a_server"]


class FlakyLaunches:
    """Stands in for the server's launch and connection: the first `failing` connections fail,
    the last of them on a timeout, and the next ones list the counted tool and answer its benign
    call with `answer`, then fail their teardown when `teardown_fails`."""

    def __init__(self, failing: int, answer: ToolResponse, teardown_fails: bool) -> None:
        self.launches = 0
        self._failing = failing
        self._answer = answer
        self._teardown_fails = teardown_fails

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
        yield FakeMCPClient(listed, {COUNTED_TOOL: self._answer})
        if self._teardown_fails:
            raise OSError("container removal failed")


def launches_failing(
    monkeypatch: pytest.MonkeyPatch,
    failing: int,
    answer: ToolResponse | None = None,
    teardown_fails: bool = False,
) -> FlakyLaunches:
    expected = ToolResponse(content=f"{COUNTED_TOOL} answered")
    flaky = FlakyLaunches(failing, answer or expected, teardown_fails)
    monkeypatch.setattr(nuisance_vetting, "nuisance_environment", flaky.environment)
    monkeypatch.setattr(nuisance_vetting, "connect", flaky.connect)
    return flaky
