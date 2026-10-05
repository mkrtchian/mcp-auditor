import pathlib
import re
import sys
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager

from evals.cve_environments import Launch
from evals.cve_grammar import MechanismClass
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

STUB_PATH = pathlib.Path(__file__).resolve().parent / "cve_stub_server.py"
NONCE = "MCPAUDIT-stub0123456789abcdef"
OUTSIDE_AIM = re.compile(r"^/outside/")


def a_docker_that_runs_its_command_on_the_host(directory: pathlib.Path) -> pathlib.Path:
    """`docker run <command...>` execs the command itself, so a declared container runs
    without Docker."""
    docker = directory / "docker"
    docker.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    docker.chmod(0o755)
    return directory


def a_target_whose_server_exits_at_startup(cve_id: str, last_words: str) -> CVETarget:
    launch = Launch(
        "docker", ["run", sys.executable, "-c", f"import sys; sys.exit({last_words!r})"]
    )
    return _a_target(cve_id, launch, benign=_reading("/inside/file"))


def a_live_target(cve_id: str) -> CVETarget:
    return _a_stub_target(cve_id, benign=_reading("/inside/file"))


def a_target_whose_benign_call_leaks(cve_id: str) -> CVETarget:
    return _a_stub_target(cve_id, benign=_reading("/outside/flag"))


def a_target_whose_aim_matches_nothing(cve_id: str) -> CVETarget:
    return _a_stub_target(cve_id, benign=_reading("/inside/file"), aim=re.compile(r"^/nowhere/"))


def _a_stub_target(
    cve_id: str,
    benign: Callable[[MCPClientPort], Awaitable[None]],
    aim: re.Pattern[str] = OUTSIDE_AIM,
) -> CVETarget:
    launch = Launch("docker", ["run", sys.executable, str(STUB_PATH), NONCE])
    return _a_target(cve_id, launch, benign, aim)


def _reading(path: str) -> Callable[[MCPClientPort], Awaitable[None]]:
    async def read(client: MCPClientPort) -> None:
        await client.call_tool("read", {"path": path})

    return read


def _a_target(
    cve_id: str,
    launch: Launch,
    benign: Callable[[MCPClientPort], Awaitable[None]],
    aim: re.Pattern[str] = OUTSIDE_AIM,
) -> CVETarget:
    @contextmanager
    def builder(_sentinel: str) -> Generator[Launch]:
        yield launch

    return CVETarget(
        cve_id=cve_id,
        severity="CVSS 0.0",
        sentinel=NONCE,
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=aim,
        images=(),
        builder=builder,
        builder_args=(),
        exploit=_reading("/outside/flag"),
        benign=benign,
        awaited_capability=None,
        note="",
        tools_filter=None,
    )
