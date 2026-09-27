import pathlib
import sys
from collections.abc import Iterator
from contextlib import contextmanager

from evals.cve_environments import Launch
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

HONEYPOT_PATH = pathlib.Path(__file__).resolve().parents[2] / "honeypot_server.py"


def a_docker_that_runs_its_command_on_the_host(directory: pathlib.Path) -> pathlib.Path:
    """`docker run <command...>` execs the command itself, so a declared container runs
    without Docker."""
    docker = directory / "docker"
    docker.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    docker.chmod(0o755)
    return directory


def a_target_whose_server_exits_at_startup(cve_id: str, last_words: str) -> CVETarget:
    return _a_target(
        cve_id,
        Launch("docker", ["run", sys.executable, "-c", f"import sys; sys.exit({last_words!r})"]),
    )


def a_live_target(cve_id: str) -> CVETarget:
    return _a_target(cve_id, Launch("docker", ["run", sys.executable, str(HONEYPOT_PATH)]))


def _a_target(cve_id: str, launch: Launch) -> CVETarget:
    @contextmanager
    def environment() -> Iterator[Launch]:
        yield launch

    async def calibrate(client: MCPClientPort) -> bool:
        return len(await client.list_tools()) > 0

    return CVETarget(
        cve_id=cve_id,
        severity="CVSS 0.0",
        sentinel="unused",
        environment=environment,
        calibrate=calibrate,
        awaited_capability=None,
        note="",
        tools_filter=None,
    )
