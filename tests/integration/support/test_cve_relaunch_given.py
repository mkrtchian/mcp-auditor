import os
import secrets
import subprocess
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from typing import Any

from evals.cve.detection.targets import ACCEPTANCE_TARGETS, Target
from evals.cve.environments import Launch, connect
from evals.cve.exchange_log import ExchangeLog
from evals.cve.grammar import PlantedTarget
from evals.cve.images import ComposeImageStore, stale_services
from evals.cve.launch_audit import named
from evals.cve.places import DETECTION_PLACES, kept_records, load_places
from evals.cve.planting_base import LABEL
from evals.cve.proofs import proofs_in
from evals.cve.units import unit_of_exchanges
from evals.detection_preflight import expected_services
from mcp_auditor.adapters.docker import DockerRuntime
from mcp_auditor.domain.audited_server import AuditedServer, SendAttempt
from mcp_auditor.domain.container_name import declared_container_name
from mcp_auditor.domain.models import AuditCategory, AuditPayload, ToolDefinition
from mcp_auditor.domain.ports import MCPClientPort

KUBERNETES = "CVE-2025-53355"
FETCH = "CVE-2025-65513"  # its launch joins a namespace holder that carries its sentinels
FILESYSTEM = "CVE-2025-53109"

# Long enough for any call of a fixture to answer, short enough to wait out once per case.
_TOOL_CALL_TIMEOUT = 10

_PLACES = load_places(DETECTION_PLACES)
_TARGETS = {target.flaw_id: target for target in ACCEPTANCE_TARGETS}


@dataclass(frozen=True)
class Call:
    tool: str
    arguments: dict[str, Any]


# `kubectl get events --watch` never returns, and the server runs it synchronously, so it answers
# nothing more, a ping included.
BLOCKING_KUBECTL_CALL = Call(
    "kubectl_generic",
    {
        "command": "get",
        "resourceType": "events",
        "flags": {"watch": True, "request-timeout": "2147483647s"},
    },
)


def missing_prerequisite() -> str | None:
    if not DockerRuntime().available():
        return "the relaunch test needs Docker"
    stale = stale_services(expected_services(ACCEPTANCE_TARGETS), ComposeImageStore())
    if stale:
        return (
            "the relaunch test builds no image, build the absent or stale ones first: "
            f"docker compose -f evals/docker/compose.yml build {' '.join(stale)}"
        )
    return None


@dataclass(frozen=True)
class AuditedTarget:
    target: Target
    launch: Launch
    container: str  # the name the launch gives its container
    nonces: Mapping[str, str]
    server: AuditedServer
    client: MCPClientPort
    tools: Mapping[str, ToolDefinition]

    async def attempt(self, call: Call) -> SendAttempt:
        payload = AuditPayload(
            category=AuditCategory.INPUT_VALIDATION,
            description="a call of the relaunch test",
            arguments=call.arguments,
        )
        return await self.server.attempt(self.tools[call.tool], payload)


@asynccontextmanager
async def an_audited_target(flaw_id: str, name: str | None = None) -> AsyncGenerator[AuditedTarget]:
    """The vulnerable version launched through its fixture and reached through an
    `AuditedServer`, as an audit of the suite reaches it. `name` is the name the fixture's launch
    would carry itself, where the audit otherwise adds its own."""
    target = _TARGETS[flaw_id]
    async with target.launched(kept_records(target.kept_places, _PLACES)) as planted:
        launch = named(planted.launch if name is None else _carrying(planted.launch, name))
        container = declared_container_name(launch.args)
        assert isinstance(container, str)
        try:
            with open(os.devnull, "w") as devnull:
                async with connect(launch, devnull, tool_call_timeout=_TOOL_CALL_TIMEOUT) as client:
                    server = AuditedServer(client)
                    tools = {tool.name: tool for tool in await server.list_tools()}
                    yield AuditedTarget(
                        target, launch, container, planted.nonces, server, client, tools
                    )
        finally:
            # A container a failed case left paused outlives its session, and the fixture cannot
            # remove the holder or the network it is still attached to.
            _docker("rm", "-f", "-v", container)


def _carrying(launch: Launch, name: str) -> Launch:
    assert "--rm" in launch.args
    return replace(launch, args=["run", "--name", name, *launch.args[1:]])


def a_container_name() -> str:
    return f"{LABEL}-relaunch-test-{secrets.token_hex(6)}"


async def the_benign_call(audited: AuditedTarget) -> Call:
    """The last call of the target's benign call, which the live server has just answered."""
    log = ExchangeLog(audited.client)
    await audited.target.benign(_PLACES, log)
    tool, arguments, _ = log.exchanges[-1]
    return Call(tool, arguments)


async def places_surfacing_in_the_exploits(audited: AuditedTarget) -> set[str]:
    """The kept places whose nonce the target's calibration exploits surface on the server as it
    now runs: each nonce is still planted, and the server reaches it."""
    planted_target = PlantedTarget(audited.target.classes, audited.target.aim, audited.nonces)
    surfacing: set[str] = set()
    for exploit in audited.target.exploits:
        log = ExchangeLog(audited.client)
        await exploit(_PLACES, log)
        unit = unit_of_exchanges([(args, response.content) for _, args, response in log.exchanges])
        surfacing |= set(proofs_in(unit, planted_target))
    return surfacing


def joins_a_namespace_holder(audited: AuditedTarget) -> bool:
    return any(argument.startswith("container:") for argument in audited.launch.args)


def stops_answering(container: str) -> None:
    """Frozen, for a server none of whose calls blocks: its calls and its pings time out."""
    _docker("pause", container, check=True)


def ends_without_the_auditors_removal(container: str) -> None:
    _docker("kill", container, check=True)


def container_id(container: str) -> str | None:
    """None when no container has that name or id."""
    inspected = _docker("inspect", "--format", "{{.Id}}", container)
    return inspected.stdout.strip() if inspected.returncode == 0 else None


def _docker(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)
