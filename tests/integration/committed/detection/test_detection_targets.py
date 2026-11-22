from collections.abc import Awaitable, Callable

import pytest
import yaml

from evals.cve.detection.targets import (
    ACCEPTANCE_TARGETS,
    OUT_OF_SCOPE_FLAWS,
    FallbackScope,
    FallbackScopeKind,
    LaunchMode,
    Target,
)
from evals.cve.exchange_log import ExchangeLog
from evals.cve.layout import PROJECT
from evals.cve.places import Places
from evals.cve.planting_base import LayoutMount
from evals.cve.proofs import is_aimed
from evals.cve.units import Unit, unit_of_exchanges
from evals.honeypots import REPO_ROOT
from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.detection.support.fictional_places import a_fictional_places

COMPOSE_PATH = REPO_ROOT / "evals" / "docker" / "compose.yml"

ExploitCall = Callable[[Places, MCPClientPort], Awaitable[None]]


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
async def test_every_exploit_reads_as_aimed_and_the_benign_call_does_not(target: Target):
    for exploit in target.exploits:
        assert is_aimed(await _recorded(exploit), target.aim)
    benign = await _recorded(target.benign)

    assert not is_aimed(benign, target.aim)


def test_four_targets_remain_and_the_prefix_collision_merged_into_the_symlink_target():
    ids = [target.flaw_id for target in ACCEPTANCE_TARGETS]

    assert len(ids) == 4
    assert "CVE-2025-53110" not in ids
    assert "CVE-2025-68145" not in ids


def test_the_repository_bypass_cve_is_out_of_scope_with_a_reason():
    assert "CVE-2025-68145" not in {target.flaw_id for target in ACCEPTANCE_TARGETS}

    bypass = next(cve for cve in OUT_OF_SCOPE_FLAWS if cve.flaw_id == "CVE-2025-68145")
    assert bypass.reason


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
async def test_the_tools_filter_names_exactly_the_tools_its_exploits_call(target: Target):
    called: set[str] = set()
    for exploit in target.exploits:
        client = FakeMCPClient(
            [],
            responses={"list_directory": ToolResponse(content="archive0\n")},
        )
        await exploit(a_fictional_places(), client)
        called.update(name for name, _ in client.calls)

    assert target.tools_filter == frozenset(called)


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
def test_every_server_and_patched_image_of_a_target_is_a_compose_service(target: Target):
    services = yaml.safe_load(COMPOSE_PATH.read_text())["services"]

    assert target.images
    assert set(target.images) <= set(services)
    assert target.server_image in services
    assert target.patched_image in services


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
def test_every_surviving_target_carries_a_fallback_scope_and_the_normal_launch_mode(
    target: Target,
):
    assert target.launch_mode is LaunchMode.NORMAL
    assert isinstance(target.fallback_scope, FallbackScope)
    assert isinstance(target.fallback_scope.kind, FallbackScopeKind)


def test_only_the_git_target_declares_a_read_write_layout():
    mounts = {t.flaw_id: t.planting_host.layout_mount for t in ACCEPTANCE_TARGETS}

    assert [cve for cve, mount in mounts.items() if mount is LayoutMount.READ_WRITE] == [
        "CVE-2025-68143"
    ]


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
def test_every_acceptance_target_runs_from_the_checkout(target: Target):
    assert target.planting_host.working_directory == PROJECT


async def _recorded(call: ExploitCall) -> Unit:
    # The symlink traversal discovers the planted links by listing the checkout, so the fake
    # names at least one archive<N> for its read chain to issue an aimed read_file.
    listing = ToolResponse(content="archive0\narchive7\n")
    recorder = ExchangeLog(FakeMCPClient([], responses={"list_directory": listing}))
    await call(a_fictional_places(), recorder)
    return unit_of_exchanges([(args, response.content) for _, args, response in recorder.exchanges])
