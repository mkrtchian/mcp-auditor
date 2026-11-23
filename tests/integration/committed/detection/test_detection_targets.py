from collections.abc import Awaitable, Callable

import pytest
import yaml

from evals.cve.detection.targets import (
    ACCEPTANCE_TARGETS,
    OUT_OF_SCOPE_FLAWS,
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
from evals.repository import REPO_ROOT
from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.detection.support.fictional_places import a_fictional_places
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, an_acceptance_target

COMPOSE_PATH = REPO_ROOT / "evals" / "docker" / "compose.yml"
SSRF_TARGET = an_acceptance_target("CVE-2025-65513")

ExploitCall = Callable[[Places, MCPClientPort], Awaitable[None]]


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
async def test_every_exploit_reads_as_aimed_and_the_benign_call_does_not(target: Target):
    for exploit in target.exploits:
        assert is_aimed(await _recorded(exploit), target.aim)
    benign = await _recorded(target.benign)

    assert not is_aimed(benign, target.aim)


def test_the_repository_bypass_flaw_is_out_of_scope_with_a_reason():
    assert "CVE-2025-68145" not in {target.flaw_id for target in ACCEPTANCE_TARGETS}

    bypass = next(flaw for flaw in OUT_OF_SCOPE_FLAWS if flaw.flaw_id == "CVE-2025-68145")
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
def test_every_acceptance_target_runs_its_normal_launch(target: Target):
    assert target.launch_mode is LaunchMode.NORMAL


def test_only_the_git_target_declares_a_read_write_layout():
    mounts = {t.flaw_id: t.planting_host.layout_mount for t in ACCEPTANCE_TARGETS}

    assert [flaw_id for flaw_id, mount in mounts.items() if mount is LayoutMount.READ_WRITE] == [
        "CVE-2025-68143"
    ]


@pytest.mark.parametrize(
    "target", ACCEPTANCE_TARGETS, ids=[target.flaw_id for target in ACCEPTANCE_TARGETS]
)
def test_every_acceptance_target_runs_from_the_checkout(target: Target):
    assert target.planting_host.working_directory == PROJECT


def test_the_filesystem_target_aims_at_both_scope_escapes():
    filesystem = an_acceptance_target(FILESYSTEM)

    assert filesystem.aim.search("/srv/app/archive0/report")  # the symlink out of scope
    assert filesystem.aim.search("/srv/app.git/config")  # the prefix-collision sibling


def test_the_git_target_falls_back_to_no_scope_because_its_scope_is_optional():
    git = an_acceptance_target(GIT)

    assert git.fallback_scope.kind is FallbackScopeKind.OPTIONAL


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/admin",
        "http://127.1/",
        "http://127.0.1:8080/admin",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.10/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fd12:3456::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://sentinel/",
        "http://sentinel:80/flag",
    ],
)
def test_the_ssrf_aim_reads_an_internal_host_as_aimed(url: str):
    assert SSRF_TARGET.aim.search(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "https://example.com/?next=http://127.0.0.1/",
        "http://172.32.0.1/",
        "http://example.invalid/",
    ],
)
def test_the_ssrf_aim_does_not_read_a_public_host_as_aimed(url: str):
    assert not SSRF_TARGET.aim.search(url)


async def _recorded(call: ExploitCall) -> Unit:
    # The symlink traversal discovers the planted links by listing the checkout, so the fake
    # names at least one archive<N> for its read chain to issue an aimed read_file.
    listing = ToolResponse(content="archive0\narchive7\n")
    log = ExchangeLog(FakeMCPClient([], responses={"list_directory": listing}))
    await call(a_fictional_places(), log)
    return unit_of_exchanges([(args, response.content) for _, args, response in log.exchanges])
