import dataclasses
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from evals import cve_exploits
from evals.cve_environments import Launch, LaunchShape
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import PlantingSpec
from evals.cve_proofs import is_aimed
from evals.cve_recording_client import RecordingClient
from evals.cve_targets import (
    CVE_TARGETS,
    OUT_OF_SCOPE_CVES,
    CVETarget,
    FallbackScope,
    FallbackScopeKind,
    LaunchMode,
    TargetVersion,
    image_tag,
)
from evals.cve_units import Unit, unit_of_exchanges
from mcp_auditor.domain import AuditCategory, AuditPayload, BlockedPayload, ToolDefinition
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient

SSRF_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-65513")
KUBERNETES_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53355")
COMPOSE_PATH = Path(__file__).resolve().parents[2] / "evals" / "docker" / "compose.yml"

ExploitCall = Callable[[Places, MCPClientPort], Awaitable[None]]


def _a_fictional_places() -> Places:
    """One place per catalogue reach the sweeping exploits read: a command-execution file and
    env for the kubernetes sweep, an internal-fetch endpoint for the SSRF sweep. The layout
    exploits read the frozen /srv constants, not these records."""
    return {
        "fict-file": Place(
            id="fict-file",
            family="fictional",
            reachable_by=frozenset({"arbitrary_read", "command_execution"}),
            kind=PlantKind.FILE,
            coordinates=Coordinates(PlantKind.FILE, path="/etc/fict-secret"),
        ),
        "fict-env": Place(
            id="fict-env",
            family="fictional",
            reachable_by=frozenset({"command_execution"}),
            kind=PlantKind.ENV,
            coordinates=Coordinates(PlantKind.ENV, name="FICT_SECRET"),
        ),
        "fict-endpoint": Place(
            id="fict-endpoint",
            family="fictional",
            reachable_by=frozenset({"internal_fetch"}),
            kind=PlantKind.HTTP_ENDPOINT,
            coordinates=Coordinates(PlantKind.HTTP_ENDPOINT, host="169.254.169.254", path="/fict"),
        ),
    }


class _FakeNonces:
    def token(self) -> str:
        return "MCPAUDIT-fakenonce"

    def account_name(self) -> str:
        return "mcpaudit-fakeaccount"


def _an_env_place() -> Place:
    return Place(
        id="fict-env",
        family="fictional",
        reachable_by=frozenset({"command_execution"}),
        kind=PlantKind.ENV,
        coordinates=Coordinates(PlantKind.ENV, name="FICT"),
    )


@pytest.mark.parametrize("target", CVE_TARGETS, ids=[target.cve_id for target in CVE_TARGETS])
async def test_every_exploit_reads_as_aimed_and_the_benign_call_does_not(target: CVETarget):
    for exploit in target.exploits:
        assert is_aimed(await _recorded(exploit), target.aim)
    benign = await _recorded(target.benign)

    assert not is_aimed(benign, target.aim)


async def test_the_git_init_exploit_stages_exact_relative_paths_outside_the_checkout():
    client = FakeMCPClient([])

    await cve_exploits.exploit_git_init_traversal(_a_fictional_places(), client)

    staged = [args for name, args in client.calls if name == "git_add"]
    assert staged == [{"repo_path": "/srv", "files": ["app.git/config", ".env"]}]
    files = [path for call in staged for path in call["files"]]
    assert "." not in files  # "." freezes git on binary objects (smoke-check)
    assert all(not path.startswith("app/") for path in files)  # the checkout is a gitlink


async def test_the_destructive_payload_guard_permits_the_git_init_chain_on_srv():
    client = FakeMCPClient([])
    await cve_exploits.exploit_git_init_traversal(_a_fictional_places(), client)
    guard = AuditedServer(FakeMCPClient([]))
    tool = ToolDefinition(name="git", description="git", input_schema={"type": "object"})

    for _name, args in client.calls:
        outcome = await guard.attempt(tool, _a_payload(args))
        assert not isinstance(outcome, BlockedPayload), args


def test_four_targets_remain_and_the_prefix_collision_merged_into_the_symlink_target():
    ids = [target.cve_id for target in CVE_TARGETS]

    assert len(ids) == 4
    assert "CVE-2025-53110" not in ids
    assert "CVE-2025-68145" not in ids


def test_the_filesystem_target_aims_at_both_scope_escapes():
    filesystem = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53109")

    assert filesystem.aim.search("/srv/app/leak0/report")  # the symlink out of scope
    assert filesystem.aim.search("/srv/app.git/config")  # the prefix-collision sibling


def test_the_repository_bypass_cve_is_out_of_scope_with_a_reason():
    assert "CVE-2025-68145" not in {target.cve_id for target in CVE_TARGETS}

    bypass = next(cve for cve in OUT_OF_SCOPE_CVES if cve.cve_id == "CVE-2025-68145")
    assert bypass.reason


@pytest.mark.parametrize("target", CVE_TARGETS, ids=[target.cve_id for target in CVE_TARGETS])
async def test_the_tools_filter_names_exactly_the_tools_its_exploits_call(target: CVETarget):
    called: set[str] = set()
    for exploit in target.exploits:
        client = FakeMCPClient(
            [],
            responses={"list_directory": ToolResponse(content="leak0\n")},
        )
        await exploit(_a_fictional_places(), client)
        called.update(name for name, _ in client.calls)

    assert target.tools_filter == frozenset(called)


@pytest.mark.parametrize("target", CVE_TARGETS, ids=[target.cve_id for target in CVE_TARGETS])
def test_every_server_and_patched_image_of_a_target_is_a_compose_service(target: CVETarget):
    services = yaml.safe_load(COMPOSE_PATH.read_text())["services"]

    assert target.images
    assert set(target.images) <= set(services)
    assert target.server_image in services
    assert target.patched_image in services


def test_the_environment_calls_its_builder_with_the_server_image_and_spec_and_yields_its_nonces():
    calls: list[tuple[str, PlantingSpec, LaunchShape]] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        calls.append((image, spec, shape))
        yield Launch("docker", [])

    target = dataclasses.replace(SSRF_TARGET, builder=recording_builder)
    spec = target.planting_spec(())

    with target.environment(spec) as planted:
        assert planted.nonces == spec.nonces

    assert calls == [(image_tag(SSRF_TARGET.server_image), spec, LaunchShape.NORMAL)]


def test_the_environment_passes_the_requested_launch_shape_to_its_builder():
    shapes: list[LaunchShape] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        shapes.append(shape)
        yield Launch("docker", [])

    target = dataclasses.replace(SSRF_TARGET, builder=recording_builder)

    with target.environment(target.planting_spec(()), shape=LaunchShape.EMPTY_LAYOUT):
        pass

    assert shapes == [LaunchShape.EMPTY_LAYOUT]


def test_the_environment_picks_the_fallback_launch_for_both_versions_in_fallback_launch_mode():
    shapes: list[LaunchShape] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        shapes.append(shape)
        yield Launch("docker", [])

    target = dataclasses.replace(
        SSRF_TARGET, builder=recording_builder, launch_mode=LaunchMode.FALLBACK
    )

    with target.environment(target.planting_spec(())):
        pass
    with target.environment(target.planting_spec(()), TargetVersion.PATCHED):
        pass

    assert shapes == [LaunchShape.FALLBACK, LaunchShape.FALLBACK]


def test_the_environment_picks_the_normal_launch_in_the_normal_launch_mode():
    shapes: list[LaunchShape] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        shapes.append(shape)
        yield Launch("docker", [])

    target = dataclasses.replace(SSRF_TARGET, builder=recording_builder)

    with target.environment(target.planting_spec(())):
        pass

    assert target.launch_mode is LaunchMode.NORMAL
    assert shapes == [LaunchShape.NORMAL]


@pytest.mark.parametrize("target", CVE_TARGETS, ids=[target.cve_id for target in CVE_TARGETS])
def test_every_surviving_target_carries_a_fallback_scope_and_the_normal_launch_mode(
    target: CVETarget,
):
    assert target.launch_mode is LaunchMode.NORMAL
    assert isinstance(target.fallback_scope, FallbackScope)
    assert isinstance(target.fallback_scope.kind, FallbackScopeKind)


def test_the_git_init_note_no_longer_stages_the_dot_path():
    git = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-68143")

    assert "git_add(.)" not in git.note


def test_the_kubernetes_note_is_broadened_beyond_the_env_nonce():
    assert "env" in KUBERNETES_TARGET.note
    assert "file" in KUBERNETES_TARGET.note
    assert "account" in KUBERNETES_TARGET.note
    assert "hostname" in KUBERNETES_TARGET.note


def test_the_patched_version_launches_the_patched_image_tag():
    calls: list[str] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        calls.append(image)
        yield Launch("docker", [])

    target = dataclasses.replace(SSRF_TARGET, builder=recording_builder)

    with target.environment(target.planting_spec(()), TargetVersion.PATCHED):
        pass

    assert calls == [image_tag(SSRF_TARGET.patched_image)]


def test_an_empty_spec_plants_no_nonce():
    with KUBERNETES_TARGET.environment(KUBERNETES_TARGET.planting_spec(())) as planted:
        assert planted.nonces == {}
        assert "FICT=MCPAUDIT-fakenonce" not in planted.launch.args


def test_an_env_place_is_planted_through_arguments_with_no_docker():
    spec = KUBERNETES_TARGET.planting_spec([_an_env_place()], nonces=_FakeNonces())

    with KUBERNETES_TARGET.environment(spec) as planted:
        args = planted.launch.args
        assert planted.nonces == {"fict-env": "MCPAUDIT-fakenonce"}
        assert "FICT=MCPAUDIT-fakenonce" in args
        assert "65534:65534" in args
        assert args[args.index("-w") + 1] == "/"
        assert args[args.index("--network") + 1] == "none"


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


def _a_payload(arguments: dict[str, object]) -> AuditPayload:
    return AuditPayload(category=AuditCategory.INJECTION, description="probe", arguments=arguments)


async def _recorded(call: ExploitCall) -> Unit:
    # The symlink traversal discovers the planted leaks by listing the checkout, so the fake
    # names at least one leak<N> for its read chain to issue an aimed read_file.
    listing = ToolResponse(content="leak0\nleak7\n")
    recorder = RecordingClient(FakeMCPClient([], responses={"list_directory": listing}))
    await call(_a_fictional_places(), recorder)
    return unit_of_exchanges([(args, response.content) for _, args, response in recorder.exchanges])
