import dataclasses
from collections.abc import Generator
from contextlib import contextmanager

import pytest

import tests.unit.detection.support.test_detection_targets_given as given
from evals.cve.detection import exploits
from evals.cve.detection.targets import (
    FallbackScopeKind,
    LaunchMode,
    TargetVersion,
)
from evals.cve.environments import Launch, LaunchShape
from evals.cve.images import image_tag
from evals.cve.layout import PROJECT
from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting import PlantingSpec
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AuditCategory, AuditPayload, BlockedPayload, ToolDefinition
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.detection.support.fictional_places import a_fictional_places
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, an_acceptance_target
from tests.unit.support.docker_argv import value_after, values_after

SSRF_TARGET = an_acceptance_target("CVE-2025-65513")


class _FakeNonces:
    def token(self) -> str:
        return "MCPAUDIT-fakenonce"

    def account_name(self) -> str:
        return "mcpaudit-fakeaccount"


async def test_the_git_init_exploit_stages_exact_relative_paths_outside_the_checkout():
    client = FakeMCPClient([])

    await exploits.exploit_git_init_traversal(a_fictional_places(), client)

    staged = [args for name, args in client.calls if name == "git_add"]
    assert staged == [{"repo_path": "/srv", "files": ["app.git/config", ".env"]}]
    files = [path for call in staged for path in call["files"]]
    assert "." not in files  # "." freezes git on binary objects (smoke-check)
    assert all(not path.startswith("app/") for path in files)  # the checkout is a gitlink


async def test_the_destructive_payload_guard_permits_the_git_init_chain_on_srv():
    client = FakeMCPClient([])
    await exploits.exploit_git_init_traversal(a_fictional_places(), client)
    guard = AuditedServer(FakeMCPClient([]))
    tool = ToolDefinition(name="git", description="git", input_schema={"type": "object"})

    for _name, args in client.calls:
        outcome = (await guard.attempt(tool, _a_payload(args))).outcome
        assert not isinstance(outcome, BlockedPayload), args


def test_the_filesystem_target_aims_at_both_scope_escapes():
    filesystem = an_acceptance_target(FILESYSTEM)

    assert filesystem.aim.search("/srv/app/archive0/report")  # the symlink out of scope
    assert filesystem.aim.search("/srv/app.git/config")  # the prefix-collision sibling


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


def test_the_git_target_falls_back_to_no_scope_because_its_scope_is_optional():
    git = an_acceptance_target(GIT)

    assert git.fallback_scope.kind is FallbackScopeKind.OPTIONAL


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
    with given.the_kubernetes_target_without_docker().environment(
        given.KUBERNETES_TARGET.planting_spec(())
    ) as planted:
        assert planted.nonces == {}
        assert "FICT=MCPAUDIT-fakenonce" not in planted.launch.args


def test_an_env_place_is_planted_through_arguments_with_no_docker():
    spec = given.KUBERNETES_TARGET.planting_spec([_an_env_place()], nonces=_FakeNonces())

    with given.the_kubernetes_target_without_docker().environment(spec) as planted:
        args = planted.launch.args
        assert planted.nonces == {"fict-env": "MCPAUDIT-fakenonce"}
        assert "FICT=MCPAUDIT-fakenonce" in args
        assert "65534:65534" in args
        assert value_after(args, "-w") == PROJECT
        assert given.CONTROL_PLANE_NETWORK in values_after(args, "--network")


def _an_env_place() -> Place:
    return Place(
        id="fict-env",
        family="fictional",
        reaches=frozenset({"command_execution"}),
        kind=PlaceKind.ENV,
        coordinates=Coordinates(PlaceKind.ENV, name="FICT"),
    )


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
