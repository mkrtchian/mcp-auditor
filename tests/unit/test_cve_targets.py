import dataclasses
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from evals.cve_environments import Launch
from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import PlantingSpec
from evals.cve_proofs import is_aimed
from evals.cve_recording_client import RecordingClient
from evals.cve_targets import CVE_TARGETS, CVETarget, TargetVersion, image_tag
from evals.cve_units import Unit, unit_of_exchanges
from mcp_auditor.domain.ports import MCPClientPort
from tests.fakes.mcp_client import FakeMCPClient

SSRF_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-65513")
KUBERNETES_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53355")
COMPOSE_PATH = Path(__file__).resolve().parents[2] / "evals" / "docker" / "compose.yml"


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


@pytest.mark.parametrize("target", CVE_TARGETS, ids=[target.cve_id for target in CVE_TARGETS])
def test_every_server_and_patched_image_of_a_target_is_a_compose_service(target: CVETarget):
    services = yaml.safe_load(COMPOSE_PATH.read_text())["services"]

    assert target.images
    assert set(target.images) <= set(services)
    assert target.server_image in services
    assert target.patched_image in services


def test_the_environment_calls_its_builder_with_the_server_image_and_spec_and_yields_its_nonces():
    calls: list[tuple[str, PlantingSpec]] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec) -> Generator[Launch]:
        calls.append((image, spec))
        yield Launch("docker", [])

    target = dataclasses.replace(SSRF_TARGET, builder=recording_builder)
    spec = target.planting_spec(())

    with target.environment(spec) as planted:
        assert planted.nonces == spec.nonces

    assert calls == [(image_tag(SSRF_TARGET.server_image), spec)]


def test_the_patched_version_launches_the_patched_image_tag():
    calls: list[str] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec) -> Generator[Launch]:
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


async def _recorded(call: Callable[[MCPClientPort], Awaitable[None]]) -> Unit:
    recorder = RecordingClient(FakeMCPClient([]))
    await call(recorder)
    return unit_of_exchanges([(args, response.content) for _, args, response in recorder.exchanges])
