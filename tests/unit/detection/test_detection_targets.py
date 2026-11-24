import tests.unit.detection.support.test_detection_targets_given as given
import tests.unit.support.fictional_planting as planting
from evals.cve.detection import exploits
from evals.cve.detection.targets import LaunchMode, TargetVersion, target_services
from evals.cve.environments import LaunchShape
from evals.cve.images import image_tag
from evals.cve.layout import PROJECT
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AuditCategory, AuditPayload, BlockedPayload, ToolDefinition
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.detection.support.fictional_places import a_fictional_places
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target
from tests.unit.support.docker_argv import value_after, values_after


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


def test_the_environment_calls_its_builder_with_the_server_image_and_spec_and_yields_its_nonces():
    target, calls = given.a_target_recording_its_launches()
    spec = target.planting_spec(())

    with target.environment(spec) as planted:
        assert planted.nonces == spec.nonces

    assert calls == [(image_tag(target.server_image), spec, LaunchShape.NORMAL)]


def test_the_environment_passes_the_requested_launch_shape_to_its_builder():
    target, calls = given.a_target_recording_its_launches()

    with target.environment(target.planting_spec(()), shape=LaunchShape.EMPTY_LAYOUT):
        pass

    assert [shape for _, _, shape in calls] == [LaunchShape.EMPTY_LAYOUT]


def test_the_environment_picks_the_fallback_launch_for_both_versions_in_fallback_launch_mode():
    target, calls = given.a_target_recording_its_launches(LaunchMode.FALLBACK)

    with target.environment(target.planting_spec(())):
        pass
    with target.environment(target.planting_spec(()), TargetVersion.PATCHED):
        pass

    assert [shape for _, _, shape in calls] == [LaunchShape.FALLBACK, LaunchShape.FALLBACK]


def test_the_patched_version_launches_the_patched_image_tag():
    target, calls = given.a_target_recording_its_launches()

    with target.environment(target.planting_spec(()), TargetVersion.PATCHED):
        pass

    assert [image for image, _, _ in calls] == [image_tag(target.patched_image)]


def test_an_empty_spec_plants_no_nonce():
    with given.the_kubernetes_target_without_docker().environment(
        given.KUBERNETES_TARGET.planting_spec(())
    ) as planted:
        assert planted.nonces == {}
        assert "FICT=MCPAUDIT-fakenonce" not in planted.launch.args


def test_an_env_place_is_planted_through_arguments_with_no_docker():
    spec = given.KUBERNETES_TARGET.planting_spec(
        [planting.env_place("fict-env", name="FICT")],
        nonces=planting.FixedTokenNonces("MCPAUDIT-fakenonce"),
    )

    with given.the_kubernetes_target_without_docker().environment(spec) as planted:
        args = planted.launch.args
        assert planted.nonces == {"fict-env": "MCPAUDIT-fakenonce"}
        assert "FICT=MCPAUDIT-fakenonce" in args
        assert "65534:65534" in args
        assert value_after(args, "-w") == PROJECT
        assert given.CONTROL_PLANE_NETWORK in values_after(args, "--network")


def _a_payload(arguments: dict[str, object]) -> AuditPayload:
    return AuditPayload(category=AuditCategory.INJECTION, description="probe", arguments=arguments)


def test_target_services_dedups_images_and_patched_images():
    first = an_acceptance_target(FILESYSTEM, images=("app",), patched_image="app-patched")
    second = an_acceptance_target(
        FILESYSTEM, images=("app", "sentinel"), patched_image="other-patched"
    )

    services = target_services([first, second])

    assert services == ["app", "app-patched", "sentinel", "other-patched"]


def test_target_services_is_empty_for_no_target():
    assert target_services([]) == []
