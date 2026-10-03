from pathlib import Path

import pytest

import tests.unit.support.test_target_execution_given as given
from mcp_auditor.domain.confinement import environment_names_passed, steers_docker_client
from mcp_auditor.domain.models import ExecutionRegime
from mcp_auditor.domain.relayed_environment import RelayRequest
from mcp_auditor.target_execution import (
    IMAGE_BY_LAUNCHER,
    LaunchRefused,
    TargetExecution,
    decide_launch,
)
from tests.fakes import FakeContainerRuntime


def test_the_launcher_table_is_closed():
    assert IMAGE_BY_LAUNCHER["uvx"] == "ghcr.io/astral-sh/uv:python3.14-trixie-slim"
    assert IMAGE_BY_LAUNCHER["npx"] == "node:24-bookworm-slim"
    for launcher in ("python", "node", "uv", "bun"):
        assert IMAGE_BY_LAUNCHER.get(launcher) is None


def test_unconfined_keeps_the_command_and_reaches_no_runtime():
    context = given.a_context(FakeContainerRuntime(untouchable=True), unconfined=True)

    decision = decide_launch("python", ["server.py"], context)

    assert decision.launch.regime == ExecutionRegime.UNCONFINED
    assert (decision.launch.command, decision.launch.args) == ("python", ("server.py",))
    assert decision.warnings == ()


def test_unconfined_warns_that_an_image_means_nothing():
    runtime = FakeContainerRuntime(untouchable=True)
    context = given.a_context(runtime, unconfined=True, image="node:24")

    decision = decide_launch("python", ["server.py"], context)

    assert len(decision.warnings) == 1
    assert "--unconfined" in decision.warnings[0]


def test_unconfined_warns_that_a_mount_means_nothing():
    runtime = FakeContainerRuntime(untouchable=True)
    context = given.a_context(runtime, unconfined=True, mounts=("/data:rw",))

    decision = decide_launch("python", ["server.py"], context)

    assert len(decision.warnings) == 1
    assert "--unconfined" in decision.warnings[0]


def test_a_declared_container_passes_through_with_the_docker_environment():
    context = given.a_context(FakeContainerRuntime(untouchable=True))

    decision = decide_launch("docker", ["run", "-i", "an-image"], context)

    assert decision.launch.regime == ExecutionRegime.DECLARED_CONTAINER
    assert decision.launch.args == ("run", "-i", "an-image")
    assert decision.launch.client_env == given.DOCKER_ENV
    assert decision.warnings == ()


def test_an_unknown_launcher_stops_before_any_runtime_call():
    context = given.a_context(FakeContainerRuntime(untouchable=True))

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("python", ["server.py"], context)

    assert "no confinement profile" in str(refusal.value)
    assert "--unconfined" in str(refusal.value)


def test_an_image_given_for_an_unknown_launcher_is_used(tmp_path: Path):
    runtime = FakeContainerRuntime()
    context = given.a_context(runtime, image="my-own-image")

    decision = decide_launch("python", [str(tmp_path / "server.py")], context)

    assert runtime.pulled == ["my-own-image"]
    assert decision.launch.record(None).image == "my-own-image"


def test_an_image_given_for_a_known_launcher_replaces_the_table_image():
    runtime = FakeContainerRuntime()

    decision = decide_launch("npx", ["a-server"], given.a_context(runtime, image="node:22"))

    assert runtime.pulled == ["node:22"]
    assert decision.launch.record(None).image == "node:22"


def test_docker_unavailable_names_the_way_out():
    context = given.a_context(FakeContainerRuntime(available=False))

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("npx", ["a-server"], context)

    assert "--unconfined" in str(refusal.value)


def test_a_remote_endpoint_stops_before_anything_is_pulled():
    runtime = FakeContainerRuntime(endpoint="tcp://example:2375")

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("npx", ["a-server"], given.a_context(runtime))

    assert "tcp://example:2375" in str(refusal.value)
    assert runtime.pulled == []


def test_a_rootless_socket_is_a_local_endpoint():
    runtime = FakeContainerRuntime(endpoint="unix:///run/user/1000/docker.sock")

    decision = decide_launch("npx", ["a-server"], given.a_context(runtime))

    assert decision.launch.regime == ExecutionRegime.CONFINED


def test_a_refused_root_in_argv_stops_before_anything_is_pulled():
    runtime = FakeContainerRuntime()

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("npx", [given.FILESYSTEM_SERVER, "/etc"], given.a_context(runtime))

    assert "/etc" in str(refusal.value)
    assert "--mount" in str(refusal.value)
    assert runtime.pulled == []


def test_a_declared_mount_on_a_missing_path_names_it():
    context = given.a_context(FakeContainerRuntime(), mounts=("/no/such/path:rw",))

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("npx", ["a-server"], context)

    assert "/no/such/path" in str(refusal.value)


def test_a_pull_error_carries_the_daemon_message():
    context = given.a_context(FakeContainerRuntime(pull_error="toomanyrequests: rate limit"))

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("npx", ["a-server"], context)

    assert "toomanyrequests: rate limit" in str(refusal.value)


def test_a_confined_launch_records_its_image_digest_and_writable_path(tmp_path: Path):
    context = given.a_context(FakeContainerRuntime(digest="sha256:deadbeef"))

    launch = decide_launch("npx", [given.FILESYSTEM_SERVER, str(tmp_path)], context).launch

    record = launch.record(False)
    assert record.regime == ExecutionRegime.CONFINED
    assert record.image == IMAGE_BY_LAUNCHER["npx"]
    assert record.image_digest == "sha256:deadbeef"
    assert record.writable_paths == [str(tmp_path.resolve())]
    assert launch.client_env == given.DOCKER_ENV


def test_an_existing_bare_word_is_reported_and_not_mounted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "build").mkdir()
    monkeypatch.chdir(tmp_path)

    decision = decide_launch("npx", ["a-server", "build"], given.a_context(FakeContainerRuntime()))

    assert any("build" in warning for warning in decision.warnings)
    assert decision.launch.record(None).writable_paths == []


def test_a_host_that_cannot_enforce_the_pids_limit_is_reported():
    context = given.a_context(FakeContainerRuntime(pids_limit_enforced=False))

    decision = decide_launch("npx", ["a-server"], context)

    assert any("runs without it" in warning for warning in decision.warnings)


def test_a_host_whose_pids_limit_cannot_be_read_warns_about_nothing():
    context = given.a_context(FakeContainerRuntime(pids_limit_enforced=None))

    decision = decide_launch("npx", ["a-server"], context)

    assert decision.warnings == ()


def test_a_host_that_enforces_the_pids_limit_warns_about_nothing():
    context = given.a_context(FakeContainerRuntime(pids_limit_enforced=True))

    decision = decide_launch("npx", ["a-server"], context)

    assert decision.warnings == ()


async def test_a_confined_execution_removes_its_container_and_records_the_kill_state():
    runtime = FakeContainerRuntime(oom_killed=True)
    launch = decide_launch("npx", ["a-server"], given.a_context(runtime)).launch

    execution = TargetExecution(launch, runtime)
    async with execution:
        assert execution.record is None

    assert runtime.removed == [given.CONTAINER_NAME]
    assert execution.record is not None
    assert execution.record.oom_killed is True


async def test_a_confined_execution_removes_its_container_when_the_block_raises():
    runtime = FakeContainerRuntime()
    launch = decide_launch("npx", ["a-server"], given.a_context(runtime)).launch

    with pytest.raises(ConnectionError):
        async with TargetExecution(launch, runtime):
            raise ConnectionError("the server died")

    assert runtime.removed == [given.CONTAINER_NAME]


async def test_an_unconfined_execution_reaches_no_runtime():
    runtime = FakeContainerRuntime(untouchable=True)
    context = given.a_context(runtime, unconfined=True)
    launch = decide_launch("python", ["server.py"], context).launch

    execution = TargetExecution(launch, runtime)
    async with execution:
        pass

    assert execution.record is not None
    assert execution.record.regime == ExecutionRegime.UNCONFINED
    assert execution.record.oom_killed is None


DOCKER_STEERING_NAMES = ("HOME", "PATH", "DOCKER_HOST", "DOCKER_DEFAULT_PLATFORM")
CONTAINER_TARGETS = (("npx", ["a-server"]), ("docker", ["run", "-i", "-e", "X", "an-image"]))


@pytest.mark.parametrize("name", DOCKER_STEERING_NAMES)
@pytest.mark.parametrize(("command", "args"), CONTAINER_TARGETS)
def test_a_name_that_steers_the_docker_client_is_refused_in_a_container(
    name: str, command: str, args: list[str]
):
    context = given.a_context_relaying(FakeContainerRuntime(untouchable=True), name)

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch(command, args, context)

    assert f"{name} steers the docker client" in str(refusal.value)
    assert "--unconfined" in str(refusal.value)


@pytest.mark.parametrize("name", DOCKER_STEERING_NAMES)
def test_a_name_that_steers_the_docker_client_is_relayed_unconfined(name: str):
    runtime = FakeContainerRuntime(untouchable=True)
    context = given.a_context_relaying(runtime, name, unconfined=True)

    decision = decide_launch("python", ["server.py"], context)

    assert decision.launch.relayed.values == {name: given.TOKEN_VALUE}


@pytest.mark.parametrize(
    ("name", "steers"),
    [
        ("HOME", True),
        ("PATH", True),
        ("DOCKER_HOST", True),
        ("DOCKER_CONFIG", True),
        ("DOCKER_DEFAULT_PLATFORM", True),
        ("GITHUB_TOKEN", False),
        ("MY_DOCKER_HOST", False),
        ("PATHS", False),
        ("docker_host", False),
    ],
)
def test_steers_docker_client(name: str, steers: bool):
    assert steers_docker_client(name) is steers


def test_a_relay_refusal_stops_before_any_runtime_call():
    context = given.a_context(
        FakeContainerRuntime(untouchable=True), relay=RelayRequest(redacted=("TOKEN=abc",))
    )

    with pytest.raises(LaunchRefused) as refusal:
        decide_launch("npx", ["a-server"], context)

    assert "--env TOKEN=value" in str(refusal.value)


def test_each_regime_launches_with_the_relayed_variables():
    runtime = FakeContainerRuntime()

    launches = [
        decide_launch("python", ["s.py"], given.a_context_relaying(runtime, "T", unconfined=True)),
        decide_launch("npx", ["a-server"], given.a_context_relaying(runtime, "T")),
        decide_launch("docker", ["run", "-e", "T", "img"], given.a_context_relaying(runtime, "T")),
    ]

    assert all(d.launch.relayed.values == {"T": given.TOKEN_VALUE} for d in launches)


def test_the_relay_warnings_are_surfaced():
    runtime = FakeContainerRuntime(untouchable=True)
    context = given.a_context(
        runtime, unconfined=True, relay=RelayRequest(plain=("API_KEY=k",)), environ={}
    )

    decision = decide_launch("python", ["server.py"], context)

    assert any("API_KEY looks like a secret" in warning for warning in decision.warnings)


def test_a_declared_container_that_does_not_pass_a_relayed_name_is_warned_about():
    context = given.a_context_relaying(FakeContainerRuntime(untouchable=True), "TOKEN")

    decision = decide_launch("docker", ["run", "-i", "an-image"], context)

    assert decision.warnings == (
        "your docker run does not pass TOKEN to the container: add -e TOKEN to it",
    )


@pytest.mark.parametrize(
    "passing",
    [["-e", "TOKEN"], ["--env=TOKEN"], ["--env-file", "f"]],
)
def test_a_declared_container_that_passes_the_relayed_name_is_not_warned_about(
    passing: list[str],
):
    context = given.a_context_relaying(FakeContainerRuntime(untouchable=True), "TOKEN")

    decision = decide_launch("docker", ["run", "-i", *passing, "an-image"], context)

    assert decision.warnings == ()


@pytest.mark.parametrize(
    ("args", "names", "env_file"),
    [
        (["run", "img"], set[str](), False),
        (["run", "-e", "A", "img"], {"A"}, False),
        (["run", "-e", "A=1", "img"], {"A"}, False),
        (["run", "--env", "A", "img"], {"A"}, False),
        (["run", "--env", "A=1", "img"], {"A"}, False),
        (["run", "--env=A", "img"], {"A"}, False),
        (["run", "--env=A=1", "img"], {"A"}, False),
        (["run", "-e", "A", "--env=B", "img"], {"A", "B"}, False),
        (["run", "--env-file", "f", "img"], set[str](), True),
        (["run", "--env-file=f", "img"], set[str](), True),
        (["run", "img", "-e"], set[str](), False),
    ],
)
def test_environment_names_passed(args: list[str], names: set[str], env_file: bool):
    assert environment_names_passed(args) == (frozenset(names), env_file)
