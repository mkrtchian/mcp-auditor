import pytest

import tests.unit.support.test_server_launch_given as given
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime


def test_confined_launch_spawns_docker_and_keeps_the_user_command():
    launch = ServerLaunch.confined("python", ["s.py"], given.the_quick_start_profile(), {})

    assert launch.spawn_command == "docker"
    assert launch.spawn_args[-3:] == [given.IMAGE, "python", "s.py"]
    assert (launch.command, launch.args) == ("python", ("s.py",))


def test_confined_regime_without_a_profile_is_refused():
    with pytest.raises(ValueError):
        ServerLaunch(command="python", args=("s.py",), regime=ExecutionRegime.CONFINED)


def test_a_profile_under_another_regime_is_refused():
    with pytest.raises(ValueError):
        ServerLaunch(
            command="python",
            args=("s.py",),
            regime=ExecutionRegime.UNCONFINED,
            profile=given.the_quick_start_profile(),
        )


def test_a_declared_container_that_is_not_a_docker_run_is_refused():
    with pytest.raises(ValueError):
        ServerLaunch.declared_container("python", ["x.py"], {})


def test_unconfined_launch_spawns_the_command_verbatim():
    launch = ServerLaunch.unconfined("python", ["s.py"])

    assert (launch.spawn_command, launch.spawn_args) == ("python", ["s.py"])
    assert launch.regime == ExecutionRegime.UNCONFINED
    assert launch.client_env is None


def test_declared_container_spawns_verbatim_and_carries_the_client_environment():
    launch = ServerLaunch.declared_container(
        "docker", ["run", "-i", "img"], {"DOCKER_HOST": "unix:///sock"}
    )

    assert (launch.spawn_command, launch.spawn_args) == ("docker", ["run", "-i", "img"])
    assert launch.regime == ExecutionRegime.DECLARED_CONTAINER
    assert launch.client_env == {"DOCKER_HOST": "unix:///sock"}


def test_the_quick_start_profile_renders_the_hardened_argv():
    launch = ServerLaunch.confined(
        given.QUICK_START_COMMAND, given.QUICK_START_ARGS, given.the_quick_start_profile(), {}
    )

    assert launch.spawn_args == [
        "run",
        "-i",
        "--init",
        "--name",
        given.CONTAINER_NAME,
        "--label",
        "mcp-auditor",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "2g",
        "--memory-swap",
        "2g",
        "--user",
        "1000:1000",
        "--tmpfs",
        "/home/audit:exec,uid=1000,gid=1000",
        "-e",
        "HOME=/home/audit",
        "-v",
        "/tmp/sandbox:/tmp/sandbox",
        given.IMAGE,
        "npx",
        "@modelcontextprotocol/server-filesystem",
        "/tmp/sandbox",
    ]


def test_a_read_only_mount_and_a_rewrite_reach_the_container_argv_only():
    launch = ServerLaunch.confined(
        "npx", ["server", "./data"], given.a_profile_with_a_read_only_mount_and_a_rewrite(), {}
    )

    assert "-v /data:/data:ro" in " ".join(launch.spawn_args)
    assert launch.spawn_args[-1] == "/home/alice/proj/data"
    assert launch.args == ("server", "./data")


def test_a_confined_record_carries_the_container_and_its_kill_state():
    launch = ServerLaunch.confined(
        "npx", ["server"], given.a_profile_with_a_read_only_mount_and_a_rewrite(), {}
    )

    record = launch.record(False)

    assert record.regime == ExecutionRegime.CONFINED
    assert (record.image, record.image_digest) == (given.IMAGE, given.DIGEST)
    assert record.writable_paths == ["/home/alice/proj/data"]
    assert record.read_only_paths == ["/data"]
    assert record.oom_killed is False


def test_an_unconfined_record_carries_nothing_but_its_regime():
    record = ServerLaunch.unconfined("python", ["s.py"]).record(None)

    assert record.regime == ExecutionRegime.UNCONFINED
    assert record.image is None
    assert record.image_digest is None
    assert record.writable_paths is None
    assert record.read_only_paths is None
    assert record.oom_killed is None
