import pytest

import tests.unit.support.test_backend_lifecycle_given as given
from evals import doris_backend, mysql_backend, neo4j_backend
from evals.cve_planting_base import LABEL
from evals.holdout_kit.kit_backend_launch import backend_launch, lifecycle_of
from evals.nuisance_backends import BACKENDS
from evals.nuisance_confinement import MEMORY_BOUND, memory_bound_args
from evals.nuisance_images import image_tag


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_key_resolves_to_the_lifecycle_carrying_it(key: str):
    assert lifecycle_of(key).key == key


def test_an_unknown_backend_key_is_refused_by_name():
    with pytest.raises(ValueError, match="ghost"):
        lifecycle_of("ghost")


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_the_kit_backend_launch_is_the_provisioner_launch(
    key: str, monkeypatch: pytest.MonkeyPatch
):
    lifecycle = given.a_lifecycle_without_side_effects(key, monkeypatch)
    server = given.a_server_with_backend(key)

    with BACKENDS[key].provisioner(server) as run_launch:
        run_args = run_launch.args
    with backend_launch(lifecycle, image_tag(server.service), server.host, server.launch) as kit:
        kit_command, kit_args = kit.command, kit.args

    assert kit_command == run_launch.command
    assert given.with_the_name_masked(kit_args) == given.with_the_name_masked(run_args)


def test_the_kit_backend_launch_names_its_server_after_the_backend():
    recording = given.RecordingLifecycle()

    with backend_launch(recording.lifecycle, "image", given.a_host(), ["serve"]) as launch:
        name = given.name_of(launch.args)

    assert name.startswith(f"{LABEL}-fake-server-")


def test_the_kit_backend_launch_ensures_on_entry_and_removes_its_server_on_exit():
    recording = given.RecordingLifecycle()

    with backend_launch(recording.lifecycle, "image", given.a_host(), ["serve"]) as launch:
        assert recording.events == ["ensure"]

    assert recording.events == ["ensure", f"remove {given.name_of(launch.args)}"]


def test_the_kit_backend_launch_removes_its_server_when_the_body_raises():
    recording = given.RecordingLifecycle()

    with (
        pytest.raises(RuntimeError),
        backend_launch(recording.lifecycle, "image", given.a_host(), ["serve"]),
    ):
        raise RuntimeError("the probe failed")

    assert recording.events[0] == "ensure"
    assert recording.events[1].startswith(f"remove {LABEL}-fake-server-")


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_backend_server_argv_carries_the_memory_bound(key: str):
    args = lifecycle_of(key).server_args("name", "image", given.a_host(), ["serve"])

    assert _carries(args, ["--memory", MEMORY_BOUND, "--memory-swap", MEMORY_BOUND])


def test_every_responder_singleton_argv_carries_the_memory_bound():
    responders = given.every_responder()

    assert len(responders) == 11
    for responder in responders:
        assert _carries(responder.singleton_run_args(), memory_bound_args()), responder.container


@pytest.mark.parametrize(
    "args",
    [
        doris_backend.doris_cluster_run_args(),
        mysql_backend.backend_container_run_args(
            mysql_backend.MYSQL_CONTAINER, [mysql_backend.MYSQL_IMAGE]
        ),
        mysql_backend.backend_container_run_args(mysql_backend.MOTO_CONTAINER, ["moto"]),
        neo4j_backend.database_run_args(),
    ],
    ids=["doris cluster", "mysql engine", "moto stub", "neo4j database"],
)
def test_every_built_backend_container_argv_carries_the_memory_bound(args: list[str]):
    assert _carries(args, memory_bound_args())


def _carries(args: list[str], segment: list[str]) -> bool:
    return any(args[i : i + len(segment)] == segment for i in range(len(args)))
