import pytest

import tests.unit.support.test_backend_lifecycle_given as given
import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
from evals import ckan_backend, doris_backend, gravitino_backend
from evals.cve_planting_base import LABEL, resolver_args
from evals.holdout_kit.kit_backend_launch import backend_launch, lifecycle_of
from evals.nuisance_backends import BACKENDS
from evals.nuisance_confinement import MEMORY_BOUND, memory_bound_args
from evals.nuisance_images import image_tag
from evals.nuisance_provisioners import provisioner_of
from evals.responder_backend import Responder
from tests.unit.support.docker_argv import carries, count, value_after


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_key_resolves_to_the_lifecycle_carrying_it(key: str):
    assert lifecycle_of(key).key == key


def test_an_unknown_backend_key_is_refused_by_name():
    with pytest.raises(ValueError, match="ghost"):
        lifecycle_of("ghost")


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_the_kit_backend_launch_is_the_provisioner_launch(key: str):
    quiet = given.a_lifecycle_without_side_effects(key)
    server = edits.with_the_registered_backend(admission_given.an_admitted_server(), key)

    with provisioner_of(quiet)(server) as run_launch:
        run_args = run_launch.args
    with backend_launch(quiet, image_tag(server.service), server.host, server.launch) as kit:
        kit_command, kit_args = kit.command, kit.args

    assert kit_command == run_launch.command
    assert given.with_the_name_masked(kit_args) == given.with_the_name_masked(run_args)


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_the_registry_and_the_kit_read_one_lifecycle(key: str):
    assert BACKENDS[key].lifecycle is lifecycle_of(key)


LAUNCHERS = [
    pytest.param(given.through_the_provisioner, id="provisioner"),
    pytest.param(given.through_the_kit, id="kit"),
]


@pytest.mark.parametrize("launch_through", LAUNCHERS)
@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_launch_names_its_server_after_the_backend(
    key: str, launch_through: given.Launcher
):
    with launch_through(given.a_lifecycle_without_side_effects(key)) as launch:
        name = given.name_of(launch.args)

    assert name.startswith(f"{LABEL}-{key}-server-")


@pytest.mark.parametrize("launch_through", LAUNCHERS)
def test_a_backend_launch_ensures_on_entry_and_removes_its_server_on_exit(
    launch_through: given.Launcher,
):
    recording = given.RecordingLifecycle()

    with launch_through(recording.lifecycle) as launch:
        assert recording.events == ["ensure"]

    assert recording.events == ["ensure", f"remove {given.name_of(launch.args)}"]


@pytest.mark.parametrize("launch_through", LAUNCHERS)
def test_a_backend_launch_removes_its_server_when_the_body_raises(launch_through: given.Launcher):
    recording = given.RecordingLifecycle()

    with pytest.raises(RuntimeError), launch_through(recording.lifecycle):
        raise RuntimeError("the probe failed")

    assert recording.events[0] == "ensure"
    assert recording.events[1].startswith(f"remove {LABEL}-fake-server-")


@pytest.mark.parametrize("launch_through", LAUNCHERS)
def test_two_launches_of_one_backend_are_open_at_once(launch_through: given.Launcher):
    recording = given.RecordingLifecycle()

    with launch_through(recording.lifecycle) as first:
        assert not recording.lifecycle.lock.locked()
        with launch_through(recording.lifecycle) as second:
            assert given.name_of(second.args) != given.name_of(first.args)


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_backend_server_joins_its_registered_bridge_confined_as_the_hosts_user(key: str):
    args = lifecycle_of(key).server_args("server-name", "image", given.a_host(), ["serve"])

    assert value_after(args, "--network") == BACKENDS[key].network
    assert value_after(args, "--name") == "server-name"
    assert value_after(args, "--label") == LABEL
    assert "--rm" in args
    assert value_after(args, "--cap-drop") == "ALL"
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "-w") == "/srv"
    assert args[-2:] == ["image", "serve"]


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_backend_server_argv_carries_the_memory_bound_and_the_resolver_option(key: str):
    args = lifecycle_of(key).server_args("name", "image", given.a_host(), ["serve"])

    assert carries(args, ["--memory", MEMORY_BOUND, "--memory-swap", MEMORY_BOUND])
    assert count(args, resolver_args()) == 1


@pytest.mark.parametrize("responder", given.every_responder(), ids=lambda r: r.container)
def test_every_responder_singleton_argv_carries_the_memory_bound_and_the_resolver_option(
    responder: Responder,
):
    args = responder.singleton_run_args()

    assert carries(args, memory_bound_args())
    assert count(args, resolver_args()) == 1


@pytest.mark.parametrize(
    "args",
    [
        doris_backend.doris_cluster_run_args(),
        *(part.run_args() for part in ckan_backend.CKAN_PARTS),
        *(part.run_args() for part in gravitino_backend.GRAVITINO_PARTS),
    ],
    ids=[
        "doris cluster",
        *(part.container for part in ckan_backend.CKAN_PARTS),
        *(part.container for part in gravitino_backend.GRAVITINO_PARTS),
    ],
)
def test_every_built_backend_container_argv_carries_the_memory_bound_and_the_resolver_option(
    args: list[str],
):
    assert carries(args, memory_bound_args())
    assert count(args, resolver_args()) == 1


def test_the_doris_cluster_sets_the_backends_public_host_to_its_alias():
    assert carries(
        doris_backend.doris_cluster_run_args(), ["-e", "BE_CONFIG_EXTRA=public_host = doris"]
    )


def test_the_doris_cluster_answers_on_its_alias():
    assert carries(doris_backend.doris_cluster_run_args(), ["--network-alias", "doris"])


def test_the_doris_cluster_is_named_after_its_alias():
    assert carries(doris_backend.doris_cluster_run_args(), ["--hostname", "doris"])
