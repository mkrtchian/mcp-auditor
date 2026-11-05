from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.gitlab_backend import GITLAB_BRIDGE, gitlab_server_args
from tests.unit.support.docker_argv import value_after, values_after

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
LAUNCH = ["node", "/app/build/index.js"]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = gitlab_server_args("server-name", "image", HOST, LAUNCH)

    assert value_after(args, "--network") == GITLAB_BRIDGE
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "-w") == "/"


def test_the_server_is_confined_and_named():
    args = gitlab_server_args("server-name", "image", HOST, LAUNCH)

    assert value_after(args, "--name") == "server-name"
    assert "--rm" in args
    assert value_after(args, "--cap-drop") == "ALL"


def test_the_server_launch_follows_the_image():
    args = gitlab_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_the_server_takes_its_gitlab_address_from_the_image_environment():
    args = gitlab_server_args("server-name", "image", HOST, LAUNCH)

    environment = values_after(args, "-e")
    assert not [entry for entry in environment if entry.startswith("GITLAB_")]
