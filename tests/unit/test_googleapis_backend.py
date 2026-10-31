from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.googleapis_backend import GOOGLEAPIS_BRIDGE, googleapis_server_args

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
LAUNCH = ["node", "/app/build/index.js"]


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = googleapis_server_args("server-name", "image", HOST, LAUNCH)

    assert _value_after(args, "--network") == GOOGLEAPIS_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert _value_after(args, "-w") == "/"


def test_the_server_is_confined_and_named():
    args = googleapis_server_args("server-name", "image", HOST, LAUNCH)

    assert _value_after(args, "--name") == "server-name"
    assert "--rm" in args
    assert _value_after(args, "--cap-drop") == "ALL"


def test_the_server_launch_follows_the_image():
    args = googleapis_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_the_server_takes_its_upstream_address_from_the_image_environment():
    args = googleapis_server_args("server-name", "image", HOST, LAUNCH)

    environment = [args[index + 1] for index, arg in enumerate(args) if arg == "-e"]
    assert environment == ["HOME=/tmp"]
