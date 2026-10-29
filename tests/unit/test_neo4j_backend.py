from evals.cve_planting_base import LABEL, PlantingHost, SymbolicUser
from evals.neo4j_backend import NEO4J_BRIDGE, NEO4J_IMAGE, neo4j_server_args

_LAUNCH = ["--read-only"]


def _a_host() -> PlantingHost:
    return PlantingHost(user=SymbolicUser.UNPRIVILEGED, working_directory="/", has_network=True)


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_server_joins_the_bridge_under_its_name_and_label():
    args = neo4j_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert _value_after(args, "--network") == NEO4J_BRIDGE
    assert _value_after(args, "--name") == "server-name"
    assert _value_after(args, "--label") == LABEL


def test_the_server_runs_confined_as_the_hosts_user_in_its_working_directory():
    args = neo4j_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert _value_after(args, "--user") == "65534:65534"
    assert _value_after(args, "-w") == "/"
    assert "--cap-drop" in args


def test_the_server_launch_follows_the_image():
    args = neo4j_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert args[-len(_LAUNCH) - 1 :] == ["image", *_LAUNCH]


def test_the_connection_is_left_to_the_server_image():
    args = neo4j_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert not [arg for arg in args if arg.startswith("NEO4J_")]


def test_the_backend_image_is_the_locally_built_tag():
    assert NEO4J_IMAGE == "mcp-auditor-cve-neo4j-backend:local"
