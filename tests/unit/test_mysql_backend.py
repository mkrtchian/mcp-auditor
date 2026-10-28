from evals.cve_planting_base import LABEL, PlantingHost, SymbolicUser
from evals.mysql_backend import MYSQL_BRIDGE, MYSQL_IMAGE, mysql_server_args

_LAUNCH = ["--hostname", "db", "--port", "3306"]


def _a_host() -> PlantingHost:
    return PlantingHost(user=SymbolicUser.UNPRIVILEGED, working_directory="/", has_network=True)


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_server_joins_the_bridge_under_its_name_and_label():
    args = mysql_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert _value_after(args, "--network") == MYSQL_BRIDGE
    assert _value_after(args, "--name") == "server-name"
    assert _value_after(args, "--label") == LABEL


def test_the_server_runs_as_the_hosts_user_in_its_working_directory():
    args = mysql_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert _value_after(args, "--user") == "65534:65534"
    assert _value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = mysql_server_args("server-name", "image", _a_host(), _LAUNCH)

    assert args[-len(_LAUNCH) - 1 :] == ["image", *_LAUNCH]


def test_the_backend_image_is_the_pinned_mysql_server():
    assert MYSQL_IMAGE == "mysql:8.0.46"
