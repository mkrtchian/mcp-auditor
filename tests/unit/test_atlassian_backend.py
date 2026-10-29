from evals.atlassian_backend import (
    ATLASSIAN_BRIDGE,
    ATLASSIAN_RESPONDER_IP,
    atlassian_env_args,
    atlassian_server_args,
)
from evals.cve_planting_base import PlantingHost, SymbolicUser

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
LAUNCH = ["--transport", "stdio"]


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _environment(args: list[str]) -> dict[str, str]:
    pairs = (args[index + 1] for index, arg in enumerate(args) if arg == "-e")
    return dict(pair.split("=", 1) for pair in pairs)


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = atlassian_server_args("server-name", "image", HOST, LAUNCH)

    assert _value_after(args, "--network") == ATLASSIAN_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert _value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = atlassian_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_both_clients_point_at_the_responder():
    environment = _environment(atlassian_server_args("server-name", "image", HOST, LAUNCH))

    assert environment["JIRA_URL"] == f"http://{ATLASSIAN_RESPONDER_IP}"
    assert environment["CONFLUENCE_URL"] == f"http://{ATLASSIAN_RESPONDER_IP}"


def test_both_clients_carry_a_dummy_token_and_the_allowlist():
    environment = _environment(atlassian_server_args("server-name", "image", HOST, LAUNCH))

    assert environment["JIRA_PERSONAL_TOKEN"]
    assert environment["CONFLUENCE_PERSONAL_TOKEN"]
    assert environment["JIRA_PROJECTS_FILTER"] == "ALLOWED"
    assert environment["CONFLUENCE_SPACES_FILTER"] == "ALLOWED"


def test_the_environment_points_at_the_responder_address_it_is_given():
    environment = _environment(atlassian_env_args("198.18.0.77"))

    assert environment["JIRA_URL"] == "http://198.18.0.77"
    assert environment["CONFLUENCE_URL"] == "http://198.18.0.77"
