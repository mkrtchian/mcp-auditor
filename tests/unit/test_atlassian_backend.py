from evals.atlassian_backend import (
    ATLASSIAN_BRIDGE,
    ATLASSIAN_RESPONDER_IP,
    atlassian_env_args,
    atlassian_server_args,
)
from evals.cve_planting_base import PlantingHost, SymbolicUser
from tests.unit.support.docker_argv import environment, value_after

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
LAUNCH = ["--transport", "stdio"]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = atlassian_server_args("server-name", "image", HOST, LAUNCH)

    assert value_after(args, "--network") == ATLASSIAN_BRIDGE
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = atlassian_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_both_clients_point_at_the_responder():
    variables = environment(atlassian_server_args("server-name", "image", HOST, LAUNCH))

    assert variables["JIRA_URL"] == f"http://{ATLASSIAN_RESPONDER_IP}"
    assert variables["CONFLUENCE_URL"] == f"http://{ATLASSIAN_RESPONDER_IP}"


def test_both_clients_carry_a_dummy_token_and_the_allowlist():
    variables = environment(atlassian_server_args("server-name", "image", HOST, LAUNCH))

    assert variables["JIRA_PERSONAL_TOKEN"]
    assert variables["CONFLUENCE_PERSONAL_TOKEN"]
    assert variables["JIRA_PROJECTS_FILTER"] == "ALLOWED"
    assert variables["CONFLUENCE_SPACES_FILTER"] == "ALLOWED"


def test_the_environment_points_at_the_responder_address_it_is_given():
    variables = environment(atlassian_env_args("198.18.0.77"))

    assert variables["JIRA_URL"] == "http://198.18.0.77"
    assert variables["CONFLUENCE_URL"] == "http://198.18.0.77"
