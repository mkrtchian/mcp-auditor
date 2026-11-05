from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.figma_backend import (
    FIGMA_BENIGN_HOST,
    FIGMA_BRIDGE,
    FIGMA_RESPONDER_IP,
    figma_network_args,
    figma_server_args,
)
from tests.unit.support.docker_argv import value_after, values_after

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
LAUNCH = ["node", "dist/bin.js", "--stdio"]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = figma_server_args("server-name", "image", HOST, LAUNCH)

    assert value_after(args, "--network") == FIGMA_BRIDGE
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = figma_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_the_benign_host_resolves_to_the_responder():
    args = figma_server_args("server-name", "image", HOST, LAUNCH)

    assert values_after(args, "--add-host") == [f"{FIGMA_BENIGN_HOST}:{FIGMA_RESPONDER_IP}"]


def test_both_the_fetch_and_the_curl_child_trust_the_responder_certificate():
    environment = values_after(figma_network_args("198.18.6.77"), "-e")

    assert "NODE_EXTRA_CA_CERTS=/ca.pem" in environment
    assert "CURL_CA_BUNDLE=/ca.pem" in environment


def test_the_server_gets_the_dummy_key_it_needs_to_start():
    environment = values_after(figma_network_args("198.18.6.77"), "-e")

    assert "FIGMA_API_KEY=dummy" in environment


def test_the_network_args_leave_the_stdio_flag_to_the_server_launch():
    args = figma_network_args("198.18.6.77")

    assert not any("--stdio" in arg for arg in args)


def test_the_host_resolves_to_the_responder_address_it_is_given():
    aliases = values_after(figma_network_args("198.18.6.77"), "--add-host")

    assert aliases == [f"{FIGMA_BENIGN_HOST}:198.18.6.77"]
