from evals.apify_backend import (
    API_HOST,
    APIFY_BENIGN_HOST,
    APIFY_BRIDGE,
    APIFY_RESPONDER_IP,
    APIFY_SUFFIX_HOST,
    apify_network_args,
    apify_server_args,
)
from evals.cve_planting_base import PlantingHost, SymbolicUser

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
API_STAND_IN_PIN = f"{API_HOST}:198.18.1.3"
LAUNCH = ["--transport", "stdio"]


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _values_after(args: list[str], flag: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args) if arg == flag]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = apify_server_args("server-name", "image", HOST, LAUNCH)

    assert _value_after(args, "--network") == APIFY_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert _value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = apify_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_the_documentation_hosts_resolve_to_the_responder_and_the_api_to_its_stand_in():
    aliases = _values_after(apify_server_args("server-name", "image", HOST, LAUNCH), "--add-host")

    assert sorted(aliases) == sorted(
        [
            f"{APIFY_BENIGN_HOST}:{APIFY_RESPONDER_IP}",
            f"{APIFY_SUFFIX_HOST}:{APIFY_RESPONDER_IP}",
            API_STAND_IN_PIN,
        ]
    )


def test_the_suffix_host_extends_the_benign_one():
    assert APIFY_SUFFIX_HOST.startswith(f"{APIFY_BENIGN_HOST}.")


def test_the_server_trusts_the_self_signed_responder_through_its_own_environment():
    args = apify_server_args("server-name", "image", HOST, LAUNCH)

    assert "NODE_TLS_REJECT_UNAUTHORIZED=0" in _values_after(args, "-e")


def test_the_server_carries_a_dummy_token_it_needs_to_start():
    args = apify_server_args("server-name", "image", HOST, LAUNCH)

    assert "APIFY_TOKEN=calib-token" in _values_after(args, "-e")


def test_the_documentation_hosts_resolve_to_the_responder_address_it_is_given():
    aliases = _values_after(apify_network_args("198.18.1.77"), "--add-host")

    assert sorted(aliases) == sorted(
        [f"{APIFY_BENIGN_HOST}:198.18.1.77", f"{APIFY_SUFFIX_HOST}:198.18.1.77", API_STAND_IN_PIN]
    )
