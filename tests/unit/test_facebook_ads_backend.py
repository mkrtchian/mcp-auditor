from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.facebook_ads_backend import (
    FACEBOOK_ADS_ATTACKER_HOST,
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_BRIDGE,
    FACEBOOK_ADS_RESPONDER_IP,
    facebook_ads_network_args,
    facebook_ads_server_args,
)

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
LAUNCH = ["--fb-token", "dummy"]


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _values_after(args: list[str], flag: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args) if arg == flag]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert _value_after(args, "--network") == FACEBOOK_ADS_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert _value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_the_benign_and_the_attacker_hosts_both_resolve_to_the_responder():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert sorted(_values_after(args, "--add-host")) == sorted(
        [
            f"{FACEBOOK_ADS_BENIGN_HOST}:{FACEBOOK_ADS_RESPONDER_IP}",
            f"{FACEBOOK_ADS_ATTACKER_HOST}:{FACEBOOK_ADS_RESPONDER_IP}",
        ]
    )


def test_the_server_trusts_the_responder_certificate_through_its_own_environment():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert "REQUESTS_CA_BUNDLE=/ca.pem" in _values_after(args, "-e")


def test_the_network_args_carry_no_token_the_server_reads_it_off_its_command_line():
    environment = _values_after(facebook_ads_network_args("198.18.5.77"), "-e")

    assert environment == ["REQUESTS_CA_BUNDLE=/ca.pem"]


def test_the_hosts_resolve_to_the_responder_address_it_is_given():
    aliases = _values_after(facebook_ads_network_args("198.18.5.77"), "--add-host")

    assert sorted(aliases) == sorted(
        [
            f"{FACEBOOK_ADS_BENIGN_HOST}:198.18.5.77",
            f"{FACEBOOK_ADS_ATTACKER_HOST}:198.18.5.77",
        ]
    )
