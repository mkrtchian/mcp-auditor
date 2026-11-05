from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.facebook_ads_backend import (
    FACEBOOK_ADS_ATTACKER_HOST,
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_BRIDGE,
    FACEBOOK_ADS_RESPONDER_IP,
    facebook_ads_network_args,
    facebook_ads_server_args,
)
from tests.unit.support.docker_argv import value_after, values_after

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
LAUNCH = ["--fb-token", "dummy"]


def test_the_server_joins_the_responder_bridge_as_the_hosts_user():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert value_after(args, "--network") == FACEBOOK_ADS_BRIDGE
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "-w") == "/"


def test_the_server_launch_follows_the_image():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert args[-len(LAUNCH) - 1 :] == ["image", *LAUNCH]


def test_the_benign_and_the_attacker_hosts_both_resolve_to_the_responder():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert sorted(values_after(args, "--add-host")) == sorted(
        [
            f"{FACEBOOK_ADS_BENIGN_HOST}:{FACEBOOK_ADS_RESPONDER_IP}",
            f"{FACEBOOK_ADS_ATTACKER_HOST}:{FACEBOOK_ADS_RESPONDER_IP}",
        ]
    )


def test_the_server_trusts_the_responder_certificate_through_its_own_environment():
    args = facebook_ads_server_args("server-name", "image", HOST, LAUNCH)

    assert "REQUESTS_CA_BUNDLE=/ca.pem" in values_after(args, "-e")


def test_the_network_args_carry_no_token_the_server_reads_it_off_its_command_line():
    environment = values_after(facebook_ads_network_args("198.18.5.77"), "-e")

    assert environment == ["REQUESTS_CA_BUNDLE=/ca.pem"]


def test_the_hosts_resolve_to_the_responder_address_it_is_given():
    aliases = values_after(facebook_ads_network_args("198.18.5.77"), "--add-host")

    assert sorted(aliases) == sorted(
        [
            f"{FACEBOOK_ADS_BENIGN_HOST}:198.18.5.77",
            f"{FACEBOOK_ADS_ATTACKER_HOST}:198.18.5.77",
        ]
    )
