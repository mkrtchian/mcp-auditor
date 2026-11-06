from evals.facebook_ads_backend import (
    FACEBOOK_ADS_ATTACKER_HOST,
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_CA_BUNDLE,
    facebook_ads_network_args,
)
from evals.nuisance_fix_checks import cve_2026_19956_facebook_ads as fix_check
from tests.unit.support.docker_argv import environment, values_after


def test_the_hosts_resolve_to_the_responder_address_it_is_given():
    aliases = values_after(facebook_ads_network_args("198.18.5.77"), "--add-host")

    assert sorted(aliases) == sorted(
        [
            f"{FACEBOOK_ADS_BENIGN_HOST}:198.18.5.77",
            f"{FACEBOOK_ADS_ATTACKER_HOST}:198.18.5.77",
        ]
    )


def test_the_server_trusts_the_responder_cert_baked_into_its_image():
    variables = environment(facebook_ads_network_args("198.18.5.77"))

    assert variables["REQUESTS_CA_BUNDLE"] == FACEBOOK_ADS_CA_BUNDLE


def test_the_fix_check_server_reads_the_token_it_needs_to_start_off_its_command_line():
    args = fix_check.server_args("image", "198.18.5.77")

    assert args[-3:] == ["image", "--fb-token", "dummy"]
