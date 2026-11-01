from evals.facebook_ads_backend import (
    FACEBOOK_ADS_ATTACKER_HOST,
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_BRIDGE,
)
from evals.nuisance_fix_checks import cve_2026_19956_facebook_ads as facebook_ads

RESPONDER_IP = "198.18.5.77"


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_responder_carries_the_nonce_at_its_own_address():
    args = facebook_ads.responder_args("name", "nonce-value", RESPONDER_IP)

    assert "WITNESS_NONCE=nonce-value" in args
    assert _value_after(args, "--ip") == RESPONDER_IP
    assert _value_after(args, "--network") == FACEBOOK_ADS_BRIDGE


def test_the_server_resolves_both_hosts_to_its_own_responder_unprivileged_with_its_token():
    args = facebook_ads.server_args("image", RESPONDER_IP)

    assert f"{FACEBOOK_ADS_BENIGN_HOST}:{RESPONDER_IP}" in args
    assert f"{FACEBOOK_ADS_ATTACKER_HOST}:{RESPONDER_IP}" in args
    assert _value_after(args, "--user") == "65534:65534"
    assert args[args.index("image") + 1 :] == ["--fb-token", "dummy"]


def test_the_aim_matches_the_attacker_host_url_only():
    assert facebook_ads.AIM.search(f"https://{FACEBOOK_ADS_ATTACKER_HOST}/sentinel")
    assert not facebook_ads.AIM.search(
        f"https://{FACEBOOK_ADS_BENIGN_HOST}/v22.0/act_000000000000000/insights?after=EXAMPLE_CURSOR"
    )
