from evals.apify_backend import APIFY_BENIGN_HOST, APIFY_BRIDGE, APIFY_SUFFIX_HOST
from evals.nuisance_fix_checks import cve_2026_46341_apify as apify

RESPONDER_IP = "198.18.1.77"


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_responder_carries_the_nonce_at_its_own_address():
    args = apify.responder_args("name", "nonce-value", RESPONDER_IP)

    assert "WITNESS_NONCE=nonce-value" in args
    assert _value_after(args, "--ip") == RESPONDER_IP
    assert _value_after(args, "--network") == APIFY_BRIDGE


def test_the_server_resolves_both_hosts_to_its_own_responder_unprivileged():
    args = apify.server_args("image", RESPONDER_IP)

    assert f"{APIFY_BENIGN_HOST}:{RESPONDER_IP}" in args
    assert f"{APIFY_SUFFIX_HOST}:{RESPONDER_IP}" in args
    assert _value_after(args, "--user") == "65534:65534"
    assert "image" in args


def test_the_aim_matches_the_suffix_host_url_only():
    assert apify.AIM.search(f"https://{APIFY_SUFFIX_HOST}/mirror")
    assert not apify.AIM.search(f"https://{APIFY_BENIGN_HOST}/platform/actors.md")
