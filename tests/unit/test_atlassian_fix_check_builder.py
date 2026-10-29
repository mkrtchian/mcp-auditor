from evals.atlassian_backend import ATLASSIAN_BRIDGE
from evals.nuisance_fix_checks import cve_2026_77252_atlassian as atlassian

RESPONDER_IP = "198.18.0.77"


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_responder_carries_the_nonce_at_its_own_address():
    args = atlassian.responder_args("name", "nonce-value", RESPONDER_IP)

    assert "WITNESS_NONCE=nonce-value" in args
    assert _value_after(args, "--ip") == RESPONDER_IP
    assert _value_after(args, "--network") == ATLASSIAN_BRIDGE


def test_the_server_reaches_its_own_responder_unprivileged():
    args = atlassian.server_args("image", RESPONDER_IP)

    assert f"JIRA_URL=http://{RESPONDER_IP}" in args
    assert f"CONFLUENCE_URL=http://{RESPONDER_IP}" in args
    assert _value_after(args, "--network") == ATLASSIAN_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert "image" in args
