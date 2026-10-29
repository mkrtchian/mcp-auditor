from evals.jenkins_backend import JENKINS_BRIDGE
from evals.nuisance_fix_checks import cve_2026_10276_jenkins as jenkins

RESPONDER_IP = "198.18.2.77"


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_responder_carries_the_nonce_at_its_own_address():
    args = jenkins.responder_args("name", "nonce-value", RESPONDER_IP)

    assert "WITNESS_NONCE=nonce-value" in args
    assert _value_after(args, "--ip") == RESPONDER_IP
    assert _value_after(args, "--network") == JENKINS_BRIDGE


def test_the_server_overrides_the_baked_url_with_its_own_responder_unprivileged():
    args = jenkins.server_args("image", RESPONDER_IP)

    assert f"JENKINS_URL=http://{RESPONDER_IP}" in args
    assert _value_after(args, "--network") == JENKINS_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert "image" in args


def test_the_aim_matches_the_encoded_traversal_only():
    assert jenkins.AIM.search("job/public/%2e%2e/%2e%2e/internal/secret")
    assert not jenkins.AIM.search("job/MyJob")
