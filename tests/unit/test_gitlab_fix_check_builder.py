from evals.gitlab_backend import GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE
from evals.nuisance_fix_checks import cve_2026_61462_gitlab as gitlab

RESPONDER_IP = "198.18.4.77"


def _value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_the_responder_carries_the_nonce_at_its_own_address():
    args = gitlab.responder_args("name", "nonce-value", RESPONDER_IP)

    assert "WITNESS_NONCE=nonce-value" in args
    assert _value_after(args, "--ip") == RESPONDER_IP
    assert _value_after(args, "--network") == GITLAB_BRIDGE
    assert GITLAB_RESPONDER_IMAGE in args


def test_the_server_overrides_the_baked_api_url_with_its_own_responder_unprivileged():
    args = gitlab.server_args("image", RESPONDER_IP)

    assert f"GITLAB_API_URL=http://{RESPONDER_IP}/api/v4" in args
    assert _value_after(args, "--network") == GITLAB_BRIDGE
    assert _value_after(args, "--user") == "65534:65534"
    assert args[-1] == "image"


def test_the_aim_matches_the_literal_traversal_only():
    assert gitlab.AIM.search("../../../../../../internal/secret")
    assert not gitlab.AIM.search("42")
