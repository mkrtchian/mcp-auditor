from evals.googleapis_backend import GOOGLEAPIS_BRIDGE, GOOGLEAPIS_RESPONDER_IMAGE
from evals.nuisance_fix_checks import cve_2026_11720_googleapis as googleapis
from tests.unit.support.docker_argv import values_after

LAUNCH_HOST = 123


def test_the_responder_sits_on_both_bridges_and_redirects_to_its_private_address():
    args = googleapis.responder_args("name", "nonce-value", LAUNCH_HOST)

    assert "WITNESS_NONCE=nonce-value" in args
    assert values_after(args, "--network") == [
        f"name={GOOGLEAPIS_BRIDGE},ip=198.18.3.{LAUNCH_HOST}",
        f"name={googleapis.INTERNAL_BRIDGE},ip=10.199.0.{LAUNCH_HOST}",
    ]
    assert f"REDIRECT_TARGET=http://10.199.0.{LAUNCH_HOST}/sentinel" in args
    assert GOOGLEAPIS_RESPONDER_IMAGE in args


def test_the_server_reaches_its_own_responder_on_the_public_address_unprivileged():
    args = googleapis.server_args("image", LAUNCH_HOST)

    assert values_after(args, "--network") == [GOOGLEAPIS_BRIDGE, googleapis.INTERNAL_BRIDGE]
    assert f"UPSTREAM_URL=http://198.18.3.{LAUNCH_HOST}" in values_after(args, "-e")
    assert values_after(args, "--user") == ["65534:65534"]
    assert args[-1] == "image"


def test_each_aim_matches_its_own_exploit_only():
    base_path_escape = googleapis.EXPLOIT_BASE_PATH_ESCAPE
    redirect = googleapis.EXPLOIT_REDIRECT
    benign = googleapis.BENIGN_ARGUMENTS

    assert googleapis.TARGET_11720.aim.search(str(base_path_escape))
    assert not googleapis.TARGET_11720.aim.search(str(redirect))
    assert not googleapis.TARGET_11720.aim.search(str(benign))
    assert googleapis.TARGET_14540.aim.search(str(redirect))
    assert not googleapis.TARGET_14540.aim.search(str(base_path_escape))
    assert not googleapis.TARGET_14540.aim.search(str(benign))
