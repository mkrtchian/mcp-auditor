from evals.cve.nuisance.fix_checks import cve_2026_11720_googleapis as googleapis
from evals.googleapis_backend import GOOGLEAPIS_BRIDGE, GOOGLEAPIS_RESPONDER_IMAGE
from tests.unit.support.docker_argv import values_after

LAUNCH_HOST = 123


def test_the_witness_responder_sits_on_both_bridges_and_redirects_to_its_private_address():
    args = googleapis.responder_args("name", "nonce-value", LAUNCH_HOST)

    assert "WITNESS_NONCE=nonce-value" in args
    assert values_after(args, "--network") == [
        f"name={GOOGLEAPIS_BRIDGE},ip=198.18.3.{LAUNCH_HOST}",
        f"name={googleapis.INTERNAL_BRIDGE},ip=10.199.0.{LAUNCH_HOST}",
    ]
    assert f"REDIRECT_TARGET=http://10.199.0.{LAUNCH_HOST}/sentinel" in args
    assert googleapis.WITNESS_RESPONDER_IMAGE in args
    assert GOOGLEAPIS_RESPONDER_IMAGE not in args


def test_the_server_reaches_its_own_responder_on_the_public_address_unprivileged():
    args = googleapis.server_args("image", LAUNCH_HOST)

    assert values_after(args, "--network") == [GOOGLEAPIS_BRIDGE, googleapis.INTERNAL_BRIDGE]
    assert f"UPSTREAM_URL=http://198.18.3.{LAUNCH_HOST}" in values_after(args, "-e")
    assert values_after(args, "--user") == ["65534:65534"]
    assert args[-1] == "image"
