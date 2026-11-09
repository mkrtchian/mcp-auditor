import pytest

import tests.unit.support.test_responder_fix_checks_given as given
from tests.unit.support.docker_argv import carries, value_after

ADDRESS = given.RESPONDER_ADDRESS


@pytest.mark.parametrize("check", given.RESPONDER_FIX_CHECKS, ids=lambda c: c.flaw)
def test_each_responder_serves_its_witness_nonce_at_the_given_address_on_its_bridge(
    check: given.ResponderFixCheck,
):
    args = check.responder_args("name", "nonce-value", ADDRESS)

    assert carries(args, ["-e", f"{check.witness_variable}=nonce-value"])
    assert value_after(args, "--ip") == ADDRESS
    assert value_after(args, "--network") == check.bridge
    assert args[-1] == check.responder_image


@pytest.mark.parametrize("check", given.RESPONDER_FIX_CHECKS, ids=lambda c: c.flaw)
def test_each_server_runs_unprivileged_on_the_bridge_pointed_at_its_responder(
    check: given.ResponderFixCheck,
):
    args = check.server_args("image", ADDRESS)

    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "--network") == check.bridge
    assert [pointer for pointer in check.pointers(ADDRESS) if pointer not in args] == []
    assert "image" in args
