from evals.figma_backend import FIGMA_BENIGN_HOST, figma_network_args
from tests.unit.support.docker_argv import values_after


def test_the_host_resolves_to_the_responder_address_it_is_given():
    aliases = values_after(figma_network_args("198.18.6.77"), "--add-host")

    assert aliases == [f"{FIGMA_BENIGN_HOST}:198.18.6.77"]
