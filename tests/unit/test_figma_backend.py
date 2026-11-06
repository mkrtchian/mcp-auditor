from evals.figma_backend import FIGMA_BENIGN_HOST, FIGMA_CA_BUNDLE, figma_network_args
from tests.unit.support.docker_argv import environment, values_after


def test_the_host_resolves_to_the_responder_address_it_is_given():
    aliases = values_after(figma_network_args("198.18.6.77"), "--add-host")

    assert aliases == [f"{FIGMA_BENIGN_HOST}:198.18.6.77"]


def test_the_server_trusts_the_responder_cert_baked_into_its_image():
    variables = environment(figma_network_args("198.18.6.77"))

    assert variables["NODE_EXTRA_CA_CERTS"] == variables["CURL_CA_BUNDLE"] == FIGMA_CA_BUNDLE
