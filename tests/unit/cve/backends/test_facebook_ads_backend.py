from evals.cve.backends.facebook_ads import (
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_RESPONDER,
    facebook_ads_server_args,
)
from evals.cve.planting_base import PlantingHost, SymbolicUser
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.cve.backends.support.fixture_authority import trusts_the_fixture_authority
from tests.unit.support.docker_argv import mount_of, values_after

GRAPH_FILES = stand_in_files(FACEBOOK_ADS_BENIGN_HOST)
RUN_HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


def test_the_run_resolves_only_the_graph_host_to_the_responder():
    aliases = values_after(run_launch(), "--add-host")

    assert [alias.split(":")[0] for alias in aliases] == [FACEBOOK_ADS_BENIGN_HOST]


def run_launch() -> list[str]:
    return facebook_ads_server_args("name", "image", RUN_HOST, ["--fb-token", "token"])


def test_the_server_trusts_the_fixture_authority_mounted_read_only():
    trusts_the_fixture_authority(run_launch(), "REQUESTS_CA_BUNDLE", FACEBOOK_ADS_BENIGN_HOST)


def test_the_responder_serves_the_graph_leaf_of_the_fixture_authority():
    args = FACEBOOK_ADS_RESPONDER.singleton_run_args()

    assert mount_of(args, "/cert.pem") == f"{GRAPH_FILES.certificate}:/cert.pem:ro"
    assert mount_of(args, "/key.pem") == f"{GRAPH_FILES.key}:/key.pem:ro"
