from pathlib import Path

from evals.cve.backends.facebook_ads import (
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_CA_BUNDLE,
    FACEBOOK_ADS_RESPONDER,
    facebook_ads_server_args,
)
from evals.cve.nuisance.fix_checks import cve_2026_19956_facebook_ads as fix_check
from evals.cve.planting_base import PlantingHost, SymbolicUser
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.cve.backends.support.fixture_authority import trusts_the_fixture_authority
from tests.unit.support.docker_argv import count, mount_of, values_after

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


def test_the_fix_check_launch_trusts_its_own_bundle_and_aliases_the_attacker_host():
    bundle = Path("/scratch/bundle.pem")

    args = fix_check.server_args("image", "198.18.5.77", bundle)

    assert f"{fix_check.ATTACKER_HOST}:198.18.5.77" in values_after(args, "--add-host")
    assert mount_of(args, FACEBOOK_ADS_CA_BUNDLE) == f"{bundle}:{FACEBOOK_ADS_CA_BUNDLE}:ro"
    assert sum(value.startswith("REQUESTS_CA_BUNDLE=") for value in values_after(args, "-e")) == 1
    assert count(args, ["-v"]) == 1


def test_the_fix_check_bundle_holds_the_authority_and_the_sentinel_certificate(tmp_path: Path):
    bundle = fix_check.write_trust_bundle(tmp_path, "ATTACKER HOST CERTIFICATE\n")

    text = bundle.read_text()
    assert text.startswith(GRAPH_FILES.authority.read_text())
    assert text.endswith("ATTACKER HOST CERTIFICATE\n")


def test_the_fix_check_server_starts_with_the_token_its_readme_documents():
    args = fix_check.server_args("image", "198.18.5.77", Path("/scratch/bundle.pem"))

    assert args[-3:] == ["image", "--fb-token", "YOUR_META_ACCESS_TOKEN"]
