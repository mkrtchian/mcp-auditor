from pathlib import Path

from evals.cve.backends.facebook_ads import FACEBOOK_ADS_BENIGN_HOST, FACEBOOK_ADS_CA_BUNDLE
from evals.cve.nuisance.fix_checks import cve_2026_19956_facebook_ads as fix_check
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.support.docker_argv import count, mount_of, values_after

GRAPH_FILES = stand_in_files(FACEBOOK_ADS_BENIGN_HOST)


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
