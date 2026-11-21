from evals.cve.backends.ckan import (
    CKAN_FRONT_IP,
    CKAN_PARTS,
    EUROPA_IP,
    MOUNTED_FILES,
    ckan_server_args,
)
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.planting_base import PlantingHost, SymbolicUser
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.cve.backends.support.fixture_authority import trusts_the_fixture_authority
from tests.unit.support.docker_argv import mount_of, value_after, values_after

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)


def test_the_ckan_front_names_resolve_to_the_front_and_data_europa_eu_to_its_stand_in():
    args = ckan_server_args("server-name", "image", HOST, ["serve"])

    assert sorted(values_after(args, "--add-host")) == [
        f"data.europa.eu:{EUROPA_IP}",
        f"demo.ckan.org:{CKAN_FRONT_IP}",
        f"www.dati.gov.it:{CKAN_FRONT_IP}",
    ]


def test_the_ckan_server_trusts_the_mounted_fixture_authority_and_keeps_tls_verification():
    args = ckan_server_args("server-name", "image", HOST, ["serve"])

    trusts_the_fixture_authority(args, "NODE_EXTRA_CA_CERTS", "data.europa.eu")


def test_the_ckan_front_and_its_stand_in_stand_at_the_addresses_the_server_resolves():
    addresses = {part.container: value_after(part.run_args(), "--ip") for part in CKAN_PARTS}

    assert addresses["mcp-auditor-cve-ckan-front"] == CKAN_FRONT_IP
    assert addresses["mcp-auditor-cve-ckan-europa"] == EUROPA_IP
    assert len(set(addresses.values())) == len(CKAN_PARTS)


def test_the_ckan_front_serves_each_front_name_from_its_mounted_leaf():
    front = next(part for part in CKAN_PARTS if part.container == "mcp-auditor-cve-ckan-front")
    args = front.run_args()

    for name in ("www.dati.gov.it", "demo.ckan.org"):
        files = stand_in_files(name)
        tls = f"/etc/nginx/tls/{name}"
        assert mount_of(args, f"{tls}.pem") == f"{files.certificate}:{tls}.pem:ro"
        assert mount_of(args, f"{tls}-key.pem") == f"{files.key}:{tls}-key.pem:ro"


def test_the_data_europa_eu_stand_in_serves_its_capture_under_its_leaf():
    europa = next(part for part in CKAN_PARTS if part.container == "mcp-auditor-cve-ckan-europa")
    args = europa.run_args()
    files = stand_in_files("data.europa.eu")

    assert mount_of(args, "/stand-in/capture.json") == f"{files.capture}:/stand-in/capture.json:ro"
    assert mount_of(args, "/stand-in/cert.pem") == f"{files.certificate}:/stand-in/cert.pem:ro"
    assert mount_of(args, "/stand-in/key.pem") == f"{files.key}:/stand-in/key.pem:ro"


def test_the_ckan_registry_entry_serves_every_file_its_lifecycle_mounts():
    assert set(MOUNTED_FILES) <= set(BACKENDS["ckan"].served)
