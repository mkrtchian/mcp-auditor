import pytest

import tests.unit.support.test_backend_lifecycle_given as given
from evals.ckan_backend import (
    CKAN_FRONT_IP,
    CKAN_PARTS,
    EUROPA_IP,
    MOUNTED_FILES,
    BackendPart,
    ckan_server_args,
)
from evals.docker_paths import DOCKER_DIRECTORY
from evals.gitlab_backend import GITLAB_RESPONDER_IP
from evals.googleapis_backend import GOOGLEAPIS_RESPONDER_IP
from evals.jenkins_backend import JENKINS_RESPONDER_IP
from evals.n8n_backend import N8N_IP, n8n_server_args, singleton_run_args
from evals.nuisance_backends import BACKENDS
from evals.nuisance_confinement import memory_bound_args
from evals.public_stand_ins import stand_in_files
from tests.unit.support.docker_argv import (
    carries,
    environment,
    mount_of,
    value_after,
    values_after,
)

# These servers take their backend's address from their image, so the address baked into the run
# Dockerfile and its vulnerable twin has to be the one the backend stands its responder at.
_BAKED_ADDRESSES = {
    "jenkins": f"JENKINS_URL=http://{JENKINS_RESPONDER_IP}",
    "gitlab": f"GITLAB_API_URL=http://{GITLAB_RESPONDER_IP}/",
    "googleapis": f"UPSTREAM_URL=http://{GOOGLEAPIS_RESPONDER_IP}",
}


@pytest.mark.parametrize(
    ("dockerfile", "baked"),
    [
        (f"Dockerfile.{service}{suffix}", baked)
        for service, baked in _BAKED_ADDRESSES.items()
        for suffix in ("", "-vuln")
    ],
)
def test_the_run_image_bakes_the_address_its_backend_stands_at(dockerfile: str, baked: str):
    assert baked in (DOCKER_DIRECTORY / dockerfile).read_text()


def test_the_ckan_front_names_resolve_to_the_front_and_data_europa_eu_to_its_stand_in():
    args = ckan_server_args("server-name", "image", given.a_host(), ["serve"])

    assert sorted(values_after(args, "--add-host")) == [
        f"data.europa.eu:{EUROPA_IP}",
        f"demo.ckan.org:{CKAN_FRONT_IP}",
        f"www.dati.gov.it:{CKAN_FRONT_IP}",
    ]


def test_the_ckan_server_trusts_the_mounted_fixture_authority_and_keeps_tls_verification():
    args = ckan_server_args("server-name", "image", given.a_host(), ["serve"])
    authority = stand_in_files("data.europa.eu").authority

    assert environment(args)["NODE_EXTRA_CA_CERTS"] == "/etc/ssl/extra-ca.pem"
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in environment(args)
    assert mount_of(args, "/etc/ssl/extra-ca.pem") == f"{authority}:/etc/ssl/extra-ca.pem:ro"


def test_the_ckan_front_and_its_stand_in_stand_at_the_addresses_the_server_resolves():
    addresses = {part.container: value_after(part.run_args(), "--ip") for part in CKAN_PARTS}

    assert addresses["mcp-auditor-cve-ckan-front"] == CKAN_FRONT_IP
    assert addresses["mcp-auditor-cve-ckan-europa"] == EUROPA_IP
    assert len(set(addresses.values())) == len(CKAN_PARTS)


@pytest.mark.parametrize("part", CKAN_PARTS, ids=lambda part: part.container)
def test_no_ckan_backend_container_is_granted_a_capability(part: BackendPart):
    assert "--cap-add" not in part.run_args()


def test_the_ckan_front_serves_each_front_name_from_its_mounted_leaf():
    front = next(part for part in CKAN_PARTS if part.container == "mcp-auditor-cve-ckan-front")
    args = front.run_args()

    for name in ("www.dati.gov.it", "demo.ckan.org"):
        files = stand_in_files(name)
        tls = f"/etc/nginx/tls/{name}"
        assert mount_of(args, f"{tls}.pem") == f"{files.certificate}:{tls}.pem:ro"
        assert mount_of(args, f"{tls}-key.pem") == f"{files.key}:{tls}-key.pem:ro"


def test_the_data_europa_eu_stand_in_replays_its_capture_under_its_leaf():
    europa = next(part for part in CKAN_PARTS if part.container == "mcp-auditor-cve-ckan-europa")
    args = europa.run_args()
    files = stand_in_files("data.europa.eu")

    assert mount_of(args, "/stand-in/capture.json") == f"{files.capture}:/stand-in/capture.json:ro"
    assert mount_of(args, "/stand-in/cert.pem") == f"{files.certificate}:/stand-in/cert.pem:ro"
    assert mount_of(args, "/stand-in/key.pem") == f"{files.key}:/stand-in/key.pem:ro"


def test_the_ckan_registry_entry_serves_every_file_its_lifecycle_mounts():
    assert set(MOUNTED_FILES) <= set(BACKENDS["ckan"].served)


def test_the_n8n_server_reaches_the_instance_on_its_default_port_with_its_issued_key():
    args = n8n_server_args("server-name", "image", given.a_host(), ["serve"])

    assert environment(args)["N8N_API_URL"] == f"http://{N8N_IP}:5678/"
    assert "N8N_API_KEY" in environment(args)


def test_the_n8n_server_leaves_telemetry_at_its_documented_default():
    args = n8n_server_args("server-name", "image", given.a_host(), ["serve"])

    assert "N8N_MCP_TELEMETRY_DISABLED" not in environment(args)


def test_the_n8n_instance_stands_confined_at_the_address_the_server_reaches_on_its_bridge():
    args = singleton_run_args()

    assert value_after(args, "--network") == BACKENDS["n8n"].network
    assert value_after(args, "--ip") == N8N_IP
    assert args[-1] == BACKENDS["n8n"].image
    assert value_after(args, "--cap-drop") == "ALL"
    assert "--cap-add" not in args
    assert carries(args, memory_bound_args())


def test_the_n8n_registry_entry_builds_the_instance_and_serves_its_dockerfile():
    entry = BACKENDS["n8n"]

    assert entry.built_services == ("n8n-instance",)
    assert DOCKER_DIRECTORY / "Dockerfile.n8n-instance" in entry.served
