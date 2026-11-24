# The integration test of the real CVE planting path: a real sentinel served by a real
# busybox container, read by a container started with the target's planted arguments. It is
# the only instrument of the production `DockerPlanting` and the readiness probe (the fake
# stands in everywhere else), so it must go red on a planting regression.
#
# Skipped or failed as `docker_prerequisites` says. A missing or foreign sentinel image is rebuilt
# through compose before the first case.
import time

import pytest

import tests.integration.support.planting_specs as planting_specs
import tests.integration.support.recording_planting as recording_planting
import tests.integration.support.test_cve_planting_given as given
import tests.integration.support.test_cve_planting_then as then
from evals.cve import planting_docker
from evals.cve.planting import DockerPlanting, PlantingFailed, planted
from evals.cve.planting_base import SENTINEL_IMAGE, SENTINEL_SERVICE
from tests.integration.support.docker_prerequisites import image_prerequisites


@pytest.fixture(autouse=True, scope="module")
def _planting_prerequisites() -> None:
    image_prerequisites([SENTINEL_SERVICE])


@pytest.mark.parametrize("shape", ["no_network", "holder", "bridge_alias"])
def test_a_planted_target_reads_no_search_domain_nor_an_audit_name(shape: str):
    if not given.host_search_domain_reaches_a_plain_container():
        pytest.skip("the host hands a plain container no search domain to keep out")
    spec = given.a_launch_of_shape(shape)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        identity = given.identity_as_target(args)

    then.no_search_domain_nor_audit_name(identity)


def test_the_holder_and_the_target_run_under_the_memory_bound_with_no_swap():
    spec = given.a_launch_of_shape("holder")
    docker = recording_planting.RecordingPlanting()

    with planted(spec, SENTINEL_IMAGE, docker) as args:
        [holder] = docker.holders
        holder_bound = given.inspected_memory_bound(holder)
        target_bound = given.memory_max_as_target(args)

    assert holder_bound.memory == given.MEMORY_BOUND_BYTES
    assert holder_bound.memory_swap == holder_bound.memory
    assert target_bound == given.MEMORY_BOUND_BYTES


def test_a_planted_ip_literal_endpoint_serves_its_nonce():
    spec = planting_specs.spec_of(planting_specs.IP_LITERAL, "/fict/secret")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, planting_specs.IP_LITERAL, "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


def test_two_coexisting_launches_each_serve_their_own_nonce():
    spec_a = planting_specs.spec_of(planting_specs.IP_LITERAL, "/fict/a")
    spec_b = planting_specs.spec_of(planting_specs.IP_LITERAL, "/fict/b")

    with (
        planted(spec_a, SENTINEL_IMAGE, DockerPlanting()) as args_a,
        planted(spec_b, SENTINEL_IMAGE, DockerPlanting()) as args_b,
    ):
        body_a = given.read_as_target(args_a, planting_specs.IP_LITERAL, "/fict/a")
        body_b = given.read_as_target(args_b, planting_specs.IP_LITERAL, "/fict/b")

    assert body_a == spec_a.nonces["endpoint-1"]
    assert body_b == spec_b.nonces["endpoint-1"]
    assert body_a != body_b


@pytest.mark.parametrize(
    "path",
    [
        "/fict/dir/",
        "/fict/meta?api-version=1",
        "/fict/a#frag",
        "/fict/sp ace/x",
        "/fict/a%20b",
        "/",
        "/fict/café",
    ],
)
def test_a_path_a_client_rewrites_on_the_wire_serves_the_nonce(path: str):
    spec = planting_specs.spec_of(planting_specs.IP_LITERAL, path)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, planting_specs.IP_LITERAL, path)

    assert body == spec.nonces["endpoint-1"]


@pytest.mark.parametrize(
    ("host", "has_network"),
    [("meta.fict", False), ("meta.fict", True), ("localhost", False)],
    ids=["reserved_block_add_host", "bridge_alias", "localhost"],
)
def test_a_name_host_serves_its_nonce_read_by_name(host: str, has_network: bool):
    spec = planting_specs.spec_of(host, "/fict/secret", has_network=has_network)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, host, "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


@pytest.mark.parametrize("has_network", [False, True], ids=["no_network", "network"])
def test_a_file_place_beside_a_name_host_still_serves_its_nonce(has_network: bool):
    spec = planting_specs.spec_of(
        "meta.fict", "/fict/secret", has_network=has_network, file_at="/etc/fict"
    )

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, "meta.fict", "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


def test_a_file_place_over_etc_hosts_beside_a_name_host_fails_the_probe(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr("evals.cve.planting_docker._SENTINEL_PROBE_BUDGET", 3.0)
    spec = planting_specs.spec_of("meta.fict", "/fict/secret", file_at="/etc/hosts")

    with pytest.raises(PlantingFailed), planted(spec, SENTINEL_IMAGE, DockerPlanting()):
        pass


def test_a_file_place_over_resolv_conf_beside_a_bridge_alias_fails_the_probe(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr("evals.cve.planting_docker._SENTINEL_PROBE_BUDGET", 3.0)
    spec = planting_specs.spec_of(
        "meta.fict", "/fict/secret", has_network=True, file_at="/etc/resolv.conf"
    )

    with pytest.raises(PlantingFailed), planted(spec, SENTINEL_IMAGE, DockerPlanting()):
        pass


def test_a_one_sentinel_launch_tears_down_well_under_the_sigterm_grace():
    spec = planting_specs.spec_of(planting_specs.IP_LITERAL, "/fict/secret")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        assert given.read_as_target(args, planting_specs.IP_LITERAL, "/fict/secret")
        start = time.monotonic()
    teardown = time.monotonic() - start

    assert teardown < 8.0  # `docker rm -f`, never the 10 s `docker stop` SIGTERM grace


def test_no_labelled_container_or_network_outlives_two_launches():
    docker = recording_planting.RecordingPlanting()

    for suffix in ("/fict/one", "/fict/two"):
        spec = planting_specs.spec_of(planting_specs.IP_LITERAL, suffix, has_network=True)
        with planted(spec, SENTINEL_IMAGE, docker) as args:
            assert (
                given.read_as_target(args, planting_specs.IP_LITERAL, suffix)
                == spec.nonces["endpoint-1"]
            )

    recording_planting.nothing_it_made_outlives(docker)


@pytest.mark.parametrize("with_an_account", [False, True], ids=["unprivileged", "planted"])
def test_work_starts_empty_takes_a_file_and_names_no_nonce_as_its_owner(with_an_account: bool):
    spec = planting_specs.a_work_spec(with_an_account=with_an_account)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        observed = given.work_as_target(args)

    assert observed.at_start == ""
    assert observed.created
    assert not any(nonce in observed.listing for nonce in spec.nonces.values())
    assert "nobody" in observed.listing


def test_a_probe_killed_past_its_run_timeout_leaves_no_container(monkeypatch: pytest.MonkeyPatch):
    # Below `wget`'s 5 s bound, above a container's start-up of about 2.5 s.
    monkeypatch.setattr(planting_docker, "_PROBE_RUN_TIMEOUT", 4.0)

    with given.a_listener_that_accepts_and_never_answers() as listener:
        server_args, label = given.labelled_probe_args(listener.network)
        body = planting_docker._probe_read(server_args, f"http://{listener.name}/")

        assert body is None
        then.no_container_carries(label)
