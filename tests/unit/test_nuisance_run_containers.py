"""The images a nuisance run rebuilds: a backend-less server with public names adds the holder's
and the stand-in's images, which the run rebuilds but never sweeps by tag, since the launch
removes its own containers and a calibration may share those images. The removal at the start
also resets the Doris cluster, a pulled backend, by its container name."""

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_run_backends_given as backends_given
import tests.unit.support.test_nuisance_run_given as run_given
from evals.cve_planting_base import (
    SENTINEL_SERVICE,
    STAND_IN_SERVICE,
    PlantingHost,
    PublicNames,
    SymbolicUser,
)
from evals.doris_backend import DORIS_CONTAINER
from evals.nuisance_run_containers import remove_backend_containers, run_images

SERVED = PlantingHost(
    SymbolicUser.UNPRIVILEGED, "/", False, PublicNames(stand_ins=("example.com",))
)


def test_a_backend_less_server_with_public_names_rebuilds_the_holder_and_stand_in_images():
    server = admission_given.with_host(run_given.a_server("npm:served"), SERVED)

    images = run_images([run_given.a_server("npm:plain"), server])

    assert images.backend_services == [SENTINEL_SERVICE, STAND_IN_SERVICE]
    assert images.backend_tags == []


def test_servers_without_public_names_rebuild_no_shared_image():
    images = run_images([run_given.a_server("npm:plain")])

    assert images.backend_services == []


def test_the_stand_in_a_backend_also_builds_is_rebuilt_once():
    ckan = edits.on_the_ckan_backend(run_given.a_server("npm:ckan"))
    served = admission_given.with_host(run_given.a_server("npm:served"), SERVED)

    images = run_images([ckan, served])

    assert images.backend_services.count(STAND_IN_SERVICE) == 1
    assert SENTINEL_SERVICE in images.backend_services


def test_a_gravitino_server_lists_the_three_gravitino_part_images_among_the_backend_tags():
    gravitino = edits.with_the_registered_backend(run_given.a_server("npm:g"), "gravitino")

    images = run_images([gravitino])

    assert {
        "mcp-auditor-cve-gravitino-instance:local",
        "mcp-auditor-cve-gravitino-db:local",
        "mcp-auditor-cve-gravitino-kafka:local",
    } <= set(images.backend_tags)


def test_the_removal_at_start_resets_the_doris_cluster_by_its_name():
    doris = edits.with_the_registered_backend(run_given.a_server("PyPI:d"), "doris")
    docker = backends_given.DockerHost({backends_given.DORIS_TAG: [DORIS_CONTAINER]})

    remove_backend_containers(backends_given.host_of(docker), run_images([doris]))

    assert docker.removed == [DORIS_CONTAINER]


def test_the_removal_at_start_resets_no_container_by_name_for_a_built_backend():
    ckan = edits.on_the_ckan_backend(run_given.a_server("npm:ckan"))
    docker = backends_given.DockerHost({backends_given.CKAN_TAG: ["stale_front"]})

    remove_backend_containers(backends_given.host_of(docker), run_images([ckan]))

    assert docker.removed == ["stale_front"]
