"""The built backend images of a nuisance holdout run: rebuilt with the server images, their running
containers replaced at the start and swept at the end. The pulled Doris cluster is removed by
name at the start, never rebuilt nor swept. No Docker, no LLM."""

import pytest

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_docker_hosts as docker_hosts
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.backends.doris import DORIS_CONTAINER
from evals.cve.planting_base import STAND_IN_IMAGE
from evals.eval_session import Refused


async def test_the_rebuild_builds_the_backend_service_with_the_server_service():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost()

    await holdout_runs.run([server], docker_hosts.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched", *docker_hosts.CKAN_SERVICES]


async def test_a_backend_container_running_at_start_is_removed_before_the_rebuild():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost({docker_hosts.CKAN_TAG: ["stale_responder"]})

    result = await holdout_runs.run([server], docker_hosts.deps_on(host, server))

    assert "stale_responder" in host.removed
    assert "stale_responder" not in host.running_at_rebuild
    assert [entry.server_package for entry in result.servers] == [server.server_package]


async def test_the_containers_of_every_built_image_of_the_backend_are_removed_before_the_rebuild():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost(
        {docker_hosts.CKAN_TAG: ["stale_responder"], STAND_IN_IMAGE: ["stale_stand_in"]}
    )

    await holdout_runs.run([server], docker_hosts.deps_on(host, server))

    assert {"stale_responder", "stale_stand_in"} <= set(host.removed)
    assert host.running_at_rebuild == []


async def test_a_server_container_running_at_start_still_refuses_and_nothing_is_removed():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost(
        {docker_hosts.SERVER_TAG: ["leftover_server"], docker_hosts.CKAN_TAG: ["stale_responder"]}
    )

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([server], docker_hosts.deps_on(host, server))

    assert any("leftover_server" in reason for reason in refused.value.reasons)
    assert host.rebuilt == []
    assert host.removed == []


async def test_the_backend_container_started_during_the_run_is_removed_at_its_end():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost()

    await holdout_runs.run([server], docker_hosts.deps_on(host, server))

    assert host.removed == ["ckan_started"]


async def test_a_pulled_backend_is_removed_at_start_but_neither_rebuilt_nor_swept():
    server = mutations.with_the_registered_backend(holdout_runs.a_server(), "doris")
    host = docker_hosts.DockerHost({docker_hosts.DORIS_TAG: [DORIS_CONTAINER]})

    await holdout_runs.run([server], docker_hosts.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched"]
    assert host.removed == [DORIS_CONTAINER]
    assert host.running([docker_hosts.DORIS_TAG]) == ["doris_started"]
