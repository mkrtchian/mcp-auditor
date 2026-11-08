"""The built backend images of a nuisance run: rebuilt with the server images, their running
containers replaced at the start and swept at the end. Pulled backends are left alone. No Docker,
no LLM."""

import pytest

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_run_backends_given as given
import tests.unit.support.test_nuisance_run_given as run_given
from evals.cve_planting_base import STAND_IN_IMAGE
from evals.eval_session import Refused


async def test_the_rebuild_builds_the_backend_service_with_the_server_service():
    server = edits.on_the_ckan_backend(run_given.a_server())
    host = given.DockerHost()

    await run_given.run([server], given.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched", *given.CKAN_SERVICES]


async def test_every_built_service_of_the_backend_is_rebuilt():
    server = edits.with_the_registered_backend(run_given.a_server(), "apify")
    host = given.DockerHost()

    await run_given.run([server], given.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched", "apify-responder", "stand-in"]


async def test_a_backend_container_running_at_start_is_removed_before_the_rebuild():
    server = edits.on_the_ckan_backend(run_given.a_server())
    host = given.DockerHost({given.CKAN_TAG: ["stale_responder"]})

    result = await run_given.run([server], given.deps_on(host, server))

    assert "stale_responder" in host.removed
    assert "stale_responder" not in host.running_at_rebuild
    assert [entry.server_package for entry in result.servers] == [server.server_package]


async def test_the_containers_of_every_built_image_of_the_backend_are_removed_before_the_rebuild():
    server = edits.with_the_registered_backend(run_given.a_server(), "apify")
    host = given.DockerHost(
        {given.APIFY_TAG: ["stale_responder"], STAND_IN_IMAGE: ["stale_stand_in"]}
    )

    await run_given.run([server], given.deps_on(host, server))

    assert {"stale_responder", "stale_stand_in"} <= set(host.removed)
    assert host.running_at_rebuild == []


async def test_a_server_container_running_at_start_still_refuses_and_nothing_is_removed():
    server = edits.on_the_ckan_backend(run_given.a_server())
    host = given.DockerHost(
        {given.SERVER_TAG: ["leftover_server"], given.CKAN_TAG: ["stale_responder"]}
    )

    with pytest.raises(Refused) as refused:
        await run_given.run([server], given.deps_on(host, server))

    assert any("leftover_server" in reason for reason in refused.value.reasons)
    assert host.rebuilt == []
    assert host.removed == []


async def test_the_backend_container_started_during_the_run_is_removed_at_its_end():
    server = edits.on_the_ckan_backend(run_given.a_server())
    host = given.DockerHost()

    await run_given.run([server], given.deps_on(host, server))

    assert host.removed == ["ckan_started"]


async def test_a_pulled_backend_is_neither_rebuilt_refused_nor_swept():
    server = edits.with_the_registered_backend(run_given.a_server(), "doris")
    host = given.DockerHost({given.DORIS_TAG: ["doris_cluster"]})

    await run_given.run([server], given.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched"]
    assert host.removed == []
