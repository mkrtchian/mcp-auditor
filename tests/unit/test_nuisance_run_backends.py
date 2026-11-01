"""The built backend images of a nuisance run: rebuilt with the server images, their running
containers replaced at the start and swept at the end. Pulled backends are left alone. No Docker,
no LLM."""

import pytest

import tests.unit.support.test_nuisance_run_backends_given as given
import tests.unit.support.test_nuisance_run_given as run_given
from evals.eval_session import Refused


@pytest.fixture(autouse=True)
def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


async def test_the_rebuild_builds_the_backend_service_with_the_server_service():
    server = given.a_server_on("ckan")
    host = given.DockerHost()

    await run_given.run([server], given.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched", "ckan-responder"]


async def test_a_backend_container_running_at_start_is_removed_before_the_rebuild():
    server = given.a_server_on("ckan")
    host = given.DockerHost({given.CKAN_TAG: ["stale_responder"]})

    result = await run_given.run([server], given.deps_on(host, server))

    assert "stale_responder" in host.removed
    assert "stale_responder" not in host.running_at_rebuild
    assert [entry.server_package for entry in result.servers] == [server.server_package]


async def test_a_server_container_running_at_start_still_refuses_and_nothing_is_removed():
    server = given.a_server_on("ckan")
    host = given.DockerHost(
        {given.SERVER_TAG: ["leftover_server"], given.CKAN_TAG: ["stale_responder"]}
    )

    with pytest.raises(Refused) as refused:
        await run_given.run([server], given.deps_on(host, server))

    assert any("leftover_server" in reason for reason in refused.value.reasons)
    assert host.rebuilt == []
    assert host.removed == []


async def test_the_backend_container_started_during_the_run_is_removed_at_its_end():
    server = given.a_server_on("ckan")
    host = given.DockerHost()

    await run_given.run([server], given.deps_on(host, server))

    assert host.removed == ["ckan_started"]


async def test_a_pulled_backend_is_neither_rebuilt_refused_nor_swept():
    server = given.a_server_on("doris")
    host = given.DockerHost({given.DORIS_TAG: ["doris_cluster"]})

    await run_given.run([server], given.deps_on(host, server))

    assert host.rebuilt == ["filesystem-patched"]
    assert host.removed == []
