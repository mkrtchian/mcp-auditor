"""The containers the nuisance gate leaves running are swept at its end, even when it raises."""

from pathlib import Path

import pytest

import tests.unit.nuisance.gate.support.nuisance_gate_sessions as sessions
from evals.cve.nuisance.gate.gate_session import run_gate
from evals.cve.nuisance.images import image_tag
from tests.fakes import FakeContainerSweep
from tests.unit.support.admission_mutations import on_the_ckan_backend
from tests.unit.support.nuisance_docker_hosts import DockerHost


async def test_the_gate_removes_the_server_and_built_backend_containers_left_running(
    tmp_path: Path,
):
    server = on_the_ckan_backend(sessions.FILESYSTEM)
    host = DockerHost({image_tag(server.service): ["leftover_server"]})
    audit = sessions.scripted({server.server_package: sessions.clean_runs()})

    await run_gate(sessions.options([server]), sessions.a_harness(tmp_path, audit, containers=host))

    assert "leftover_server" in host.removed
    assert "ckan_started" in host.removed


async def test_a_gate_that_raises_still_removes_the_containers_left_running(tmp_path: Path):
    containers = FakeContainerSweep(["leftover_server"])

    with pytest.raises(AssertionError, match="unscripted audit"):
        await run_gate(
            sessions.options([sessions.FILESYSTEM]),
            sessions.a_harness(tmp_path, sessions.scripted({}), containers=containers),
        )

    assert containers.removed == ["leftover_server"]
