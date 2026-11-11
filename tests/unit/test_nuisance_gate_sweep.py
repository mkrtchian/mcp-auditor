"""The containers the nuisance gate leaves running are swept at its end, even when it raises."""

from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_gate_session_given as given
from evals.cve.nuisance.backend_registry import built_backend_tags
from evals.cve.nuisance.gate_session import run_gate
from evals.cve.nuisance.images import image_tag
from tests.fakes import FakeContainerSweep
from tests.unit.support.test_nuisance_admission_edits_given import on_the_ckan_backend


async def test_the_gate_removes_the_server_and_built_backend_containers_left_running(
    tmp_path: Path,
):
    server = on_the_ckan_backend(given.FILESYSTEM)
    # The first listing is the built backend containers the gate removes at its start.
    containers = FakeContainerSweep([], ["leftover_server", "leftover_responder"])
    audit = given.scripted({server.server_package: given.clean_runs()})

    await run_gate(given.options([server]), given.a_harness(tmp_path, audit, containers=containers))

    assert containers.removed == ["leftover_server", "leftover_responder"]
    assert containers.listed_tags[-1] == [image_tag(server.service), *built_backend_tags([server])]


async def test_a_gate_that_raises_still_removes_the_containers_left_running(tmp_path: Path):
    containers = FakeContainerSweep(["leftover_server"])

    with pytest.raises(AssertionError, match="unscripted audit"):
        await run_gate(
            given.options([given.FILESYSTEM]),
            given.a_harness(tmp_path, given.scripted({}), containers=containers),
        )

    assert containers.removed == ["leftover_server"]
