"""The containers of the run's images: one running at the start or appearing after the rebuild
refuses the run, and the ones left running at its end are swept, even when it raises."""

import dataclasses

import pytest

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_run_given as given
from evals.cve.nuisance.results import RunInterrupted
from evals.cve.provider_errors import ProviderFatal
from evals.eval_session import Refused, TreeState
from evals.nuisance_admission import BackendFixture
from tests.fakes import FakeContainerSweep


async def test_a_container_of_the_run_images_running_at_start_refuses_before_the_rebuild():
    deps = dataclasses.replace(
        given.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        running_containers=FakeContainerSweep.running_before_the_rebuild("leftover_server").running,
    )

    with pytest.raises(Refused) as refused:
        await given.run([given.a_server()], deps)

    assert any("leftover_server" in reason for reason in refused.value.reasons)


async def test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    server = given.a_server()
    containers = FakeContainerSweep.appearing_after_the_rebuild("concurrent_server")
    deps = given.deps_auditing(given.scripted({server.server_package: []}), containers=containers)

    with pytest.raises(Refused) as refused:
        await given.run([server], deps)

    assert any("concurrent_server" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_the_containers_left_running_at_the_end_are_removed():
    server = given.a_server()
    containers = FakeContainerSweep.left_at_the_end("stuck_one", "stuck_two")
    audit = given.scripted({server.server_package: [given.an_audit(False) for _ in range(3)]})

    await given.run([server], given.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one", "stuck_two"]


async def test_no_container_left_at_the_end_removes_and_prints_nothing(
    capsys: pytest.CaptureFixture[str],
):
    server = given.a_server()
    containers = FakeContainerSweep()
    audit = given.scripted({server.server_package: [given.an_audit(False) for _ in range(3)]})

    await given.run([server], given.deps_auditing(audit, containers=containers))

    assert containers.removed == []
    assert capsys.readouterr().out == ""


async def test_the_sweep_runs_when_an_audit_raises():
    containers = FakeContainerSweep.left_at_the_end("stuck_one")

    async def audit(_server: object) -> given.Outcome:
        raise ProviderFatal(PermissionError("the key was revoked"))

    with pytest.raises(RunInterrupted):
        await given.run([given.a_server()], given.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one"]


async def test_the_sweep_runs_when_no_server_survives():
    server = given.a_server()
    containers = FakeContainerSweep.left_at_the_end("stuck_one")
    deps = given.deps_auditing(
        given.scripted({server.server_package: []}),
        benign_call={server.server_package: "benign call errored"},
        containers=containers,
    )

    with pytest.raises(Refused, match="nuisance run refused"):
        await given.run([server], deps)

    assert containers.removed == ["stuck_one"]


async def test_the_containers_are_looked_up_by_the_run_image_tags_only():
    server = admission.with_a_backend(
        given.a_server(),
        BackendFixture(provisioner="doris", image="apache/doris:all-in-one-4.1.3", network="net"),
    )
    containers = FakeContainerSweep()
    audit = given.scripted({server.server_package: [given.an_audit(False) for _ in range(3)]})

    await given.run([server], given.deps_auditing(audit, containers=containers))

    run_tags = ["mcp-auditor-nuisance-filesystem-patched:local"]
    assert containers.listed_tags and all(tags == run_tags for tags in containers.listed_tags)
