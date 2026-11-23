"""The containers of the run's images: one running at the start or appearing after the rebuild
refuses the run, and the ones left running at its end are swept, even when it raises."""

import dataclasses

import pytest

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance.admission.admission import BackendFixture
from evals.cve.provider_errors import ProviderFatal
from evals.cve.run_files import RunInterrupted
from evals.eval_session import Refused, TreeState
from tests.fakes import FakeContainerSweep


async def test_a_container_of_the_run_images_running_at_start_refuses_before_the_rebuild():
    containers = FakeContainerSweep.running_before_the_rebuild("leftover_server")
    deps = dataclasses.replace(
        holdout_runs.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        sweep=containers.sweep,
    )

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([holdout_runs.a_server()], deps)

    assert any("leftover_server" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    server = holdout_runs.a_server()
    containers = FakeContainerSweep.appearing_after_the_rebuild("concurrent_server")
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({server.server_package: []}), containers=containers
    )

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([server], deps)

    assert any("concurrent_server" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_the_containers_left_running_at_the_end_are_removed():
    server = holdout_runs.a_server()
    containers = FakeContainerSweep.left_at_the_end("stuck_one", "stuck_two")
    audit = holdout_runs.scripted({server.server_package: holdout_runs.clean_audits()})

    await holdout_runs.run([server], holdout_runs.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one", "stuck_two"]


async def test_no_container_left_at_the_end_removes_and_prints_nothing(
    capsys: pytest.CaptureFixture[str],
):
    server = holdout_runs.a_server()
    containers = FakeContainerSweep()
    audit = holdout_runs.scripted({server.server_package: holdout_runs.clean_audits()})

    await holdout_runs.run([server], holdout_runs.deps_auditing(audit, containers=containers))

    assert containers.removed == []
    assert capsys.readouterr().out == ""


async def test_the_sweep_runs_when_an_audit_raises():
    containers = FakeContainerSweep.left_at_the_end("stuck_one")

    async def audit(_server: object) -> holdout_runs.Outcome:
        raise ProviderFatal(PermissionError("the key was revoked"))

    with pytest.raises(RunInterrupted):
        await holdout_runs.run(
            [holdout_runs.a_server()], holdout_runs.deps_auditing(audit, containers=containers)
        )

    assert containers.removed == ["stuck_one"]


async def test_the_sweep_runs_when_no_server_survives():
    server = holdout_runs.a_server()
    containers = FakeContainerSweep.left_at_the_end("stuck_one")
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({server.server_package: []}),
        benign_call={server.server_package: "benign call errored"},
        containers=containers,
    )

    with pytest.raises(Refused, match="nuisance holdout run refused"):
        await holdout_runs.run([server], deps)

    assert containers.removed == ["stuck_one"]


async def test_the_containers_are_looked_up_by_the_run_image_tags_only():
    server = mutations.with_a_backend(
        holdout_runs.a_server(),
        BackendFixture(
            provisioner="doris", images=["apache/doris:all-in-one-4.1.3"], network="net"
        ),
    )
    containers = FakeContainerSweep()
    audit = holdout_runs.scripted({server.server_package: holdout_runs.clean_audits()})

    await holdout_runs.run([server], holdout_runs.deps_auditing(audit, containers=containers))

    run_tags = ["mcp-auditor-nuisance-filesystem-patched:local"]
    assert containers.listed_tags and all(tags == run_tags for tags in containers.listed_tags)
