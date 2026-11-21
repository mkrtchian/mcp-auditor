"""The container hygiene of a holdout run: a container of the run's images running before or
after the rebuild refuses the run, and the containers left at its end are removed, even when
it raises. No Docker, no LLM."""

import dataclasses

import pytest

from evals.cve.detection.holdout_results import RunInterrupted
from evals.cve.provider_errors import ProviderFatal
from evals.eval_session import Refused, TreeState
from tests.fakes import FakeContainerSweep
from tests.unit.support import holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, KUBERNETES


async def test_a_container_of_the_run_images_running_at_start_refuses_before_the_rebuild():
    deps = dataclasses.replace(
        holdout_runs.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        running_containers=FakeContainerSweep.running_before_the_rebuild(
            "leftover_filesystem"
        ).running,
    )

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([holdout_runs.a_target(FILESYSTEM)], deps)

    assert any("leftover_filesystem" in reason for reason in refused.value.reasons)


async def test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    target = holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep.appearing_after_the_rebuild("concurrent_filesystem")
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({target.flaw_id: []}), containers=containers
    )

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([target], deps)

    assert any("concurrent_filesystem" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_the_containers_left_running_at_the_end_are_removed():
    target = holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep.left_at_the_end("stuck_one", "stuck_two")
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({target.flaw_id: holdout_runs.three_detections()}),
        containers=containers,
    )

    await holdout_runs.run([target], deps)

    assert containers.removed == ["stuck_one", "stuck_two"]


async def test_no_container_left_at_the_end_removes_and_prints_nothing(
    capsys: pytest.CaptureFixture[str],
):
    target = holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep()
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({target.flaw_id: holdout_runs.three_detections()}),
        containers=containers,
    )

    await holdout_runs.run([target], deps)

    assert containers.removed == []
    assert capsys.readouterr().out == ""


async def test_the_sweep_runs_when_an_audit_raises():
    target = holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep.left_at_the_end("stuck_one")

    async def audit(_target: object) -> holdout_runs.Outcome:
        raise ProviderFatal(PermissionError("the key was revoked"))

    with pytest.raises(RunInterrupted):
        await holdout_runs.run([target], holdout_runs.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one"]


async def test_the_sweep_runs_when_no_target_survives():
    unfit = holdout_runs.a_target(KUBERNETES)
    containers = FakeContainerSweep.left_at_the_end("stuck_one")
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({unfit.flaw_id: []}),
        check={unfit.flaw_id: ["vulnerable: no exploit surfaces"]},
        containers=containers,
    )

    with pytest.raises(Refused, match="no target survived"):
        await holdout_runs.run([unfit], deps)

    assert containers.removed == ["stuck_one"]


async def test_the_containers_are_looked_up_by_the_run_image_tags_only():
    target = holdout_runs.a_target(backend_images=("apache/doris:all-in-one-4.1.3",))
    containers = FakeContainerSweep()
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({target.flaw_id: holdout_runs.three_detections()}),
        containers=containers,
    )

    await holdout_runs.run([target], deps)

    run_tags = ["mcp-auditor-cve-filesystem:local", "mcp-auditor-cve-filesystem-patched:local"]
    assert containers.listed_tags and all(tags == run_tags for tags in containers.listed_tags)
