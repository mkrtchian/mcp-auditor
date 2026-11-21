"""The container hygiene of a detection holdout run: a container of the run's images running before
or after the rebuild refuses the run, and the containers left at its end are removed, even when
it raises. No Docker, no LLM."""

import dataclasses

import pytest

from evals.cve.detection.holdout_results import RunInterrupted
from evals.cve.provider_errors import ProviderFatal
from evals.eval_session import Refused, TreeState
from tests.fakes import FakeContainerSweep
from tests.unit.support import detection_holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, KUBERNETES


async def test_a_container_of_the_run_images_running_at_start_refuses_before_the_rebuild():
    deps = dataclasses.replace(
        detection_holdout_runs.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        running_containers=FakeContainerSweep.running_before_the_rebuild(
            "leftover_filesystem"
        ).running,
    )

    with pytest.raises(Refused) as refused:
        await detection_holdout_runs.run([detection_holdout_runs.a_target(FILESYSTEM)], deps)

    assert any("leftover_filesystem" in reason for reason in refused.value.reasons)


async def test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    target = detection_holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep.appearing_after_the_rebuild("concurrent_filesystem")
    deps = detection_holdout_runs.deps_auditing(
        detection_holdout_runs.scripted({target.flaw_id: []}), containers=containers
    )

    with pytest.raises(Refused) as refused:
        await detection_holdout_runs.run([target], deps)

    assert any("concurrent_filesystem" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_the_containers_left_running_at_the_end_are_removed():
    target = detection_holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep.left_at_the_end("stuck_one", "stuck_two")
    deps = detection_holdout_runs.deps_auditing(
        detection_holdout_runs.scripted(
            {target.flaw_id: detection_holdout_runs.three_detections()}
        ),
        containers=containers,
    )

    await detection_holdout_runs.run([target], deps)

    assert containers.removed == ["stuck_one", "stuck_two"]


async def test_no_container_left_at_the_end_removes_and_prints_nothing(
    capsys: pytest.CaptureFixture[str],
):
    target = detection_holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep()
    deps = detection_holdout_runs.deps_auditing(
        detection_holdout_runs.scripted(
            {target.flaw_id: detection_holdout_runs.three_detections()}
        ),
        containers=containers,
    )

    await detection_holdout_runs.run([target], deps)

    assert containers.removed == []
    assert capsys.readouterr().out == ""


async def test_the_sweep_runs_when_an_audit_raises():
    target = detection_holdout_runs.a_target(FILESYSTEM)
    containers = FakeContainerSweep.left_at_the_end("stuck_one")

    async def audit(_target: object) -> detection_holdout_runs.Outcome:
        raise ProviderFatal(PermissionError("the key was revoked"))

    with pytest.raises(RunInterrupted):
        await detection_holdout_runs.run(
            [target], detection_holdout_runs.deps_auditing(audit, containers=containers)
        )

    assert containers.removed == ["stuck_one"]


async def test_the_sweep_runs_when_no_target_survives():
    unfit = detection_holdout_runs.a_target(KUBERNETES)
    containers = FakeContainerSweep.left_at_the_end("stuck_one")
    deps = detection_holdout_runs.deps_auditing(
        detection_holdout_runs.scripted({unfit.flaw_id: []}),
        check={unfit.flaw_id: ["vulnerable: no exploit surfaces"]},
        containers=containers,
    )

    with pytest.raises(Refused, match="no target survived"):
        await detection_holdout_runs.run([unfit], deps)

    assert containers.removed == ["stuck_one"]


async def test_the_containers_are_looked_up_by_the_run_image_tags_only():
    target = detection_holdout_runs.a_target(backend_images=("apache/doris:all-in-one-4.1.3",))
    containers = FakeContainerSweep()
    deps = detection_holdout_runs.deps_auditing(
        detection_holdout_runs.scripted(
            {target.flaw_id: detection_holdout_runs.three_detections()}
        ),
        containers=containers,
    )

    await detection_holdout_runs.run([target], deps)

    run_tags = ["mcp-auditor-cve-filesystem:local", "mcp-auditor-cve-filesystem-patched:local"]
    assert containers.listed_tags and all(tags == run_tags for tags in containers.listed_tags)
