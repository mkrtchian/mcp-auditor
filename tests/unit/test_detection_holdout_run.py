"""The holdout orchestrator, with the audit and the two no-LLM checks injected as fakes: the
per-target assembly, the pre-run drops, the refused-run accounting and the up-front refusals.
No Docker, no LLM."""

import dataclasses

import pytest

import tests.unit.support.test_detection_holdout_pre_run_check_given as pre_run_check
import tests.unit.support.test_detection_holdout_run_given as given
from evals.cve.detection.holdout_audit import DroppedRun, IncompleteRun
from evals.cve.detection.holdout_results import NotRunCause, RunInterrupted
from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.replay import ReplayAttemptFailure, UncheckedReason
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import LaunchMode
from evals.cve.grammar import FlawClass, TargetStatus
from evals.cve.provider_errors import ProviderFatal
from evals.cve.server_health import ServerHealth
from evals.eval_session import Refused, TreeState
from evals.probe.analysis import call_cost
from mcp_auditor.domain.models import MissCause, ProviderUsage
from tests.fakes import FakeContainerSweep


async def test_a_target_is_assembled_from_its_runs():
    target = given.a_target(given.KUBERNETES)  # command_execution, NORMAL
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    judge = ProviderUsage(input_tokens=100, output_tokens=200)
    report = given.a_report(provider, judge)
    outcomes: list[given.Outcome] = [
        given.graded(
            TargetStatus.DETECTED, report, surfaced_places=frozenset({"etc-shadow"}), aimed=True
        ),
        given.graded(
            TargetStatus.DETECTED,
            report,
            surfaced_places=frozenset({"etc-shadow"}),
            unchecked_places=frozenset({"etc-shadow"}),
            status_if_unchecked_missed=TargetStatus.MISSED,
            aimed=True,
        ),
        given.graded(TargetStatus.MISSED, report, aimed=True, fail_without_proof=True),
    ]
    audit = given.scripted({target.flaw_id: outcomes})

    result = await given.run([target], given.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.detected_runs == 2
    assert assembled.detection_share == pytest.approx(2 / 3)
    assert assembled.detected_runs_if_unchecked_missed == 1  # the second run misses if unchecked
    assert assembled.unchecked_places == [[], ["etc-shadow"], []]
    assert assembled.aimed_runs == 3
    assert assembled.fail_without_proof_runs == 1
    assert assembled.incomplete_runs == 0
    assert assembled.tools_count == 1
    assert assembled.class_labels == ("command_execution",)
    assert assembled.run_cost == pytest.approx(3 * call_cost(provider, given.LUNA_PRICE))


async def test_a_union_target_is_assembled_with_its_class_labels_sorted():
    target = given.a_target(
        classes=frozenset({FlawClass.READ_OUTSIDE_SCOPE, FlawClass.COMMAND_EXECUTION})
    )
    audit = given.scripted({target.flaw_id: given.three_detections()})

    result = await given.run([target], given.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.class_labels == ("command_execution", "read_outside_scope")


async def test_a_target_records_its_backend_images_beside_its_services():
    target = given.a_target(backend_images=("apache/doris:all-in-one-4.1.3",))
    audit = given.scripted({target.flaw_id: given.three_detections()})

    result = await given.run([target], given.deps_auditing(audit))

    assert result.image_ids == {
        "filesystem": "sha256:filesystem",
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_an_incomplete_run_counts_as_not_detected_and_is_billed():
    target = given.a_target(given.KUBERNETES)
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    refused_report = given.a_report(provider, ProviderUsage())
    outcomes: list[given.Outcome] = [
        given.graded(TargetStatus.DETECTED, given.a_report(provider, ProviderUsage()), aimed=True),
        IncompleteRun(refused_report),
        IncompleteRun(refused_report),
    ]
    audit = given.scripted({target.flaw_id: outcomes})

    result = await given.run([target], given.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.detected_runs == 1
    assert assembled.incomplete_runs == 2
    assert result.incomplete_run_count == 2
    assert assembled.run_cost == pytest.approx(3 * call_cost(provider, given.LUNA_PRICE))


async def test_each_run_status_carries_its_server_health_and_its_replay_and_miss_causes():
    target = given.a_target(given.KUBERNETES)
    detection = given.graded(
        TargetStatus.DETECTED, given.a_report(ProviderUsage(), ProviderUsage())
    )
    unchecked = GradedAudit(
        detection.grade,
        detection.report,
        ServerHealth(non_protocol_lines=2, lost_connection_responses=1),
        UncheckedReason.NO_ATTEMPT_DECIDED,
        (ReplayAttemptFailure.LAUNCH_FAILED, ReplayAttemptFailure.LOST_CONNECTION),
    )
    refused = IncompleteRun(
        given.a_report_missing(MissCause.UNREADABLE_ANSWER, MissCause.PROVIDER_REFUSAL),
        ServerHealth(non_protocol_lines=0, lost_connection_responses=3),
    )
    audit = given.scripted({target.flaw_id: [unchecked, refused, detection]})

    result = await given.run([target], given.deps_auditing(audit))

    (assembled,) = result.targets
    first, second, third = assembled.statuses
    assert (first.non_protocol_lines, first.lost_connection_responses) == (2, 1)
    assert first.unchecked_reason == "no_attempt_decided"
    assert first.replay_attempt_failures == ["launch_failed", "lost_connection"]
    assert first.missed_call_causes == []
    assert second.missed_call_causes == ["provider_refusal", "unreadable_answer"]
    assert (second.unchecked_reason, second.replay_attempt_failures) == (None, [])
    assert (third.non_protocol_lines, third.lost_connection_responses) == (0, 0)
    assert (assembled.non_protocol_lines, assembled.lost_connection_responses) == (2, 4)
    assert assembled.unchecked_runs_by_reason == {"no_attempt_decided": 1}
    assert assembled.replay_attempt_failures_by_cause == {"launch_failed": 1, "lost_connection": 1}
    assert assembled.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}


async def test_a_target_dead_on_a_version_is_not_run():
    unfit, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    audit = given.scripted({unfit.flaw_id: [], healthy.flaw_id: given.three_detections()})
    deps = given.deps_auditing(
        audit, check={unfit.flaw_id: ["patched: exploit 0 still surfaces etc-shadow"]}
    )

    result = await given.run([unfit, healthy], deps)

    assert [t.flaw_id for t in result.targets] == [healthy.flaw_id]
    (not_run,) = result.not_run
    assert not_run.flaw_id == unfit.flaw_id
    assert "patched: exploit 0 still surfaces etc-shadow" in not_run.reason
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_normal_target_the_layout_breaks_is_dropped():
    broken, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    audit = given.scripted({broken.flaw_id: [], healthy.flaw_id: given.three_detections()})
    deps = given.deps_auditing(
        audit, layout={broken.flaw_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])}
    )

    result = await given.run([broken, healthy], deps)

    assert [t.flaw_id for t in result.targets] == [healthy.flaw_id]
    (not_run,) = result.not_run
    assert not_run.flaw_id == broken.flaw_id
    assert not_run.reason == "the layout breaks the server under the normal launch"
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_fallback_target_the_layout_breaks_is_kept():
    target = given.a_target(given.KUBERNETES, launch_mode=LaunchMode.FALLBACK)
    audit = given.scripted({target.flaw_id: given.three_detections()})
    deps = given.deps_auditing(
        audit, layout={target.flaw_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])}
    )

    result = await given.run([target], deps)

    (assembled,) = result.targets
    assert assembled.ran_in_fallback is True
    assert result.not_run == []


async def test_a_target_clean_on_its_solo_second_pre_run_pass_runs_and_is_named():
    flaky = given.a_target(given.KUBERNETES)
    audit = given.scripted({flaky.flaw_id: given.three_detections()})
    checks = pre_run_check.ScriptedChecks(
        out_of_calibration={flaky.flaw_id: [["vulnerable: exploit 3 surfaces no nonce"], []]}
    )
    deps = dataclasses.replace(given.deps_auditing(audit), check=checks.check, layout=checks.layout)

    result = await given.run([flaky], deps)

    assert [t.flaw_id for t in result.targets] == [flaky.flaw_id]
    assert result.not_run == []
    assert result.second_pass == [flaky.flaw_id]


async def test_a_target_whose_run_fails_to_launch_is_dropped_for_the_whole_run():
    sick, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    report = given.a_report(ProviderUsage(), ProviderUsage())
    launch_failure = DroppedRun(NotRunCause.LAUNCH_FAILURE)
    sick_outcomes: list[given.Outcome] = [
        given.graded(TargetStatus.DETECTED, report, aimed=True),
        launch_failure,
        launch_failure,
    ]
    audit = given.scripted({sick.flaw_id: sick_outcomes, healthy.flaw_id: given.three_detections()})

    result = await given.run([sick, healthy], given.deps_auditing(audit))

    assert [t.flaw_id for t in result.targets] == [healthy.flaw_id]
    (not_run,) = result.not_run
    assert not_run.flaw_id == sick.flaw_id
    assert not_run.reason == "a run failed to launch after retries"
    assert not_run.cause is NotRunCause.LAUNCH_FAILURE


async def test_a_target_with_any_throttled_run_is_dropped_as_throttled():
    sick, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    report = given.a_report(ProviderUsage(), ProviderUsage())
    sick_outcomes: list[given.Outcome] = [
        DroppedRun(NotRunCause.LAUNCH_FAILURE),
        DroppedRun(NotRunCause.THROTTLED),
        given.graded(TargetStatus.DETECTED, report, aimed=True),
    ]
    audit = given.scripted({sick.flaw_id: sick_outcomes, healthy.flaw_id: given.three_detections()})

    result = await given.run([sick, healthy], given.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.flaw_id == sick.flaw_id
    assert not_run.reason == "throttled by the model provider past every retry"
    assert not_run.cause is NotRunCause.THROTTLED


async def test_a_provider_error_wins_over_a_launch_failure():
    sick, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    report = given.a_report(ProviderUsage(), ProviderUsage())
    sick_outcomes: list[given.Outcome] = [
        DroppedRun(NotRunCause.LAUNCH_FAILURE),
        DroppedRun(NotRunCause.PROVIDER_ERROR),
        given.graded(TargetStatus.DETECTED, report, aimed=True),
    ]
    audit = given.scripted({sick.flaw_id: sick_outcomes, healthy.flaw_id: given.three_detections()})

    result = await given.run([sick, healthy], given.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.reason == "a run hit a provider error past every retry"
    assert not_run.cause is NotRunCause.PROVIDER_ERROR


async def test_the_run_announces_the_audits_of_the_surviving_targets_only():
    unfit, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    audit = given.scripted({unfit.flaw_id: [], healthy.flaw_id: given.three_detections()})
    announced: list[int] = []
    deps = dataclasses.replace(
        given.deps_auditing(audit, check={unfit.flaw_id: ["vulnerable: no exploit surfaces"]}),
        announce_audits=announced.append,
    )

    await given.run([unfit, healthy], deps, runs=3)

    assert announced == [3]


async def test_the_result_carries_the_concurrency_and_the_throttled_requests():
    target = given.a_target(given.FILESYSTEM)
    audit = given.scripted({target.flaw_id: given.three_detections()})

    result = await given.run([target], given.deps_auditing(audit, throttled=7), concurrency=4)

    assert result.concurrency == 4
    assert result.throttled_requests == 7


async def test_the_result_carries_the_run_timestamp():
    target = given.a_target(given.FILESYSTEM)
    audit = given.scripted({target.flaw_id: given.three_detections()})

    result = await given.run([target], given.deps_auditing(audit))

    assert result.recorded_at == given.RECORDED_AT


async def test_a_drawn_target_with_a_tools_filter_refuses_before_any_check():
    target = given.a_target(given.KUBERNETES, tools_filter=frozenset({"kubectl_generic"}))

    with pytest.raises(Refused, match="tools filter"):
        await given.run([target], given.deps_reaching_nothing())


async def test_tracing_refuses_before_any_container(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "1")

    with pytest.raises(Refused, match="trace"):
        await given.run([given.a_target(given.KUBERNETES)], given.deps_reaching_nothing())


async def test_a_target_absent_from_the_census_refuses_before_any_dep():
    target = given.a_target(given.KUBERNETES)

    with pytest.raises(Refused, match="census"):
        await given.run([target], given.deps_reaching_nothing(), dates={})


async def test_a_dirty_tree_refuses_before_rebuild_and_audit():
    deps = dataclasses.replace(
        given.deps_reaching_nothing(), read_tree=lambda: TreeState(commit="c0ffee", dirty=True)
    )

    with pytest.raises(Refused, match="dirty"):
        await given.run([given.a_target(given.KUBERNETES)], deps)


async def test_every_target_dropped_refuses_with_the_reasons():
    unfit, broken = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    deps = given.deps_auditing(
        given.scripted({unfit.flaw_id: [], broken.flaw_id: []}),
        check={unfit.flaw_id: ["patched: exploit 0 still surfaces etc-shadow"]},
        layout={broken.flaw_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])},
    )

    with pytest.raises(Refused, match="no target survived") as caught:
        await given.run([unfit, broken], deps)

    reasons = caught.value.reasons
    assert any("etc-shadow" in reason for reason in reasons)
    assert any("the layout breaks" in reason for reason in reasons)


async def test_a_target_with_an_unknown_kept_place_refuses_before_any_dep():
    target = given.a_target(given.KUBERNETES, kept_places=("no-such-place",))

    with pytest.raises(Refused, match="no such place"):
        await given.run([target], given.deps_reaching_nothing())


async def test_a_container_of_the_run_images_running_at_start_refuses_before_the_rebuild():
    deps = dataclasses.replace(
        given.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        running_containers=FakeContainerSweep.running_before_the_rebuild(
            "leftover_filesystem"
        ).running,
    )

    with pytest.raises(Refused) as refused:
        await given.run([given.a_target(given.FILESYSTEM)], deps)

    assert any("leftover_filesystem" in reason for reason in refused.value.reasons)


async def test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    target = given.a_target(given.FILESYSTEM)
    containers = FakeContainerSweep.appearing_after_the_rebuild("concurrent_filesystem")
    deps = given.deps_auditing(given.scripted({target.flaw_id: []}), containers=containers)

    with pytest.raises(Refused) as refused:
        await given.run([target], deps)

    assert any("concurrent_filesystem" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_the_containers_left_running_at_the_end_are_removed():
    target = given.a_target(given.FILESYSTEM)
    containers = FakeContainerSweep.left_at_the_end("stuck_one", "stuck_two")
    deps = given.deps_auditing(
        given.scripted({target.flaw_id: given.three_detections()}), containers=containers
    )

    await given.run([target], deps)

    assert containers.removed == ["stuck_one", "stuck_two"]


async def test_no_container_left_at_the_end_removes_and_prints_nothing(
    capsys: pytest.CaptureFixture[str],
):
    target = given.a_target(given.FILESYSTEM)
    containers = FakeContainerSweep()
    deps = given.deps_auditing(
        given.scripted({target.flaw_id: given.three_detections()}), containers=containers
    )

    await given.run([target], deps)

    assert containers.removed == []
    assert capsys.readouterr().out == ""


async def test_the_sweep_runs_when_an_audit_raises():
    target = given.a_target(given.FILESYSTEM)
    containers = FakeContainerSweep.left_at_the_end("stuck_one")

    async def audit(_target: object) -> given.Outcome:
        raise ProviderFatal(PermissionError("the key was revoked"))

    with pytest.raises(RunInterrupted):
        await given.run([target], given.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one"]


async def test_the_sweep_runs_when_no_target_survives():
    unfit = given.a_target(given.KUBERNETES)
    containers = FakeContainerSweep.left_at_the_end("stuck_one")
    deps = given.deps_auditing(
        given.scripted({unfit.flaw_id: []}),
        check={unfit.flaw_id: ["vulnerable: no exploit surfaces"]},
        containers=containers,
    )

    with pytest.raises(Refused, match="no target survived"):
        await given.run([unfit], deps)

    assert containers.removed == ["stuck_one"]


async def test_the_containers_are_looked_up_by_the_run_image_tags_only():
    target = given.a_target(backend_images=("apache/doris:all-in-one-4.1.3",))
    containers = FakeContainerSweep()
    deps = given.deps_auditing(
        given.scripted({target.flaw_id: given.three_detections()}), containers=containers
    )

    await given.run([target], deps)

    run_tags = ["mcp-auditor-cve-filesystem:local", "mcp-auditor-cve-filesystem-patched:local"]
    assert containers.listed_tags and all(tags == run_tags for tags in containers.listed_tags)
