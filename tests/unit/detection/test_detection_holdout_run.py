"""The holdout orchestrator, with the audit and the two no-LLM checks injected as fakes: the
per-target assembly, the in-run drops, the refused-run accounting and the up-front refusals.
No Docker, no LLM."""

import dataclasses

import pytest

import tests.unit.detection.support.test_detection_holdout_run_given as given
from evals.cve.detection.holdout_audit import DroppedRun, IncompleteRun
from evals.cve.detection.holdout_results import NotRunCause
from evals.cve.detection.replay import ReplayAttemptFailure, UncheckedReason
from evals.cve.detection.session_model import GradedAudit
from evals.cve.grammar import FlawClass, TargetStatus
from evals.cve.server_health import ServerHealth
from evals.eval_session import Refused, TreeState
from evals.probe.analysis import call_cost
from mcp_auditor.domain.models import MissCause, ProviderUsage
from tests.unit.support import detection_holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, KUBERNETES


async def test_a_target_is_assembled_from_its_runs():
    target = detection_holdout_runs.a_target(KUBERNETES)  # command_execution, NORMAL
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    judge = ProviderUsage(input_tokens=100, output_tokens=200)
    report = detection_holdout_runs.a_report(provider, judge)
    outcomes: list[detection_holdout_runs.Outcome] = [
        detection_holdout_runs.graded(
            TargetStatus.DETECTED, report, surfaced_places=frozenset({"etc-shadow"}), aimed=True
        ),
        detection_holdout_runs.graded(
            TargetStatus.DETECTED,
            report,
            surfaced_places=frozenset({"etc-shadow"}),
            unchecked_places=frozenset({"etc-shadow"}),
            status_if_unchecked_missed=TargetStatus.MISSED,
            aimed=True,
        ),
        detection_holdout_runs.graded(
            TargetStatus.MISSED, report, aimed=True, fail_without_proof=True
        ),
    ]
    audit = detection_holdout_runs.scripted({target.flaw_id: outcomes})

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

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
    assert assembled.run_cost == pytest.approx(
        3 * call_cost(provider, detection_holdout_runs.LUNA_PRICE)
    )


async def test_a_union_target_is_assembled_with_its_class_labels_sorted():
    target = detection_holdout_runs.a_target(
        classes=frozenset({FlawClass.READ_OUTSIDE_SCOPE, FlawClass.COMMAND_EXECUTION})
    )
    audit = detection_holdout_runs.scripted(
        {target.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.class_labels == ("command_execution", "read_outside_scope")


async def test_a_target_records_its_backend_images_beside_its_services():
    target = detection_holdout_runs.a_target(backend_images=("apache/doris:all-in-one-4.1.3",))
    audit = detection_holdout_runs.scripted(
        {target.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

    assert result.image_ids == {
        "filesystem": "sha256:filesystem",
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_an_incomplete_run_counts_as_not_detected_and_is_billed():
    target = detection_holdout_runs.a_target(KUBERNETES)
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    refused_report = detection_holdout_runs.a_report(provider, ProviderUsage())
    outcomes: list[detection_holdout_runs.Outcome] = [
        detection_holdout_runs.graded(
            TargetStatus.DETECTED,
            detection_holdout_runs.a_report(provider, ProviderUsage()),
            aimed=True,
        ),
        IncompleteRun(refused_report),
        IncompleteRun(refused_report),
    ]
    audit = detection_holdout_runs.scripted({target.flaw_id: outcomes})

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.detected_runs == 1
    assert assembled.incomplete_runs == 2
    assert result.incomplete_run_count == 2
    assert assembled.run_cost == pytest.approx(
        3 * call_cost(provider, detection_holdout_runs.LUNA_PRICE)
    )


async def test_each_run_status_carries_the_relaunches_calls_not_sent_and_cut_responses():
    target = detection_holdout_runs.a_target(KUBERNETES)
    detection = detection_holdout_runs.graded(
        TargetStatus.DETECTED, detection_holdout_runs.a_report(ProviderUsage(), ProviderUsage())
    )
    relaunched = dataclasses.replace(
        detection,
        health=ServerHealth(
            non_protocol_lines=0,
            lost_connection_responses=0,
            relaunches=1,
            unsent_calls=4,
            cut_responses=2,
        ),
    )
    refused = IncompleteRun(
        given.a_report_missing(MissCause.PROVIDER_REFUSAL),
        ServerHealth(
            non_protocol_lines=0, lost_connection_responses=0, relaunches=2, cut_responses=1
        ),
    )
    audit = detection_holdout_runs.scripted({target.flaw_id: [relaunched, refused, detection]})

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

    (assembled,) = result.targets
    assert [
        (status.relaunches, status.unsent_calls, status.cut_responses)
        for status in assembled.statuses
    ] == [(1, 4, 2), (2, 0, 1), (0, 0, 0)]
    assert (assembled.relaunches, assembled.unsent_calls, assembled.cut_responses) == (3, 4, 3)


async def test_each_run_status_carries_its_server_health_and_its_replay_and_miss_causes():
    target = detection_holdout_runs.a_target(KUBERNETES)
    detection = detection_holdout_runs.graded(
        TargetStatus.DETECTED, detection_holdout_runs.a_report(ProviderUsage(), ProviderUsage())
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
    audit = detection_holdout_runs.scripted({target.flaw_id: [unchecked, refused, detection]})

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

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


async def test_a_target_whose_run_fails_to_launch_is_dropped_for_the_whole_run():
    sick, healthy = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    report = detection_holdout_runs.a_report(ProviderUsage(), ProviderUsage())
    launch_failure = DroppedRun(NotRunCause.LAUNCH_FAILURE)
    sick_outcomes: list[detection_holdout_runs.Outcome] = [
        detection_holdout_runs.graded(TargetStatus.DETECTED, report, aimed=True),
        launch_failure,
        launch_failure,
    ]
    audit = detection_holdout_runs.scripted(
        {sick.flaw_id: sick_outcomes, healthy.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run(
        [sick, healthy], detection_holdout_runs.deps_auditing(audit)
    )

    assert [t.flaw_id for t in result.targets] == [healthy.flaw_id]
    (not_run,) = result.not_run
    assert not_run.flaw_id == sick.flaw_id
    assert not_run.reason == "a run failed to launch after retries"
    assert not_run.cause is NotRunCause.LAUNCH_FAILURE


async def test_a_target_with_any_throttled_run_is_dropped_as_throttled():
    sick, healthy = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    report = detection_holdout_runs.a_report(ProviderUsage(), ProviderUsage())
    sick_outcomes: list[detection_holdout_runs.Outcome] = [
        DroppedRun(NotRunCause.LAUNCH_FAILURE),
        DroppedRun(NotRunCause.THROTTLED),
        detection_holdout_runs.graded(TargetStatus.DETECTED, report, aimed=True),
    ]
    audit = detection_holdout_runs.scripted(
        {sick.flaw_id: sick_outcomes, healthy.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run(
        [sick, healthy], detection_holdout_runs.deps_auditing(audit)
    )

    (not_run,) = result.not_run
    assert not_run.flaw_id == sick.flaw_id
    assert not_run.reason == "throttled by the model provider past every retry"
    assert not_run.cause is NotRunCause.THROTTLED


async def test_a_provider_error_wins_over_a_launch_failure():
    sick, healthy = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    report = detection_holdout_runs.a_report(ProviderUsage(), ProviderUsage())
    sick_outcomes: list[detection_holdout_runs.Outcome] = [
        DroppedRun(NotRunCause.LAUNCH_FAILURE),
        DroppedRun(NotRunCause.PROVIDER_ERROR),
        detection_holdout_runs.graded(TargetStatus.DETECTED, report, aimed=True),
    ]
    audit = detection_holdout_runs.scripted(
        {sick.flaw_id: sick_outcomes, healthy.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run(
        [sick, healthy], detection_holdout_runs.deps_auditing(audit)
    )

    (not_run,) = result.not_run
    assert not_run.reason == "a run hit a provider error past every retry"
    assert not_run.cause is NotRunCause.PROVIDER_ERROR


async def test_the_run_announces_the_audits_of_the_surviving_targets_only():
    unfit, healthy = (
        detection_holdout_runs.a_target(KUBERNETES),
        detection_holdout_runs.a_target(FILESYSTEM),
    )
    audit = detection_holdout_runs.scripted(
        {unfit.flaw_id: [], healthy.flaw_id: detection_holdout_runs.three_detections()}
    )
    announced: list[int] = []
    deps = dataclasses.replace(
        detection_holdout_runs.deps_auditing(
            audit, check={unfit.flaw_id: ["vulnerable: no exploit surfaces"]}
        ),
        announce_audits=announced.append,
    )

    await detection_holdout_runs.run([unfit, healthy], deps, runs=3)

    assert announced == [3]


async def test_the_result_carries_the_concurrency_and_the_throttled_requests():
    target = detection_holdout_runs.a_target(FILESYSTEM)
    audit = detection_holdout_runs.scripted(
        {target.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run(
        [target], detection_holdout_runs.deps_auditing(audit, throttled=7), concurrency=4
    )

    assert result.concurrency == 4
    assert result.throttled_requests == 7


async def test_the_result_carries_the_run_timestamp():
    target = detection_holdout_runs.a_target(FILESYSTEM)
    audit = detection_holdout_runs.scripted(
        {target.flaw_id: detection_holdout_runs.three_detections()}
    )

    result = await detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))

    assert result.recorded_at == detection_holdout_runs.RECORDED_AT


async def test_a_drawn_target_with_a_tools_filter_refuses_before_any_check():
    target = detection_holdout_runs.a_target(
        KUBERNETES, tools_filter=frozenset({"kubectl_generic"})
    )

    with pytest.raises(Refused, match="tools filter"):
        await detection_holdout_runs.run([target], detection_holdout_runs.deps_reaching_nothing())


async def test_tracing_refuses_before_any_container(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "1")

    with pytest.raises(Refused, match="trace"):
        await detection_holdout_runs.run(
            [detection_holdout_runs.a_target(KUBERNETES)],
            detection_holdout_runs.deps_reaching_nothing(),
        )


async def test_a_target_absent_from_the_census_refuses_before_any_dep():
    target = detection_holdout_runs.a_target(KUBERNETES)

    with pytest.raises(Refused, match="census"):
        await detection_holdout_runs.run(
            [target], detection_holdout_runs.deps_reaching_nothing(), dates={}
        )


async def test_a_dirty_tree_refuses_before_rebuild_and_audit():
    deps = dataclasses.replace(
        detection_holdout_runs.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=True),
    )

    with pytest.raises(Refused, match="dirty"):
        await detection_holdout_runs.run([detection_holdout_runs.a_target(KUBERNETES)], deps)


async def test_a_target_with_an_unknown_kept_place_refuses_before_any_dep():
    target = detection_holdout_runs.a_target(KUBERNETES, kept_places=("no-such-place",))

    with pytest.raises(Refused, match="no such place"):
        await detection_holdout_runs.run([target], detection_holdout_runs.deps_reaching_nothing())
