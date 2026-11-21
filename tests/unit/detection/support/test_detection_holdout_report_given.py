import dataclasses

from evals.cve.detection.holdout_results import HoldoutRunResult, HoldoutTargetResult
from tests.unit.detection.support.holdout_report_runs import a_run_result

INCOMPLETE_RUNS = "Incomplete runs (a model call missed: refused, unreadable or too long)"


def a_run_with_incidents() -> HoldoutRunResult:
    run = a_run_result()
    first, second = run.targets
    return dataclasses.replace(
        run, targets=(_with_incidents(first), second), incomplete_run_count=2
    )


def _with_incidents(target: HoldoutTargetResult) -> HoldoutTargetResult:
    unchecked, refused, clean = target.statuses
    return dataclasses.replace(
        target,
        statuses=(
            dataclasses.replace(
                unchecked,
                non_protocol_lines=2,
                lost_connection_responses=1,
                relaunches=1,
                unsent_calls=3,
                cut_responses=1,
                unchecked_reason="no_attempt_decided",
                replay_attempt_failures=["launch_failed", "launch_failed"],
            ),
            dataclasses.replace(
                refused,
                detected=False,
                detected_if_unchecked_missed=False,
                surfaced_places=[],
                incomplete=True,
                missed_call_causes=["provider_refusal", "unreadable_answer"],
            ),
            clean,
        ),
    )
