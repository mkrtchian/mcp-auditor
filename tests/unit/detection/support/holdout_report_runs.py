from datetime import date

from evals.cve.detection.holdout_results import (
    DetectionHoldoutRunResult,
    DetectionHoldoutRunStatus,
    HoldoutTargetResult,
    NotRunCause,
    NotRunTarget,
)
from evals.cve.holdout_conditions import Cutoff

LUNA_CUTOFF = Cutoff(
    date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
)
RUNS = 3
RECORDED_AT = "2026-10-28T09:30:00+00:00"


def a_target_result(
    flaw_id: str, *, disclosure_date: date, detected_runs: int, incomplete_runs: int = 0
) -> HoldoutTargetResult:
    return HoldoutTargetResult(
        flaw_id=flaw_id,
        disclosure_date=disclosure_date,
        class_labels=("command_execution", "read_outside_scope"),
        tools_count=5,
        ran_in_fallback=False,
        statuses=tuple(
            DetectionHoldoutRunStatus(
                detected=index < detected_runs,
                detected_if_unchecked_missed=index < detected_runs,
                surfaced_places=["srv_config"] if index < detected_runs else [],
                struck_places=[],
                unchecked_places=[],
                aimed=index < detected_runs,
                fail_without_proof=False,
                incomplete=index >= RUNS - incomplete_runs,
                non_protocol_lines=0,
                lost_connection_responses=0,
                relaunches=0,
                unsent_calls=0,
                cut_responses=0,
                unchecked_reason=None,
                replay_attempt_failures=[],
                missed_call_causes=["provider_refusal"] if index >= RUNS - incomplete_runs else [],
            )
            for index in range(RUNS)
        ),
        run_cost=0.02,
    )


def a_run_result() -> DetectionHoldoutRunResult:
    targets = [
        a_target_result("CVE-A", disclosure_date=date(2026, 1, 1), detected_runs=3),
        a_target_result(
            "CVE-B", disclosure_date=date(2026, 12, 1), detected_runs=1, incomplete_runs=1
        ),
    ]
    return DetectionHoldoutRunResult(
        runs=RUNS,
        budget=10,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        cutoffs={"gpt-6-luna": LUNA_CUTOFF},
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        grammar_fingerprint="grammar-abc",
        fixture_fingerprints={"CVE-A": "fa", "CVE-B": "fb"},
        commit="deadbeef",
        census_commit="cafe1234",
        image_ids={"vuln": "sha256:1"},
        recorded_at=RECORDED_AT,
        targets=tuple(targets),
        not_run=(
            NotRunTarget(
                flaw_id="CVE-C",
                reason="out of calibration: patched: exploit 0 surfaces",
                cause=NotRunCause.PRE_RUN_CHECK,
            ),
        ),
        incomplete_run_count=1,
        total_cost=0.06,
        prices_as_of=date(2026, 10, 15),
        concurrency=6,
        throttled_requests=0,
    )
