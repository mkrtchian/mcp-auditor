from evals.baseline import BaselineStatus, RecordingRef
from evals.cve.detection.baseline import DetectionBaseline, DetectionRunConditions
from evals.cve.detection.gate import TargetCandidate, TargetComparison, TargetOutcome
from evals.cve_grammar import CVEStatus
from evals.gate import RetestRule

CVE_ID = "CVE-2025-53355"
FIXTURE = "fixture"
RECORDED_COMMIT = "0123abc"

DETECTED = CVEStatus.DETECTED
MISSED = CVEStatus.MISSED


def conditions(budget: int = 10) -> DetectionRunConditions:
    return DetectionRunConditions(
        runs=3,
        budget=budget,
        tools_filtered=True,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        grammar_fingerprint="grammar",
    )


def a_gated_baseline(flaw_id: str = CVE_ID) -> DetectionBaseline:
    return a_confirmed_baseline([DETECTED] * 6, flaw_id)


def a_confirmed_baseline(runs: list[CVEStatus], flaw_id: str = CVE_ID) -> DetectionBaseline:
    first = RecordingRef(commit=RECORDED_COMMIT, recorded_at="2026-09-28T09:00:00+00:00")
    return an_unconfirmed_baseline(runs, flaw_id).model_copy(
        update={"status": BaselineStatus.CONFIRMED, "confirms": first}
    )


def an_unconfirmed_baseline(
    runs: list[CVEStatus] | None = None, flaw_id: str = CVE_ID
) -> DetectionBaseline:
    return DetectionBaseline(
        flaw_id=flaw_id,
        status=BaselineStatus.UNCONFIRMED,
        conditions=conditions(),
        fixture_fingerprint=FIXTURE,
        retest_rule=RetestRule(),
        commit=RECORDED_COMMIT,
        recorded_at="2026-09-28T10:00:00+00:00",
        runs=runs if runs is not None else [DETECTED] * 3,
        image_ids={"kubernetes": "sha256:0123"},
    )


def a_candidate(
    runs: list[CVEStatus] | None = None,
    fixture: str = FIXTURE,
    completed: bool = True,
    flaw_id: str = CVE_ID,
    depends_on_unchecked: bool = False,
) -> TargetCandidate:
    return TargetCandidate(
        flaw_id=flaw_id,
        fixture_fingerprint=fixture,
        runs=runs if runs is not None else [DETECTED] * 3,
        completed=completed,
        depends_on_unchecked=depends_on_unchecked,
    )


def a_comparison(outcome: TargetOutcome, flaw_id: str = CVE_ID) -> TargetComparison:
    return TargetComparison(flaw_id=flaw_id, outcome=outcome, candidate_runs=[DETECTED] * 3)
