from evals.baseline import BaselineStatus, RecordingRef
from evals.cve_baseline import CVERunConditions, CVETargetBaseline
from evals.cve_gate import TargetCandidate, TargetComparison, TargetOutcome
from evals.cve_grammar import CVEStatus
from evals.gate import ReplayRule

CVE_ID = "CVE-2025-53355"
FIXTURE = "fixture"
RECORDED_COMMIT = "0123abc"

DETECTED = CVEStatus.DETECTED
EXECUTION_ONLY = CVEStatus.DETECTED_EXECUTION_ONLY
MISSED = CVEStatus.MISSED


def conditions(budget: int = 10) -> CVERunConditions:
    return CVERunConditions(
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


def a_gated_baseline(cve_id: str = CVE_ID) -> CVETargetBaseline:
    return a_confirmed_baseline([DETECTED] * 6, cve_id)


def a_confirmed_baseline(runs: list[CVEStatus], cve_id: str = CVE_ID) -> CVETargetBaseline:
    first = RecordingRef(commit=RECORDED_COMMIT, recorded_at="2026-09-28T09:00:00+00:00")
    return an_exploratory_baseline(runs, cve_id).model_copy(
        update={"status": BaselineStatus.CONFIRMED, "confirms": first}
    )


def an_exploratory_baseline(
    runs: list[CVEStatus] | None = None, cve_id: str = CVE_ID
) -> CVETargetBaseline:
    return CVETargetBaseline(
        cve_id=cve_id,
        status=BaselineStatus.EXPLORATORY,
        conditions=conditions(),
        fixture_fingerprint=FIXTURE,
        replay_rule=ReplayRule(),
        commit=RECORDED_COMMIT,
        recorded_at="2026-09-28T10:00:00+00:00",
        runs=runs if runs is not None else [DETECTED] * 3,
        image_ids={"kubernetes": "sha256:0123"},
    )


def a_candidate(
    runs: list[CVEStatus] | None = None,
    fixture: str = FIXTURE,
    completed: bool = True,
    cve_id: str = CVE_ID,
) -> TargetCandidate:
    return TargetCandidate(
        cve_id=cve_id,
        fixture_fingerprint=fixture,
        runs=runs if runs is not None else [DETECTED] * 3,
        completed=completed,
    )


def a_comparison(outcome: TargetOutcome, cve_id: str = CVE_ID) -> TargetComparison:
    return TargetComparison(cve_id=cve_id, outcome=outcome, candidate_runs=[DETECTED] * 3)
