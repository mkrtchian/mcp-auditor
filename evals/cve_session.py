"""One gated CVE benchmark run (ADR 024): the runs, the gate and the replays of fallen gated
targets, with git, Docker, the clock and the baseline directory injected. The value objects
live in cve_session_model, the baseline recording in cve_session_recording."""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

from evals.cve_baseline import CVETargetBaseline, fixture_fingerprint
from evals.cve_gate import (
    CVEGateResult,
    TargetCandidate,
    TargetComparison,
    TargetOutcome,
    compare_target,
    condition_mismatches,
    exit_code,
    judge,
    settle,
)
from evals.cve_grammar import DETECTION_RUNGS, RunGrade
from evals.cve_session_model import (
    CVEAudit,
    CVEHarness,
    CVEOptions,
    GatedSession,
    GradedAudit,
    TargetRuns,
)
from evals.cve_session_recording import WrittenBaseline, load_checked, record, recording_tree
from evals.cve_targets import CVETarget
from evals.eval_session import REFUSED_BEFORE_ANY_LLM_CALL
from evals.recording import RecordingRefused


@dataclass(frozen=True)
class CVESessionResult:
    grades: dict[str, list[RunGrade]]  # the completed runs of each target, for the report
    audits: list[CVEAudit]  # the completed main runs, never a replay
    gate: CVEGateResult | None  # None under --ungated
    orphans: list[str]  # baseline files of targets no longer benchmarked
    written: list[WrittenBaseline]
    recording_refused: list[str]  # why a recording was refused once the runs were paid for
    exit_code: int


async def run_gated(options: CVEOptions, harness: CVEHarness) -> CVESessionResult:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    session = _open(options, harness)
    runs = await _run_targets(session)
    gate = None if options.ungated else await _gate(session, runs)
    recorded = record(session, runs, gate) if gate is not None else []
    refused = isinstance(recorded, RecordingRefused)
    return CVESessionResult(
        grades={target_runs.target.cve_id: target_runs.grades for target_runs in runs},
        audits=[audit for target_runs in runs for audit in target_runs.audits],
        gate=gate,
        orphans=session.orphans(),
        written=[] if refused else recorded,
        recording_refused=recorded.reasons if refused else [],
        exit_code=0 if gate is None else exit_code(gate.verdict),
    )


def _open(options: CVEOptions, harness: CVEHarness) -> GatedSession:
    files = load_checked(harness.baselines, REFUSED_BEFORE_ANY_LLM_CALL)
    session = GatedSession(options, harness, files, tree=None)
    if not options.record_baseline:
        return session
    return GatedSession(options, harness, files, tree=recording_tree(session))


async def _run_targets(session: GatedSession) -> list[TargetRuns]:
    count = session.options.conditions.runs
    targets = session.options.targets
    # gather keeps submission order, so each target's runs keep the order of a sequence.
    outcomes = await asyncio.gather(
        *(session.harness.audit(target) for target in targets for _ in range(count))
    )
    return [
        _target_runs(target, outcomes[index * count : (index + 1) * count])
        for index, target in enumerate(targets)
    ]


def _target_runs(target: CVETarget, outcomes: Sequence[GradedAudit | None]) -> TargetRuns:
    audits = [
        CVEAudit(target.cve_id, run_index, outcome.report)
        for run_index, outcome in enumerate(outcomes)
        if outcome is not None
    ]
    grades = [outcome.grade for outcome in outcomes if outcome is not None]
    # A target with no run is never complete: an empty candidate would read as held.
    completed = bool(grades) and len(grades) == len(outcomes)
    return TargetRuns(target, grades, completed, audits)


async def _gate(session: GatedSession, runs: list[TargetRuns]) -> CVEGateResult:
    baselines = session.baselines()
    mismatches = condition_mismatches(baselines, session.options.conditions)
    comparisons = [
        compare_target(baselines.get(target_runs.target.cve_id), _candidate(target_runs))
        for target_runs in runs
    ]
    if not mismatches:
        comparisons = await asyncio.gather(
            *(
                _settled(comparison, target_runs.target, session)
                for comparison, target_runs in zip(comparisons, runs, strict=True)
            )
        )
    return judge(comparisons, mismatches)


async def _settled(
    comparison: TargetComparison, target: CVETarget, session: GatedSession
) -> TargetComparison:
    baseline = session.baselines().get(target.cve_id)
    if baseline is None:
        return comparison
    return await _replayed(comparison, target, baseline, session.harness)


def _candidate(target_runs: TargetRuns) -> TargetCandidate:
    return TargetCandidate(
        cve_id=target_runs.target.cve_id,
        fixture_fingerprint=fixture_fingerprint(target_runs.target),
        runs=[grade.status for grade in target_runs.grades],
        completed=target_runs.completed,
    )


async def _replayed(
    comparison: TargetComparison,
    target: CVETarget,
    baseline: CVETargetBaseline,
    harness: CVEHarness,
) -> TargetComparison:
    """One audit at a time, until the replay rule decides or a replay does not complete."""
    replays: list[bool | None] = []
    settled = comparison
    while settled.outcome == TargetOutcome.PENDING_REPLAY:
        audit = await harness.audit(target)
        replays.append(None if audit is None else audit.grade.status not in DETECTION_RUNGS)
        settled = settle(comparison, replays, baseline.replay_rule)
    return settled
