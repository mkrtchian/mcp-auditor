"""One gated run of the detection suite (ADR 024): a no-LLM pre-run check of every target, then
the runs of the targets it passed, the gate and the retests of fallen gated targets, with git,
Docker, the clock and the baseline directory injected. A target the check fails is not audited,
reads not_run with its out-of-calibration reasons, and leaves the gate not comparable (ADR 030).
The value objects live in session_model, the baseline recording in session_recording."""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

from evals.cve.detection.baseline import DetectionBaseline, fixture_fingerprint
from evals.cve.detection.gate import (
    DetectionGateResult,
    TargetCandidate,
    TargetComparison,
    TargetOutcome,
    apply_retests,
    compare_target,
    condition_mismatches,
    decide,
    depends_on_unchecked,
    exit_code,
)
from evals.cve.detection.session_model import (
    DetectionAudit,
    DetectionHarness,
    DetectionOptions,
    GatedSession,
    GradedAudit,
    TargetRuns,
)
from evals.cve.detection.session_recording import (
    WrittenBaseline,
    load_checked,
    record,
    recording_tree,
)
from evals.cve.detection.targets import Target
from evals.cve_grammar import DETECTION_RUNGS, RunGrade
from evals.cve_places import Places
from evals.eval_session import RECORDING_REFUSED, REFUSED_BEFORE_ANY_LLM_CALL, Refused
from evals.recording import RecordingRefused


@dataclass(frozen=True)
class DetectionSessionResult:
    grades: dict[str, list[RunGrade]]  # the completed runs of each target, for the report
    audits: list[DetectionAudit]  # the completed main runs, never a retest
    gate: DetectionGateResult | None  # None under --no-baseline
    not_run: dict[str, list[str]]  # target to its out-of-calibration reasons, every mode
    orphans: list[str]  # baseline files of targets no longer benchmarked
    written: list[WrittenBaseline]
    recording_refused: list[str]  # why a recording was refused once the runs were paid for
    exit_code: int


async def run_gated(options: DetectionOptions, harness: DetectionHarness) -> DetectionSessionResult:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    session = _open(options, harness)
    not_run = await _checked(session)
    runs = await _run_targets(session, not_run)
    gate = None if options.no_baseline else await _gate(session, runs, not_run)
    recorded = record(session, runs, gate) if gate is not None else []
    refused = isinstance(recorded, RecordingRefused)
    grades = {target_runs.target.flaw_id: target_runs.grades for target_runs in runs}
    grades.update({flaw_id: [] for flaw_id in not_run})
    return DetectionSessionResult(
        grades=grades,
        audits=[audit for target_runs in runs for audit in target_runs.audits],
        gate=gate,
        not_run=not_run,
        orphans=session.orphans(),
        written=[] if refused else recorded,
        recording_refused=recorded.reasons if refused else [],
        exit_code=0 if gate is None else exit_code(gate.outcome),
    )


async def _checked(session: GatedSession) -> dict[str, list[str]]:
    """The pre-run check gathered over every target, before any audit. A configuration error it
    raises propagates out of the gather, so the run crashes (exit 4) before any audit instead of
    reading a target not_run. Under --record-baseline a failing target refuses the recording."""
    targets = session.options.targets
    reasons = await asyncio.gather(*(session.harness.check(target) for target in targets))
    not_run = {
        target.flaw_id: target_reasons
        for target, target_reasons in zip(targets, reasons, strict=True)
        if target_reasons
    }
    _refuse_recording_of_not_run(session, not_run)
    return not_run


def _refuse_recording_of_not_run(session: GatedSession, not_run: dict[str, list[str]]) -> None:
    if not session.options.record_baseline or not not_run:
        return
    refusals = [
        f"{flaw_id}: {reason}" for flaw_id, reasons in not_run.items() for reason in reasons
    ]
    raise Refused(RECORDING_REFUSED, refusals)


def _open(options: DetectionOptions, harness: DetectionHarness) -> GatedSession:
    files = load_checked(harness.baselines, REFUSED_BEFORE_ANY_LLM_CALL)
    session = GatedSession(options, harness, files, tree=None)
    if not options.record_baseline:
        return session
    return GatedSession(options, harness, files, tree=recording_tree(session))


async def _run_targets(session: GatedSession, not_run: dict[str, list[str]]) -> list[TargetRuns]:
    count = session.options.conditions.runs
    targets = [t for t in session.options.targets if t.flaw_id not in not_run]
    session.harness.announce_audits(len(targets) * count)
    # gather keeps submission order, so each target's runs keep the order of a sequence.
    outcomes = await asyncio.gather(
        *(session.harness.audit(target) for target in targets for _ in range(count))
    )
    return [
        _target_runs(target, outcomes[index * count : (index + 1) * count])
        for index, target in enumerate(targets)
    ]


def _target_runs(target: Target, outcomes: Sequence[GradedAudit | None]) -> TargetRuns:
    audits = [
        DetectionAudit(target.flaw_id, run_index, outcome.report)
        for run_index, outcome in enumerate(outcomes)
        if outcome is not None
    ]
    grades = [outcome.grade for outcome in outcomes if outcome is not None]
    # A target with no run is never complete: an empty candidate would read as held.
    completed = bool(grades) and len(grades) == len(outcomes)
    return TargetRuns(target, grades, completed, audits)


async def _gate(
    session: GatedSession, runs: list[TargetRuns], not_run: dict[str, list[str]]
) -> DetectionGateResult:
    baselines = session.baselines()
    mismatches = condition_mismatches(baselines, session.options.conditions)
    places = session.harness.places
    audited = [
        compare_target(baselines.get(tr.target.flaw_id), _candidate(tr, places)) for tr in runs
    ]
    if not mismatches:
        audited = list(
            await asyncio.gather(
                *(_with_retests(c, tr.target, session) for c, tr in zip(audited, runs, strict=True))
            )
        )
    by_id = {tr.target.flaw_id: comparison for tr, comparison in zip(runs, audited, strict=True)}
    comparisons = [
        _not_run_comparison(target.flaw_id, not_run[target.flaw_id], baselines.get(target.flaw_id))
        if target.flaw_id in not_run
        else by_id[target.flaw_id]
        for target in session.options.targets
    ]
    return decide(comparisons, mismatches)


def _not_run_comparison(
    flaw_id: str, reasons: list[str], baseline: DetectionBaseline | None
) -> TargetComparison:
    return TargetComparison(
        flaw_id=flaw_id,
        outcome=TargetOutcome.NOT_RUN,
        candidate_runs=[],
        baseline_runs=[] if baseline is None else baseline.runs,
        detail=", ".join(reasons),
    )


async def _with_retests(
    comparison: TargetComparison, target: Target, session: GatedSession
) -> TargetComparison:
    baseline = session.baselines().get(target.flaw_id)
    if baseline is None:
        return comparison
    return await _retested(comparison, target, baseline, session.harness)


def _candidate(target_runs: TargetRuns, places: Places) -> TargetCandidate:
    return TargetCandidate(
        flaw_id=target_runs.target.flaw_id,
        fixture_fingerprint=fixture_fingerprint(target_runs.target, places),
        runs=[grade.status for grade in target_runs.grades],
        completed=target_runs.completed,
        depends_on_unchecked=any(depends_on_unchecked(grade) for grade in target_runs.grades),
    )


async def _retested(
    comparison: TargetComparison,
    target: Target,
    baseline: DetectionBaseline,
    harness: DetectionHarness,
) -> TargetComparison:
    """One audit at a time, until the retest rule decides or a retest does not complete. A retest
    whose status depends on unchecked credits ends the retests as UNCHECKED_DECIDES, not as a
    reproduced or cleared miss (ADR 030)."""
    retests: list[bool | None] = []
    retested = comparison
    while retested.outcome == TargetOutcome.PENDING_RETEST:
        audit = await harness.audit(target)
        if audit is not None and depends_on_unchecked(audit.grade):
            return comparison.model_copy(
                update={
                    "outcome": TargetOutcome.UNCHECKED_DECIDES,
                    "detail": "a retest's status rests on credits the replay could not check",
                }
            )
        retests.append(None if audit is None else audit.grade.status not in DETECTION_RUNGS)
        retested = apply_retests(comparison, retests, baseline.retest_rule)
    return retested
