"""One gated CVE benchmark run (ADR 024): a no-LLM pre-run check of every target, then the runs
of the targets it passed, the gate and the replays of fallen gated targets, with git, Docker, the
clock and the baseline directory injected. A target the check fails is not audited, reads not_run
with its conditions, and leaves the gate not comparable (ADR 030). The value objects live in
cve_session_model, the baseline recording in cve_session_recording."""

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
    depends_on_unchecked,
    exit_code,
    judge,
    settle,
)
from evals.cve_grammar import DETECTION_RUNGS, RunGrade
from evals.cve_places import Places
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
from evals.eval_session import RECORDING_REFUSED, REFUSED_BEFORE_ANY_LLM_CALL, Refused
from evals.recording import RecordingRefused


@dataclass(frozen=True)
class CVESessionResult:
    grades: dict[str, list[RunGrade]]  # the completed runs of each target, for the report
    audits: list[CVEAudit]  # the completed main runs, never a replay
    gate: CVEGateResult | None  # None under --ungated
    not_run: dict[str, list[str]]  # target to the pre-run check's dead conditions, every mode
    orphans: list[str]  # baseline files of targets no longer benchmarked
    written: list[WrittenBaseline]
    recording_refused: list[str]  # why a recording was refused once the runs were paid for
    exit_code: int


async def run_gated(options: CVEOptions, harness: CVEHarness) -> CVESessionResult:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    session = _open(options, harness)
    not_run = await _checked(session)
    runs = await _run_targets(session, not_run)
    gate = None if options.ungated else await _gate(session, runs, not_run)
    recorded = record(session, runs, gate) if gate is not None else []
    refused = isinstance(recorded, RecordingRefused)
    grades = {target_runs.target.cve_id: target_runs.grades for target_runs in runs}
    grades.update({cve_id: [] for cve_id in not_run})
    return CVESessionResult(
        grades=grades,
        audits=[audit for target_runs in runs for audit in target_runs.audits],
        gate=gate,
        not_run=not_run,
        orphans=session.orphans(),
        written=[] if refused else recorded,
        recording_refused=recorded.reasons if refused else [],
        exit_code=0 if gate is None else exit_code(gate.verdict),
    )


async def _checked(session: GatedSession) -> dict[str, list[str]]:
    """The pre-run check gathered over every target, before any audit. A configuration error it
    raises propagates out of the gather, so the run crashes (exit 4) before any audit instead of
    reading a target not_run. Under --record-baseline a failing target refuses the recording."""
    targets = session.options.targets
    conditions = await asyncio.gather(*(session.harness.check(target) for target in targets))
    not_run = {
        target.cve_id: target_conditions
        for target, target_conditions in zip(targets, conditions, strict=True)
        if target_conditions
    }
    _refuse_recording_of_not_run(session, not_run)
    return not_run


def _refuse_recording_of_not_run(session: GatedSession, not_run: dict[str, list[str]]) -> None:
    if not session.options.record_baseline or not not_run:
        return
    reasons = [
        f"{cve_id}: {condition}"
        for cve_id, conditions in not_run.items()
        for condition in conditions
    ]
    raise Refused(RECORDING_REFUSED, reasons)


def _open(options: CVEOptions, harness: CVEHarness) -> GatedSession:
    files = load_checked(harness.baselines, REFUSED_BEFORE_ANY_LLM_CALL)
    session = GatedSession(options, harness, files, tree=None)
    if not options.record_baseline:
        return session
    return GatedSession(options, harness, files, tree=recording_tree(session))


async def _run_targets(session: GatedSession, not_run: dict[str, list[str]]) -> list[TargetRuns]:
    count = session.options.conditions.runs
    targets = [t for t in session.options.targets if t.cve_id not in not_run]
    session.harness.announce_audits(len(targets) * count)
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


async def _gate(
    session: GatedSession, runs: list[TargetRuns], not_run: dict[str, list[str]]
) -> CVEGateResult:
    baselines = session.baselines()
    mismatches = condition_mismatches(baselines, session.options.conditions)
    places = session.harness.places
    audited = [
        compare_target(baselines.get(tr.target.cve_id), _candidate(tr, places)) for tr in runs
    ]
    if not mismatches:
        audited = list(
            await asyncio.gather(
                *(_settled(c, tr.target, session) for c, tr in zip(audited, runs, strict=True))
            )
        )
    by_id = {tr.target.cve_id: comparison for tr, comparison in zip(runs, audited, strict=True)}
    comparisons = [
        _not_run_comparison(target.cve_id, not_run[target.cve_id], baselines.get(target.cve_id))
        if target.cve_id in not_run
        else by_id[target.cve_id]
        for target in session.options.targets
    ]
    return judge(comparisons, mismatches)


def _not_run_comparison(
    cve_id: str, conditions: list[str], baseline: CVETargetBaseline | None
) -> TargetComparison:
    return TargetComparison(
        cve_id=cve_id,
        outcome=TargetOutcome.NOT_RUN,
        candidate_runs=[],
        baseline_runs=[] if baseline is None else baseline.runs,
        detail=", ".join(conditions),
    )


async def _settled(
    comparison: TargetComparison, target: CVETarget, session: GatedSession
) -> TargetComparison:
    baseline = session.baselines().get(target.cve_id)
    if baseline is None:
        return comparison
    return await _replayed(comparison, target, baseline, session.harness)


def _candidate(target_runs: TargetRuns, places: Places) -> TargetCandidate:
    return TargetCandidate(
        cve_id=target_runs.target.cve_id,
        fixture_fingerprint=fixture_fingerprint(target_runs.target, places),
        runs=[grade.status for grade in target_runs.grades],
        completed=target_runs.completed,
        depends_on_unchecked=any(depends_on_unchecked(grade) for grade in target_runs.grades),
    )


async def _replayed(
    comparison: TargetComparison,
    target: CVETarget,
    baseline: CVETargetBaseline,
    harness: CVEHarness,
) -> TargetComparison:
    """One audit at a time, until the replay rule decides or a replay does not complete. A replay
    audit whose status depends on unchecked credits ends the settlement as UNCHECKED_DECIDES, not
    as a reproduced or cleared miss (ADR 030)."""
    replays: list[bool | None] = []
    settled = comparison
    while settled.outcome == TargetOutcome.PENDING_REPLAY:
        audit = await harness.audit(target)
        if audit is not None and depends_on_unchecked(audit.grade):
            return comparison.model_copy(
                update={
                    "outcome": TargetOutcome.UNCHECKED_DECIDES,
                    "detail": "a replay's status rests on credits the replay could not check",
                }
            )
        replays.append(None if audit is None else audit.grade.status not in DETECTION_RUNGS)
        settled = settle(comparison, replays, baseline.replay_rule)
    return settled
