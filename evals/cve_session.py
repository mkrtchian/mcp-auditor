"""One gated CVE benchmark run (ADR 024): the runs, the replays of fallen gated targets, and
the recording, with git, Docker, the clock and the baseline directory injected."""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.baseline import BaselineStatus
from evals.cve_baseline import (
    CVERunConditions,
    CVETargetBaseline,
    baseline_integrity,
    fixture_fingerprint,
    load_baselines,
    write_baseline,
)
from evals.cve_gate import (
    WHOLE_RESET,
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
from evals.cve_recording import (
    TargetRecording,
    decide_recording,
    decide_recordings,
    leaves_gated_set,
)
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.eval_session import (
    RECORDING_REFUSED,
    REFUSED_BEFORE_ANY_LLM_CALL,
    Refused,
    TreeState,
    tree_drift,
)
from evals.recording import RecordingRefused

type AuditTarget = Callable[[CVETarget], Awaitable[RunGrade | None]]
"""One audit of one target, None when it did not complete (launch or infra failure)."""

type Baselines = dict[str, CVETargetBaseline]


@dataclass(frozen=True)
class CVEOptions:
    targets: list[CVETarget]  # already filtered by --cve
    conditions: CVERunConditions
    ungated: bool
    record_baseline: bool


@dataclass(frozen=True)
class CVEHarness:
    audit: AuditTarget
    baselines: Path
    read_tree: Callable[[], TreeState]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    clock: Callable[[], str]  # ISO timestamp for recorded_at


@dataclass(frozen=True)
class WrittenBaseline:
    cve_id: str
    status: BaselineStatus
    leaves_gated_set: bool


@dataclass(frozen=True)
class CVESessionResult:
    grades: dict[str, list[RunGrade]]  # the completed runs of each target, for the report
    gate: CVEGateResult | None  # None under --ungated
    orphans: list[str]  # baseline files of targets no longer benchmarked
    written: list[WrittenBaseline]
    exit_code: int


@dataclass(frozen=True)
class _TargetRuns:
    target: CVETarget
    grades: list[RunGrade]
    completed: bool


@dataclass(frozen=True)
class _Session:
    """Fixed before any audit. `tree` is set exactly when the run records."""

    options: CVEOptions
    harness: CVEHarness
    files: Baselines  # every file read at start, orphans included
    tree: TreeState | None

    def baselines(self) -> Baselines:
        return {cve_id: b for cve_id, b in self.files.items() if cve_id in _BENCHMARKED}

    def orphans(self) -> list[str]:
        return [f"{cve_id}.json" for cve_id in sorted(self.files) if cve_id not in _BENCHMARKED]


_BENCHMARKED = frozenset(target.cve_id for target in CVE_TARGETS)


async def run_gated(options: CVEOptions, harness: CVEHarness) -> CVESessionResult:
    """Raises Refused on a run that cannot be compared before it starts, or a refused recording."""
    session = _open(options, harness)
    runs = [await _run_target(target, session) for target in options.targets]
    gate = None if options.ungated else await _gate(session, runs)
    written = _record(session, runs, gate) if gate is not None else []
    return CVESessionResult(
        grades={target_runs.target.cve_id: target_runs.grades for target_runs in runs},
        gate=gate,
        orphans=session.orphans(),
        written=written,
        exit_code=0 if gate is None else exit_code(gate.verdict),
    )


def _open(options: CVEOptions, harness: CVEHarness) -> _Session:
    files = _load_checked(harness.baselines, REFUSED_BEFORE_ANY_LLM_CALL)
    session = _Session(options, harness, files, tree=None)
    if not options.record_baseline:
        return session
    return _Session(options, harness, files, tree=_recording_tree(session))


def _load_checked(directory: Path, title: str) -> Baselines:
    try:
        baselines = load_baselines(directory)
    except ValueError as error:
        raise Refused(title, [f"{directory} holds an invalid baseline file: {error}"]) from error
    problems = [problem for b in baselines.values() for problem in baseline_integrity(b)]
    if problems:
        raise Refused(title, problems)
    return baselines


def _recording_tree(session: _Session) -> TreeState:
    """What refuses a recording already before the runs, so no paid run is wasted."""
    if session.options.ungated:
        reason = (
            "--record-baseline cannot run --ungated: a baseline records the conditions it gates"
        )
        raise Refused(RECORDING_REFUSED, [reason])
    tree = session.harness.read_tree()
    reasons = condition_mismatches(session.baselines(), session.options.conditions)
    reasons += [WHOLE_RESET] if reasons else []
    if tree.dirty:
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    if reasons:
        raise Refused(RECORDING_REFUSED, reasons)
    return tree


async def _run_target(target: CVETarget, session: _Session) -> _TargetRuns:
    runs = session.options.conditions.runs
    outcomes = [await session.harness.audit(target) for _ in range(runs)]
    grades = [grade for grade in outcomes if grade is not None]
    # A target with no run is never complete: an empty candidate would read as held.
    return _TargetRuns(target, grades, completed=bool(grades) and len(grades) == runs)


async def _gate(session: _Session, runs: list[_TargetRuns]) -> CVEGateResult:
    baselines = session.baselines()
    mismatches = condition_mismatches(baselines, session.options.conditions)
    comparisons: list[TargetComparison] = []
    for target_runs in runs:
        baseline = baselines.get(target_runs.target.cve_id)
        comparison = compare_target(baseline, _candidate(target_runs))
        if baseline is not None and not mismatches:
            comparison = await _replayed(comparison, target_runs.target, baseline, session.harness)
        comparisons.append(comparison)
    return judge(comparisons, mismatches)


def _candidate(target_runs: _TargetRuns) -> TargetCandidate:
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
        grade = await harness.audit(target)
        replays.append(None if grade is None else grade.status not in DETECTION_RUNGS)
        settled = settle(comparison, replays, baseline.replay_rule)
    return settled


def _record(
    session: _Session, runs: list[_TargetRuns], gate: CVEGateResult
) -> list[WrittenBaseline]:
    if session.tree is None:
        return []
    drift = _recording_drift(session, session.tree)
    if drift:
        raise Refused(RECORDING_REFUSED, drift)
    baselines = session.baselines()
    comparisons = {comparison.cve_id: comparison for comparison in gate.targets}
    recordings = _recordings(session, session.tree, runs)
    decisions = {
        cve_id: decide_recording(baselines.get(cve_id), recording, comparisons.get(cve_id))
        for cve_id, recording in recordings.items()
    }
    decided = decide_recordings(decisions)
    if isinstance(decided, RecordingRefused):
        raise Refused(RECORDING_REFUSED, decided.reasons)
    for baseline in decided:
        write_baseline(session.harness.baselines, baseline)
    return [
        WrittenBaseline(b.cve_id, b.status, leaves_gated_set(baselines.get(b.cve_id), b))
        for b in decided
    ]


def _recording_drift(session: _Session, tree: TreeState) -> list[str]:
    drift = tree_drift(tree, session.harness.read_tree())
    if _load_checked(session.harness.baselines, RECORDING_REFUSED) != session.files:
        drift.append("the baseline files changed during the runs: record again")
    return drift


def _recordings(
    session: _Session, tree: TreeState, runs: list[_TargetRuns]
) -> dict[str, TargetRecording]:
    recorded_at = session.harness.clock()
    return {
        target_runs.target.cve_id: TargetRecording(
            cve_id=target_runs.target.cve_id,
            conditions=session.options.conditions,
            fixture_fingerprint=fixture_fingerprint(target_runs.target),
            commit=tree.commit,
            recorded_at=recorded_at,
            runs=[grade.status for grade in target_runs.grades],
            completed=target_runs.completed,
            image_ids=session.harness.image_ids(target_runs.target.images),
        )
        for target_runs in runs
    }
