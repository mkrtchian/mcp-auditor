"""Recording the CVE benchmark baseline: what refuses a recording before the paid runs, and
the write of one file per target once the gate has decided."""

from dataclasses import dataclass
from pathlib import Path

from evals.baseline import BaselineStatus
from evals.cve_baseline import (
    baseline_integrity,
    fixture_fingerprint,
    load_baselines,
    write_baseline,
)
from evals.cve_gate import WHOLE_RESET, CVEGateResult, condition_mismatches
from evals.cve_recording import (
    TargetRecording,
    decide_recording,
    decide_recordings,
    leaves_gated_set,
)
from evals.cve_session_model import Baselines, GatedSession, TargetRuns
from evals.eval_session import RECORDING_REFUSED, Refused, TreeState, tree_drift
from evals.recording import RecordingRefused


@dataclass(frozen=True)
class WrittenBaseline:
    cve_id: str
    status: BaselineStatus
    leaves_gated_set: bool


def load_checked(directory: Path, title: str) -> Baselines:
    try:
        baselines = load_baselines(directory)
    except ValueError as error:
        raise Refused(title, [f"{directory} holds an invalid baseline file: {error}"]) from error
    problems = [problem for b in baselines.values() for problem in baseline_integrity(b)]
    if problems:
        raise Refused(title, problems)
    return baselines


def recording_tree(session: GatedSession) -> TreeState:
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


def record(
    session: GatedSession, runs: list[TargetRuns], gate: CVEGateResult
) -> list[WrittenBaseline] | RecordingRefused:
    if session.tree is None:
        return []
    drift = _recording_drift(session, session.tree)
    if drift:
        return RecordingRefused(reasons=drift)
    baselines = session.baselines()
    comparisons = {comparison.cve_id: comparison for comparison in gate.targets}
    recordings = _recordings(session, session.tree, runs)
    decisions = {
        cve_id: decide_recording(baselines.get(cve_id), recording, comparisons.get(cve_id))
        for cve_id, recording in recordings.items()
    }
    decided = decide_recordings(decisions)
    if isinstance(decided, RecordingRefused):
        return decided
    for baseline in decided:
        write_baseline(session.harness.baselines, baseline)
    return [
        WrittenBaseline(b.cve_id, b.status, leaves_gated_set(baselines.get(b.cve_id), b))
        for b in decided
    ]


def _recording_drift(session: GatedSession, tree: TreeState) -> list[str]:
    drift = tree_drift(tree, session.harness.read_tree())
    try:
        changed = load_checked(session.harness.baselines, RECORDING_REFUSED) != session.files
    except Refused as invalid:
        return drift + invalid.reasons
    if changed:
        drift.append("the baseline files changed during the runs: record again")
    return drift


def _recordings(
    session: GatedSession, tree: TreeState, runs: list[TargetRuns]
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
