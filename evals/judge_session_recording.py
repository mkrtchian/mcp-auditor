"""Recording the judge isolation baseline: what refuses a recording before the paid runs, and
the write once the gate has decided."""

from pydantic import ValidationError

from evals.eval_session import TreeState, tree_drift
from evals.judge_baseline import JudgeBaseline, load_judge_baseline, write_judge_baseline
from evals.judge_gate import CaseRuns, JudgeGateResult, judge_ci_condition_mismatches
from evals.judge_recording import (
    JudgeRecording,
    decide_judge_recording,
    judge_condition_refusals,
    judge_exploratory_commit_refusal,
)
from evals.judge_session_model import JudgeSession
from evals.recording import RecordingRefused


def recording_refusals(session: JudgeSession, tree: TreeState) -> list[str]:
    reasons = [
        f"a baseline records the conditions CI runs at, {mismatch}"
        for mismatch in judge_ci_condition_mismatches(session.conditions)
    ]
    if tree.dirty:
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    if session.baseline is not None:
        reasons += judge_exploratory_commit_refusal(session.baseline, tree.commit)
        reasons += judge_condition_refusals(session.baseline, session.conditions)
    return reasons


def record(
    session: JudgeSession, runs: CaseRuns, gate: JudgeGateResult
) -> tuple[JudgeBaseline | None, list[str]]:
    if session.tree is None:
        return None, []
    harness = session.harness
    drift = _recording_drift(session, session.tree)
    if drift:
        return None, drift
    recording = JudgeRecording(
        conditions=session.conditions,
        commit=session.tree.commit,
        recorded_at=harness.clock().isoformat(),
        runs=runs,
        ground_truth=session.ground_truth,
    )
    decision = decide_judge_recording(session.baseline, recording, gate)
    if isinstance(decision, RecordingRefused):
        return None, decision.reasons
    write_judge_baseline(harness.baseline_path, decision)
    return decision, []


def _recording_drift(session: JudgeSession, tree: TreeState) -> list[str]:
    harness = session.harness
    drift = tree_drift(tree, harness.read_tree())
    try:
        reloaded = load_judge_baseline(harness.baseline_path)
    except ValidationError as error:
        return [*drift, f"{harness.baseline_path} is not a valid baseline: {error}"]
    if reloaded != session.baseline:
        drift.append("the baseline file changed during the runs: record again")
    return drift
