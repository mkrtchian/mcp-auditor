"""Recording the nuisance gate's baseline: what refuses a recording before the paid runs, and the
write of one file per server once the gate has decided, the mirror of `cve_session_recording`."""

from pathlib import Path

from evals.eval_session import RECORDING_REFUSED, Refused, TreeState, tree_drift
from evals.nuisance_gate import NuisanceGateResult
from evals.nuisance_gate_baseline import (
    WHOLE_RESET,
    baseline_integrity,
    condition_mismatches,
    load_baselines,
    write_baseline,
)
from evals.nuisance_gate_recording import (
    ServerRecording,
    decide_recording,
    decide_recordings,
    leaves_gated_set,
)
from evals.nuisance_gate_session_model import Baselines, OpenedGate, ServerRuns, WrittenBaseline
from evals.nuisance_images import nuisance_fixture_fingerprint
from evals.recording import RecordingRefused


def load_checked(directory: Path, title: str) -> Baselines:
    try:
        baselines = load_baselines(directory)
    except ValueError as error:
        raise Refused(title, [f"{directory} holds an invalid baseline file: {error}"]) from error
    problems = [problem for b in baselines.values() for problem in baseline_integrity(b)]
    if problems:
        raise Refused(title, problems)
    return baselines


def recording_tree(opened: OpenedGate) -> TreeState:
    """What refuses a recording already before the runs, so no paid run is wasted."""
    tree = opened.harness.read_tree()
    reasons = condition_mismatches(opened.baselines(), opened.options.conditions)
    reasons += [WHOLE_RESET] if reasons else []
    if tree.dirty:
        reasons.append("the git tree has tracked modifications: record from a clean tree")
    if reasons:
        raise Refused(RECORDING_REFUSED, reasons)
    return tree


def record(
    opened: OpenedGate, runs: list[ServerRuns], gate: NuisanceGateResult
) -> list[WrittenBaseline] | RecordingRefused:
    if opened.tree is None:
        return []
    drift = _recording_drift(opened, opened.tree)
    if drift:
        return RecordingRefused(reasons=drift)
    baselines = opened.baselines()
    comparisons = {comparison.server_package: comparison for comparison in gate.servers}
    decisions = {
        package: decide_recording(baselines.get(package), recording, comparisons.get(package))
        for package, recording in _recordings(opened, opened.tree, runs).items()
    }
    decided = decide_recordings(decisions)
    if isinstance(decided, RecordingRefused):
        return decided
    for baseline in decided:
        write_baseline(opened.harness.baselines, baseline)
    return [
        WrittenBaseline(
            b.server_package, b.status, leaves_gated_set(baselines.get(b.server_package), b)
        )
        for b in decided
    ]


def _recording_drift(opened: OpenedGate, tree: TreeState) -> list[str]:
    drift = tree_drift(tree, opened.harness.read_tree())
    try:
        changed = load_checked(opened.harness.baselines, RECORDING_REFUSED) != opened.files
    except Refused as invalid:
        return drift + invalid.reasons
    if changed:
        drift.append("the baseline files changed during the runs: record again")
    return drift


def _recordings(
    opened: OpenedGate, tree: TreeState, runs: list[ServerRuns]
) -> dict[str, ServerRecording]:
    recorded_at = opened.harness.clock()
    return {
        server_runs.server.server_package: ServerRecording(
            server_package=server_runs.server.server_package,
            conditions=opened.options.conditions,
            fixture_fingerprint=nuisance_fixture_fingerprint(server_runs.server),
            commit=tree.commit,
            recorded_at=recorded_at,
            runs=[run.flagged for run in server_runs.runs],
            completed=server_runs.completed,
            image_ids=opened.harness.image_ids([server_runs.server.service]),
        )
        for server_runs in runs
    }
