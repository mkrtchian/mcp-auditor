"""Recording the nuisance gate's baseline: what refuses a recording before the paid runs, and the
write of one file per server once the gate has decided, the mirror of
`evals.cve.detection.session_recording`."""

from evals.cve.file_baselines import (
    BASELINE_FILES_CHANGED,
    all_or_none,
    leaves_gated_set,
    load_checked,
)
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.gate.gate import NuisanceGateResult
from evals.cve.nuisance.gate.gate_baseline import (
    NUISANCE_GATE_BASELINE_STORE,
    WHOLE_RESET,
    condition_mismatches,
    write_baseline,
)
from evals.cve.nuisance.gate.gate_recording import ServerRecording, decide_recording
from evals.cve.nuisance.gate.gate_session_model import OpenedGate, ServerRuns, WrittenBaseline
from evals.eval_session import DIRTY_TREE_REFUSAL, RECORDING_REFUSED, Refused, TreeState, tree_drift
from evals.recording import RecordingRefused


def recording_tree(opened: OpenedGate) -> TreeState:
    """What refuses a recording already before the runs, so no paid run is wasted."""
    tree = opened.harness.read_tree()
    reasons = condition_mismatches(opened.baselines(), opened.options.conditions)
    reasons += [WHOLE_RESET] if reasons else []
    if tree.dirty:
        reasons.append(DIRTY_TREE_REFUSAL)
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
    decided = all_or_none(decisions)
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
        files = load_checked(
            opened.harness.baselines, RECORDING_REFUSED, NUISANCE_GATE_BASELINE_STORE
        )
    except Refused as invalid:
        return drift + invalid.reasons
    if files != opened.files:
        drift.append(BASELINE_FILES_CHANGED)
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
            runs=[audit.flagged for audit in server_runs.audits],
            completed=server_runs.completed,
            image_ids={
                **opened.harness.image_ids([server_runs.server.service]),
                **opened.harness.backend_image_ids(
                    server_runs.server.backend.images if server_runs.server.backend else []
                ),
            },
        )
        for server_runs in runs
    }
