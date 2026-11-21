from pathlib import Path

import pytest

from evals.baseline import BaselineStatus
from evals.cve.detection.baseline import load_baselines
from evals.cve.detection.session import run_gated
from evals.eval_session import Refused, TreeState
from evals.gate_outcome import GateOutcome
from tests.unit.detection.support.detection_sessions import (
    BROKEN_LAYOUT,
    COMMIT,
    KUBERNETES,
    SYMLINK,
    ScriptedAudit,
    ScriptedCheck,
    ScriptedLayout,
    a_gated_file,
    a_harness,
    a_miss,
    an_unchecked_detected_grade,
    options,
)


async def test_a_layout_failure_refuses_a_recording_before_any_audit(tmp_path: Path):
    layout = ScriptedLayout({KUBERNETES.flaw_id: BROKEN_LAYOUT})
    audit = ScriptedAudit()

    with pytest.raises(Refused) as refusal:
        await run_gated(options(record_baseline=True), a_harness(audit, tmp_path, layout=layout))

    assert audit.calls == []
    assert any(KUBERNETES.flaw_id in reason for reason in refusal.value.reasons)


async def test_a_recording_with_an_unchecked_dependent_run_is_refused(tmp_path: Path):
    audit = ScriptedAudit({KUBERNETES.flaw_id: [an_unchecked_detected_grade()] * 3})

    result = await run_gated(options(record_baseline=True), a_harness(audit, tmp_path))

    assert result.written == []
    assert any(KUBERNETES.flaw_id in reason for reason in result.recording_refused)
    assert not list(tmp_path.glob("*.json"))


async def test_a_failing_check_refuses_a_recording_before_any_audit(tmp_path: Path):
    check = ScriptedCheck({KUBERNETES.flaw_id: ["keeps no place"]})
    audit = ScriptedAudit()

    with pytest.raises(Refused) as refusal:
        await run_gated(options(record_baseline=True), a_harness(audit, tmp_path, check=check))

    assert audit.calls == []
    assert any("keeps no place" in reason for reason in refusal.value.reasons)


async def test_a_second_recording_at_the_same_commit_confirms_one_file_per_target(tmp_path: Path):
    targets = [KUBERNETES, SYMLINK]
    recording = options(targets=targets, record_baseline=True)

    first = await run_gated(recording, a_harness(ScriptedAudit(), tmp_path))
    second = await run_gated(recording, a_harness(ScriptedAudit(), tmp_path))

    assert [written.status for written in first.written] == [BaselineStatus.UNCONFIRMED] * 2
    assert [written.status for written in second.written] == [BaselineStatus.CONFIRMED] * 2
    files = load_baselines(tmp_path)
    assert sorted(files) == sorted(target.flaw_id for target in targets)
    assert all(len(baseline.runs) == 6 for baseline in files.values())


async def test_a_recording_records_the_patched_image_id_beside_the_server_image(tmp_path: Path):
    recording = options(record_baseline=True)

    await run_gated(recording, a_harness(ScriptedAudit(), tmp_path))

    baseline = load_baselines(tmp_path)[KUBERNETES.flaw_id]
    assert KUBERNETES.patched_image in baseline.image_ids
    assert KUBERNETES.server_image in baseline.image_ids


async def test_a_recording_refused_after_the_runs_still_returns_the_graded_runs(tmp_path: Path):
    a_gated_file(tmp_path)
    audit = ScriptedAudit({KUBERNETES.flaw_id: [a_miss()] * 7})
    before = (tmp_path / f"{KUBERNETES.flaw_id}.json").read_text()

    result = await run_gated(options(record_baseline=True), a_harness(audit, tmp_path))

    assert result.recording_refused != []
    assert result.written == []
    assert len(result.grades[KUBERNETES.flaw_id]) == 3
    assert result.gate is not None
    assert result.gate.outcome == GateOutcome.RED
    assert (tmp_path / f"{KUBERNETES.flaw_id}.json").read_text() == before


async def test_a_dirty_tree_refuses_a_recording_before_any_audit(tmp_path: Path):
    audit = ScriptedAudit()
    dirty = TreeState(commit=COMMIT, dirty=True)

    with pytest.raises(Refused):
        await run_gated(options(record_baseline=True), a_harness(audit, tmp_path, dirty))

    assert audit.calls == []
