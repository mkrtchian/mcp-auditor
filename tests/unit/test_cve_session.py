from pathlib import Path

import pytest

import tests.unit.support.test_cve_session_given as given
from evals.baseline import BaselineStatus
from evals.cve_baseline import load_baselines
from evals.cve_gate import CVEGateVerdict, TargetOutcome
from evals.cve_session import run_gated
from evals.eval_session import Refused, TreeState


async def test_a_gated_target_missed_once_is_replayed_until_the_miss_is_decided(tmp_path: Path):
    given.a_gated_file(tmp_path)
    miss = given.a_miss()
    audit = given.ScriptedAudit(
        {given.KUBERNETES.cve_id: [miss, given.a_detected_grade(), miss, *[miss] * 5]}
    )

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    assert result.gate is not None
    [comparison] = result.gate.targets
    assert comparison.outcome == TargetOutcome.REGRESSION
    assert comparison.replays == [True, True, True, True]
    assert result.gate.verdict == CVEGateVerdict.RED
    assert result.exit_code == 1


async def test_a_miss_cleared_twice_stops_the_replays_and_keeps_the_gate_green(tmp_path: Path):
    given.a_gated_file(tmp_path)
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_miss()]})

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    assert result.gate is not None
    [comparison] = result.gate.targets
    assert comparison.outcome == TargetOutcome.MISS_NOT_REPRODUCED
    assert comparison.replays == [False, False]
    assert result.exit_code == 0


async def test_no_replay_runs_when_the_conditions_differ_from_the_files(tmp_path: Path):
    given.a_gated_file(tmp_path, budget=20)
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_miss()]})

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    assert result.gate is not None
    assert result.gate.targets[0].replays == []
    assert result.gate.verdict == CVEGateVerdict.NOT_COMPARABLE
    assert result.exit_code == 3


async def test_a_replay_that_does_not_complete_makes_the_run_not_comparable(tmp_path: Path):
    given.a_gated_file(tmp_path)
    miss = given.a_miss()
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [miss, miss, miss, None]})

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    assert result.gate is not None
    assert result.gate.targets[0].outcome == TargetOutcome.INCOMPLETE
    assert result.gate.verdict == CVEGateVerdict.NOT_COMPARABLE


async def test_an_ungated_run_compares_nothing_and_exits_zero(tmp_path: Path):
    given.a_gated_file(tmp_path)
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_miss()]})

    result = await run_gated(given.options(ungated=True), given.a_harness(audit, tmp_path))

    assert result.gate is None
    assert result.exit_code == 0
    assert len(result.grades[given.KUBERNETES.cve_id]) == 3


async def test_a_second_recording_at_the_same_commit_confirms_one_file_per_target(tmp_path: Path):
    targets = [given.KUBERNETES, given.SYMLINK]
    recording = given.options(targets=targets, record_baseline=True)

    first = await run_gated(recording, given.a_harness(given.ScriptedAudit(), tmp_path))
    second = await run_gated(recording, given.a_harness(given.ScriptedAudit(), tmp_path))

    assert [written.status for written in first.written] == [BaselineStatus.EXPLORATORY] * 2
    assert [written.status for written in second.written] == [BaselineStatus.CONFIRMED] * 2
    files = load_baselines(tmp_path)
    assert sorted(files) == sorted(target.cve_id for target in targets)
    assert all(len(baseline.runs) == 6 for baseline in files.values())


async def test_a_dirty_tree_refuses_a_recording_before_any_audit(tmp_path: Path):
    audit = given.ScriptedAudit()
    dirty = TreeState(commit=given.COMMIT, dirty=True)

    with pytest.raises(Refused):
        await run_gated(
            given.options(record_baseline=True), given.a_harness(audit, tmp_path, dirty)
        )

    assert audit.calls == []


async def test_a_baseline_file_failing_integrity_refuses_before_any_audit(tmp_path: Path):
    given.a_file_holding_one_run_of_three(tmp_path)
    audit = given.ScriptedAudit()

    with pytest.raises(Refused) as refusal:
        await run_gated(given.options(), given.a_harness(audit, tmp_path))

    assert "holds 1 runs" in refusal.value.reasons[0]
    assert audit.calls == []


async def test_without_a_baseline_directory_every_target_has_no_baseline_and_the_gate_is_green(
    tmp_path: Path,
):
    targets = [given.KUBERNETES, given.SYMLINK]
    harness = given.a_harness(given.ScriptedAudit(), tmp_path / "missing")

    result = await run_gated(given.options(targets=targets), harness)

    assert result.gate is not None
    assert {comparison.outcome for comparison in result.gate.targets} == {TargetOutcome.NO_BASELINE}
    assert result.gate.verdict == CVEGateVerdict.GREEN


async def test_a_file_of_a_target_no_longer_benchmarked_is_orphaned_and_not_compared(
    tmp_path: Path,
):
    orphan = given.an_orphaned_file(tmp_path)

    result = await run_gated(given.options(), given.a_harness(given.ScriptedAudit(), tmp_path))

    assert result.orphans == [orphan]
    assert result.gate is not None
    assert [comparison.cve_id for comparison in result.gate.targets] == [given.KUBERNETES.cve_id]
    assert result.gate.verdict == CVEGateVerdict.GREEN
