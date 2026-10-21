import asyncio
from pathlib import Path

import pytest

import tests.unit.support.test_cve_session_given as given
import tests.unit.support.test_cve_session_then as then
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

    comparison = then.the_one_target_ends(result, TargetOutcome.REGRESSION, CVEGateVerdict.RED)
    assert comparison.replays == [True, True, True, True]
    assert result.exit_code == 1


async def test_a_miss_cleared_twice_stops_the_replays_and_keeps_the_gate_green(tmp_path: Path):
    given.a_gated_file(tmp_path)
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_miss()]})

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    comparison = then.the_one_target_ends(result, TargetOutcome.MISS_NOT_REPRODUCED)
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

    then.the_one_target_ends(result, TargetOutcome.INCOMPLETE, CVEGateVerdict.NOT_COMPARABLE)


async def test_a_target_failing_the_pre_run_check_is_not_run_and_the_gate_is_not_comparable(
    tmp_path: Path,
):
    check = given.ScriptedCheck({given.KUBERNETES.cve_id: ["keeps no place"]})
    audit = given.ScriptedAudit()

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path, check=check))

    assert audit.calls == []
    assert result.not_run == {given.KUBERNETES.cve_id: ["keeps no place"]}
    assert result.grades[given.KUBERNETES.cve_id] == []
    then.the_one_target_ends(result, TargetOutcome.NOT_RUN, CVEGateVerdict.NOT_COMPARABLE)


async def test_a_passing_target_is_audited_while_a_failing_one_is_not_run_in_target_order(
    tmp_path: Path,
):
    targets = [given.KUBERNETES, given.SYMLINK]
    check = given.ScriptedCheck({given.SYMLINK.cve_id: ["keeps no place"]})
    audit = given.ScriptedAudit()

    result = await run_gated(
        given.options(targets=targets), given.a_harness(audit, tmp_path, check=check)
    )

    assert given.SYMLINK.cve_id not in audit.calls
    assert len(result.grades[given.KUBERNETES.cve_id]) == 3
    assert result.grades[given.SYMLINK.cve_id] == []
    assert result.gate is not None
    assert [c.cve_id for c in result.gate.targets] == [t.cve_id for t in targets]
    outcomes = {c.cve_id: c.outcome for c in result.gate.targets}
    assert outcomes[given.SYMLINK.cve_id] == TargetOutcome.NOT_RUN
    assert outcomes[given.KUBERNETES.cve_id] == TargetOutcome.NO_BASELINE


async def test_a_run_depending_on_unchecked_credits_is_not_comparable(tmp_path: Path):
    audit = given.ScriptedAudit(
        {given.KUBERNETES.cve_id: [given.an_unchecked_detected_grade()] * 3}
    )

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.UNCHECKED_DECIDES, CVEGateVerdict.NOT_COMPARABLE)


async def test_a_run_with_no_unchecked_credits_stays_comparable(tmp_path: Path):
    # A detected grade carries no unchecked credit, so its status equals status_if_unchecked_missed
    # and the run is comparable. The "unchecked but status-preserving" case does not occur: a
    # replayed unchecked run's only proofs are its credits, so an unchecked credit always leaves
    # status_if_unchecked_missed at MISSED. No test constructs that unreachable case.
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_detected_grade()] * 3})

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.NO_BASELINE)


async def test_a_settlement_meeting_an_unchecked_replay_ends_unchecked(tmp_path: Path):
    given.a_gated_file(tmp_path)
    miss = given.a_miss()
    audit = given.ScriptedAudit(
        {given.KUBERNETES.cve_id: [miss, miss, miss, given.an_unchecked_detected_grade()]}
    )

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.UNCHECKED_DECIDES, CVEGateVerdict.NOT_COMPARABLE)


async def test_a_recording_with_an_unchecked_dependent_run_is_refused(tmp_path: Path):
    audit = given.ScriptedAudit(
        {given.KUBERNETES.cve_id: [given.an_unchecked_detected_grade()] * 3}
    )

    result = await run_gated(given.options(record_baseline=True), given.a_harness(audit, tmp_path))

    assert result.written == []
    assert any(given.KUBERNETES.cve_id in reason for reason in result.recording_refused)
    assert not list(tmp_path.glob("*.json"))


async def test_an_ungated_run_still_reports_a_failing_check_in_not_run(tmp_path: Path):
    check = given.ScriptedCheck({given.KUBERNETES.cve_id: ["keeps no place"]})
    audit = given.ScriptedAudit()

    result = await run_gated(
        given.options(ungated=True), given.a_harness(audit, tmp_path, check=check)
    )

    assert audit.calls == []
    assert result.gate is None
    assert result.not_run == {given.KUBERNETES.cve_id: ["keeps no place"]}
    assert result.grades[given.KUBERNETES.cve_id] == []
    assert result.exit_code == 0


async def test_a_failing_check_refuses_a_recording_before_any_audit(tmp_path: Path):
    check = given.ScriptedCheck({given.KUBERNETES.cve_id: ["keeps no place"]})
    audit = given.ScriptedAudit()

    with pytest.raises(Refused) as refusal:
        await run_gated(
            given.options(record_baseline=True), given.a_harness(audit, tmp_path, check=check)
        )

    assert audit.calls == []
    assert any("keeps no place" in reason for reason in refusal.value.reasons)


async def test_a_check_that_raises_a_configuration_error_crashes_before_any_audit(tmp_path: Path):
    check = given.ScriptedCheck(error=ValueError("a kept id with no record"))
    audit = given.ScriptedAudit()

    with pytest.raises(ValueError, match="a kept id with no record"):
        await run_gated(given.options(), given.a_harness(audit, tmp_path, check=check))

    assert audit.calls == []


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


async def test_a_recording_records_the_patched_image_id_beside_the_server_image(tmp_path: Path):
    recording = given.options(record_baseline=True)

    await run_gated(recording, given.a_harness(given.ScriptedAudit(), tmp_path))

    baseline = load_baselines(tmp_path)[given.KUBERNETES.cve_id]
    assert given.KUBERNETES.patched_image in baseline.image_ids
    assert given.KUBERNETES.server_image in baseline.image_ids


async def test_a_recording_refused_after_the_runs_still_returns_the_graded_runs(tmp_path: Path):
    given.a_gated_file(tmp_path)
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_miss()] * 7})
    before = (tmp_path / f"{given.KUBERNETES.cve_id}.json").read_text()

    result = await run_gated(given.options(record_baseline=True), given.a_harness(audit, tmp_path))

    assert result.recording_refused != []
    assert result.written == []
    assert len(result.grades[given.KUBERNETES.cve_id]) == 3
    assert result.gate is not None
    assert result.gate.verdict == CVEGateVerdict.RED
    assert (tmp_path / f"{given.KUBERNETES.cve_id}.json").read_text() == before


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


async def test_the_runs_of_two_targets_overlap(tmp_path: Path):
    targets = [given.KUBERNETES, given.SYMLINK]
    audit = given.OverlappingAudit({target.cve_id for target in targets})

    async with asyncio.timeout(1):
        result = await run_gated(given.options(targets=targets), given.a_harness(audit, tmp_path))

    assert [len(grades) for grades in result.grades.values()] == [3, 3]


async def test_two_gated_targets_missed_once_settle_their_replays_in_target_order(tmp_path: Path):
    targets = [given.KUBERNETES, given.SYMLINK]
    for target in targets:
        given.a_gated_file(tmp_path, target)
    audit = given.ScriptedAudit({target.cve_id: [given.a_miss()] for target in targets})

    result = await run_gated(given.options(targets=targets), given.a_harness(audit, tmp_path))

    assert result.gate is not None
    assert [comparison.cve_id for comparison in result.gate.targets] == [
        target.cve_id for target in targets
    ]
    assert [comparison.outcome for comparison in result.gate.targets] == [
        TargetOutcome.MISS_NOT_REPRODUCED
    ] * 2
    assert [comparison.replays for comparison in result.gate.targets] == [[False, False]] * 2


async def test_the_completed_main_runs_are_kept_with_their_run_index(tmp_path: Path):
    targets = [given.KUBERNETES, given.SYMLINK]
    audit = given.ScriptedAudit({given.SYMLINK.cve_id: [None]})

    result = await run_gated(given.options(targets=targets), given.a_harness(audit, tmp_path))

    kubernetes, symlink = given.KUBERNETES.cve_id, given.SYMLINK.cve_id
    assert [(a.cve_id, a.run_index, a.report.target) for a in result.audits] == [
        (kubernetes, 0, given.audit_name(kubernetes, 0)),
        (kubernetes, 1, given.audit_name(kubernetes, 1)),
        (kubernetes, 2, given.audit_name(kubernetes, 2)),
        (symlink, 1, given.audit_name(symlink, 1)),
        (symlink, 2, given.audit_name(symlink, 2)),
    ]


async def test_an_audit_made_by_a_replay_is_not_kept(tmp_path: Path):
    given.a_gated_file(tmp_path)
    audit = given.ScriptedAudit({given.KUBERNETES.cve_id: [given.a_miss()]})

    result = await run_gated(given.options(), given.a_harness(audit, tmp_path))

    assert len(audit.calls) == 5
    assert [audit.report.target for audit in result.audits] == [
        given.audit_name(given.KUBERNETES.cve_id, call) for call in range(3)
    ]
