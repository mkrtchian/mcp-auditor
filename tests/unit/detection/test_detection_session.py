import asyncio
from pathlib import Path

import pytest

import tests.unit.detection.support.test_detection_session_given as given
import tests.unit.detection.support.test_detection_session_then as then
from evals.cve.detection.gate import TargetOutcome
from evals.cve.detection.layout_check import layout_failure
from evals.cve.detection.session import run_gated
from evals.cve.grammar import TargetStatus
from evals.eval_session import Refused
from evals.gate_outcome import GateOutcome
from tests.unit.detection.support.detection_sessions import (
    BROKEN_LAYOUT,
    KUBERNETES,
    SYMLINK,
    ScriptedAudit,
    ScriptedCheck,
    ScriptedLayout,
    a_gated_file,
    a_harness,
    a_miss,
    an_unchecked_detected_grade,
    audit_name,
    options,
)


async def test_a_gated_target_missed_once_is_replayed_until_the_miss_is_decided(tmp_path: Path):
    a_gated_file(tmp_path)
    miss = a_miss()
    audit = ScriptedAudit({KUBERNETES.flaw_id: [miss, given.a_detected_grade(), miss, *[miss] * 5]})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    comparison = then.the_one_target_ends(result, TargetOutcome.REGRESSION, GateOutcome.RED)
    assert comparison.retests == [True, True, True, True]
    assert result.exit_code == 1


async def test_a_miss_cleared_twice_stops_the_replays_and_keeps_the_gate_green(tmp_path: Path):
    a_gated_file(tmp_path)
    audit = ScriptedAudit({KUBERNETES.flaw_id: [a_miss()]})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    comparison = then.the_one_target_ends(result, TargetOutcome.MISS_NOT_REPRODUCED)
    assert comparison.retests == [False, False]
    assert result.exit_code == 0


async def test_no_replay_runs_when_the_conditions_differ_from_the_files(tmp_path: Path):
    a_gated_file(tmp_path, budget=20)
    audit = ScriptedAudit({KUBERNETES.flaw_id: [a_miss()]})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    assert result.gate is not None
    assert result.gate.targets[0].retests == []
    assert result.gate.outcome == GateOutcome.NOT_COMPARABLE
    assert result.exit_code == 3


async def test_a_replay_that_does_not_complete_makes_the_run_not_comparable(tmp_path: Path):
    a_gated_file(tmp_path)
    miss = a_miss()
    audit = ScriptedAudit({KUBERNETES.flaw_id: [miss, miss, miss, None]})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.INCOMPLETE, GateOutcome.NOT_COMPARABLE)


async def test_a_target_failing_the_pre_run_check_is_not_run_and_the_gate_is_not_comparable(
    tmp_path: Path,
):
    check = ScriptedCheck({KUBERNETES.flaw_id: ["keeps no place"]})
    audit = ScriptedAudit()

    result = await run_gated(options(), a_harness(audit, tmp_path, check=check))

    assert audit.calls == []
    assert result.not_run == {KUBERNETES.flaw_id: ["keeps no place"]}
    assert result.grades[KUBERNETES.flaw_id] == []
    then.the_one_target_ends(result, TargetOutcome.NOT_RUN, GateOutcome.NOT_COMPARABLE)


async def test_a_target_the_layout_breaks_under_the_normal_launch_is_not_run(tmp_path: Path):
    layout = ScriptedLayout({KUBERNETES.flaw_id: BROKEN_LAYOUT})
    audit = ScriptedAudit()

    result = await run_gated(options(), a_harness(audit, tmp_path, layout=layout))

    assert audit.calls == []
    assert result.not_run == {KUBERNETES.flaw_id: [layout_failure(KUBERNETES, BROKEN_LAYOUT)]}
    then.the_one_target_ends(result, TargetOutcome.NOT_RUN, GateOutcome.NOT_COMPARABLE)


async def test_a_passing_target_is_audited_while_a_failing_one_is_not_run_in_target_order(
    tmp_path: Path,
):
    targets = [KUBERNETES, SYMLINK]
    check = ScriptedCheck({SYMLINK.flaw_id: ["keeps no place"]})
    audit = ScriptedAudit()

    result = await run_gated(options(targets=targets), a_harness(audit, tmp_path, check=check))

    assert SYMLINK.flaw_id not in audit.calls
    assert len(result.grades[KUBERNETES.flaw_id]) == 3
    assert result.grades[SYMLINK.flaw_id] == []
    assert result.gate is not None
    assert [c.flaw_id for c in result.gate.targets] == [t.flaw_id for t in targets]
    outcomes = {c.flaw_id: c.outcome for c in result.gate.targets}
    assert outcomes[SYMLINK.flaw_id] == TargetOutcome.NOT_RUN
    assert outcomes[KUBERNETES.flaw_id] == TargetOutcome.NO_BASELINE


async def test_the_session_announces_the_audits_of_the_targets_the_check_let_through(
    tmp_path: Path,
):
    check = ScriptedCheck({SYMLINK.flaw_id: ["keeps no place"]})
    audit = ScriptedAudit()
    announce = given.RecordingAnnounce(audit)
    harness = a_harness(audit, tmp_path, check=check, announce=announce)

    await run_gated(options(targets=[KUBERNETES, SYMLINK]), harness)

    assert announce.announced == [(3, 0)]


async def test_a_not_run_target_with_a_baseline_carries_its_baseline_runs(tmp_path: Path):
    a_gated_file(tmp_path)
    check = ScriptedCheck({KUBERNETES.flaw_id: ["keeps no place"]})

    result = await run_gated(options(), a_harness(ScriptedAudit(), tmp_path, check=check))

    comparison = then.the_one_target_ends(result, TargetOutcome.NOT_RUN, GateOutcome.NOT_COMPARABLE)
    assert comparison.baseline_runs == [TargetStatus.DETECTED] * 6


async def test_a_run_depending_on_unchecked_credits_is_not_comparable(tmp_path: Path):
    audit = ScriptedAudit({KUBERNETES.flaw_id: [an_unchecked_detected_grade()] * 3})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.UNCHECKED_DECIDES, GateOutcome.NOT_COMPARABLE)


async def test_a_run_with_no_unchecked_credits_stays_comparable(tmp_path: Path):
    # A detected grade carries no unchecked credit, so its status equals status_if_unchecked_missed
    # and the run is comparable. The "unchecked but status-preserving" case does not occur: a
    # replayed unchecked run's only proofs are its credits, so an unchecked credit always leaves
    # status_if_unchecked_missed at MISSED. No test constructs that unreachable case.
    audit = ScriptedAudit({KUBERNETES.flaw_id: [given.a_detected_grade()] * 3})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.NO_BASELINE)


async def test_a_settlement_meeting_an_unchecked_replay_ends_unchecked(tmp_path: Path):
    a_gated_file(tmp_path)
    miss = a_miss()
    audit = ScriptedAudit({KUBERNETES.flaw_id: [miss, miss, miss, an_unchecked_detected_grade()]})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    then.the_one_target_ends(result, TargetOutcome.UNCHECKED_DECIDES, GateOutcome.NOT_COMPARABLE)


async def test_a_no_baseline_run_still_reports_a_failing_check_in_not_run(tmp_path: Path):
    check = ScriptedCheck({KUBERNETES.flaw_id: ["keeps no place"]})
    audit = ScriptedAudit()

    result = await run_gated(options(no_baseline=True), a_harness(audit, tmp_path, check=check))

    assert audit.calls == []
    assert result.gate is None
    assert result.not_run == {KUBERNETES.flaw_id: ["keeps no place"]}
    assert result.grades[KUBERNETES.flaw_id] == []
    assert result.exit_code == 0


async def test_a_check_that_raises_a_configuration_error_crashes_before_any_audit(tmp_path: Path):
    check = ScriptedCheck(error=ValueError("a kept id with no record"))
    audit = ScriptedAudit()

    with pytest.raises(ValueError, match="a kept id with no record"):
        await run_gated(options(), a_harness(audit, tmp_path, check=check))

    assert audit.calls == []


async def test_a_no_baseline_run_compares_nothing_and_exits_zero(tmp_path: Path):
    a_gated_file(tmp_path)
    audit = ScriptedAudit({KUBERNETES.flaw_id: [a_miss()]})

    result = await run_gated(options(no_baseline=True), a_harness(audit, tmp_path))

    assert result.gate is None
    assert result.exit_code == 0
    assert len(result.grades[KUBERNETES.flaw_id]) == 3


async def test_a_baseline_file_failing_integrity_refuses_before_any_audit(tmp_path: Path):
    given.a_file_holding_one_run_of_three(tmp_path)
    audit = ScriptedAudit()

    with pytest.raises(Refused) as refusal:
        await run_gated(options(), a_harness(audit, tmp_path))

    assert "holds 1 runs" in refusal.value.reasons[0]
    assert audit.calls == []


async def test_without_a_baseline_directory_every_target_has_no_baseline_and_the_gate_is_green(
    tmp_path: Path,
):
    targets = [KUBERNETES, SYMLINK]
    harness = a_harness(ScriptedAudit(), tmp_path / "missing")

    result = await run_gated(options(targets=targets), harness)

    assert result.gate is not None
    assert {comparison.outcome for comparison in result.gate.targets} == {TargetOutcome.NO_BASELINE}
    assert result.gate.outcome == GateOutcome.GREEN


async def test_a_file_of_a_target_no_longer_benchmarked_is_orphaned_and_not_compared(
    tmp_path: Path,
):
    orphan = given.an_orphaned_file(tmp_path)

    result = await run_gated(options(), a_harness(ScriptedAudit(), tmp_path))

    assert result.orphans == [orphan]
    assert result.gate is not None
    assert [comparison.flaw_id for comparison in result.gate.targets] == [KUBERNETES.flaw_id]
    assert result.gate.outcome == GateOutcome.GREEN


async def test_the_runs_of_two_targets_overlap(tmp_path: Path):
    targets = [KUBERNETES, SYMLINK]
    audit = given.OverlappingAudit({target.flaw_id for target in targets})

    async with asyncio.timeout(1):
        result = await run_gated(options(targets=targets), a_harness(audit, tmp_path))

    assert [len(grades) for grades in result.grades.values()] == [3, 3]


async def test_two_gated_targets_missed_once_settle_their_replays_in_target_order(tmp_path: Path):
    targets = [KUBERNETES, SYMLINK]
    for target in targets:
        a_gated_file(tmp_path, target)
    audit = ScriptedAudit({target.flaw_id: [a_miss()] for target in targets})

    result = await run_gated(options(targets=targets), a_harness(audit, tmp_path))

    assert result.gate is not None
    assert [comparison.flaw_id for comparison in result.gate.targets] == [
        target.flaw_id for target in targets
    ]
    assert [comparison.outcome for comparison in result.gate.targets] == [
        TargetOutcome.MISS_NOT_REPRODUCED
    ] * 2
    assert [comparison.retests for comparison in result.gate.targets] == [[False, False]] * 2


async def test_the_completed_main_runs_are_kept_with_their_run_index(tmp_path: Path):
    targets = [KUBERNETES, SYMLINK]
    audit = ScriptedAudit({SYMLINK.flaw_id: [None]})

    result = await run_gated(options(targets=targets), a_harness(audit, tmp_path))

    kubernetes, symlink = KUBERNETES.flaw_id, SYMLINK.flaw_id
    assert [(a.flaw_id, a.run_index, a.report.server_command) for a in result.audits] == [
        (kubernetes, 0, audit_name(kubernetes, 0)),
        (kubernetes, 1, audit_name(kubernetes, 1)),
        (kubernetes, 2, audit_name(kubernetes, 2)),
        (symlink, 1, audit_name(symlink, 1)),
        (symlink, 2, audit_name(symlink, 2)),
    ]


async def test_an_audit_made_by_a_replay_is_not_kept(tmp_path: Path):
    a_gated_file(tmp_path)
    audit = ScriptedAudit({KUBERNETES.flaw_id: [a_miss()]})

    result = await run_gated(options(), a_harness(audit, tmp_path))

    assert len(audit.calls) == 5
    assert [audit.report.server_command for audit in result.audits] == [
        audit_name(KUBERNETES.flaw_id, call) for call in range(3)
    ]
