"""The nuisance gate session with a faked harness: no Docker, no LLM, no git."""

from pathlib import Path

import pytest

import tests.unit.nuisance.gate.support.nuisance_gate_baselines as nuisance_gate_baselines
import tests.unit.nuisance.gate.support.test_nuisance_gate_session_given as given
from evals.baseline import BaselineStatus
from evals.cve.nuisance.admission.admission import AdmittedServer, BackendFixture
from evals.cve.nuisance.gate.gate import ServerOutcome
from evals.cve.nuisance.gate.gate_audit import GateRun
from evals.cve.nuisance.gate.gate_baseline import load_baselines, write_baseline
from evals.cve.nuisance.gate.gate_session import run_gate
from evals.eval_session import RECORDING_REFUSED, Refused, TreeState
from evals.gate_outcome import GateOutcome
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import (
    COMMIT,
    FILESYSTEM,
    KUBERNETES,
    a_gate_run,
    a_gated_file,
    a_harness,
    clean_runs,
    options,
    scripted,
    the_one_server_ends,
)
from tests.unit.support.admission_mutations import with_a_backend


async def test_a_gated_server_with_clean_runs_holds_and_the_gate_is_green(tmp_path: Path):
    a_gated_file(tmp_path, FILESYSTEM)
    audit = scripted({FILESYSTEM.server_package: clean_runs()})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    the_one_server_ends(session, ServerOutcome.HELD, GateOutcome.GREEN)
    assert [audit.run_index for audit in session.audits] == [0, 1, 2]
    assert session.exit_code == 0


async def test_an_alarm_on_a_gated_server_that_reproduces_is_a_regression(tmp_path: Path):
    a_gated_file(tmp_path, FILESYSTEM)
    alarm = a_gate_run(True)
    script = [alarm, *clean_runs(2), alarm, alarm, alarm, alarm]
    audit = scripted({FILESYSTEM.server_package: script})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    comparison = the_one_server_ends(session, ServerOutcome.REGRESSION, GateOutcome.RED)
    assert comparison.retests == [True, True, True, True]
    assert session.exit_code == 1


async def test_an_alarm_that_does_not_reproduce_keeps_the_gate_green(tmp_path: Path):
    a_gated_file(tmp_path, FILESYSTEM)
    script = [a_gate_run(True), *clean_runs(4)]
    audit = scripted({FILESYSTEM.server_package: script})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    comparison = the_one_server_ends(session, ServerOutcome.ALARM_NOT_REPRODUCED, GateOutcome.GREEN)
    assert comparison.retests == [False, False]
    assert any(FILESYSTEM.server_package in reason for reason in session.gate.reasons)
    assert session.exit_code == 0


async def test_an_alarm_on_a_server_flagged_in_its_baseline_is_inconclusive(tmp_path: Path):
    given.a_flagged_file(tmp_path, FILESYSTEM)
    script = [a_gate_run(True), *clean_runs(2)]
    audit = scripted({FILESYSTEM.server_package: script})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    comparison = the_one_server_ends(session, ServerOutcome.INCONCLUSIVE, GateOutcome.GREEN)
    assert comparison.retests == []
    assert any(FILESYSTEM.server_package in reason for reason in session.gate.reasons)
    assert session.exit_code == 0


async def test_the_session_carries_the_throttled_total(tmp_path: Path):
    audit = scripted({FILESYSTEM.server_package: clean_runs()})
    harness = a_harness(tmp_path, audit, throttled_requests=7)

    session = await run_gate(options([FILESYSTEM]), harness)

    assert session.throttled_requests == 7


async def test_a_dirty_tree_refuses_a_recording_before_any_audit(tmp_path: Path):
    harness = a_harness(tmp_path, scripted({}), tree=TreeState(COMMIT, True))

    with pytest.raises(Refused) as refused:
        await run_gate(options([FILESYSTEM], record=True), harness)

    assert refused.value.title == RECORDING_REFUSED


async def test_two_recordings_at_one_commit_write_an_unconfirmed_then_a_confirmed_file(
    tmp_path: Path,
):
    servers = [FILESYSTEM, KUBERNETES]
    scripts = {server.server_package: clean_runs() for server in servers}

    first = await run_gate(options(servers, record=True), a_harness(tmp_path, scripted(scripts)))
    second = await run_gate(options(servers, record=True), a_harness(tmp_path, scripted(scripts)))

    assert [(w.server_package, w.status) for w in first.written] == [
        (FILESYSTEM.server_package, BaselineStatus.UNCONFIRMED),
        (KUBERNETES.server_package, BaselineStatus.UNCONFIRMED),
    ]
    assert [w.status for w in second.written] == [BaselineStatus.CONFIRMED] * 2
    confirmed = load_baselines(tmp_path)[FILESYSTEM.server_package]
    assert confirmed.runs == [False] * 6
    assert confirmed.image_ids == {"filesystem-patched": "sha256:filesystem-patched"}
    assert second.exit_code == 0


async def test_a_backend_server_records_its_backend_image_beside_its_service(tmp_path: Path):
    backend = BackendFixture(
        provisioner="doris", images=["apache/doris:all-in-one-4.1.3"], network="net"
    )
    server = with_a_backend(FILESYSTEM, backend)
    scripts = {server.server_package: clean_runs()}

    await run_gate(options([server], record=True), a_harness(tmp_path, scripted(scripts)))
    await run_gate(options([server], record=True), a_harness(tmp_path, scripted(scripts)))

    confirmed = load_baselines(tmp_path)[server.server_package]
    assert confirmed.image_ids == {
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_head_moving_during_the_runs_refuses_the_recording(tmp_path: Path):
    harness = a_harness(
        tmp_path,
        scripted({FILESYSTEM.server_package: clean_runs()}),
        tree_after_runs=TreeState("another", False),
    )

    session = await run_gate(options([FILESYSTEM], record=True), harness)

    assert session.recording_refused == [
        f"HEAD moved from {COMMIT} to another during the runs: record again"
    ]
    assert session.written == []
    assert load_baselines(tmp_path) == {}
    assert session.gate.outcome == GateOutcome.GREEN
    assert session.exit_code == 3


async def test_a_baseline_file_written_during_the_runs_refuses_the_recording(tmp_path: Path):
    script = scripted({FILESYSTEM.server_package: clean_runs()})

    async def audit_writing_a_file(server: AdmittedServer) -> GateRun | None:
        write_baseline(tmp_path, nuisance_gate_baselines.a_gated_baseline("npm:written-meanwhile"))
        return await script(server)

    harness = a_harness(tmp_path, audit_writing_a_file)

    session = await run_gate(options([FILESYSTEM], record=True), harness)

    assert session.recording_refused == ["the baseline files changed during the runs: record again"]
    assert set(load_baselines(tmp_path)) == {"npm:written-meanwhile"}
    assert session.exit_code == 3


async def test_a_run_that_does_not_complete_on_a_gated_server_is_not_comparable(tmp_path: Path):
    a_gated_file(tmp_path, FILESYSTEM)
    script = [None, *clean_runs(2)]
    audit = scripted({FILESYSTEM.server_package: script})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    the_one_server_ends(session, ServerOutcome.INCOMPLETE, GateOutcome.NOT_COMPARABLE)
    assert session.exit_code == 3


async def test_a_run_that_does_not_complete_refuses_the_recording_and_writes_nothing(
    tmp_path: Path,
):
    script = [None, *clean_runs(2)]
    audit = scripted({FILESYSTEM.server_package: script})

    session = await run_gate(options([FILESYSTEM], record=True), a_harness(tmp_path, audit))

    assert session.recording_refused == [
        f"{FILESYSTEM.server_package}: a run did not complete: a baseline holds every run its"
        " conditions claim"
    ]
    assert load_baselines(tmp_path) == {}
    assert session.exit_code == 3


async def test_a_retest_that_does_not_complete_is_incomplete(tmp_path: Path):
    a_gated_file(tmp_path, FILESYSTEM)
    script = [a_gate_run(True), *clean_runs(2), None]
    audit = scripted({FILESYSTEM.server_package: script})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    the_one_server_ends(session, ServerOutcome.INCOMPLETE, GateOutcome.NOT_COMPARABLE)


async def test_a_baseline_file_of_a_server_outside_the_gate_set_is_an_orphan(tmp_path: Path):
    orphan = given.an_orphaned_file(tmp_path)
    audit = scripted({FILESYSTEM.server_package: clean_runs()})

    session = await run_gate(options([FILESYSTEM]), a_harness(tmp_path, audit))

    assert session.orphans == [orphan]
    assert [s.server_package for s in session.gate.servers] == [FILESYSTEM.server_package]


async def test_a_one_server_run_leaves_the_other_gate_file_out_of_the_comparison(
    tmp_path: Path,
):
    a_gated_file(tmp_path, KUBERNETES, recorded=given.other_conditions())
    audit = scripted({FILESYSTEM.server_package: clean_runs()})
    gate_packages = {FILESYSTEM.server_package, KUBERNETES.server_package}

    session = await run_gate(
        options([FILESYSTEM], gate_packages=gate_packages),
        a_harness(tmp_path, audit),
    )

    assert [s.server_package for s in session.gate.servers] == [FILESYSTEM.server_package]
    assert session.orphans == []
    assert session.gate.outcome == GateOutcome.NOT_COMPARABLE


async def test_a_one_server_recording_is_refused_on_the_other_gate_file_mismatch(
    tmp_path: Path,
):
    a_gated_file(tmp_path, KUBERNETES, recorded=given.other_conditions())
    gate_packages = {FILESYSTEM.server_package, KUBERNETES.server_package}
    harness = a_harness(tmp_path, scripted({}))

    with pytest.raises(Refused) as refused:
        await run_gate(options([FILESYSTEM], gate_packages=gate_packages, record=True), harness)

    assert any("model" in reason for reason in refused.value.reasons)
