"""The nuisance gate session with a faked harness: no Docker, no LLM, no git."""

from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_gate_session_given as given
from evals.baseline import BaselineStatus
from evals.eval_session import RECORDING_REFUSED, Refused, TreeState
from evals.gate_verdict import GateVerdict
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_audit import GateRun
from evals.nuisance_gate import ServerComparison, ServerOutcome
from evals.nuisance_gate_baseline import load_baselines, write_baseline
from evals.nuisance_gate_session import gate_servers, not_admitted, outside_gate, run_gate
from evals.nuisance_gate_session_model import NuisanceGateSession
from evals.nuisance_results import FigureExit
from tests.unit.support.test_nuisance_admission_given import with_a_backend
from tests.unit.support.test_nuisance_gate_baseline_given import a_gated_baseline

FILESYSTEM = given.FILESYSTEM
KUBERNETES = given.KUBERNETES


async def test_a_gated_server_with_clean_runs_holds_and_the_gate_is_green(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    audit = given.scripted({FILESYSTEM.server_package: given.clean_runs()})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    _the_one_server_ends(session, ServerOutcome.HELD, GateVerdict.GREEN)
    assert [audit.run_index for audit in session.audits] == [0, 1, 2]
    assert session.exit_code == 0


async def test_an_alarm_on_a_gated_server_that_reproduces_is_a_regression(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    alarm = given.a_gate_run(True)
    script = [alarm, *given.clean_runs(2), alarm, alarm, alarm, alarm]
    audit = given.scripted({FILESYSTEM.server_package: script})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    comparison = _the_one_server_ends(session, ServerOutcome.REGRESSION, GateVerdict.RED)
    assert comparison.replays == [True, True, True, True]
    assert session.exit_code == 1


async def test_an_alarm_that_does_not_reproduce_keeps_the_gate_green(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    script = [given.a_gate_run(True), *given.clean_runs(4)]
    audit = given.scripted({FILESYSTEM.server_package: script})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    comparison = _the_one_server_ends(
        session, ServerOutcome.ALARM_NOT_REPRODUCED, GateVerdict.GREEN
    )
    assert comparison.replays == [False, False]
    assert any(FILESYSTEM.server_package in reason for reason in session.gate.reasons)
    assert session.exit_code == 0


async def test_an_alarm_on_a_server_flagged_in_its_baseline_is_inconclusive(tmp_path: Path):
    given.a_flagged_file(tmp_path, FILESYSTEM)
    script = [given.a_gate_run(True), *given.clean_runs(2)]
    audit = given.scripted({FILESYSTEM.server_package: script})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    comparison = _the_one_server_ends(session, ServerOutcome.INCONCLUSIVE, GateVerdict.GREEN)
    assert comparison.replays == []
    assert any(FILESYSTEM.server_package in reason for reason in session.gate.reasons)
    assert session.exit_code == 0


async def test_a_server_whose_benign_call_fails_is_not_run_and_not_comparable(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    harness = given.a_harness(
        tmp_path, given.scripted({}), benign_call={FILESYSTEM.server_package: "no answer"}
    )

    session = await run_gate(given.options([FILESYSTEM]), harness)

    assert session.not_run == {FILESYSTEM.server_package: "no answer"}
    assert session.audits == []
    _the_one_server_ends(session, ServerOutcome.NOT_RUN, GateVerdict.NOT_COMPARABLE)
    assert session.exit_code == 3


async def test_the_session_announces_the_runs_of_the_servers_the_benign_call_let_through(
    tmp_path: Path,
):
    announced: list[int] = []
    harness = given.a_harness(
        tmp_path,
        given.scripted({FILESYSTEM.server_package: given.clean_runs(2)}),
        benign_call={KUBERNETES.server_package: "no answer"},
        announce=announced.append,
    )

    await run_gate(given.options([FILESYSTEM, KUBERNETES], runs=2), harness)

    assert announced == [2]


async def test_the_session_carries_the_throttled_total(tmp_path: Path):
    audit = given.scripted({FILESYSTEM.server_package: given.clean_runs()})
    harness = given.a_harness(tmp_path, audit, throttled_requests=7)

    session = await run_gate(given.options([FILESYSTEM]), harness)

    assert session.throttled_requests == 7


async def test_a_not_run_server_with_a_baseline_carries_its_baseline_runs(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    harness = given.a_harness(
        tmp_path, given.scripted({}), benign_call={FILESYSTEM.server_package: "no answer"}
    )

    session = await run_gate(given.options([FILESYSTEM]), harness)

    comparison = _the_one_server_ends(session, ServerOutcome.NOT_RUN, GateVerdict.NOT_COMPARABLE)
    assert comparison.baseline_runs == [False] * 6


async def test_a_failing_benign_call_refuses_a_recording_before_any_audit(tmp_path: Path):
    harness = given.a_harness(
        tmp_path, given.scripted({}), benign_call={FILESYSTEM.server_package: "no answer"}
    )

    with pytest.raises(Refused) as refused:
        await run_gate(given.options([FILESYSTEM], record=True), harness)

    assert refused.value.title == RECORDING_REFUSED
    assert refused.value.reasons == [f"{FILESYSTEM.server_package}: no answer"]


async def test_a_dirty_tree_refuses_a_recording_before_any_audit(tmp_path: Path):
    harness = given.a_harness(tmp_path, given.scripted({}), tree=TreeState(given.COMMIT, True))

    with pytest.raises(Refused) as refused:
        await run_gate(given.options([FILESYSTEM], record=True), harness)

    assert refused.value.title == RECORDING_REFUSED


async def test_two_recordings_at_one_commit_write_an_exploratory_then_a_confirmed_file(
    tmp_path: Path,
):
    servers = [FILESYSTEM, KUBERNETES]
    scripts = {server.server_package: given.clean_runs() for server in servers}

    first = await run_gate(
        given.options(servers, record=True), given.a_harness(tmp_path, given.scripted(scripts))
    )
    second = await run_gate(
        given.options(servers, record=True), given.a_harness(tmp_path, given.scripted(scripts))
    )

    assert [(w.server_package, w.status) for w in first.written] == [
        (FILESYSTEM.server_package, BaselineStatus.EXPLORATORY),
        (KUBERNETES.server_package, BaselineStatus.EXPLORATORY),
    ]
    assert [w.status for w in second.written] == [BaselineStatus.CONFIRMED] * 2
    confirmed = load_baselines(tmp_path)[FILESYSTEM.server_package]
    assert confirmed.runs == [False] * 6
    assert confirmed.image_ids == {"filesystem-patched": "sha256:filesystem-patched"}
    assert second.exit_code == 0


async def test_a_backend_server_records_its_backend_image_beside_its_service(tmp_path: Path):
    backend = BackendFixture(
        provisioner="doris", image="apache/doris:all-in-one-4.1.3", network="net"
    )
    server = with_a_backend(FILESYSTEM, backend)
    scripts = {server.server_package: given.clean_runs()}

    await run_gate(
        given.options([server], record=True), given.a_harness(tmp_path, given.scripted(scripts))
    )
    await run_gate(
        given.options([server], record=True), given.a_harness(tmp_path, given.scripted(scripts))
    )

    confirmed = load_baselines(tmp_path)[server.server_package]
    assert confirmed.image_ids == {
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_head_moving_during_the_runs_refuses_the_recording(tmp_path: Path):
    harness = given.a_harness(
        tmp_path,
        given.scripted({FILESYSTEM.server_package: given.clean_runs()}),
        tree_after_runs=TreeState("another", False),
    )

    session = await run_gate(given.options([FILESYSTEM], record=True), harness)

    assert session.recording_refused != []
    assert session.written == []
    assert load_baselines(tmp_path) == {}
    assert session.gate.verdict == GateVerdict.GREEN
    assert session.exit_code == 3


async def test_a_baseline_file_written_during_the_runs_refuses_the_recording(tmp_path: Path):
    script = given.scripted({FILESYSTEM.server_package: given.clean_runs()})

    async def audit_writing_a_file(server: AdmittedServer) -> GateRun | None:
        write_baseline(tmp_path, a_gated_baseline("npm:written-meanwhile"))
        return await script(server)

    harness = given.a_harness(tmp_path, audit_writing_a_file)

    session = await run_gate(given.options([FILESYSTEM], record=True), harness)

    assert session.recording_refused != []
    assert set(load_baselines(tmp_path)) == {"npm:written-meanwhile"}
    assert session.exit_code == 3


async def test_a_run_that_does_not_complete_on_a_gated_server_is_not_comparable(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    script = [None, *given.clean_runs(2)]
    audit = given.scripted({FILESYSTEM.server_package: script})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    _the_one_server_ends(session, ServerOutcome.INCOMPLETE, GateVerdict.NOT_COMPARABLE)
    assert session.exit_code == 3


async def test_a_run_that_does_not_complete_refuses_the_recording_and_writes_nothing(
    tmp_path: Path,
):
    script = [None, *given.clean_runs(2)]
    audit = given.scripted({FILESYSTEM.server_package: script})

    session = await run_gate(
        given.options([FILESYSTEM], record=True), given.a_harness(tmp_path, audit)
    )

    assert session.recording_refused != []
    assert load_baselines(tmp_path) == {}
    assert session.exit_code == 3


async def test_a_replay_that_does_not_complete_is_incomplete(tmp_path: Path):
    given.a_gated_file(tmp_path, FILESYSTEM)
    script = [given.a_gate_run(True), *given.clean_runs(2), None]
    audit = given.scripted({FILESYSTEM.server_package: script})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    _the_one_server_ends(session, ServerOutcome.INCOMPLETE, GateVerdict.NOT_COMPARABLE)


async def test_a_baseline_file_of_a_server_outside_the_gate_set_is_an_orphan(tmp_path: Path):
    orphan = given.an_orphaned_file(tmp_path)
    audit = given.scripted({FILESYSTEM.server_package: given.clean_runs()})

    session = await run_gate(given.options([FILESYSTEM]), given.a_harness(tmp_path, audit))

    assert session.orphans == [orphan]
    assert [s.server_package for s in session.gate.servers] == [FILESYSTEM.server_package]


async def test_a_one_server_run_leaves_the_other_gate_file_out_of_the_comparison(
    tmp_path: Path,
):
    given.a_gated_file(tmp_path, KUBERNETES, recorded=given.other_conditions())
    audit = given.scripted({FILESYSTEM.server_package: given.clean_runs()})
    gate_packages = {FILESYSTEM.server_package, KUBERNETES.server_package}

    session = await run_gate(
        given.options([FILESYSTEM], gate_packages=gate_packages),
        given.a_harness(tmp_path, audit),
    )

    assert [s.server_package for s in session.gate.servers] == [FILESYSTEM.server_package]
    assert session.orphans == []
    assert session.gate.verdict == GateVerdict.NOT_COMPARABLE


async def test_a_one_server_recording_is_refused_on_the_other_gate_file_mismatch(
    tmp_path: Path,
):
    given.a_gated_file(tmp_path, KUBERNETES, recorded=given.other_conditions())
    gate_packages = {FILESYSTEM.server_package, KUBERNETES.server_package}
    harness = given.a_harness(tmp_path, given.scripted({}))

    with pytest.raises(Refused) as refused:
        await run_gate(
            given.options([FILESYSTEM], gate_packages=gate_packages, record=True), harness
        )

    assert any("model" in reason for reason in refused.value.reasons)


def test_the_gate_servers_are_the_current_ones_that_run_over_stdio_in_admission_order():
    no_stdio = KUBERNETES.model_copy(update={"runs_over_stdio": False})
    other = given.run_given.a_server("npm:not-current")
    admitted = given.admitting(KUBERNETES, other, FILESYSTEM)
    current = {FILESYSTEM.server_package, KUBERNETES.server_package}

    assert gate_servers(admitted, current) == [KUBERNETES, FILESYSTEM]
    assert gate_servers(given.admitting(no_stdio, FILESYSTEM), current) == [FILESYSTEM]
    assert outside_gate(given.admitting(no_stdio, FILESYSTEM), current) == [
        FigureExit(KUBERNETES.server_package, "does not run over stdio")
    ]


def test_a_current_package_no_admitted_server_carries_is_not_admitted():
    current = {FILESYSTEM.server_package, KUBERNETES.server_package, "PyPI:mcp-server-git"}

    assert not_admitted(given.admitting(FILESYSTEM), current) == [
        "PyPI:mcp-server-git",
        KUBERNETES.server_package,
    ]


def _the_one_server_ends(
    session: NuisanceGateSession, outcome: ServerOutcome, verdict: GateVerdict
) -> ServerComparison:
    [comparison] = session.gate.servers
    assert comparison.outcome == outcome
    assert session.gate.verdict == verdict
    return comparison
