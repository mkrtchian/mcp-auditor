"""The benign calls of the nuisance gate session, and their second pass."""

from pathlib import Path

import pytest

import tests.unit.nuisance.gate.support.test_nuisance_gate_benign_calls_given as given
from evals.cve.nuisance.gate.gate import ServerOutcome
from evals.cve.nuisance.gate.gate_session import run_gate
from evals.eval_session import RECORDING_REFUSED, Refused
from evals.gate_outcome import GateOutcome
from tests.fakes import FakeContainerSweep
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import (
    FILESYSTEM,
    KUBERNETES,
    a_gated_file,
    a_harness,
    clean_runs,
    options,
    scripted,
    the_one_server_ends,
)
from tests.unit.support.admission_mutations import on_the_ckan_backend


async def test_a_server_whose_benign_call_fails_is_not_run_and_not_comparable(tmp_path: Path):
    a_gated_file(tmp_path, FILESYSTEM)
    harness = a_harness(
        tmp_path, scripted({}), benign_call={FILESYSTEM.server_package: "no answer"}
    )

    session = await run_gate(options([FILESYSTEM]), harness)

    assert session.not_run == {FILESYSTEM.server_package: "no answer"}
    assert session.audits == []
    comparison = the_one_server_ends(session, ServerOutcome.NOT_RUN, GateOutcome.NOT_COMPARABLE)
    assert comparison.baseline_runs == [False] * 6
    assert session.exit_code == 3


async def test_a_server_answering_its_second_benign_call_is_audited_and_compared(
    tmp_path: Path,
):
    a_gated_file(tmp_path, FILESYSTEM)
    audit = scripted({FILESYSTEM.server_package: clean_runs()})
    harness = a_harness(tmp_path, audit, benign_call={FILESYSTEM.server_package: ["boom", None]})

    session = await run_gate(options([FILESYSTEM]), harness)

    assert session.not_run == {}
    the_one_server_ends(session, ServerOutcome.HELD, GateOutcome.GREEN)
    assert session.exit_code == 0


async def test_the_session_announces_the_runs_of_the_servers_the_benign_call_let_through(
    tmp_path: Path,
):
    announced: list[int] = []
    harness = a_harness(
        tmp_path,
        scripted({FILESYSTEM.server_package: clean_runs(2)}),
        benign_call={KUBERNETES.server_package: "no answer"},
        announce=announced.append,
    )

    await run_gate(options([FILESYSTEM, KUBERNETES], runs=2), harness)

    assert announced == [2]


async def test_a_failing_benign_call_refuses_a_recording_before_any_audit(tmp_path: Path):
    harness = a_harness(
        tmp_path, scripted({}), benign_call={FILESYSTEM.server_package: "no answer"}
    )

    with pytest.raises(Refused) as refused:
        await run_gate(options([FILESYSTEM], record=True), harness)

    assert refused.value.title == RECORDING_REFUSED
    assert refused.value.reasons == [f"{FILESYSTEM.server_package}: no answer"]


async def test_a_server_failing_both_benign_calls_refuses_a_recording(tmp_path: Path):
    harness = a_harness(
        tmp_path,
        scripted({}),
        benign_call={FILESYSTEM.server_package: ["first", "second"]},
    )

    with pytest.raises(Refused) as refused:
        await run_gate(options([FILESYSTEM], record=True), harness)

    assert refused.value.title == RECORDING_REFUSED
    assert refused.value.reasons == [f"{FILESYSTEM.server_package}: second"]


async def test_a_built_backend_container_left_running_is_removed_before_the_first_benign_call(
    tmp_path: Path,
):
    server = on_the_ckan_backend(FILESYSTEM)
    a_gated_file(tmp_path, server)
    containers = FakeContainerSweep.running_before_the_rebuild("stale_backend")
    harness, removed_at_benign_calls = given.watching_removals_at_each_benign_call(
        a_harness(
            tmp_path,
            scripted({server.server_package: clean_runs()}),
            containers=containers,
        ),
        containers,
    )

    await run_gate(options([server]), harness)

    assert removed_at_benign_calls == [["stale_backend"]]
