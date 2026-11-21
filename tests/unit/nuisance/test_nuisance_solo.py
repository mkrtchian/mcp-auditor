"""The servers played alone: their benign calls, audits and retests run after the other
servers', one at a time, while the others keep running together up to the concurrency bound.
No Docker, no LLM."""

from pathlib import Path

import pytest

import tests.unit.nuisance.gate.support.nuisance_gate_sessions as gate_sessions
import tests.unit.nuisance.support.test_nuisance_run_given as run_given
import tests.unit.nuisance.support.test_nuisance_solo_given as given
import tests.unit.nuisance.support.test_nuisance_solo_then as then
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.gate.gate_session import run_gate
from evals.cve.nuisance.vet_command import vet_servers
from evals.gate_outcome import GateOutcome


async def test_vet_makes_the_solo_benign_call_alone_after_the_others():
    others = given.others(3)
    servers = [given.SOLO_SERVER, *others]
    in_flight = given.InFlight()

    result = await vet_servers(servers, given.vet_deps(in_flight))

    then.each_played_alone_after_the_others(in_flight, [given.SOLO_SERVER], calls=1)
    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert result.surviving == servers


# Deliberate friction: the 2026-11-16 nuisance suite log decision plays heavy backends together.
@pytest.mark.parametrize("heavy", given.HEAVY_BACKEND_SERVERS, ids=lambda s: s.server_package)
async def test_vet_plays_a_heavy_backend_server_beside_the_others(heavy: AdmittedServer):
    servers = [heavy, given.SOLO_SERVER, *given.others(2)]
    in_flight = given.InFlight()

    result = await vet_servers(servers, given.vet_deps(in_flight))

    then.played_beside_another_server(in_flight, heavy)
    then.each_played_alone_after_the_others(in_flight, [given.SOLO_SERVER], calls=1)
    assert result.surviving == servers


async def test_vet_without_a_solo_server_plays_every_server_together():
    others = given.others(3)
    in_flight = given.InFlight()

    result = await vet_servers(others, given.vet_deps(in_flight))

    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert result.surviving == others


async def test_run_plays_the_solo_benign_call_and_audits_alone_after_the_others():
    others = given.others(3)
    servers = [given.SOLO_SERVER, *others]
    in_flight = given.InFlight()

    result = await run_given.run(servers, given.run_deps(in_flight, servers), runs=given.RUNS)

    then.each_played_alone_after_the_others(in_flight, [given.SOLO_SERVER], calls=1 + given.RUNS)
    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert [server.server_package for server in result.servers] == [
        server.server_package for server in servers
    ]


async def test_gate_plays_the_solo_benign_call_audits_and_retests_alone(tmp_path: Path):
    others = given.others(2)
    servers = [given.SOLO_SERVER, *others]
    in_flight = given.InFlight()
    harness = given.gate_harness_with_alarms(tmp_path, in_flight, servers)

    session = await run_gate(gate_sessions.options(servers), harness)

    calls = 1 + len(given.GATE_AUDITS)
    then.each_played_alone_after_the_others(in_flight, [given.SOLO_SERVER], calls=calls)
    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert session.gate.outcome == GateOutcome.GREEN
