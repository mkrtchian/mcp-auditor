"""A server played alone: its benign calls, audits and replays run after the other servers', one
at a time, while the others keep running together up to the concurrency bound. No Docker, no
LLM."""

from pathlib import Path

import tests.unit.support.test_nuisance_gate_session_given as gate_given
import tests.unit.support.test_nuisance_run_given as run_given
import tests.unit.support.test_nuisance_solo_given as given
import tests.unit.support.test_nuisance_solo_then as then
from evals.gate_outcome import GateOutcome
from evals.nuisance_gate_session import run_gate
from evals.nuisance_vet_command import vet_servers

MAGENTO2 = given.MAGENTO2.server_package


async def test_vet_makes_the_solo_benign_call_alone_after_the_others():
    others = given.others(3)
    in_flight = given.InFlight()

    result = await vet_servers([given.MAGENTO2, *others], given.vet_deps(in_flight))

    then.played_alone(in_flight, MAGENTO2, calls=1)
    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert result.surviving == [given.MAGENTO2, *others]


async def test_vet_without_a_solo_server_plays_every_server_together():
    others = given.others(3)
    in_flight = given.InFlight()

    result = await vet_servers(others, given.vet_deps(in_flight))

    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert result.surviving == others


async def test_run_plays_the_solo_benign_call_and_audits_alone_after_the_others():
    others = given.others(3)
    servers = [given.MAGENTO2, *others]
    in_flight = given.InFlight()

    result = await run_given.run(servers, given.run_deps(in_flight, servers), runs=3)

    then.played_alone(in_flight, MAGENTO2, calls=4)
    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert [server.server_package for server in result.servers] == [
        server.server_package for server in servers
    ]


async def test_gate_plays_the_solo_benign_call_audits_and_replays_alone(tmp_path: Path):
    others = given.others(2)
    servers = [given.MAGENTO2, *others]
    in_flight = given.InFlight()
    harness = given.gate_harness_with_alarms(tmp_path, in_flight, servers)

    session = await run_gate(gate_given.options(servers), harness)

    then.played_alone(in_flight, MAGENTO2, calls=6)
    then.played_together(in_flight, [s.server_package for s in others], peak=given.BOUND)
    assert session.gate.verdict == GateOutcome.GREEN
