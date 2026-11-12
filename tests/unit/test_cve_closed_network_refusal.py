"""The eval commands with injected dependencies refuse on a Docker daemon that cannot create a
closed network, before any image is rebuilt."""

import dataclasses
from pathlib import Path

import pytest

import tests.unit.support.test_cve_closed_network_refusal_given as given
import tests.unit.support.test_cve_closed_network_refusal_then as then
import tests.unit.support.test_detection_holdout_run_given as holdout_given
import tests.unit.support.test_nuisance_gate_session_given as gate_given
import tests.unit.support.test_nuisance_run_backends_given as backends
import tests.unit.support.test_nuisance_run_given as run_given
import tests.unit.support.test_nuisance_vet_given as vet_given
from evals.cve.nuisance.gate_session import run_gate
from evals.cve.nuisance.vet_command import vet_servers
from evals.eval_session import Refused


async def test_a_nuisance_run_refuses_before_any_rebuild():
    server = run_given.a_server()
    host = backends.DockerHost()
    deps = dataclasses.replace(
        backends.deps_on(host, server), check_networks=given.a_daemon_that_cannot_close_a_network
    )

    with pytest.raises(Refused) as refused:
        await run_given.run([server], deps)

    then.refused_for_the_daemon(refused.value)
    assert host.rebuilt == []


async def test_a_vet_refuses_before_any_rebuild():
    host = backends.DockerHost()
    deps = dataclasses.replace(
        vet_given.deps_on(host), check_networks=given.a_daemon_that_cannot_close_a_network
    )

    with pytest.raises(Refused) as refused:
        await vet_servers([run_given.a_server()], deps)

    then.refused_for_the_daemon(refused.value)
    assert host.rebuilt == []


async def test_a_gate_refuses_before_any_rebuild(tmp_path: Path):
    rebuild = given.CountingRebuild()
    harness = dataclasses.replace(
        gate_given.a_harness(tmp_path, gate_given.scripted({})),
        rebuild=rebuild,
        check_networks=given.a_daemon_that_cannot_close_a_network,
    )

    with pytest.raises(Refused) as refused:
        await run_gate(gate_given.options([gate_given.FILESYSTEM]), harness)

    then.refused_for_the_daemon(refused.value)
    assert rebuild.rebuilt == []


async def test_a_holdout_run_refuses_before_any_rebuild():
    rebuild = given.CountingRebuild()
    deps = dataclasses.replace(
        holdout_given.deps_auditing(holdout_given.scripted({})),
        rebuild=rebuild,
        check_networks=given.a_daemon_that_cannot_close_a_network,
    )

    with pytest.raises(Refused) as refused:
        await holdout_given.run([holdout_given.a_target()], deps)

    then.refused_for_the_daemon(refused.value)
    assert rebuild.rebuilt == []
