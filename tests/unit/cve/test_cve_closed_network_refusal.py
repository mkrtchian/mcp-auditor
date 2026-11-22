"""The eval commands with injected dependencies refuse on a Docker daemon that cannot create a
closed network, before any image is rebuilt."""

import dataclasses
from pathlib import Path

import pytest

import tests.unit.cve.support.test_cve_closed_network_refusal_given as given
import tests.unit.cve.support.test_cve_closed_network_refusal_then as then
import tests.unit.nuisance.gate.support.nuisance_gate_sessions as gate_sessions
import tests.unit.support.nuisance_docker_hosts as docker_hosts
import tests.unit.support.nuisance_holdout_runs as holdout_runs
import tests.unit.support.nuisance_vets as vets
from evals.cve.nuisance.gate.gate_session import run_gate
from evals.cve.nuisance.vet_command import vet_servers
from evals.eval_session import Refused
from tests.unit.support import detection_holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target


async def test_a_nuisance_holdout_run_refuses_before_any_rebuild():
    server = holdout_runs.a_server()
    host = docker_hosts.DockerHost()
    deps = dataclasses.replace(
        docker_hosts.deps_on(host, server),
        check_networks=given.a_daemon_that_cannot_close_a_network,
    )

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([server], deps)

    then.refused_for_the_daemon(refused.value)
    assert host.rebuilt == []


async def test_a_vet_refuses_before_any_rebuild():
    host = docker_hosts.DockerHost()
    deps = dataclasses.replace(
        vets.deps_on(host), check_networks=given.a_daemon_that_cannot_close_a_network
    )

    with pytest.raises(Refused) as refused:
        await vet_servers([holdout_runs.a_server()], deps)

    then.refused_for_the_daemon(refused.value)
    assert host.rebuilt == []


async def test_a_gate_refuses_before_any_rebuild(tmp_path: Path):
    rebuild = given.CountingRebuild()
    harness = dataclasses.replace(
        gate_sessions.a_harness(tmp_path, gate_sessions.scripted({})),
        rebuild=rebuild,
        check_networks=given.a_daemon_that_cannot_close_a_network,
    )

    with pytest.raises(Refused) as refused:
        await run_gate(gate_sessions.options([gate_sessions.FILESYSTEM]), harness)

    then.refused_for_the_daemon(refused.value)
    assert rebuild.rebuilt == []


async def test_a_detection_holdout_run_refuses_before_any_rebuild():
    rebuild = given.CountingRebuild()
    deps = dataclasses.replace(
        detection_holdout_runs.deps_auditing(detection_holdout_runs.scripted({})),
        rebuild=rebuild,
        check_networks=given.a_daemon_that_cannot_close_a_network,
    )

    with pytest.raises(Refused) as refused:
        await detection_holdout_runs.run(
            [an_acceptance_target(FILESYSTEM, tools_filter=None)], deps
        )

    then.refused_for_the_daemon(refused.value)
    assert rebuild.rebuilt == []
