"""The nuisance `vet` command: the run's images rebuilt, each audited server's benign calls made on
the run's launch path, and the run's container hygiene around them. No Docker, no LLM."""

import dataclasses
from pathlib import Path

import pytest

import tests.unit.nuisance.support.nuisance_queue_walks as queue_walks
import tests.unit.nuisance.support.test_nuisance_vet_given as given
import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_docker_hosts as docker_hosts
import tests.unit.support.nuisance_holdout_runs as holdout_runs
import tests.unit.support.nuisance_vets as vets
from evals import run_nuisance
from evals.cve.nuisance.commands import UNKNOWN_SERVER_EXIT
from evals.cve.nuisance.vet_command import VetDeps, vet_servers
from evals.eval_session import Refused
from tests.fakes import FakeContainerSweep


def test_every_server_answering_exits_zero_with_the_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    harness = vets.VetHarness(vets.deps_on(docker_hosts.DockerHost()))
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"{vets.SERVER}: ok" in out
    assert f"{queue_walks.QUEUE_SERVER}: ok" in out
    assert "2 of 2 servers answer their benign calls" in out


def test_a_server_failing_its_benign_call_exits_one_with_its_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    failures = {queue_walks.QUEUE_SERVER: "benign call errored: ValueError"}
    harness = vets.VetHarness(vets.deps_on(docker_hosts.DockerHost(), failures))
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    out = capsys.readouterr().out
    assert exit_code == 1
    assert f"{queue_walks.QUEUE_SERVER}: benign call errored: ValueError" in out
    assert "1 of 2 servers answer their benign calls" in out


def test_a_server_answering_only_its_second_pass_exits_zero_among_the_answering_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    failures = {queue_walks.QUEUE_SERVER: ["benign call errored: ValueError", None]}
    harness = vets.VetHarness(vets.deps_on(docker_hosts.DockerHost(), failures))
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    assert exit_code == 0
    assert "2 of 2 servers answer their benign calls" in capsys.readouterr().out


def test_a_server_failing_both_passes_exits_one_with_its_second_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    failures = {queue_walks.QUEUE_SERVER: ["first failure", "second failure"]}
    harness = vets.VetHarness(vets.deps_on(docker_hosts.DockerHost(), failures))
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    out = capsys.readouterr().out
    assert exit_code == 1
    assert f"{queue_walks.QUEUE_SERVER}: second failure, answers the ping:" in out
    assert "first failure" not in out


def test_a_server_container_running_at_start_refuses_with_nothing_rebuilt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    host = docker_hosts.DockerHost({given.SERVER_TAG: ["leftover_server"]})
    harness = vets.VetHarness(vets.deps_on(host))
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    assert exit_code == 3
    assert "leftover_server" in capsys.readouterr().out
    assert host.rebuilt == []
    assert host.removed == []


async def test_a_server_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    containers = FakeContainerSweep.appearing_after_the_rebuild("concurrent_server")
    deps = dataclasses.replace(
        vets.deps_on(docker_hosts.DockerHost()),
        sweep=containers.sweep,
    )

    with pytest.raises(Refused) as refused:
        await vet_servers([holdout_runs.a_server()], deps)

    assert any("concurrent_server" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_a_running_responder_container_is_removed_and_the_vet_goes_on():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost({docker_hosts.CKAN_TAG: ["stale_responder"]})

    result = await vet_servers([server], vets.deps_on(host))

    assert "stale_responder" in host.removed
    assert "stale_responder" not in host.running_at_rebuild
    assert result.surviving == [server]
    assert host.rebuilt == ["filesystem-patched", *docker_hosts.CKAN_SERVICES]


async def test_the_server_and_backend_containers_left_at_the_end_are_removed():
    server = mutations.on_the_ckan_backend(holdout_runs.a_server())
    host = docker_hosts.DockerHost()

    await vet_servers([server], vets.deps_on(host))

    assert sorted(host.removed) == ["ckan_started", "filesystem-patched_left"]


def test_a_failing_rebuild_exits_four_and_prints_the_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    deps: VetDeps = dataclasses.replace(
        vets.deps_on(docker_hosts.DockerHost()), rebuild=given.a_failing_rebuild
    )
    harness = vets.VetHarness(deps)
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    assert exit_code == 4
    assert "docker compose build failed for filesystem-nuisance" in capsys.readouterr().err


def test_the_server_option_restricts_the_vet_to_the_named_servers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    host = docker_hosts.DockerHost()
    harness = vets.VetHarness(vets.deps_on(host))
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(
        ["vet", *arguments, "--server", queue_walks.QUEUE_SERVER], harness.deps
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert vets.SERVER not in out
    assert "1 of 1 servers answer their benign calls" in out
    assert host.rebuilt == ["queued-nuisance"]


@pytest.mark.parametrize("named", ["npm:ghost", given.ACCEPTANCE])
def test_the_server_option_naming_no_audited_server_exits_two_naming_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], named: str
):
    host = docker_hosts.DockerHost()
    harness = vets.VetHarness(vets.deps_on(host))
    arguments = given.a_vet_of_one_server_beside_the_acceptance_one(tmp_path)

    exit_code = run_nuisance.main([*arguments, "--server", named], harness.deps)

    assert exit_code == UNKNOWN_SERVER_EXIT
    assert named in capsys.readouterr().err
    assert host.rebuilt == []


def test_a_nuisance_acceptance_server_is_not_vetted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    host = docker_hosts.DockerHost()
    harness = vets.VetHarness(vets.deps_on(host))
    arguments = given.a_vet_of_one_server_beside_the_acceptance_one(tmp_path)

    exit_code = run_nuisance.main(arguments, harness.deps)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert given.ACCEPTANCE not in out
    assert "1 of 1 servers answer their benign calls" in out
    assert host.rebuilt == ["filesystem-nuisance"]


def test_vet_without_an_admission_exits_zero_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=False)

    exit_code = run_nuisance.main(["vet", *arguments])

    assert exit_code == 0
    assert "no server is admitted" in capsys.readouterr().out
