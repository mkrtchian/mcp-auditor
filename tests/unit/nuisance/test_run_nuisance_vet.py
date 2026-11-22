"""The `vet` subcommand's options, the defaults it builds its dependencies with, and its line on
whether each server answers the ping, on its first pass or its second."""

from pathlib import Path

import pytest

import tests.unit.nuisance.support.test_nuisance_holdout_run_backends_given as backends
import tests.unit.nuisance.support.test_nuisance_vet_given as given
import tests.unit.nuisance.support.test_nuisance_vetting_given as vetting_given
import tests.unit.nuisance.support.test_run_nuisance_given as run_given
from evals import run_nuisance
from evals.cve.environments import TOOL_CALL_TIMEOUT
from evals.cve.nuisance.holdout_run import NUISANCE_CONCURRENCY
from evals.cve.nuisance.vet_command import default_vet_deps


def test_vet_builds_its_deps_with_the_run_conditions_timeout_and_concurrency(tmp_path: Path):
    harness = given.VetHarness(given.deps_on(backends.DockerHost()), run_conditions_timeout=11)
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments], harness.deps) == 0

    assert harness.built_with == (11, NUISANCE_CONCURRENCY)


def test_vet_without_a_run_conditions_timeout_builds_its_deps_with_the_default_timeout(
    tmp_path: Path,
):
    harness = given.VetHarness(given.deps_on(backends.DockerHost()), run_conditions_timeout=None)
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments], harness.deps) == 0

    assert harness.built_with == (TOOL_CALL_TIMEOUT, NUISANCE_CONCURRENCY)


def test_vet_passes_the_timeout_and_concurrency_it_is_given(tmp_path: Path):
    harness = given.VetHarness(given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)
    options = ["--tool-call-timeout", "7", "--concurrency", "2"]

    assert run_nuisance.main(["vet", *arguments, *options], harness.deps) == 0

    assert harness.built_with == (7, 2)


def test_vet_counts_the_servers_with_unrecorded_fields_and_keeps_its_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    harness = given.VetHarness(given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(
        tmp_path, admitted=True, queue_server_unrecorded=True
    )

    assert run_nuisance.main(["vet", *arguments], harness.deps) == 0

    assert (
        "1 of 2 servers have fields nuisance suite rule v3 or v4 adds not yet recorded"
        " (run and gate refuse them)" in capsys.readouterr().out
    )


def test_vet_of_recorded_servers_prints_no_unrecorded_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    harness = given.VetHarness(given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments], harness.deps) == 0

    assert "not yet recorded" not in capsys.readouterr().out


async def test_the_default_vet_deps_record_whether_each_server_answers_the_ping():
    launches = vetting_given.launches_failing(failing=0, ping_answer=False)
    deps = default_vet_deps(tool_call_timeout=30, concurrency=1, launcher=launches.launcher)

    await deps.benign_call(vetting_given.a_server())

    assert deps.ping_answers == {vetting_given.a_server().server_package: False}


@pytest.mark.parametrize(
    ("ping_answers", "answer"),
    [({given.SERVER: True}, "yes"), ({given.SERVER: False}, "no"), ({}, "unknown")],
    ids=["answered", "silent", "never_connected"],
)
def test_vet_prints_whether_each_server_answers_the_ping(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    ping_answers: dict[str, bool],
    answer: str,
):
    harness = given.VetHarness(given.deps_on(backends.DockerHost(), ping_answers=ping_answers))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments], harness.deps) == 0

    assert f"{given.SERVER}: ok, answers the ping: {answer}" in capsys.readouterr().out


def test_a_server_failing_its_benign_call_while_answering_the_ping_still_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    failures = {run_given.QUEUE_SERVER: "benign call errored: ValueError"}
    answers = {run_given.QUEUE_SERVER: True}
    deps = given.deps_on(backends.DockerHost(), failures, ping_answers=answers)
    harness = given.VetHarness(deps)
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["vet", *arguments], harness.deps)

    assert exit_code == 1
    assert (
        f"{run_given.QUEUE_SERVER}: benign call errored: ValueError, answers the ping: yes"
        in capsys.readouterr().out
    )


def test_vet_prints_a_server_answering_only_its_second_pass_with_its_first_pass_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    failures = {run_given.QUEUE_SERVER: ["boom", None]}
    harness = given.VetHarness(given.deps_on(backends.DockerHost(), failures))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments], harness.deps) == 0

    out = capsys.readouterr().out
    assert (
        f"{run_given.QUEUE_SERVER}: ok, on its second pass (first pass: boom), answers the ping:"
        in out
    )
    assert f"{given.SERVER}: ok, answers the ping:" in out
