"""The `vet` subcommand's options and the defaults it builds its dependencies with."""

from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_run_backends_given as backends
import tests.unit.support.test_nuisance_vet_given as given
import tests.unit.support.test_run_nuisance_given as run_given
from evals import run_nuisance
from evals.cve_environments import TOOL_CALL_TIMEOUT
from evals.nuisance_run import NUISANCE_CONCURRENCY


def test_vet_builds_its_deps_with_the_run_conditions_timeout_and_concurrency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = given.VetHarness(
        monkeypatch, given.deps_on(backends.DockerHost()), run_conditions_timeout=11
    )
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments]) == 0

    assert harness.built_with == (11, NUISANCE_CONCURRENCY)


def test_vet_without_a_run_conditions_timeout_builds_its_deps_with_the_default_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = given.VetHarness(
        monkeypatch, given.deps_on(backends.DockerHost()), run_conditions_timeout=None
    )
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments]) == 0

    assert harness.built_with == (TOOL_CALL_TIMEOUT, NUISANCE_CONCURRENCY)


def test_vet_passes_the_timeout_and_concurrency_it_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = given.VetHarness(monkeypatch, given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)
    options = ["--tool-call-timeout", "7", "--concurrency", "2"]

    assert run_nuisance.main(["vet", *arguments, *options]) == 0

    assert harness.built_with == (7, 2)


def test_vet_counts_the_servers_with_unrecorded_fields_and_keeps_its_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.VetHarness(monkeypatch, given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(
        tmp_path, admitted=True, queue_server_unrecorded=True
    )

    assert run_nuisance.main(["vet", *arguments]) == 0

    assert (
        "1 of 2 servers have fields rule v3 or v4 adds not yet recorded (run and gate refuse them)"
        in capsys.readouterr().out
    )


def test_vet_of_recorded_servers_prints_no_unrecorded_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.VetHarness(monkeypatch, given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments]) == 0

    assert "not yet recorded" not in capsys.readouterr().out
