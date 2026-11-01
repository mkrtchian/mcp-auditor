"""The `vet` subcommand's options and the defaults it builds its dependencies with."""

from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_run_backends_given as backends
import tests.unit.support.test_nuisance_vet_given as given
import tests.unit.support.test_run_nuisance_given as run_given
from evals import run_nuisance
from evals.cve_environments import TOOL_CALL_TIMEOUT
from evals.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.nuisance_run import NUISANCE_CONCURRENCY


def test_vet_builds_its_deps_with_the_run_conditions_timeout_and_concurrency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = given.VetHarness(monkeypatch, given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    assert run_nuisance.main(["vet", *arguments]) == 0

    timeout = load_conditions(CONDITIONS_PATH).tool_call_timeout or TOOL_CALL_TIMEOUT
    assert harness.built_with == (timeout, NUISANCE_CONCURRENCY)


def test_vet_passes_the_timeout_and_concurrency_it_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    harness = given.VetHarness(monkeypatch, given.deps_on(backends.DockerHost()))
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)
    options = ["--tool-call-timeout", "7", "--concurrency", "2"]

    assert run_nuisance.main(["vet", *arguments, *options]) == 0

    assert harness.built_with == (7, 2)
