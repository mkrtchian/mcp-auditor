"""A nuisance holdout run stopped by an exception out of a server's runs: the pending servers are
cancelled and the finished ones are kept in a partial result. No Docker, no LLM."""

import pytest

import tests.unit.nuisance.support.test_nuisance_holdout_run_interrupted_given as given
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance.results import NuisanceHoldoutRunResult
from evals.cve.run_files import RunInterrupted
from evals.model_provider_errors import ProviderFatal


async def test_a_fatal_provider_error_keeps_the_finished_server_in_a_partial_result():
    servers = [
        holdout_runs.a_server(package) for package in ("npm:done", "npm:failing", "npm:pending")
    ]
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit("npm:done", "npm:failing", fatal)

    with pytest.raises(RunInterrupted) as interrupted:
        await holdout_runs.run(servers, holdout_runs.deps_auditing(audit))

    assert interrupted.value.cause is fatal
    partial = interrupted.value.partial
    assert isinstance(partial, NuisanceHoldoutRunResult)
    assert partial.partial
    assert [server.server_package for server in partial.servers] == ["npm:done"]


async def test_the_runs_still_in_flight_are_cancelled():
    servers = [
        holdout_runs.a_server(package) for package in ("npm:done", "npm:failing", "npm:pending")
    ]
    fatal = ProviderFatal(PermissionError("the key was revoked"))
    audit = given.InterruptingAudit("npm:done", "npm:failing", fatal)

    with pytest.raises(RunInterrupted):
        await holdout_runs.run(servers, holdout_runs.deps_auditing(audit))

    assert set(audit.cancelled) == {"npm:failing", "npm:pending"}


async def test_any_other_exception_interrupts_the_run_the_same_way():
    servers = [holdout_runs.a_server(package) for package in ("npm:done", "npm:failing")]
    bug = KeyError("a bug in the run")
    audit = given.InterruptingAudit("npm:done", "npm:failing", bug)

    with pytest.raises(RunInterrupted) as interrupted:
        await holdout_runs.run(servers, holdout_runs.deps_auditing(audit))

    assert interrupted.value.cause is bug
    partial = interrupted.value.partial
    assert isinstance(partial, NuisanceHoldoutRunResult)
    assert [server.server_package for server in partial.servers] == ["npm:done"]


async def test_the_partial_result_names_the_servers_run_after_their_second_pass():
    servers = [holdout_runs.a_server(package) for package in ("npm:done", "npm:failing")]
    audit = given.InterruptingAudit("npm:done", "npm:failing", KeyError("a bug in the run"))
    deps = holdout_runs.deps_auditing(audit, benign_call={"npm:done": ["boom", None]})

    with pytest.raises(RunInterrupted) as interrupted:
        await holdout_runs.run(servers, deps)

    partial = interrupted.value.partial
    assert isinstance(partial, NuisanceHoldoutRunResult)
    assert partial.partial
    assert partial.second_pass == {"npm:done": "boom"}
