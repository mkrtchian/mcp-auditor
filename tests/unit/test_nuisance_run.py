"""The nuisance orchestrator, with the audit and the benign check injected as fakes. No Docker,
no LLM."""

import dataclasses

import pytest

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_run_given as given
from evals.cve.detection.holdout_run import HOLDOUT_BUDGET
from evals.cve.nuisance.audit import DroppedRun
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.results import NotRunCause, ServerExit
from evals.eval_session import Refused, TreeState
from evals.nuisance_admission import BackendFixture
from evals.nuisance_counter import counter_fingerprint
from evals.probe.analysis import call_cost
from mcp_auditor.domain.models import MissCause, ProviderUsage


async def test_every_audited_server_is_assembled_with_the_run_conditions():
    first, second = given.a_server("npm:first"), given.a_server("npm:second")
    usage = ProviderUsage(input_tokens=10, output_tokens=20)
    refused = given.an_audit(False, missed=MissCause.PROVIDER_REFUSAL, provider=usage)
    audit = given.scripted(
        {
            "npm:first": [given.an_audit(True, provider=usage) for _ in range(3)],
            "npm:second": [refused, given.an_audit(False), given.an_audit(False)],
        }
    )
    exits = [ServerExit("npm:walked", "marked by the walk")]

    result = await given.run([first, second], given.deps_auditing(audit), exits=exits)

    assert [server.server_package for server in result.servers] == ["npm:first", "npm:second"]
    assert result.budget == HOLDOUT_BUDGET
    assert result.commit == "c0ffee"
    assert result.recorded_at == given.RECORDED_AT
    assert result.counter_fingerprint == counter_fingerprint()
    assert result.fixture_fingerprints == {
        "npm:first": nuisance_fixture_fingerprint(first),
        "npm:second": nuisance_fixture_fingerprint(second),
    }
    assert result.exits == exits
    assert result.image_ids == {"filesystem-patched": "sha256:filesystem-patched"}
    assert result.not_run == []
    assert result.incomplete_run_count == 1
    assert result.total_cost == pytest.approx(sum(s.run_cost for s in result.servers))
    assert result.total_cost == pytest.approx(4 * call_cost(usage, given.LUNA_PRICE))


async def test_a_run_records_the_census_and_walk_record_commits_apart():
    audit = given.scripted({"npm:first": [given.an_audit(False) for _ in range(3)]})

    result = await given.run([given.a_server("npm:first")], given.deps_auditing(audit))

    assert (result.census_commit, result.walk_record_commit) == ("cafe", "beef")


async def test_the_run_announces_the_audits_of_the_surviving_servers_only():
    failing, healthy = given.a_server("npm:failing"), given.a_server("npm:healthy")
    audit = given.scripted({"npm:healthy": [given.an_audit(False) for _ in range(3)]})
    announced: list[int] = []
    deps = dataclasses.replace(
        given.deps_auditing(audit, benign_call={"npm:failing": "boom"}),
        announce_audits=announced.append,
    )

    await given.run([failing, healthy], deps, runs=3)

    assert announced == [3]


async def test_the_result_carries_the_concurrency_and_the_throttled_requests():
    server = given.a_server()
    audit = given.scripted({server.server_package: [given.an_audit(False) for _ in range(3)]})

    result = await given.run([server], given.deps_auditing(audit, throttled=7), concurrency=4)

    assert result.concurrency == 4
    assert result.throttled_requests == 7


async def test_a_backend_server_records_its_backend_image_beside_its_service():
    server = admission.with_a_backend(
        given.a_server(),
        BackendFixture(provisioner="doris", image="apache/doris:all-in-one-4.1.3", network="net"),
    )
    audit = given.scripted({server.server_package: [given.an_audit(False) for _ in range(3)]})

    result = await given.run([server], given.deps_auditing(audit))

    assert result.image_ids == {
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_a_server_failing_its_benign_call_is_never_audited():
    failing, kept = given.a_server("npm:failing"), given.a_server("npm:kept")
    audit = given.scripted(
        {"npm:failing": [], "npm:kept": [given.an_audit(False) for _ in range(3)]}
    )
    deps = given.deps_auditing(audit, benign_call={"npm:failing": "benign call errored"})

    result = await given.run([failing, kept], deps)

    (not_run,) = result.not_run
    assert (not_run.server_package, not_run.reason, not_run.cause) == (
        "npm:failing",
        "benign call errored",
        NotRunCause.BENIGN_CALL_FAILED,
    )
    (server,) = result.servers
    assert server.server_package == "npm:kept"
    assert server.runs == 3


async def test_a_server_dropped_in_one_run_is_not_run():
    dropped, kept = given.a_server("npm:dropped"), given.a_server("npm:kept")
    audit = given.scripted(
        {
            "npm:dropped": [
                given.an_audit(False),
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                given.an_audit(False),
            ],
            "npm:kept": [given.an_audit(False) for _ in range(3)],
        }
    )

    result = await given.run([dropped, kept], given.deps_auditing(audit))

    (not_run,) = result.not_run
    assert (not_run.server_package, not_run.cause) == ("npm:dropped", NotRunCause.LAUNCH_FAILURE)
    assert [server.server_package for server in result.servers] == ["npm:kept"]


async def test_throttled_wins_over_a_launch_failure():
    dropped, kept = given.a_server("npm:dropped"), given.a_server("npm:kept")
    audit = given.scripted(
        {
            "npm:dropped": [
                DroppedRun(NotRunCause.THROTTLED),
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                given.an_audit(False),
            ],
            "npm:kept": [given.an_audit(False) for _ in range(3)],
        }
    )

    result = await given.run([dropped, kept], given.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.cause == NotRunCause.THROTTLED


async def test_a_provider_error_wins_over_a_launch_failure():
    dropped, kept = given.a_server("npm:dropped"), given.a_server("npm:kept")
    audit = given.scripted(
        {
            "npm:dropped": [
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                DroppedRun(NotRunCause.PROVIDER_ERROR),
                given.an_audit(False),
            ],
            "npm:kept": [given.an_audit(False) for _ in range(3)],
        }
    )

    result = await given.run([dropped, kept], given.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.cause == NotRunCause.PROVIDER_ERROR


async def test_a_run_where_every_server_drops_is_refused_with_each_reason():
    failing, dropped = given.a_server("npm:failing"), given.a_server("npm:dropped")
    audit = given.scripted(
        {"npm:failing": [], "npm:dropped": [DroppedRun(NotRunCause.LAUNCH_FAILURE)] * 3}
    )
    deps = given.deps_auditing(audit, benign_call={"npm:failing": "benign call errored"})

    with pytest.raises(Refused) as refused:
        await given.run([failing, dropped], deps)

    assert "benign call errored" in refused.value.reasons
    assert "a run failed to launch after retries" in refused.value.reasons


async def test_tracing_refuses_before_the_tree_is_read(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    with pytest.raises(Refused):
        await given.run([given.a_server()], given.deps_reaching_nothing())


async def test_a_dirty_tree_refuses_before_any_rebuild_or_audit():
    deps = dataclasses.replace(
        given.deps_reaching_nothing(), read_tree=lambda: TreeState(commit="c0ffee", dirty=True)
    )

    with pytest.raises(Refused):
        await given.run([given.a_server()], deps)
