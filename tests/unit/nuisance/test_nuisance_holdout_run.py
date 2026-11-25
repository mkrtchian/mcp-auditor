"""The nuisance orchestrator, with the audit and the benign check injected as fakes. No Docker,
no LLM."""

import dataclasses

import pytest

import tests.unit.nuisance.support.test_nuisance_holdout_run_then as then
import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.holdout_conditions import HOLDOUT_TEST_BUDGET
from evals.cve.nuisance.admission.admission import BackendFixture
from evals.cve.nuisance.audit import DroppedRun
from evals.cve.nuisance.counter import counter_fingerprint
from evals.cve.nuisance.exits import ExitReason
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.results import NotRunCause, ServerExit
from evals.cve.nuisance.solo import SOLO_SERVERS
from evals.eval_session import Refused, TreeState
from evals.pricing import call_cost
from mcp_auditor.domain.model_calls import MissedCallCause
from mcp_auditor.domain.models import ProviderUsage
from tests.unit.support import holdout_run_conditions


async def test_every_audited_server_is_assembled_with_the_run_conditions():
    first, second = holdout_runs.a_server("npm:first"), holdout_runs.a_server("npm:second")
    usage = ProviderUsage(input_tokens=10, output_tokens=20)
    refused = holdout_runs.an_audit(False, missed=MissedCallCause.PROVIDER_REFUSAL, provider=usage)
    audit = holdout_runs.scripted(
        {
            "npm:first": [holdout_runs.an_audit(True, provider=usage) for _ in range(3)],
            "npm:second": [refused, holdout_runs.an_audit(False), holdout_runs.an_audit(False)],
        }
    )
    exits = [ServerExit("npm:walked", ExitReason.EXCLUDED_SERVER)]

    result = await holdout_runs.run([first, second], holdout_runs.deps_auditing(audit), exits=exits)

    assert [server.server_package for server in result.servers] == ["npm:first", "npm:second"]
    assert result.budget == HOLDOUT_TEST_BUDGET
    assert result.commit == "c0ffee"
    assert result.recorded_at == holdout_runs.RECORDED_AT
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
    assert result.total_cost == pytest.approx(
        4 * call_cost(usage, holdout_run_conditions.LUNA_PRICE)
    )


async def test_a_run_records_the_census_walk_record_and_admission_commits_apart():
    audit = holdout_runs.scripted({"npm:first": holdout_runs.clean_audits()})

    result = await holdout_runs.run(
        [holdout_runs.a_server("npm:first")], holdout_runs.deps_auditing(audit)
    )

    assert (result.census_commit, result.walk_record_commit, result.admission_commit) == (
        "cafe",
        "beef",
        "f00d",
    )


async def test_a_run_carries_the_servers_whose_admission_is_pending():
    audit = holdout_runs.scripted({"npm:first": holdout_runs.clean_audits()})

    result = await holdout_runs.run(
        [holdout_runs.a_server("npm:first")],
        holdout_runs.deps_auditing(audit),
        pending=["npm:pending"],
    )

    assert result.pending_admission == ["npm:pending"]


async def test_the_run_announces_the_audits_of_the_surviving_servers_only():
    failing, healthy = holdout_runs.a_server("npm:failing"), holdout_runs.a_server("npm:healthy")
    audit = holdout_runs.scripted({"npm:healthy": holdout_runs.clean_audits()})
    announced: list[int] = []
    deps = dataclasses.replace(
        holdout_runs.deps_auditing(audit, benign_call={"npm:failing": "boom"}),
        announce_audits=announced.append,
    )

    await holdout_runs.run([failing, healthy], deps, runs=3)

    assert announced == [3]


async def test_the_run_announces_each_finished_run_of_a_server_with_its_status():
    flagged, dropped = holdout_runs.a_server("npm:flagged"), holdout_runs.a_server("npm:dropped")
    solo_package = min(SOLO_SERVERS)
    solo = holdout_runs.a_server(solo_package)
    flagged_runs = [holdout_runs.an_audit(True), holdout_runs.an_audit(False)]
    dropped_runs = [DroppedRun(NotRunCause.LAUNCH_FAILURE), holdout_runs.an_audit(False)]
    solo_runs = [
        holdout_runs.an_audit(False),
        holdout_runs.an_audit(False, missed=MissedCallCause.UNREADABLE_ANSWER),
    ]
    audit = holdout_runs.scripted(
        {"npm:flagged": flagged_runs, "npm:dropped": dropped_runs, solo_package: solo_runs}
    )
    announced: list[str] = []

    await holdout_runs.run(
        [solo, flagged, dropped], holdout_runs.deps_auditing(audit, announced=announced), runs=2
    )

    then.runs_announced(
        announced,
        together=[
            *((flagged, outcome) for outcome in flagged_runs),
            *((dropped, outcome) for outcome in dropped_runs),
        ],
        alone=[(solo, outcome) for outcome in solo_runs],
    )


async def test_a_run_with_no_surviving_server_announces_no_run():
    announced: list[str] = []
    deps = holdout_runs.deps_auditing(
        holdout_runs.scripted({"npm:failing": []}),
        benign_call={"npm:failing": "benign call errored"},
        announced=announced,
    )

    with pytest.raises(Refused):
        await holdout_runs.run([holdout_runs.a_server("npm:failing")], deps)

    assert announced == []


async def test_the_result_carries_the_concurrency_and_the_throttled_requests():
    server = holdout_runs.a_server()
    audit = holdout_runs.scripted({server.server_package: holdout_runs.clean_audits()})

    result = await holdout_runs.run(
        [server], holdout_runs.deps_auditing(audit, throttled=7), concurrency=4
    )

    assert result.concurrency == 4
    assert result.throttled_requests == 7


async def test_the_run_conditions_carry_one_id_per_image_of_a_two_image_backend():
    two_images = BackendFixture(
        provisioner="doris", images=["front:1.0", "back:1.0"], network="net"
    )
    server = mutations.with_a_backend(holdout_runs.a_server(), two_images)
    audit = holdout_runs.scripted({server.server_package: holdout_runs.clean_audits()})

    result = await holdout_runs.run([server], holdout_runs.deps_auditing(audit))

    assert result.image_ids == {
        "filesystem-patched": "sha256:filesystem-patched",
        "front:1.0": "sha256:front:1.0",
        "back:1.0": "sha256:back:1.0",
    }


async def test_a_server_failing_its_benign_call_is_never_audited():
    failing, kept = holdout_runs.a_server("npm:failing"), holdout_runs.a_server("npm:kept")
    audit = holdout_runs.scripted({"npm:failing": [], "npm:kept": holdout_runs.clean_audits()})
    deps = holdout_runs.deps_auditing(audit, benign_call={"npm:failing": "benign call errored"})

    result = await holdout_runs.run([failing, kept], deps)

    (not_run,) = result.not_run
    assert (not_run.server_package, not_run.reason, not_run.cause) == (
        "npm:failing",
        "benign call errored",
        NotRunCause.BENIGN_CALL_FAILED,
    )
    (server,) = result.servers
    assert server.server_package == "npm:kept"
    assert server.runs == 3


async def test_a_server_answering_only_its_second_pass_is_audited_with_its_first_reason():
    flaky, steady = holdout_runs.a_server("npm:flaky"), holdout_runs.a_server("npm:steady")
    audit = holdout_runs.scripted(
        {package: holdout_runs.clean_audits() for package in ("npm:flaky", "npm:steady")}
    )
    deps = holdout_runs.deps_auditing(audit, benign_call={"npm:flaky": ["boom", None]})

    result = await holdout_runs.run([flaky, steady], deps)

    assert [server.server_package for server in result.servers] == ["npm:flaky", "npm:steady"]
    assert result.not_run == []
    assert result.second_pass == {"npm:flaky": "boom"}


async def test_a_run_where_every_server_answers_its_first_pass_has_no_second_pass():
    audit = holdout_runs.scripted({"npm:first": holdout_runs.clean_audits()})

    result = await holdout_runs.run(
        [holdout_runs.a_server("npm:first")], holdout_runs.deps_auditing(audit)
    )

    assert result.second_pass == {}


async def test_a_server_dropped_in_one_run_is_not_run():
    dropped, kept = holdout_runs.a_server("npm:dropped"), holdout_runs.a_server("npm:kept")
    audit = holdout_runs.scripted(
        {
            "npm:dropped": [
                holdout_runs.an_audit(False),
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                holdout_runs.an_audit(False),
            ],
            "npm:kept": holdout_runs.clean_audits(),
        }
    )

    result = await holdout_runs.run([dropped, kept], holdout_runs.deps_auditing(audit))

    (not_run,) = result.not_run
    assert (not_run.server_package, not_run.cause) == ("npm:dropped", NotRunCause.LAUNCH_FAILURE)
    assert [server.server_package for server in result.servers] == ["npm:kept"]


async def test_throttled_wins_over_a_launch_failure():
    dropped, kept = holdout_runs.a_server("npm:dropped"), holdout_runs.a_server("npm:kept")
    audit = holdout_runs.scripted(
        {
            "npm:dropped": [
                DroppedRun(NotRunCause.THROTTLED),
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                holdout_runs.an_audit(False),
            ],
            "npm:kept": holdout_runs.clean_audits(),
        }
    )

    result = await holdout_runs.run([dropped, kept], holdout_runs.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.cause == NotRunCause.THROTTLED


async def test_a_provider_error_wins_over_a_launch_failure():
    dropped, kept = holdout_runs.a_server("npm:dropped"), holdout_runs.a_server("npm:kept")
    audit = holdout_runs.scripted(
        {
            "npm:dropped": [
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                DroppedRun(NotRunCause.PROVIDER_ERROR),
                holdout_runs.an_audit(False),
            ],
            "npm:kept": holdout_runs.clean_audits(),
        }
    )

    result = await holdout_runs.run([dropped, kept], holdout_runs.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.cause == NotRunCause.PROVIDER_ERROR


async def test_a_run_where_every_server_drops_is_refused_with_each_reason():
    failing, dropped = holdout_runs.a_server("npm:failing"), holdout_runs.a_server("npm:dropped")
    audit = holdout_runs.scripted(
        {"npm:failing": [], "npm:dropped": [DroppedRun(NotRunCause.LAUNCH_FAILURE)] * 3}
    )
    deps = holdout_runs.deps_auditing(audit, benign_call={"npm:failing": "benign call errored"})

    with pytest.raises(Refused) as refused:
        await holdout_runs.run([failing, dropped], deps)

    assert "benign call errored" in refused.value.reasons
    assert "a run failed to launch after retries" in refused.value.reasons


async def test_tracing_refuses_before_the_tree_is_read(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    with pytest.raises(Refused):
        await holdout_runs.run([holdout_runs.a_server()], holdout_runs.deps_reaching_nothing())


async def test_a_dirty_tree_refuses_before_any_rebuild_or_audit():
    deps = dataclasses.replace(
        holdout_runs.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=True),
    )

    with pytest.raises(Refused):
        await holdout_runs.run([holdout_runs.a_server()], deps)
