"""The nuisance orchestrator and its per-server assembly, with the audit and the benign check
injected as fakes. No Docker, no LLM."""

import dataclasses
from datetime import date

import pytest

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_run_given as given
from evals.cve_grammar import MechanismClass
from evals.eval_session import Refused, TreeState
from evals.holdout_run import HOLDOUT_BUDGET
from evals.nuisance_admission import BackendFixture
from evals.nuisance_assembly import assemble_server, split_flaw_of
from evals.nuisance_audit import DroppedRun
from evals.nuisance_counter import counter_fingerprint
from evals.nuisance_images import nuisance_fixture_fingerprint
from evals.nuisance_results import FigureExit, NotRunCause, NuisanceRunStatus, RunInterrupted
from evals.nuisance_run import benign_call
from evals.probe import call_cost
from evals.provider_errors import ProviderFatal
from mcp_auditor.domain.models import MissCause, ProviderUsage, ToolResponse

_EARLY = date(2025, 3, 1)
_LATE = date(2026, 4, 1)
_PRICES = (given.LUNA_PRICE, given.LUNA_PRICE)


@pytest.fixture(autouse=True)
def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


def test_the_split_flaw_is_the_first_counted_flaw_in_draw_order():
    server = given.a_two_flaw_server()
    draw = given.draw_entries((given.SECOND_FLAW, _LATE), (given.FIRST_FLAW, _EARLY))

    split = split_flaw_of(server, draw)

    assert split is not None
    assert (split.identifier, split.disclosure_date) == (given.SECOND_FLAW, _LATE)


def test_a_counted_flaw_absent_from_the_draw_order_is_never_the_split_flaw():
    server = given.a_two_flaw_server()

    assert split_flaw_of(server, given.draw_entries(("CVE-2099-0001", _EARLY))) is None


def test_a_flaw_with_no_counted_tool_is_skipped_for_the_next():
    needing_a_backend = admission.a_flaw_record(
        given.SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, admission.PATCHED_VERSION
    ).model_copy(update={"backend_need": "external"})
    server = given.a_server(flaws=[given.a_two_flaw_server().flaws[0], needing_a_backend])
    draw = given.draw_entries((given.SECOND_FLAW, _LATE), (given.FIRST_FLAW, _EARLY))

    split = split_flaw_of(server, draw)

    assert split is not None and split.identifier == given.FIRST_FLAW


def test_a_server_is_assembled_from_its_reports_in_run_order():
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    judge = ProviderUsage(input_tokens=100, output_tokens=200)
    reports = [
        given.a_report(True, provider=provider, judge=judge),
        given.a_report(True, missed=MissCause.PROVIDER_REFUSAL, provider=provider, judge=judge),
        given.a_report(False, missed=MissCause.UNREADABLE_ANSWER, provider=provider, judge=judge),
    ]
    draw = given.draw_entries((given.FIRST_FLAW, _EARLY))

    result = assemble_server(given.a_server(), reports, draw, _PRICES)

    assert result.statuses == (
        NuisanceRunStatus(flagged=True, split_flagged=True, incomplete=False, raw_fail_count=1),
        NuisanceRunStatus(True, True, True, 1),
        NuisanceRunStatus(False, False, True, 0),
    )
    assert result.flagged_per_run == [True, True, False]
    assert result.flagged_runs == 2
    assert result.flagged_share == pytest.approx(2 / 3)
    assert result.incomplete_runs == 2
    assert result.incomplete_unflagged_runs == 1
    assert result.raw_fail_per_run == [1, 1, 0]
    assert (result.counted_tools_count, result.tools_count) == (1, 1)
    generator = reports[0].generator_usage
    one_run = call_cost(generator, given.LUNA_PRICE) + call_cost(judge, given.LUNA_PRICE)
    assert result.run_cost == pytest.approx(3 * one_run)
    assert (result.split_flaw, result.split_disclosure_date) == (given.FIRST_FLAW, _EARLY)


def test_a_flag_on_a_tool_of_another_flaw_is_not_split_flagged():
    draw = given.draw_entries((given.SECOND_FLAW, _LATE), (given.FIRST_FLAW, _EARLY))
    reports = [given.a_report(True) for _ in range(3)]

    result = assemble_server(given.a_two_flaw_server(), reports, draw, _PRICES)

    assert result.split_flaw == given.SECOND_FLAW
    assert result.flagged_runs == 3
    assert [status.split_flagged for status in result.statuses] == [False, False, False]
    assert result.split_flagged_runs == 0


async def test_every_audited_server_is_assembled_with_the_run_conditions():
    first, second = given.a_server("npm:first"), given.a_server("npm:second")
    usage = ProviderUsage(input_tokens=10, output_tokens=20)
    refused = given.a_report(False, missed=MissCause.PROVIDER_REFUSAL, provider=usage)
    audit = given.scripted(
        {
            "npm:first": [given.a_report(True, provider=usage) for _ in range(3)],
            "npm:second": [refused, given.a_report(False), given.a_report(False)],
        }
    )
    exits = [FigureExit("npm:walked", "marked by the walk")]

    result = await given.run([first, second], given.deps_auditing(audit), outside_figure=exits)

    assert [server.server_package for server in result.servers] == ["npm:first", "npm:second"]
    assert result.budget == HOLDOUT_BUDGET
    assert result.commit == "c0ffee"
    assert result.recorded_at == given.RECORDED_AT
    assert result.counter_fingerprint == counter_fingerprint()
    assert result.fixture_fingerprints == {
        "npm:first": nuisance_fixture_fingerprint(first),
        "npm:second": nuisance_fixture_fingerprint(second),
    }
    assert result.outside_figure == exits
    assert result.image_ids == {"filesystem-patched": "sha256:filesystem-patched"}
    assert result.not_run == []
    assert result.incomplete_run_count == 1
    assert result.total_cost == pytest.approx(sum(s.run_cost for s in result.servers))
    assert result.total_cost == pytest.approx(4 * call_cost(usage, given.LUNA_PRICE))


async def test_the_run_announces_the_audits_of_the_surviving_servers_only():
    failing, healthy = given.a_server("npm:failing"), given.a_server("npm:healthy")
    audit = given.scripted({"npm:healthy": [given.a_report(False) for _ in range(3)]})
    announced: list[int] = []
    deps = dataclasses.replace(
        given.deps_auditing(audit, benign_call={"npm:failing": "boom"}),
        announce_audits=announced.append,
    )

    await given.run([failing, healthy], deps, runs=3)

    assert announced == [3]


async def test_the_result_carries_the_concurrency_and_the_throttled_requests():
    server = given.a_server()
    audit = given.scripted({server.server_package: [given.a_report(False) for _ in range(3)]})

    result = await given.run([server], given.deps_auditing(audit, throttled=7), concurrency=4)

    assert result.concurrency == 4
    assert result.throttled_requests == 7


async def test_a_backend_server_records_its_backend_image_beside_its_service():
    server = admission.with_a_backend(
        given.a_server(),
        BackendFixture(provisioner="doris", image="apache/doris:all-in-one-4.1.3", network="net"),
    )
    audit = given.scripted({server.server_package: [given.a_report(False) for _ in range(3)]})

    result = await given.run([server], given.deps_auditing(audit))

    assert result.image_ids == {
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_a_server_failing_its_benign_call_is_never_audited():
    failing, kept = given.a_server("npm:failing"), given.a_server("npm:kept")
    audit = given.scripted(
        {"npm:failing": [], "npm:kept": [given.a_report(False) for _ in range(3)]}
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
                given.a_report(False),
                DroppedRun(NotRunCause.LAUNCH_FAILURE),
                given.a_report(False),
            ],
            "npm:kept": [given.a_report(False) for _ in range(3)],
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
                given.a_report(False),
            ],
            "npm:kept": [given.a_report(False) for _ in range(3)],
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
                given.a_report(False),
            ],
            "npm:kept": [given.a_report(False) for _ in range(3)],
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


async def test_a_benign_call_whose_connection_fails_twice_then_answers_passes(
    monkeypatch: pytest.MonkeyPatch,
):
    launches = given.launches_failing(monkeypatch, failing=2)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason is None
    assert launches.launches == 3


async def test_a_benign_call_whose_connection_fails_three_times_keeps_the_last_reason(
    monkeypatch: pytest.MonkeyPatch,
):
    launches = given.launches_failing(monkeypatch, failing=3)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason == "failed to connect for the benign call: TimeoutError"
    assert launches.launches == 3


async def test_a_benign_call_answering_with_an_error_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
):
    answer = ToolResponse(content="denied", is_error=True)
    launches = given.launches_failing(monkeypatch, failing=0, answer=answer)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason == f"benign call of {given.COUNTED_TOOL!r} returned an error: denied"
    assert launches.launches == 1


async def test_a_benign_call_whose_teardown_fails_once_connected_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
):
    launches = given.launches_failing(monkeypatch, failing=0, teardown_fails=True)

    reason = await benign_call(given.a_server(), timeout=30)

    assert reason == "failed to connect for the benign call: OSError"
    assert launches.launches == 1


async def test_a_container_of_the_run_images_running_at_start_refuses_before_the_rebuild():
    deps = dataclasses.replace(
        given.deps_reaching_nothing(),
        read_tree=lambda: TreeState(commit="c0ffee", dirty=False),
        running_containers=given.RunningContainers(["leftover_server"]).running,
    )

    with pytest.raises(Refused) as refused:
        await given.run([given.a_server()], deps)

    assert any("leftover_server" in reason for reason in refused.value.reasons)


async def test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running():
    server = given.a_server()
    containers = given.RunningContainers([], ["concurrent_server"])
    deps = given.deps_auditing(given.scripted({server.server_package: []}), containers=containers)

    with pytest.raises(Refused) as refused:
        await given.run([server], deps)

    assert any("concurrent_server" in reason for reason in refused.value.reasons)
    assert containers.removed == []


async def test_the_containers_left_running_at_the_end_are_removed_and_counted(
    capsys: pytest.CaptureFixture[str],
):
    server = given.a_server()
    containers = given.RunningContainers([], [], ["stuck_one", "stuck_two"])
    audit = given.scripted({server.server_package: [given.a_report(False) for _ in range(3)]})

    await given.run([server], given.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one", "stuck_two"]
    assert "2" in capsys.readouterr().out


async def test_no_container_left_at_the_end_removes_and_prints_nothing(
    capsys: pytest.CaptureFixture[str],
):
    server = given.a_server()
    containers = given.RunningContainers()
    audit = given.scripted({server.server_package: [given.a_report(False) for _ in range(3)]})

    await given.run([server], given.deps_auditing(audit, containers=containers))

    assert containers.removed == []
    assert capsys.readouterr().out == ""


async def test_the_sweep_runs_when_an_audit_raises():
    containers = given.RunningContainers([], [], ["stuck_one"])

    async def audit(_server: object) -> given.Outcome:
        raise ProviderFatal(PermissionError("the key was revoked"))

    with pytest.raises(RunInterrupted):
        await given.run([given.a_server()], given.deps_auditing(audit, containers=containers))

    assert containers.removed == ["stuck_one"]


async def test_the_sweep_runs_when_no_server_survives():
    server = given.a_server()
    containers = given.RunningContainers([], [], ["stuck_one"])
    deps = given.deps_auditing(
        given.scripted({server.server_package: []}),
        benign_call={server.server_package: "benign call errored"},
        containers=containers,
    )

    with pytest.raises(Refused, match="nuisance run refused"):
        await given.run([server], deps)

    assert containers.removed == ["stuck_one"]


async def test_the_containers_are_looked_up_by_the_run_image_tags_only():
    server = admission.with_a_backend(
        given.a_server(),
        BackendFixture(provisioner="doris", image="apache/doris:all-in-one-4.1.3", network="net"),
    )
    containers = given.RunningContainers()
    audit = given.scripted({server.server_package: [given.a_report(False) for _ in range(3)]})

    await given.run([server], given.deps_auditing(audit, containers=containers))

    run_tags = ["mcp-auditor-nuisance-filesystem-patched:local"]
    assert containers.listed_tags == [run_tags, run_tags, run_tags]
