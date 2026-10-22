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
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.nuisance_assembly import assemble_server, split_flaw_of
from evals.nuisance_audit import DroppedRun
from evals.nuisance_counter import counter_fingerprint
from evals.nuisance_images import nuisance_fixture_fingerprint
from evals.nuisance_results import FigureExit, NotRunCause, NuisanceRunStatus
from evals.nuisance_run import run_population
from evals.nuisance_walk import NuisanceServer, ServerMark
from evals.probe import call_cost
from mcp_auditor.domain.models import MissCause, ProviderUsage

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
    ).model_copy(update={"needs_backend": True})
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
    assert result.not_run == []
    assert result.incomplete_run_count == 1
    assert result.total_cost == pytest.approx(sum(s.run_cost for s in result.servers))
    assert result.total_cost == pytest.approx(4 * call_cost(usage, given.LUNA_PRICE))


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


def test_each_standing_exit_keeps_its_server_outside_the_figure():
    walked = [
        _walked("npm:excluded", ServerMark.EXCLUDED),
        _walked("npm:accepted", ServerMark.ACCEPTANCE),
    ]
    admitted = _admitting(
        _admitted("npm:no-stdio", runs_over_stdio=False),
        _admitted("npm:no-container", runs_in_container=False),
    )

    population = run_population(walked, admitted)

    assert population.audited == []
    assert sorted(population.outside_figure, key=lambda row: row.server_package) == [
        FigureExit("npm:accepted", "an acceptance server"),
        FigureExit("npm:excluded", "an excluded server"),
        FigureExit("npm:no-container", "its patched version does not run in a container"),
        FigureExit("npm:no-stdio", "does not run over stdio"),
    ]


def test_an_unmarked_stdio_containerised_server_is_audited():
    kept = _admitted("npm:kept")

    population = run_population([_walked("npm:kept", None)], _admitting(kept))

    assert population.audited == [kept]
    assert population.outside_figure == []


def test_an_admitted_server_marked_by_the_walk_is_outside_the_figure_once():
    marked = _admitted("npm:marked", runs_over_stdio=False)

    population = run_population([_walked("npm:marked", ServerMark.EXCLUDED)], _admitting(marked))

    assert population.audited == []
    assert population.outside_figure == [FigureExit("npm:marked", "an excluded server")]


def _walked(package: str, mark: ServerMark | None) -> NuisanceServer:
    return NuisanceServer(package, given.FIRST_FLAW, (given.FIRST_FLAW,), (given.FIRST_FLAW,), mark)


def _admitted(package: str, **update: bool) -> AdmittedServer:
    return given.a_server(package).model_copy(update=update)


def _admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return admission.an_admission().model_copy(update={"servers": list(servers)})
