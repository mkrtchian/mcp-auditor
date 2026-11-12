"""One server's result assembled from its audits, and its split flaw read from the draw order."""

from datetime import date

import pytest

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_assembly_given as given
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.assembly import assemble_server, split_flaw_of
from evals.cve.nuisance.results import NuisanceRunStatus
from evals.cve.server_health import ServerHealth
from evals.probe.analysis import call_cost
from mcp_auditor.domain.models import MissCause, ProviderUsage

_EARLY = date(2025, 3, 1)
_LATE = date(2026, 4, 1)
_PRICES = (given.LUNA_PRICE, given.LUNA_PRICE)


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
        given.SECOND_FLAW, FlawClass.COMMAND_EXECUTION, admission.PATCHED_VERSION
    ).model_copy(update={"backend_need": "external"})
    server = given.a_server(flaws=[given.a_two_flaw_server().flaws[0], needing_a_backend])
    draw = given.draw_entries((given.SECOND_FLAW, _LATE), (given.FIRST_FLAW, _EARLY))

    split = split_flaw_of(server, draw)

    assert split is not None and split.identifier == given.FIRST_FLAW


def test_a_server_is_assembled_from_its_audits_in_run_order():
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    judge = ProviderUsage(input_tokens=100, output_tokens=200)
    audits = [
        given.an_audit(True, provider=provider, judge=judge),
        given.an_audit(True, missed=MissCause.PROVIDER_REFUSAL, provider=provider, judge=judge),
        given.an_audit(False, missed=MissCause.UNREADABLE_ANSWER, provider=provider, judge=judge),
    ]
    draw = given.draw_entries((given.FIRST_FLAW, _EARLY))

    result = assemble_server(given.a_server(), audits, draw, _PRICES)

    assert [(status.flagged, status.split_flagged) for status in result.statuses] == [
        (True, True),
        (True, True),
        (False, False),
    ]
    assert [status.incomplete for status in result.statuses] == [False, True, True]
    assert result.flagged_per_run == [True, True, False]
    assert result.flagged_runs == 2
    assert result.flagged_share == pytest.approx(2 / 3)
    assert result.incomplete_runs == 2
    assert result.incomplete_unflagged_runs == 1
    assert result.raw_fail_per_run == [1, 1, 0]
    assert result.declared_function_fail_per_run == [0, 0, 0]
    assert (result.counted_tools_count, result.tools_count) == (1, 1)
    generator = audits[0].report.generator_usage
    one_run = call_cost(generator, given.LUNA_PRICE) + call_cost(judge, given.LUNA_PRICE)
    assert result.run_cost == pytest.approx(3 * one_run)
    assert (result.split_flaw, result.split_disclosure_date) == (given.FIRST_FLAW, _EARLY)


def test_each_run_status_carries_its_server_health_and_missed_call_causes():
    audits = [
        given.an_audit(False, health=ServerHealth(2, 1)),
        given.an_audit(False, missed=MissCause.PROVIDER_REFUSAL, health=ServerHealth(0, 3)),
        given.an_audit(False, missed=MissCause.UNREADABLE_ANSWER),
    ]

    result = assemble_server(given.a_server(), audits, given.draw_entries(), _PRICES)

    assert result.statuses == (
        NuisanceRunStatus(False, False, False, 0, 0, 2, 1, []),
        NuisanceRunStatus(False, False, True, 0, 0, 0, 3, ["provider_refusal"]),
        NuisanceRunStatus(False, False, True, 0, 0, 0, 0, ["unreadable_answer"]),
    )
    assert (result.non_protocol_lines, result.lost_connection_responses) == (2, 4)
    assert result.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}


def test_each_run_status_counts_the_fails_on_the_tools_left_out_by_their_declared_function():
    audits = [given.an_audit(True), given.an_audit(False)]
    server = given.a_server_whose_declared_function_is_its_effect()

    result = assemble_server(server, audits, given.draw_entries(), _PRICES)

    assert result.flagged_per_run == [False, False]
    assert result.raw_fail_per_run == [1, 0]
    assert result.declared_function_fail_per_run == [1, 0]


def test_a_throttled_step_is_not_a_miss_cause_of_a_run():
    audits = [given.an_audit(False, missed=MissCause.PROVIDER_THROTTLED)]

    result = assemble_server(given.a_server(), audits, given.draw_entries(), _PRICES)

    assert result.statuses[0].missed_call_causes == []
    assert result.incomplete_runs_by_cause == {}


def test_a_flag_on_a_tool_of_another_flaw_is_not_split_flagged():
    draw = given.draw_entries((given.SECOND_FLAW, _LATE), (given.FIRST_FLAW, _EARLY))
    audits = [given.an_audit(True) for _ in range(3)]

    result = assemble_server(given.a_two_flaw_server(), audits, draw, _PRICES)

    assert result.split_flaw == given.SECOND_FLAW
    assert result.flagged_runs == 3
    assert [status.split_flagged for status in result.statuses] == [False, False, False]
    assert result.split_flagged_runs == 0
