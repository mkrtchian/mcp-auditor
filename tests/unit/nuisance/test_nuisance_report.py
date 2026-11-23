"""The nuisance report model and its markdown: the structural guarantee that a nuisance holdout run
keeps no proof. The model carries no evidence, no judge input and no per-case verdict field."""

import dataclasses
import re
from datetime import date

import tests.unit.nuisance.support.test_nuisance_report_given as given
from evals.cve.holdout_report_lines import CutoffModel
from evals.cve.nuisance.exits import ExitReason
from evals.cve.nuisance.markdown import render_markdown
from evals.cve.nuisance.report import build_report
from evals.cve.nuisance.results import NotRunCause, NotRunServer, ServerExit
from tests.unit.nuisance.support.nuisance_report_runs import (
    LUNA_CUTOFF,
    RECORDED_AT,
    a_run,
    a_server_result,
)
from tests.unit.support.coarse_grid import COARSE_GRID

PROOF_WORDS = {"evidence", "justification", "response", "payload", "verdict"}
COUNTS_NAMING_RESPONSES = {"lost_connection_responses", "cut_responses"}


def test_the_holdout_nuisance_rate_is_published_as_an_upper_bound():
    run = a_run(
        [
            a_server_result("A", flagged_runs=3),
            a_server_result("B", flagged_runs=3),
            a_server_result("C", flagged_runs=0),
        ]
    )

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert "Holdout nuisance rate: at most 0.667 (95% Wilson " in markdown


def test_a_server_row_shows_its_status_per_run_in_order():
    run = a_run([a_server_result("npm:@acme/files", flagged_runs=1)])

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert (
        "## Servers\n- npm:@acme/files: flagged share 0.333, flagged, not flagged, not flagged"
        in (markdown)
    )
    assert "counted tools 1 of 4" in markdown


def test_the_raw_fail_count_is_reported_per_server_and_per_run():
    run = a_run([a_server_result("A", flagged_runs=2), a_server_result("B")])

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert (
        "## Raw FAIL count (report-only, never compared)\n"
        "- A: 1, 1, 0 (on the tools left out by their declared function: 0, 0, 0)\n"
        "- B: 0, 0, 0 (on the tools left out by their declared function: 0, 0, 0)\n"
    ) in markdown


def test_the_raw_fail_count_shows_its_part_on_the_tools_left_out_by_their_declared_function():
    server = a_server_result("A", flagged_runs=1, declared_function_fail_runs=2)

    report = build_report(a_run([server]), grid=COARSE_GRID)

    assert report.servers[0].declared_function_fail_per_run == [1, 1, 0]
    assert (
        "- A: 2, 1, 0 (on the tools left out by their declared function: 1, 1, 0)\n"
        in render_markdown(report)
    )


def test_a_server_line_keeps_its_split_flaw_and_the_facts_of_each_run():
    server = a_server_result("A", flagged_runs=1, split_flagged_runs=0, incomplete_unflagged_runs=1)

    line = build_report(a_run([server]), grid=COARSE_GRID).servers[0]

    assert (line.split_flaw, line.split_disclosure_date) == ("CVE-2025-0001", date(2026, 1, 1))
    assert line.per_run == [
        given.a_clean_run_line(flagged=True, incomplete=False),
        given.a_clean_run_line(flagged=False, incomplete=False),
        given.a_clean_run_line(flagged=False, incomplete=True),
    ]


def test_a_server_line_sums_its_health_and_counts_its_incomplete_runs_by_cause():
    report = build_report(given.a_run_with_incidents(), grid=COARSE_GRID)

    line = report.servers[0]

    assert (line.non_protocol_lines, line.lost_connection_responses) == (2, 1)
    assert (line.relaunches, line.unsent_calls) == (1, 3)
    assert (line.per_run[0].relaunches, line.per_run[0].unsent_calls) == (1, 3)
    assert (line.cut_responses, line.per_run[0].cut_responses) == (1, 1)
    assert line.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}
    assert line.per_run[0].non_protocol_lines == 2
    assert line.per_run[1].missed_call_causes == ["provider_refusal", "unreadable_answer"]
    assert report.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}


def test_the_markdown_names_each_server_with_a_health_count():
    markdown = render_markdown(build_report(given.a_run_with_incidents(), grid=COARSE_GRID))

    assert (
        "## Server health\n- A: non-protocol lines 2, connection lost on 1 call(s),"
        " relaunched 1 time(s), 3 call(s) not sent, 1 response(s) shown cut\n"
    ) in markdown
    assert "- B: non-protocol" not in markdown


def test_the_markdown_names_a_server_that_was_only_relaunched():
    markdown = render_markdown(
        build_report(given.a_run_with_a_server_only_relaunched(), grid=COARSE_GRID)
    )

    assert "## Server health\n- A: relaunched 2 time(s)\n" in markdown


def test_the_markdown_splits_the_incomplete_runs_by_cause():
    markdown = render_markdown(build_report(given.a_run_with_incidents(), grid=COARSE_GRID))

    assert (
        "Incomplete runs (a model call missed: refused, unreadable or too long): 1 (A)\n"
        "- provider_refusal: 1 run(s)\n"
        "- unreadable_answer: 1 run(s)\n"
    ) in markdown


def test_the_markdown_leaves_the_health_section_out_when_nothing_happened():
    markdown = render_markdown(build_report(a_run([a_server_result("A")]), grid=COARSE_GRID))

    assert "## Server health" not in markdown


def test_the_recorded_at_line_carries_the_run_timestamp():
    markdown = render_markdown(build_report(a_run([a_server_result("A")]), grid=COARSE_GRID))

    assert f"Recorded at: {RECORDED_AT}\n" in markdown


def test_the_provenance_line_names_the_census_walk_record_and_admission_commits():
    report = build_report(a_run([a_server_result("A")]), grid=COARSE_GRID)

    assert (
        "Commits: run deadbeef, census cafe1234, walk record beef5678, admission feed4321\n"
        in render_markdown(report)
    )


def test_the_run_cutoff_is_the_latest_of_the_run_models():
    later = dataclasses.replace(LUNA_CUTOFF, date=date(2026, 6, 30))
    run = a_run([a_server_result("A")], cutoffs={"gpt-6-luna": LUNA_CUTOFF, "judge": later})

    cutoff = build_report(run, grid=COARSE_GRID).run_cutoff

    assert (cutoff.model, cutoff.date) == ("judge", date(2026, 6, 30))


def test_the_split_section_names_the_run_cutoff_and_both_sides():
    run = a_run(
        [
            a_server_result("A", split_disclosure_date=date(2026, 1, 1), flagged_runs=3),
            a_server_result("B", split_disclosure_date=date(2026, 12, 1)),
        ]
    )

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert (
        "## Split by cutoff side\n"
        "- run cutoff: 2026-05-18 (training), gpt-6-luna, https://example.test/luna\n"
    ) in markdown
    assert "- pre_cutoff: 1.000 (" in markdown
    assert "), 1 server(s)\n" in markdown
    assert "- post_cutoff: 0.000 (" in markdown
    assert "- contrast: not computed (a side has fewer than 5 servers)" in markdown


def test_the_markdown_ends_with_the_total_cost():
    markdown = render_markdown(build_report(a_run([a_server_result("A")]), grid=COARSE_GRID))

    assert markdown.endswith("Total cost: $0.06")


def test_the_throttled_requests_follow_the_incomplete_runs_line_with_the_concurrency():
    run = a_run(
        [a_server_result("A", incomplete_unflagged_runs=1)], throttled_requests=12, concurrency=4
    )

    report = build_report(run, grid=COARSE_GRID)
    markdown = render_markdown(report)

    assert (report.throttled_requests, report.concurrency) == (12, 4)
    assert (
        "Incomplete runs (a model call missed: refused, unreadable or too long): 1 (A)\n"
        "Throttled by the model provider: 12 requests at concurrency 4\n"
    ) in markdown


def test_no_throttled_line_when_nothing_was_throttled():
    markdown = render_markdown(build_report(a_run([a_server_result("A")]), grid=COARSE_GRID))

    assert "Throttled" not in markdown


def test_the_report_writes_the_holdout_nuisance_rate_and_the_exits_under_the_glossary_keys():
    run = a_run(
        [a_server_result("A")], exits=[ServerExit("npm:excluded", ExitReason.EXCLUDED_SERVER)]
    )

    dumped = build_report(run, grid=COARSE_GRID).model_dump(mode="json")

    assert {"holdout_nuisance_rate", "exits"} <= dumped.keys()
    assert dumped["exits"] == [{"server_package": "npm:excluded", "reason": "excluded_server"}]


def test_the_report_writes_the_pending_servers_and_the_admission_commit():
    run = a_run([a_server_result("A")], pending_admission=["npm:pending"])

    dumped = build_report(run, grid=COARSE_GRID).model_dump(mode="json")

    assert dumped["pending_admission"] == ["npm:pending"]
    assert dumped["admission_commit"] == "feed4321"


def test_build_report_carries_the_run_conditions_and_provenance():
    report = build_report(a_run([a_server_result("A")]), grid=COARSE_GRID)

    assert report.counter_fingerprint == "counter-abc"
    assert report.grammar_fingerprint == "grammar-abc"
    assert report.cutoffs["gpt-6-luna"] == CutoffModel.of(LUNA_CUTOFF)


def test_the_report_holds_no_proof_text():
    run = a_run(
        [given.with_incidents(a_server_result("A", flagged_runs=1))],
        not_run=[NotRunServer("npm:b", "the benign call errored", NotRunCause.BENIGN_CALL_FAILED)],
        exits=[ServerExit("npm:c", ExitReason.ACCEPTANCE_TARGET_SERVER)],
    )

    # The health line's count of cut responses names the word and quotes no response.
    markdown = re.sub(
        r"\d+ response\(s\) shown cut", "", render_markdown(build_report(run, grid=COARSE_GRID))
    )

    for model in given.report_models():
        for name in model.model_fields.keys() - COUNTS_NAMING_RESPONSES:
            assert {token.removesuffix("s") for token in name.split("_")}.isdisjoint(PROOF_WORDS)
    assert not [word for word in PROOF_WORDS if word in markdown.lower()]
