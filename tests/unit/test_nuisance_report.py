"""The nuisance report model and its markdown: the structural guarantee that a nuisance run keeps
no proof. The model carries no evidence, no judge input and no per-case verdict field."""

import dataclasses
from datetime import date

import tests.unit.support.test_nuisance_report_given as given
from evals.cve.detection.holdout_report import (
    ConclusionLine,
    CutoffModel,
    IntervalModel,
    MethodLine,
    RunCutoffModel,
)
from evals.cve.nuisance.markdown import render_markdown
from evals.cve.nuisance.report import (
    ExitLine,
    NotRunLine,
    NuisanceReport,
    ServerLine,
    ServerRunLine,
    SideLine,
    build_report,
)
from evals.cve.nuisance.results import (
    DROPPED_RUN_REASONS,
    NotRunCause,
    NotRunServer,
    ServerExit,
)
from tests.unit.support.test_nuisance_statistic_given import a_server_result

PROOF_WORDS = {"evidence", "justification", "response", "payload", "verdict"}


def test_the_holdout_nuisance_rate_is_published_as_an_upper_bound():
    run = given.a_run(
        [
            a_server_result("A", flagged_runs=3),
            a_server_result("B", flagged_runs=3),
            a_server_result("C", flagged_runs=0),
        ]
    )

    markdown = render_markdown(build_report(run))

    assert "Holdout nuisance rate: at most 0.667 (95% Wilson " in markdown


def test_a_server_row_shows_its_status_per_run_in_order():
    run = given.a_run([a_server_result("npm:@acme/files", flagged_runs=1)])

    markdown = render_markdown(build_report(run))

    assert (
        "## Servers\n- npm:@acme/files: flagged share 0.333, flagged, not flagged, not flagged"
        in (markdown)
    )
    assert "counted tools 1 of 4" in markdown


def test_exit_rows_are_grouped_by_reason():
    run = given.a_run(
        [a_server_result("A")],
        exits=[
            ServerExit("npm:excluded-one", "an excluded server"),
            ServerExit("npm:excluded-two", "an excluded server"),
        ],
    )

    markdown = render_markdown(build_report(run))

    assert (
        "## Exits\n- an excluded server: 2 server(s): npm:excluded-one, npm:excluded-two\n"
    ) in markdown


def test_no_exit_reads_none_in_both_sections():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert "## Exits\n- none\n" in markdown
    assert "## Not run\n- none\n" in markdown


def test_the_not_run_section_counts_the_in_run_drops_against_the_servers_launched():
    throttled = DROPPED_RUN_REASONS[NotRunCause.THROTTLED]
    run = given.a_run(
        [a_server_result("A"), a_server_result("B")],
        not_run=[
            NotRunServer("npm:benign", "the benign call errored", NotRunCause.BENIGN_CALL_FAILED),
            NotRunServer("npm:throttled", throttled, NotRunCause.THROTTLED),
        ],
    )

    markdown = render_markdown(build_report(run))

    assert f"- 1 of the 3 server(s) launched: {throttled}: npm:throttled\n" in markdown
    assert "- benign call failed before the runs: 1 server(s): npm:benign\n" in markdown
    assert "- npm:benign: the benign call errored\n" in markdown
    assert f"- npm:throttled: {throttled}\n" in markdown


def test_the_raw_fail_count_is_reported_per_server_and_per_run():
    run = given.a_run([a_server_result("A", flagged_runs=2), a_server_result("B")])

    markdown = render_markdown(build_report(run))

    assert (
        "## Raw FAIL count (report-only, never compared)\n"
        "- A: 1, 1, 0 (on the tools left out by their declared function: 0, 0, 0)\n"
        "- B: 0, 0, 0 (on the tools left out by their declared function: 0, 0, 0)\n"
    ) in markdown


def test_the_raw_fail_count_shows_its_part_on_the_tools_left_out_by_their_declared_function():
    server = a_server_result("A", flagged_runs=1, declared_function_fail_runs=2)

    report = build_report(given.a_run([server]))

    assert report.servers[0].declared_function_fail_per_run == [1, 1, 0]
    assert (
        "- A: 2, 1, 0 (on the tools left out by their declared function: 1, 1, 0)\n"
        in render_markdown(report)
    )


def test_a_server_line_keeps_its_split_flaw_and_the_facts_of_each_run():
    server = a_server_result("A", flagged_runs=1, split_flagged_runs=0, incomplete_unflagged_runs=1)

    line = build_report(given.a_run([server])).servers[0]

    assert (line.split_flaw, line.split_disclosure_date) == ("CVE-2025-0001", date(2026, 1, 1))
    assert line.per_run == [
        given.a_clean_run_line(flagged=True, incomplete=False),
        given.a_clean_run_line(flagged=False, incomplete=False),
        given.a_clean_run_line(flagged=False, incomplete=True),
    ]


def test_a_server_line_sums_its_health_and_counts_its_incomplete_runs_by_cause():
    report = build_report(given.a_run_with_incidents())

    line = report.servers[0]

    assert (line.non_protocol_lines, line.lost_connection_responses) == (2, 1)
    assert line.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}
    assert line.per_run[0].non_protocol_lines == 2
    assert line.per_run[1].missed_call_causes == ["provider_refusal", "unreadable_answer"]
    assert report.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}


def test_the_markdown_names_each_server_with_a_health_count():
    markdown = render_markdown(build_report(given.a_run_with_incidents()))

    assert (
        "## Server health\n- A: non-protocol lines 2, connection lost on 1 call(s)\n"
    ) in markdown
    assert "- B: non-protocol" not in markdown


def test_the_markdown_splits_the_incomplete_runs_by_cause():
    markdown = render_markdown(build_report(given.a_run_with_incidents()))

    assert (
        "Incomplete runs (a model call refused or unreadable): 1 (A)\n"
        "- provider_refusal: 1 run(s)\n"
        "- unreadable_answer: 1 run(s)\n"
    ) in markdown


def test_the_markdown_leaves_the_health_section_out_when_nothing_happened():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert "## Server health" not in markdown


def test_the_recorded_at_line_carries_the_run_timestamp():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert f"Recorded at: {given.RECORDED_AT}\n" in markdown


def test_the_provenance_line_names_the_census_and_walk_record_commits():
    report = build_report(given.a_run([a_server_result("A")]))

    assert "Commits: run deadbeef, census cafe1234, walk record beef5678\n" in render_markdown(
        report
    )


def test_the_run_cutoff_is_the_latest_of_the_run_models():
    later = dataclasses.replace(given.LUNA_CUTOFF, date=date(2026, 6, 30))
    run = given.a_run(
        [a_server_result("A")], cutoffs={"gpt-6-luna": given.LUNA_CUTOFF, "judge": later}
    )

    cutoff = build_report(run).run_cutoff

    assert (cutoff.model, cutoff.date) == ("judge", date(2026, 6, 30))


def test_the_split_section_names_the_run_cutoff_and_both_sides():
    run = given.a_run(
        [
            a_server_result("A", split_disclosure_date=date(2026, 1, 1), flagged_runs=3),
            a_server_result("B", split_disclosure_date=date(2026, 12, 1)),
        ]
    )

    markdown = render_markdown(build_report(run))

    assert (
        "## Split by cutoff side\n"
        "- run cutoff: 2026-05-18 (training), gpt-6-luna, https://example.test/luna\n"
    ) in markdown
    assert "- pre_cutoff: 1.000 (" in markdown
    assert "), 1 server(s)\n" in markdown
    assert "- post_cutoff: 0.000 (" in markdown
    assert "- contrast: not computed (a side has fewer than 5 servers)" in markdown


def test_the_markdown_ends_with_the_total_cost():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert markdown.endswith("Total cost: $0.06")


def test_the_throttled_requests_follow_the_incomplete_runs_line_with_the_concurrency():
    run = given.a_run(
        [a_server_result("A", incomplete_unflagged_runs=1)], throttled_requests=12, concurrency=4
    )

    report = build_report(run)
    markdown = render_markdown(report)

    assert (report.throttled_requests, report.concurrency) == (12, 4)
    assert (
        "Incomplete runs (a model call refused or unreadable): 1 (A)\n"
        "Throttled by the model provider: 12 requests at concurrency 4\n"
    ) in markdown


def test_no_throttled_line_when_nothing_was_throttled():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert "Throttled" not in markdown


def test_the_report_writes_the_holdout_nuisance_rate_and_the_exits_under_the_glossary_keys():
    run = given.a_run(
        [a_server_result("A")], exits=[ServerExit("npm:excluded", "an excluded server")]
    )

    dumped = build_report(run).model_dump(mode="json")

    assert {"holdout_nuisance_rate", "exits"} <= dumped.keys()
    assert dumped["exits"] == [{"server_package": "npm:excluded", "reason": "an excluded server"}]


def test_build_report_carries_the_run_conditions_and_provenance():
    report = build_report(given.a_run([a_server_result("A")]))

    assert report.counter_fingerprint == "counter-abc"
    assert report.grammar_fingerprint == "grammar-abc"
    assert report.cutoffs["gpt-6-luna"] == CutoffModel.of(given.LUNA_CUTOFF)


def test_the_report_holds_no_proof_text():
    models = [
        NuisanceReport,
        ServerLine,
        ServerRunLine,
        SideLine,
        NotRunLine,
        ExitLine,
        MethodLine,
        ConclusionLine,
        CutoffModel,
        RunCutoffModel,
        IntervalModel,
    ]
    run = given.a_run(
        [given.with_incidents(a_server_result("A", flagged_runs=1))],
        not_run=[NotRunServer("npm:b", "the benign call errored", NotRunCause.BENIGN_CALL_FAILED)],
        exits=[ServerExit("npm:c", "the server of a current or dropped acceptance target")],
    )

    markdown = render_markdown(build_report(run)).lower()

    for model in models:
        assert set(model.model_fields).isdisjoint(PROOF_WORDS)
    assert not [word for word in PROOF_WORDS if word in markdown]
