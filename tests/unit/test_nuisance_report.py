"""The nuisance report model and its markdown: the structural guarantee that a nuisance run keeps
no proof. The model carries no evidence, no judge input and no per-case verdict field."""

from datetime import date

import tests.unit.support.test_nuisance_report_given as given
from evals.holdout_conditions import Cutoff
from evals.holdout_report import (
    ConclusionLine,
    CutoffModel,
    IntervalModel,
    MethodLine,
    RunCutoffModel,
    run_cutoff,
)
from evals.nuisance_markdown import render_markdown
from evals.nuisance_report import (
    FigureExitLine,
    NotRunLine,
    NuisanceReport,
    ServerLine,
    SideLine,
    build_report,
)
from evals.nuisance_results import DROPPED_RUN_REASONS, FigureExit, NotRunCause, NotRunServer
from tests.unit.support.test_nuisance_statistic_given import a_server_result

PROOF_WORDS = {"evidence", "justification", "response", "payload", "verdict"}


def test_the_figure_is_published_as_an_upper_bound():
    run = given.a_run(
        [
            a_server_result("A", flagged_runs=3),
            a_server_result("B", flagged_runs=3),
            a_server_result("C", flagged_runs=0),
        ]
    )

    markdown = render_markdown(build_report(run))

    assert "Figure: at most 0.667 (95% Wilson " in markdown


def test_a_server_row_shows_its_status_per_run_in_order():
    run = given.a_run([a_server_result("npm:@acme/files", flagged_runs=1)])

    markdown = render_markdown(build_report(run))

    assert (
        "## Servers\n- npm:@acme/files: flagged share 0.333, flagged, not flagged, not flagged"
        in (markdown)
    )
    assert "counted tools 1 of 4" in markdown


def test_outside_figure_rows_are_grouped_by_reason():
    run = given.a_run(
        [a_server_result("A")],
        outside_figure=[
            FigureExit("npm:excluded-one", "an excluded server"),
            FigureExit("npm:excluded-two", "an excluded server"),
        ],
    )

    markdown = render_markdown(build_report(run))

    assert (
        "## Outside the figure\n"
        "- an excluded server: 2 server(s): npm:excluded-one, npm:excluded-two\n"
    ) in markdown


def test_no_exit_reads_none_in_both_sections():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert "## Outside the figure\n- none\n" in markdown
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

    assert "## Raw FAIL count (report-only, never compared)\n- A: 1, 1, 0\n- B: 0, 0, 0\n" in (
        markdown
    )


def test_the_recorded_at_line_carries_the_run_timestamp():
    markdown = render_markdown(build_report(given.a_run([a_server_result("A")])))

    assert f"Recorded at: {given.RECORDED_AT}\n" in markdown


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


def test_the_incomplete_runs_line_names_the_servers_touched():
    run = given.a_run([a_server_result("A", incomplete_unflagged_runs=1), a_server_result("B")])

    markdown = render_markdown(build_report(run))

    assert "Incomplete runs (a step refused or unreadable): 1 (A)" in markdown
    assert markdown.endswith("Total cost: $0.06")


def test_build_report_carries_the_run_conditions_and_provenance():
    report = build_report(given.a_run([a_server_result("A")]))

    assert report.counter_fingerprint == "counter-abc"
    assert report.grammar_fingerprint == "grammar-abc"
    assert report.recorded_at == given.RECORDED_AT
    assert report.cutoffs["gpt-6-luna"] == CutoffModel.of(given.LUNA_CUTOFF)


def test_the_report_holds_no_proof_text():
    models = [
        NuisanceReport,
        ServerLine,
        SideLine,
        NotRunLine,
        FigureExitLine,
        MethodLine,
        ConclusionLine,
        CutoffModel,
        RunCutoffModel,
        IntervalModel,
    ]
    run = given.a_run(
        [a_server_result("A", flagged_runs=1)],
        not_run=[NotRunServer("npm:b", "the benign call errored", NotRunCause.BENIGN_CALL_FAILED)],
        outside_figure=[FigureExit("npm:c", "an acceptance server")],
    )

    markdown = render_markdown(build_report(run)).lower()

    for model in models:
        assert set(model.model_fields).isdisjoint(PROOF_WORDS)
    assert not [word for word in PROOF_WORDS if word in markdown]


EARLIER = Cutoff(date=date(2026, 1, 15), type="knowledge", source="https://a.test", note=None)
LATER = Cutoff(date=date(2026, 6, 30), type="training", source="https://b.test", note=None)


def test_the_run_cutoff_is_the_latest_and_the_generator_on_a_tie():
    assert run_cutoff({"generator": EARLIER, "judge": LATER}) == ("judge", LATER)
    assert run_cutoff({"generator": LATER, "judge": LATER}) == ("generator", LATER)
