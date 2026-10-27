import dataclasses

import tests.unit.support.test_nuisance_gate_report_given as given
from evals.nuisance_gate_report import GATE_LEGEND, render_markdown, server_lines
from tests.unit.support.test_nuisance_gate_session_given import FILESYSTEM, KUBERNETES
from tests.unit.support.test_nuisance_run_given import COUNTED_TOOL


def test_the_markdown_carries_the_verdict_the_runs_the_flagged_tools_and_the_lists():
    session = given.a_held_server_beside_a_regression()

    markdown = render_markdown(given.a_report_of(session))

    assert "red" in markdown
    assert "npm:mcp-server-kubernetes: regression, the alarm reproduced in 4 of 5 replays" in (
        markdown
    )
    held_row = given.row_of(markdown, FILESYSTEM.server_package)
    regression_row = given.row_of(markdown, KUBERNETES.server_package)
    assert "| ... |" in held_row
    assert "| A.. |" in regression_row
    assert "| 4/5 |" in regression_row
    assert COUNTED_TOOL in regression_row
    assert COUNTED_TOOL not in held_row
    assert given.section(markdown, "## Not admitted") == [f"- {given.NOT_ADMITTED}"]
    assert given.section(markdown, "## Outside the gate") == [
        f"- {given.OUTSIDE.server_package}: {given.OUTSIDE.reason}"
    ]


def test_the_servers_table_shows_the_baseline_runs_beside_the_runs_with_a_legend():
    markdown = render_markdown(given.a_report_of(given.a_held_server_beside_a_regression()))

    assert "| Server | Outcome | Baseline | Runs | Replays | Detail |" in markdown
    held_row = given.row_of(markdown, FILESYSTEM.server_package)
    assert held_row.startswith(f"| {FILESYSTEM.server_package} | held | ...... | ... | - |")
    assert GATE_LEGEND in markdown


def test_a_not_gated_server_shows_its_detail_before_its_flagged_tools():
    markdown = render_markdown(given.a_report_of(given.a_not_gated_server_with_an_alarm()))

    row = given.row_of(markdown, KUBERNETES.server_package)
    assert f"| {given.FLAGGED_IN_BASELINE}; run 1: {COUNTED_TOOL} |" in row
    assert "| .....A | A.. |" in row


def test_the_throttled_total_follows_the_model_line_only_when_there_is_one():
    session = given.a_held_server_beside_a_regression()

    throttled = render_markdown(given.a_report_of(session, throttled_requests=12)).splitlines()
    clean = render_markdown(given.a_report_of(session)).splitlines()

    model = next(index for index, line in enumerate(throttled) if line.startswith("Model: "))
    assert throttled[model + 1] == "Throttled by the model provider: 12 requests at concurrency 9"
    assert not any(line.startswith("Throttled") for line in clean)


def test_a_refused_recording_reads_as_refused_in_the_recording_section():
    session = dataclasses.replace(
        given.a_held_server_beside_a_regression(), recording_refused=["HEAD moved"]
    )

    markdown = render_markdown(given.a_report_of(session))

    assert given.section(markdown, "## Recording") == ["- refused: HEAD moved"]


def test_server_lines_read_each_completed_server_from_its_audits():
    session = given.a_held_server_beside_a_regression()

    lines = server_lines(session, [FILESYSTEM, KUBERNETES])

    assert [(line.server_package, line.flagged_per_run) for line in lines] == [
        (FILESYSTEM.server_package, [False, False, False]),
        (KUBERNETES.server_package, [True, False, False]),
    ]
    assert lines[1].flagged_tools_per_run == [[COUNTED_TOOL], [], []]
    assert lines[1].raw_fail_per_run == [1, 0, 0]
