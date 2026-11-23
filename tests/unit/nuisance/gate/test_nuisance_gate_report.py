import dataclasses

import tests.unit.nuisance.gate.support.test_nuisance_gate_report_then as then
from evals.cve.nuisance.exits import EXIT_REASON_TEXTS
from evals.cve.nuisance.gate.gate_report import GATE_LEGEND, render_markdown, server_lines
from tests.unit.nuisance.gate.support.nuisance_gate_reports import (
    FLAGGED_IN_BASELINE,
    NOT_ADMITTED,
    OUTSIDE,
    a_held_server_beside_a_regression,
    a_report_of,
    an_inconclusive_server_with_an_alarm,
)
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import FILESYSTEM, KUBERNETES
from tests.unit.support.nuisance_holdout_runs import COUNTED_TOOL


def test_the_markdown_carries_the_verdict_the_runs_the_flagged_tools_and_the_lists():
    session = a_held_server_beside_a_regression()

    markdown = render_markdown(a_report_of(session))

    assert "red" in markdown
    assert "npm:mcp-server-kubernetes: regression, the alarm reproduced in 4 of 5 retests" in (
        markdown
    )
    held_row = then.row_of(markdown, FILESYSTEM.server_package)
    regression_row = then.row_of(markdown, KUBERNETES.server_package)
    assert "| ... |" in held_row
    assert "| A.. |" in regression_row
    assert "| 4/5 |" in regression_row
    assert COUNTED_TOOL in regression_row
    assert COUNTED_TOOL not in held_row
    assert then.section(markdown, "## Not admitted") == [f"- {NOT_ADMITTED}"]
    assert then.section(markdown, "## Outside the gate") == [
        f"- {OUTSIDE.server_package}: {EXIT_REASON_TEXTS[OUTSIDE.reason]}"
    ]


def test_the_servers_table_shows_the_baseline_runs_beside_the_runs_with_a_legend():
    markdown = render_markdown(a_report_of(a_held_server_beside_a_regression()))

    assert "| Server | Outcome | Baseline | Runs | Retests | Detail |" in markdown
    held_row = then.row_of(markdown, FILESYSTEM.server_package)
    assert held_row.startswith(f"| {FILESYSTEM.server_package} | held | ...... | ... | - |")
    assert GATE_LEGEND in markdown


def test_an_inconclusive_server_shows_its_detail_before_its_flagged_tools():
    markdown = render_markdown(a_report_of(an_inconclusive_server_with_an_alarm()))

    row = then.row_of(markdown, KUBERNETES.server_package)
    assert f"| {FLAGGED_IN_BASELINE}; run 1: {COUNTED_TOOL} |" in row
    assert "| .....A | A.. |" in row


def test_the_throttled_total_follows_the_model_line_only_when_there_is_one():
    session = a_held_server_beside_a_regression()

    throttled = render_markdown(a_report_of(session, throttled_requests=12)).splitlines()
    clean = render_markdown(a_report_of(session)).splitlines()

    model = next(index for index, line in enumerate(throttled) if line.startswith("Model: "))
    assert throttled[model + 1] == "Throttled by the model provider: 12 requests at concurrency 9"
    assert not any(line.startswith("Throttled") for line in clean)


def test_a_refused_recording_reads_as_refused_in_the_recording_section():
    session = dataclasses.replace(
        a_held_server_beside_a_regression(), recording_refused=["HEAD moved"]
    )

    markdown = render_markdown(a_report_of(session))

    assert then.section(markdown, "## Recording") == ["- refused: HEAD moved"]


def test_server_lines_read_each_completed_server_from_its_audits():
    session = a_held_server_beside_a_regression()

    lines = server_lines(session, [FILESYSTEM, KUBERNETES])

    assert [(line.server_package, line.flagged_per_run) for line in lines] == [
        (FILESYSTEM.server_package, [False, False, False]),
        (KUBERNETES.server_package, [True, False, False]),
    ]
    assert lines[1].flagged_tools_per_run == [[COUNTED_TOOL], [], []]
    assert lines[1].raw_fail_per_run == [1, 0, 0]
