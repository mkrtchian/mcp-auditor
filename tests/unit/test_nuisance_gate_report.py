import tests.unit.support.test_nuisance_gate_report_given as given
from evals.nuisance_gate_report import render_markdown, server_lines
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
    assert "| .AAAA |" in regression_row
    assert COUNTED_TOOL in regression_row
    assert COUNTED_TOOL not in held_row
    assert given.section(markdown, "## Not admitted") == [f"- {given.NOT_ADMITTED}"]
    assert given.section(markdown, "## Outside the gate") == [
        f"- {given.OUTSIDE.server_package}: {given.OUTSIDE.reason}"
    ]


def test_server_lines_read_each_completed_server_from_its_audits():
    session = given.a_held_server_beside_a_regression()

    lines = server_lines(session, [FILESYSTEM, KUBERNETES])

    assert [(line.server_package, line.flagged_per_run) for line in lines] == [
        (FILESYSTEM.server_package, [False, False, False]),
        (KUBERNETES.server_package, [True, False, False]),
    ]
    assert lines[1].flagged_tools_per_run == [[COUNTED_TOOL], [], []]
    assert lines[1].raw_fail_per_run == [1, 0, 0]
