"""The Exits and Not run sections of the nuisance report."""

from evals.cve.nuisance.exits import EXIT_REASON_TEXTS, ExitReason
from evals.cve.nuisance.markdown import render_markdown
from evals.cve.nuisance.report import build_report
from evals.cve.nuisance.results import (
    DROPPED_RUN_REASONS,
    NotRunCause,
    NotRunServer,
    ServerExit,
)
from tests.unit.nuisance.support.nuisance_report_runs import a_run
from tests.unit.nuisance.support.test_nuisance_statistic_given import a_server_result


def test_the_exits_section_prints_every_reason_of_the_rule_in_its_order_with_its_count():
    run = a_run(
        [a_server_result("A")],
        exits=[
            ServerExit("npm:excluded-one", ExitReason.EXCLUDED_SERVER),
            ServerExit("npm:flawless", ExitReason.NO_COUNTED_FLAW),
            ServerExit("npm:excluded-two", ExitReason.EXCLUDED_SERVER),
        ],
    )

    markdown = render_markdown(build_report(run))

    counts = {
        ExitReason.NO_COUNTED_FLAW: "1 server(s): npm:flawless",
        ExitReason.EXCLUDED_SERVER: "2 server(s): npm:excluded-one, npm:excluded-two",
    }
    rows = "".join(
        f"- {EXIT_REASON_TEXTS[reason]}: {counts.get(reason, '0 server(s)')}\n"
        for reason in ExitReason
    )
    assert f"## Exits\n{rows}\n" in markdown


def test_with_no_exit_every_reason_reads_zero_and_the_not_run_section_reads_none():
    markdown = render_markdown(build_report(a_run([a_server_result("A")])))

    zero_rows = "".join(f"- {EXIT_REASON_TEXTS[reason]}: 0 server(s)\n" for reason in ExitReason)
    assert f"## Exits\n{zero_rows}\n" in markdown
    assert "## Not run\n- none\n" in markdown


def test_a_server_whose_admission_is_pending_closes_the_exits_section():
    run = a_run([a_server_result("A")], pending_admission=["npm:pending"])

    markdown = render_markdown(build_report(run))

    last_reason = EXIT_REASON_TEXTS[list(ExitReason)[-1]]
    assert (
        f"- {last_reason}: 0 server(s)\n"
        "- admission pending (not an exit of the rule): 1 server(s): npm:pending\n\n"
    ) in markdown


def test_no_pending_line_when_every_reached_server_is_admitted_or_out():
    markdown = render_markdown(build_report(a_run([a_server_result("A")])))

    assert "admission pending" not in markdown


def test_the_not_run_section_counts_the_in_run_drops_against_the_servers_launched():
    throttled = DROPPED_RUN_REASONS[NotRunCause.THROTTLED]
    run = a_run(
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


_SECOND_PASS_LINE = (
    "- npm:flaky: run after a clean solo second pass of the vet (first pass: boom)\n"
)


def test_the_not_run_section_closes_on_the_second_pass_servers_after_the_not_run_ones():
    run = a_run(
        [a_server_result("A")],
        not_run=[
            NotRunServer("npm:benign", "the benign call errored", NotRunCause.BENIGN_CALL_FAILED)
        ],
        second_pass={"npm:flaky": "boom"},
    )

    markdown = render_markdown(build_report(run))

    assert f"- npm:benign: the benign call errored\n{_SECOND_PASS_LINE}" in markdown


def test_the_second_pass_servers_follow_none_when_no_server_is_not_run():
    run = a_run([a_server_result("A")], second_pass={"npm:flaky": "boom"})

    markdown = render_markdown(build_report(run))

    assert f"## Not run\n- none\n{_SECOND_PASS_LINE}\n" in markdown


def test_no_second_pass_line_when_every_server_answered_its_first_pass():
    markdown = render_markdown(build_report(a_run([a_server_result("A")])))

    assert "second pass" not in markdown


def test_build_report_carries_each_second_pass_server_with_its_first_reason():
    run = a_run([a_server_result("A")], second_pass={"npm:flaky": "boom"})

    assert build_report(run).second_pass == {"npm:flaky": "boom"}
