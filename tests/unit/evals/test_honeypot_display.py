import pytest

import tests.unit.evals.support.test_honeypot_display_given as given
from evals.cell_grid import PARTIAL, CellTag
from evals.eval_display import print_outcome
from evals.gate import CellOutcome
from evals.gate_outcome import GateOutcome
from evals.honeypot.display import print_recorded_grid, print_summary
from tests.unit.support.captured_console import a_captured_console


def test_the_summary_states_the_throttled_requests_and_the_concurrency(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    report = given.an_eval_report({"concurrency": 6, "throttled_requests": 4})

    print_summary(report, "output/honeypot_report.json")

    assert "Throttled by the model provider: 4 requests at concurrency 6" in output.getvalue()


@pytest.mark.parametrize(
    "config", [{"concurrency": 6, "throttled_requests": 0}, {"concurrency": 6}]
)
def test_the_summary_says_nothing_of_throttling_when_nothing_was_throttled(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, config: dict[str, int]
):
    output = a_captured_console(capsys, monkeypatch)

    print_summary(given.an_eval_report(config), "output/honeypot_report.json")

    assert "Throttled" not in output.getvalue()


def test_the_summary_names_a_declared_cell_that_did_not_flip(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_summary(given.an_eval_report(declared_held=["query/injection"]), "report.json")

    assert "declared, did not flip: query/injection" in output.getvalue()


def test_the_summary_notes_the_declarations_ignored_on_a_dirty_tree(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    print_summary(
        given.an_eval_report(),
        "report.json",
        ignored_declarations=frozenset({"query/injection"}),
    )

    assert (
        "Declarations of HEAD ignored, the tree has tracked changes: query/injection"
        in output.getvalue()
    )


def test_the_summary_says_nothing_of_declarations_when_there_are_none(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    print_summary(given.an_eval_report(), "report.json")

    assert "declar" not in output.getvalue()


def test_the_summary_explains_a_partial_row(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    grid = given.a_gate_grid_with_an_outcome_row(PARTIAL)

    print_summary(given.an_eval_report(), "report.json", grid)

    assert (
        "partial: wrong in every baseline run, right in some runs of this one, not gated"
        in output.getvalue()
    )


def test_the_summary_says_nothing_of_partial_rows_when_there_are_none(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    grid = given.a_gate_grid_with_an_outcome_row(CellOutcome.REGRESSION)

    print_summary(given.an_eval_report(), "report.json", grid)

    assert "partial:" not in output.getvalue()


def test_the_summary_ends_with_the_verdict_panel(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    print_summary(given.an_eval_report(), "report.json")
    summary = output.getvalue()
    output = a_captured_console(capsys, monkeypatch)

    print_outcome(GateOutcome.GREEN, [])

    assert summary.endswith(output.getvalue())


def test_the_grid_tags_a_false_positive_and_an_improved_cell(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_recorded_grid("Baseline", given.a_grid_tagging(CellTag.FALSE_POSITIVE, CellTag.IMPROVED))

    printed = output.getvalue()
    assert " false_positive " in printed and " improved " in printed
    assert "false positive: PASS cell judged FAIL in every baseline run" in printed
    assert "miss or false-positive cell correct in every run of this one" in printed
