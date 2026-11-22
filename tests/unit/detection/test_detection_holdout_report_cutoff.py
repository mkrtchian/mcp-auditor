"""The run cutoff of the holdout report: the latest cutoff of the run's models, the date the
split by cutoff side reads, and its line in the markdown."""

import dataclasses
from datetime import date

from evals.cve.detection.holdout_markdown import render_markdown
from evals.cve.detection.holdout_report import RunCutoffModel, build_report
from evals.cve.holdout_conditions import Cutoff
from evals.cve.holdout_statistic import Side
from tests.unit.detection.support.holdout_report_runs import a_run_result, a_target_result
from tests.unit.support.coarse_grid import COARSE_GRID

EARLIER = Cutoff(
    date=date(2026, 1, 15), type="knowledge cutoff", source="https://a.test", note=None
)
LATER = Cutoff(
    date=date(2026, 6, 30),
    type="training data cutoff",
    source="https://b.test",
    note="the last day of the month is taken",
)


def test_the_run_cutoff_is_the_latest_cutoff_of_the_run_models():
    run = dataclasses.replace(a_run_result(), cutoffs={"a": EARLIER, "b": LATER})

    report = build_report(run, grid=COARSE_GRID)

    assert report.run_cutoff == RunCutoffModel(
        model="b",
        date=date(2026, 6, 30),
        type="training data cutoff",
        source="https://b.test",
        note="the last day of the month is taken",
    )


def test_the_split_uses_the_run_cutoff_date():
    targets = (
        a_target_result("CVE-A", disclosure_date=date(2026, 3, 1), detected_runs=3),
        a_target_result("CVE-B", disclosure_date=date(2026, 7, 1), detected_runs=1),
    )
    early_only = dataclasses.replace(a_run_result(), targets=targets, cutoffs={"a": EARLIER})
    both = dataclasses.replace(early_only, cutoffs={"a": EARLIER, "b": LATER})

    assert {
        line.side: line.targets for line in build_report(early_only, grid=COARSE_GRID).sides
    } == {Side.POST_CUTOFF: 2}
    assert {line.side: line.targets for line in build_report(both, grid=COARSE_GRID).sides} == {
        Side.PRE_CUTOFF: 1,
        Side.POST_CUTOFF: 1,
    }


def test_on_equal_cutoff_dates_the_first_model_of_the_run_is_named():
    same_day = dataclasses.replace(LATER, type="other wording", source="https://c.test")
    run = dataclasses.replace(a_run_result(), cutoffs={"a": same_day, "b": LATER})

    assert build_report(run, grid=COARSE_GRID).run_cutoff.model == "a"


def test_the_split_section_opens_with_the_run_cutoff_line():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert (
        "## Split by cutoff side\n"
        "- run cutoff: 2026-05-18 (training), gpt-6-luna, https://example.test/luna\n"
    ) in markdown


def test_the_run_cutoff_line_carries_the_note_when_set():
    run = dataclasses.replace(a_run_result(), cutoffs={"b": LATER})

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert (
        "- run cutoff: 2026-06-30 (training data cutoff), b, https://b.test, "
        "note: the last day of the month is taken\n"
    ) in markdown
