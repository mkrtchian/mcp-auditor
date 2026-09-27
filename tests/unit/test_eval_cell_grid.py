import pytest

import tests.unit.support.test_eval_cell_grid_given as given
import tests.unit.support.test_eval_cell_grid_then as then
from evals.cell_grid import CellTag, GridBox, OutcomeRow, cell_grid, outcome_rows
from evals.gate import CellOutcome, Observation
from mcp_auditor.domain.models import AuditCategory

FAIL = Observation.FAIL
PASS = Observation.PASS
UNCOVERED = Observation.UNCOVERED
PLANTED_CELL = given.PLANTED_CELL
SAFE_CELL = given.SAFE_CELL


def test_a_cell_identical_and_correct_across_the_runs_is_gated():
    sections = cell_grid(given.honeypots(), given.baseline_runs())

    assert then.tag_of(sections, PLANTED_CELL) == CellTag.GATE
    assert then.tag_of(sections, SAFE_CELL) == CellTag.GATE


def test_a_cell_varying_across_the_runs_is_unstable():
    runs = given.baseline_runs({SAFE_CELL: [PASS, FAIL, PASS]})

    assert then.tag_of(cell_grid(given.honeypots(), runs), SAFE_CELL) == CellTag.UNSTABLE


def test_a_planted_cell_never_detected_is_a_miss():
    runs = given.baseline_runs({PLANTED_CELL: [PASS, PASS, PASS]})

    assert then.tag_of(cell_grid(given.honeypots(), runs), PLANTED_CELL) == CellTag.MISS


def test_a_safe_cell_always_flagged_is_an_alarm():
    runs = given.baseline_runs({SAFE_CELL: [FAIL, FAIL, FAIL]})

    assert then.tag_of(cell_grid(given.honeypots(), runs), SAFE_CELL) == CellTag.ALARM


def test_a_planted_cell_seen_pass_pass_uncovered_is_unstable_not_a_miss():
    runs = given.baseline_runs({PLANTED_CELL: [PASS, PASS, UNCOVERED]})

    assert then.tag_of(cell_grid(given.honeypots(), runs), PLANTED_CELL) == CellTag.UNSTABLE


def test_only_a_planted_cell_is_marked_planted():
    sections = cell_grid(given.honeypots(), given.baseline_runs())

    assert then.box_of(sections, PLANTED_CELL) == GridBox(CellTag.GATE, planted=True)
    assert then.box_of(sections, SAFE_CELL) == GridBox(CellTag.GATE, planted=False)


def test_a_pair_outside_the_ground_truth_has_no_box():
    sections = cell_grid(given.honeypots(), given.baseline_runs())

    assert then.box_of(sections, ("list_dir", AuditCategory.INJECTION)) is None


def test_sections_rows_and_boxes_follow_honeypot_ground_truth_and_category_order():
    sections = cell_grid(given.honeypots(), given.baseline_runs())

    assert [section.honeypot for section in sections] == ["files", "database"]
    assert [row.tool for row in sections[0].rows] == ["write_file", "list_dir"]
    assert [row.tool for row in sections[1].rows] == ["query"]
    assert list(sections[0].rows[0].boxes) == list(AuditCategory)


@pytest.mark.parametrize(
    "seen", [[None, None, None], [PASS, None, PASS]], ids=["every run", "one run"]
)
def test_a_ground_truth_cell_missing_from_the_baseline_runs_is_new(
    seen: list[Observation | None],
):
    runs = given.baseline_runs({SAFE_CELL: seen})

    assert then.tag_of(cell_grid(given.honeypots(), runs), SAFE_CELL) == CellTag.NEW


@pytest.mark.parametrize(
    ("outcome", "tag"),
    [
        (CellOutcome.FLIP, CellTag.FLIP),
        (CellOutcome.FLIP_NOT_REPRODUCED, CellTag.FLIP),
        (CellOutcome.REGRESSION, CellTag.REGRESSION),
        (CellOutcome.IMPROVED, CellTag.FIXED),
        (CellOutcome.NOT_RECORDED, CellTag.NEW),
        (CellOutcome.UNCHANGED, CellTag.UNSTABLE),
        (CellOutcome.INCONCLUSIVE, CellTag.UNSTABLE),
    ],
)
def test_a_run_outcome_replaces_the_baseline_tag_unless_it_changes_nothing(
    outcome: CellOutcome, tag: CellTag
):
    runs = given.baseline_runs({SAFE_CELL: [PASS, FAIL, PASS]})
    run = given.a_run({SAFE_CELL: given.comparison(outcome)})

    assert then.tag_of(cell_grid(given.honeypots(), runs, run), SAFE_CELL) == tag


def test_outcome_rows_list_the_changed_cells_sorted_with_their_observations_and_replays():
    baseline = given.baseline_runs({PLANTED_CELL: [FAIL, FAIL, PASS]})
    candidate = given.baseline_runs({PLANTED_CELL: [FAIL, UNCOVERED, None]})
    run = given.a_run(
        {
            SAFE_CELL: given.comparison(CellOutcome.UNCHANGED),
            PLANTED_CELL: given.comparison(CellOutcome.INCONCLUSIVE),
            given.SECOND_SAFE_CELL: given.comparison(CellOutcome.REGRESSION, [True, False, True]),
        },
        candidate,
    )

    rows = outcome_rows(given.MERGED_GROUND_TRUTH, baseline, run)

    assert rows == [
        OutcomeRow(
            outcome=CellOutcome.REGRESSION,
            cell="query/injection",
            planted=False,
            baseline="PPP",
            run="PPP",
            replays="2/3",
        ),
        OutcomeRow(
            outcome=CellOutcome.INCONCLUSIVE,
            cell="write_file/injection",
            planted=True,
            baseline="FFP",
            run="F--",
            replays="-",
        ),
    ]
