# A cell grid at the end of an honeypot eval run

## Context

The honeypot gate compares a run to a recorded baseline cell by cell (ADR 016, 020, 022, 023), but the console reads as a pile of numbers. `evals/eval_display.py` prints a metrics table, a table of the cells whose outcome is not `unchanged`, and counts of protected cells ("planted FAIL cells stable and correct: 3/8, PASS cells stable and correct: 25/28, unstable: 5"). Which cells are out of the gate, unstable or stable and wrong, is never shown by name, and a green run reads as "nothing regressed" without showing that 8 of the 36 cells are not looked at. After a first recording, the gated set is printed as one "enters the gated set" line per cell, 31 lines.

This plan adds a grid of the cells, tools in rows and categories in columns, grouped by honeypot, with one coloured box per cell carrying a word for its state. It shows the comparison for what it is, paired and cell by cell. The grid is output only: no scoring rule, observation, verdict, floor, replay or recording rule changes, and the JSON report gains nothing.

A throwaway prototype was reviewed in discussion. It read the committed baseline and rendered the grid with `rich`: rounded boxes, a background colour per state, the word inside the box.

## Decisions taken in discussion

- **Words in coloured boxes, not glyphs alone.** Each box carries a short word with a background colour. The word keeps the grid readable without colour (colour-blind readers, `NO_COLOR`, a log searched with grep), and the colour makes it read at a glance.
- **Red is only for what fails the run.** `REGR` (a replay-confirmed regression, the one outcome that fails the gate) is bold white on bright red. A planted flaw the baseline never detected (`miss`) is a known weakness of the auditor, not a failure of the run: it is magenta, like a PASS cell always flagged (`alarm`), distinct from both the red of `REGR` and the yellow of `unst`.
- **The box shows the baseline state, replaced by the run's outcome only when there is one.** The raw observations and the replays go in an outcome table under the grid, which lists only the cells whose outcome is not `unchanged`. It replaces today's Cells table.
- **The grid scales with the suite.** Rows come from `HONEYPOTS` and each honeypot's ground truth, in their order, so a new honeypot or a new tool appears with no display change. Columns come from the `AuditCategory` enum, so the box holds one short word and no count: at 9 characters a column (7 plus padding), today's 5 categories take 72 columns with an 18-character tool name. A sixth brings it to 82, and rich then shrinks the tool column, its names cut with an ellipsis, to fit 80.
- **No labeling log entry.** ADR 020 counts labels, fixtures and the scoring code as the instrument. A display change is none of them, and logging it would blur the log.
- **CI shows the colours.** Rich turns colour off when its output is not a terminal. The eval steps of `.github/workflows/evals.yml` and `.github/workflows/eval-command.yml` set `TTY_COMPATIBLE: "1"` and `TTY_INTERACTIVE: "0"`, the pair rich's documentation recommends for GitHub Actions: the first makes rich emit colour, the second keeps the `Progress` bar of `_run_all` from redrawing live, which the Actions log would print frame after frame. The console output goes only to the Actions log, which renders ANSI colours. The PR comment is built from `output/eval_report.json` with `jq` and is not affected.
- **Only the 16 standard colours.** With `TERM` and `COLORTERM` unset, as on a CI runner, rich falls back to the 16 standard colours and turns an extended colour into its nearest one: an orange would come out yellow, the colour of `unst`. Using only standard colours gives the same grid in every terminal, local or CI. `miss` and `alarm` take magenta, which stays apart from the red kept for `REGR`.

## Approach

1. A new pure module, `evals/cell_grid.py`, turns the ground truth, the baseline runs and, for a gated run, the gate's comparisons and the candidate runs into rows of words: the grid sections and the outcome rows. No `rich`, no I/O.
2. `evals/eval_display.py` maps those rows to `rich` tables, with the styles and the legend. It stays untested, as today: the logic is in the pure module.
3. `evals/run_evals.py`, the composition root, builds the grid from the session's baseline and the run's outcome and passes it to the display.

## The grid

### Cell tags

A box shows one of these words:

| Tag | Meaning | Source |
|---|---|---|
| `gate` | gated: same correct verdict in every baseline run | baseline `STABLE_CORRECT` |
| `unst` | not gated: verdict varies across baseline runs | baseline `UNSTABLE` |
| `miss` | not gated: planted flaw never found | baseline `STABLE_INCORRECT` on a FAIL cell |
| `alarm` | not gated: PASS cell always flagged | baseline `STABLE_INCORRECT` on a PASS cell |
| `flip` | gated cell wrong in this run, not a regression | outcome `FLIP` or `FLIP_NOT_REPRODUCED` |
| `REGR` | gated cell wrong in this run, reproduced on replay: the gate fails | outcome `REGRESSION` |
| `fixed` | `miss` or `alarm` cell correct in every run of this one | outcome `IMPROVED` (an `unst` cell correct in every run stays `unchanged` in `compare`, so it stays `unst`) |
| `new` | cell the baseline did not record | outcome `NOT_RECORDED` |

`UNCHANGED` and `INCONCLUSIVE` keep the baseline tag: an inconclusive cell is already `unst`, and the outcome table names the outcome. `flip` covers `FLIP` too, a flip left unreplayed because the run was not comparable: the verdict panel already says so, and the outcome table shows no replay. A `*` after the tag marks a planted flaw (a FAIL cell of the ground truth). A tool/category pair that is not in the ground truth shows `·`.

### When the grid is printed

- **A gated run** (`GateMode.PAIRED`): the grid of the baseline with this run's outcomes, titled `Cells against the confirmed baseline (N runs)`, then the outcome table, then the legend.
- **A written recording** (`--record-baseline`, after the file is written): the grid of the new baseline alone, titled `Cells of the <status> baseline (N runs)`, then the legend. For a first recording it replaces the "enters the gated set" lines. For a later recording (a confirmation, or a re-recording over a confirmed baseline), the "enters" and "leaves" lines stay under the grid, since they say what changed. A re-recording over a confirmed baseline runs in `GateMode.PAIRED`, so it prints two grids: the gated run's grid against the old baseline in the summary, then the new baseline's grid once the file is written. That is intended: they show different baselines.
- **Every other mode**: no grid. With no baseline (legacy thresholds) or `--ungated` there is nothing to compare. With an exploratory baseline (floors only), `gate` would claim a gating that does not happen. The outcome table is still printed whenever the gate carries cells whose outcome is not `unchanged`, as the Cells table is today, so a second recording still shows how it compares with the first.

### Display

- One `rich` `Table` with `box=box.ROUNDED`. First column `tool`, then one column per `AuditCategory`, centered, `min_width=7`.
- One heading row per honeypot, its name in dim italic with empty cells, then one row per tool. `end_section=True` on the last row of each honeypot, so lines separate honeypots and not every row. The prototype put a line between every row. That stops scaling past about twenty tools.
- The tool column has `max_width=20` and `overflow="ellipsis"`, so a long name does not push the grid out of 80 columns. Today the longest is `get_service_status`, 18 characters.
- Column headers are short names, from a module-level `dict[AuditCategory, str]` in `eval_display.py`: `input`, `errors`, `inject`, `leak`, `abuse`. A category missing from it falls back to the first 7 characters of its value, so a new category never crashes the display.
- A box is `Text(f" {tag}{star}", style=STYLE[tag])`, where `star` is `*` or a space. Styles: `gate` `black on green`, `unst` `black on yellow`, `miss` and `alarm` `white on magenta`, `flip` `black on bright_yellow`, `REGR` `bold white on bright_red`, `fixed` `black on cyan`, `new` `black on white`. All are among the 16 standard colours (see Decisions). `·` is dim.
- No Panel around the grid: its border would push the grid past 80 columns.
- The legend is a `Table.grid(padding=(0, 2))`, one entry per line: the word on its coloured box, then its meaning, dim. It shows only the tags present in the grid, then `*  planted flaw` and `·  no such cell` when they occur, and one more line for a gated run: `a box counts the runs of the baseline, the outcome table the runs of this one`. One entry per line keeps a meaning from being cut from its word when the terminal wraps.

Reference rendering, recording view, the committed baseline (`89aedd7`), colours removed:

```
Cells of the confirmed baseline (6 runs)
╭────────────────────┬─────────┬─────────┬─────────┬─────────┬─────────╮
│ tool               │  input  │ errors  │ inject  │  leak   │  abuse  │
├────────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ honeypot           │         │         │         │         │         │
│ get_user           │    ·    │  gate*  │  gate   │  miss*  │  gate   │
│ execute_query      │  gate   │  gate   │  unst*  │  gate*  │  unst   │
│ list_items         │  unst   │  gate   │  gate   │  gate   │  gate   │
├────────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ subtle             │         │         │         │         │         │
│ search_users       │  unst   │  gate   │  gate   │  miss*  │  gate   │
│ delete_record      │  gate*  │  gate   │  gate   │  gate   │  gate   │
│ get_service_status │  gate   │  gate   │  gate   │  gate   │  gate   │
├────────────────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ chain_honeypot     │         │         │         │         │         │
│ project_manager    │    ·    │  gate   │    ·    │  unst*  │  gate   │
│ user_directory     │    ·    │  gate   │  gate   │  miss*  │  gate   │
╰────────────────────┴─────────┴─────────┴─────────┴─────────┴─────────╯
 gate    gated: same correct verdict in every baseline run
 unst    not gated: verdict varies across baseline runs
 miss    not gated: planted flaw never found
 *       planted flaw
 ·       no such cell
```

### Outcome table

It replaces `_cells_table`. Columns: `Outcome` (the `CellOutcome` value), `Cell` (the cell key, with `*` for a planted flaw), `Baseline` (the baseline observations), `Run` (the candidate observations), `Replays` (`reproduced/replayed`, or `-`). Observations are one letter per run, in run order: `P` pass, `F` fail, `-` not covered. Sorted by cell key, as today. No box (`box=None`), as in the example: the longest row (`flip_not_reproduced`, `get_service_status/input_validation*`, 6 baseline letters) already takes about 83 columns with padding, so at 80 rich folds the `Cell` column, which is acceptable for a table read rarely. The `Cause` column goes: the `Run` string shows a `-` when the cause is a cell left uncovered. A line under the table: `P pass, F fail, - not covered`.

```
 Outcome              Cell                        Baseline  Run  Replays
 flip_not_reproduced  get_user/error_handling*    FFFFFF    FPF  1/3
 inconclusive         execute_query/injection*    PPPPPF    PPF  -
```

## Files

### `evals/cell_grid.py` (new)

```python
class CellTag(StrEnum):
    GATE = "gate"
    UNSTABLE = "unst"
    MISS = "miss"
    ALARM = "alarm"
    FLIP = "flip"
    REGRESSION = "REGR"
    FIXED = "fixed"
    NEW = "new"


@dataclass(frozen=True)
class GridBox:
    tag: CellTag
    planted: bool


@dataclass(frozen=True)
class GridRow:
    tool: str
    boxes: dict[AuditCategory, GridBox | None]  # None: no such cell


@dataclass(frozen=True)
class GridSection:
    honeypot: str
    rows: list[GridRow]


@dataclass(frozen=True)
class RunAgainstBaseline:
    comparisons: dict[str, CellComparison]  # GateResult.cells, keyed by cell_key
    runs: list[dict[Cell, Observation]]


@dataclass(frozen=True)
class OutcomeRow:
    outcome: CellOutcome
    cell: str
    planted: bool
    baseline: str
    run: str
    replays: str


@dataclass(frozen=True)
class GateGrid:
    title: str
    sections: list[GridSection]  # empty against an exploratory baseline
    outcomes: list[OutcomeRow]


def cell_grid(
    honeypots: Sequence[HoneypotConfig],
    baseline_runs: list[dict[Cell, Observation]],
    run: RunAgainstBaseline | None = None,
) -> list[GridSection]: ...


def outcome_rows(
    ground_truth: GroundTruth,
    baseline_runs: list[dict[Cell, Observation]],
    run: RunAgainstBaseline,
) -> list[OutcomeRow]: ...
```

- `cell_grid` classifies the baseline runs with `classify(baseline_runs, honeypot.ground_truth)` for each honeypot, the current labels, as the gate does after `rescore`. Tools come in the order of their first cell in the honeypot's ground truth, categories in `AuditCategory` order. A ground truth cell the baseline runs do not hold (`classify` leaves it out) is `new`. With `run`, an outcome in the table of tags replaces the baseline tag.
- `outcome_rows` covers the comparisons whose outcome is not `UNCHANGED`. `baseline` and `run` are the observation letters of that cell across the runs, `-` for a run that does not hold it. `replays` is `f"{sum(replays)}/{len(replays)}"` or `-`.
- `HoneypotConfig` comes from `evals/honeypots.py`. The module imports nothing from `rich` or `eval_display`.

### `evals/eval_display.py`

- `print_summary(report, report_path, grid: GateGrid | None = None)`, where `GateGrid` is a frozen dataclass of `evals/cell_grid.py` holding `title: str`, `sections: list[GridSection]` and `outcomes: list[OutcomeRow]`. The grid, when given, prints after the metrics panel and before the protected-cells line. The outcome table replaces the Cells panel and prints when `grid.outcomes` is not empty. `grid` is None only with no baseline in the session. Against an exploratory baseline (floors-only mode), `GateGrid` carries the outcomes and no sections: `sections` is empty, and no grid or legend prints.
- `print_recorded_grid(title: str, sections: list[GridSection])`, new: the grid of a written recording and its legend, with no gated-run line. `_record` calls it right before `print_written_recording`, so the grid still prints first and `print_written_recording` keeps its three arguments (the standard aims at 3 or fewer).
- `print_written_recording(baseline, gated_changes, path)`, signature unchanged: the "enters" and "leaves" lines only when the recording replaced or confirmed an earlier one (`baseline.confirms` or `baseline.replaces` is set), then the disagreement lines, the protected-cells line and the next step, as today.
- New private helpers: `_print_grid(title, sections, gated_run)`, shared by `print_summary` and `print_recorded_grid`, `_grid_table(sections)`, `_legend(tags, gated_run)`, `_outcome_table(rows)`, and the `_STYLES` and `_SHORT_CATEGORY` dicts.
- `_cells_table` is removed.

### `evals/run_evals.py`

- `_evaluate` passes `_gate_grid(session.baseline, result)` to `print_summary`. `_gate_grid` is a new private helper, so `_evaluate` stays under 20 lines:
  - No baseline in the session (`session.baseline is None`, which covers `--ungated` too, see `EvalSession`): `None`.
  - Otherwise `outcomes = outcome_rows(MERGED_GROUND_TRUTH, baseline.observation_runs(), run)`, with `run = RunAgainstBaseline(comparisons=report.gate.cells, runs=result.outcome.observations())`, and `sections = cell_grid(HONEYPOTS, baseline.observation_runs(), run)` only when `report.gate.mode == GateMode.PAIRED`, `[]` otherwise. `GateMode` is imported from `evals.gate_verdict`.
- `_record` calls `display.print_recorded_grid(title, cell_grid(HONEYPOTS, decision.observation_runs()))`, the title built from `decision.status` and `len(decision.runs)`, then `print_written_recording` as today.

### `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`

`TTY_COMPATIBLE: "1"` and `TTY_INTERACTIVE: "0"` in the `env` of the step that runs `evals.run_evals` (`Run e2e evals` in `evals.yml`, `Run e2e eval` in `eval-command.yml`), beside `OPENAI_API_KEY`. Nothing else changes.

### Docs

- `CONTRIBUTING.md`, in "Recording an e2e baseline": one sentence saying that a gated run and a written recording print a grid of the cells, tools by categories, with what each box means in the legend under it.
- `CHANGELOG.md`, `[Unreleased]`: one line. The e2e evals print a grid of the cells, gated, unstable, missed or flagged, with this run's flips and regressions, and an outcome table with the raw observations and replays, which replaces the Cells table.
- `README.md`, `CLAUDE.md`: no change.

## What stays unchanged

- `evals/gate.py`, `evals/gate_verdict.py`, `evals/recording.py`, `evals/baseline.py`, `evals/judging.py`: no rule, state, outcome or field changes.
- The JSON report (`EvalReport`) and the baseline file format.
- The metrics panel, the verdict panel, the refusal panels, the per-run lines.
- `evals/run_judge_eval.py` and the CVE benchmark output.
- `docs/labeling-log.md`, the ADRs and every earlier plan.

## Edge cases

| Case | Expected |
|---|---|
| A tool/category pair outside the ground truth | `·` box, no tag |
| A ground truth cell the baseline runs do not hold | `new` in the grid, `not_recorded` row in the outcome table with `-` letters for the baseline |
| A planted cell seen PASS, PASS, then uncovered in the baseline | `unst*`, not `miss*`: the state comes from `classify`, never from a count of correct runs |
| A gated cell whose flip was replayed and reproduced | `REGR*` or `REGR`, outcome table with the replays |
| A flip left unreplayed because the run was not comparable | `flip`, `Replays` `-` |
| A `miss` cell detected in every run of this one | `fixed*` |
| An inconclusive cell | stays `unst`, row in the outcome table |
| A new honeypot added to `HONEYPOTS` | a new section, with no display change |
| A new `AuditCategory` without a short name | a column headed by the first 7 characters of its value |
| Floors-only mode (exploratory baseline) | no grid, outcome table if any cell changed |
| `--ungated`, or no baseline | no grid, no outcome table |
| `NO_COLOR` set, or output not a terminal outside CI | the same grid and legend, words only |

## Test scenarios

`tests/unit/test_eval_cell_grid.py`, with `tests/unit/support/test_eval_cell_grid_given.py` and `test_eval_cell_grid_then.py` where they abstract something. Test `cell_grid` and `outcome_rows` only, on small `HoneypotConfig`s built in the given module (two honeypots, a few tools, not all categories present).

- A cell stable and correct across the baseline runs is `gate`, a varying one `unst`, a FAIL cell never detected `miss`, a PASS cell always flagged `alarm`.
- A planted cell is marked planted, a PASS cell is not.
- A pair outside the ground truth is `None`.
- A planted cell seen PASS, PASS, uncovered is `unst`, not `miss`.
- Sections follow the order of the honeypots, rows the order of the tools in each ground truth, boxes the `AuditCategory` order.
- A ground truth cell missing from the baseline runs is `new`.
- With a run: each of `FLIP`, `FLIP_NOT_REPRODUCED`, `REGRESSION`, `IMPROVED`, `NOT_RECORDED` gives its tag, `UNCHANGED` and `INCONCLUSIVE` keep the baseline tag.
- `outcome_rows` lists only the changed cells, sorted by key, with the observation letters of baseline and run (`P`, `F`, `-`, including a run that lacks the cell), and `k/n` replays or `-`.

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

Then by hand, with no LLM call: a short script in the session scratchpad that loads `evals/baselines/honeypot_e2e.json`, calls `cell_grid` and `display.print_recorded_grid`, and checks that the recording view matches the reference rendering above, with and without `NO_COLOR=1`, at `COLUMNS=80`. The same script then builds a `GateGrid` from the committed baseline with fabricated outcomes (a `FLIP_NOT_REPRODUCED` on a `gate` cell with replays, a `REGRESSION`, an `INCONCLUSIVE` on an `unst` cell, an `IMPROVED` on a `miss` cell) and prints it through `print_summary` on a report stub, to see the gated-run grid, the outcome table and the gated-run legend line. A full eval run is not part of the verification.

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites, once, on 2026-09-27. Later passes read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded then, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `rich` `14.3.3` is the locked version, a 14.x as the plan says (verified against `uv.lock`)
- SETTLED: `TTY_INTERACTIVE: "0"` turns interactive mode off while colour stays on, so `Progress` prints its final state instead of redrawing (verified against the installed rich 14.3.3 `Console.__init__`, `Live.process_renderables`, `Progress.stop`, and rich.readthedocs.io, which recommends it for GitHub Actions)
- SETTLED: `box.ROUNDED`, `Table.grid(padding=(0, 2))`, `add_column(min_width=7)`, `add_column(max_width=20, overflow="ellipsis")`, `add_row(end_section=True)` exist in rich 14.3.3 (verified against the installed source)
- OPEN (unverified): the GitHub Actions log renders ANSI colours, community sources say yes for the 16 standard and bright colours, no GitHub documentation page was found, and 256-colour support was not confirmed

## Implementation steps

### Step 1: the pure cell grid module

- **Files**: `tests/unit/test_eval_cell_grid.py` (new), `tests/unit/support/test_eval_cell_grid_given.py` (new), `tests/unit/support/test_eval_cell_grid_then.py` (new, only if an assertion helper actually abstracts something), `evals/cell_grid.py` (new).
- **Do**:
  1. Tests first. In the given module, build two small `HoneypotConfig`s (from `evals/honeypots.py`, `server=Path("unused.py")` is enough, the server is never started): a few tools each, not every `AuditCategory` present for every tool, at least one FAIL and several PASS cells. Add helpers that build baseline runs (`list[dict[Cell, Observation]]`) from per-cell observation sequences, and a `RunAgainstBaseline` from a `{Cell: CellComparison}` map (keyed with `cell_key` from `evals/gate.py`) plus candidate runs. Import style as in `tests/unit/test_eval_gate.py` (`import tests.unit.support.test_eval_cell_grid_given as given`). Run the tests and see them fail (import error counts).
  2. Write `evals/cell_grid.py` with the types of the plan's "Files" section: `CellTag` (StrEnum), `GridBox`, `GridRow`, `GridSection`, `RunAgainstBaseline`, `OutcomeRow`, `GateGrid`, and the two public functions `cell_grid(honeypots, baseline_runs, run=None) -> list[GridSection]` and `outcome_rows(ground_truth, baseline_runs, run) -> list[OutcomeRow]`. Newspaper order: public functions first, private helpers under their callers.
     - `cell_grid`: for each honeypot, `states = classify(baseline_runs, honeypot.ground_truth)`. Tools in the order of their first cell in the honeypot's ground truth (dict insertion order). For each tool, one box per `AuditCategory` in enum order: `None` if `(tool, category)` is not in the ground truth, otherwise `GridBox(tag, planted=expected == EvalVerdict.FAIL)`. Baseline tag: `STABLE_CORRECT` -> `GATE`, `UNSTABLE` -> `UNSTABLE`, `STABLE_INCORRECT` -> `MISS` on a FAIL cell, `ALARM` on a PASS cell, absent from `states` -> `NEW`. With `run`, look up `run.comparisons.get(cell_key(cell))` and replace the tag by outcome: `FLIP` and `FLIP_NOT_REPRODUCED` -> `FLIP`, `REGRESSION` -> `REGRESSION`, `IMPROVED` -> `FIXED`, `NOT_RECORDED` -> `NEW`, `UNCHANGED` and `INCONCLUSIVE` keep the baseline tag (a module-level `dict[CellOutcome, CellTag]` holding only the replacing outcomes reads well).
     - `outcome_rows`: for every comparison in `run.comparisons` whose outcome is not `UNCHANGED`, sorted by key, an `OutcomeRow(outcome, cell=key, planted=ground_truth.get(parse_cell_key(key)) == EvalVerdict.FAIL, baseline=letters(baseline_runs), run=letters(run.runs), replays=...)`. Letters: one per run, `P` for `Observation.PASS`, `F` for `FAIL`, `-` for `UNCOVERED` or a run that lacks the cell. `replays`: `f"{sum(r)}/{len(r)}"` when the list is non-empty, `-` otherwise.
     - No import from `rich` or `evals.eval_display`, no I/O.
- **Test** (in `tests/unit/test_eval_cell_grid.py`, about 12 cases, parametrize the outcome-to-tag mapping):
  - Baseline tags: a cell identical and correct across runs is `gate`, a varying cell `unst`, a FAIL cell always observed PASS `miss`, a PASS cell always observed FAIL `alarm`.
  - A FAIL cell's box has `planted=True`, a PASS cell's `planted=False`.
  - A tool/category pair outside the ground truth gives `None`.
  - A planted cell observed PASS, PASS, UNCOVERED is `unst`, not `miss`.
  - Section order follows the honeypot list, row order the order of first appearance of each tool in its ground truth, box keys the `AuditCategory` order.
  - A ground truth cell missing from every baseline run (or from one run) is `new`.
  - With a run (parametrized): `FLIP` -> `flip`, `FLIP_NOT_REPRODUCED` -> `flip`, `REGRESSION` -> `REGR`, `IMPROVED` -> `fixed`, `NOT_RECORDED` -> `new`, `UNCHANGED` and `INCONCLUSIVE` keep the baseline tag.
  - `outcome_rows`: only non-`UNCHANGED` cells, sorted by key, baseline letters such as `FFP`, run letters with `-` for an uncovered observation and for a run lacking the cell, `planted` set from the ground truth, replays `2/3` for `[True, False, True]` and `-` for an empty list.
- **Verify**: `uv run pytest tests/unit/test_eval_cell_grid.py` red before the module exists, then `uv run pytest tests/unit -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green.

### Step 2: render the grid, wire it into the eval run, CI colours and docs

- **Files**: `evals/eval_display.py`, `evals/run_evals.py`, `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  1. `evals/eval_display.py` (untested, as today, the logic lives in `evals/cell_grid.py`):
     - `print_summary(report, report_path, grid: GateGrid | None = None)`. After the metrics panel: when `grid` is given and `grid.sections` is non-empty, `_print_grid(grid.title, grid.sections, gated_run=True)`. Then, when `grid` is given and `grid.outcomes` is non-empty, print `_outcome_table(grid.outcomes)` and the line `P pass, F fail, - not covered`. This replaces the Cells panel. Then the protected-cells line, report path and verdict panel as today.
     - `print_recorded_grid(title, sections)`: `_print_grid(title, sections, gated_run=False)`.
     - `print_written_recording(baseline, gated_changes, path)`, signature unchanged: print the "enters" and "leaves" lines only when `baseline.confirms is not None or baseline.replaces is not None`. Everything else as today.
     - Private helpers under their callers: `_print_grid(title, sections, gated_run)` prints the title, `_grid_table(sections)` and `_legend(tags, gated_run)`. `_grid_table`: `Table(box=box.ROUNDED)`, column `tool` with `max_width=20, overflow="ellipsis"`, then one column per `AuditCategory` (`justify="center", min_width=7`) headed by `_SHORT_CATEGORY.get(category, category.value[:7])`. Per section: a heading row with the honeypot name in `dim italic` and empty cells, then one row per tool, `end_section=True` on its last row. A box is `Text(f" {tag}{star}", style=_STYLES[tag])` with `star` `*` or a space, a `None` box is `Text("·", style="dim")`. `_legend`: `Table.grid(padding=(0, 2))`, one line per tag present in the grid (in `CellTag` order), its word on its coloured box then its meaning in dim (meanings from the plan's Cell tags table), then `*  planted flaw` and `·  no such cell` when they occur, then, for a gated run only, `a box counts the runs of the baseline, the outcome table the runs of this one`. `_outcome_table(rows)`: `Table(box=None)`, columns `Outcome`, `Cell` (key plus `*` when planted), `Baseline`, `Run`, `Replays`.
     - `_STYLES: dict[CellTag, str]` and `_SHORT_CATEGORY: dict[AuditCategory, str]` with the values of the plan's Display section (`input`, `errors`, `inject`, `leak`, `abuse`, check the enum member names in `mcp_auditor.domain.models`).
     - Remove `_cells_table` and any import it leaves unused (`CellComparison` likely).
  2. `evals/run_evals.py`:
     - `_evaluate` calls `display.print_summary(result.report, options.report, _gate_grid(session.baseline, result))`.
     - New private `_gate_grid(baseline: Baseline | None, result: EvalRunResult) -> GateGrid | None` right under `_evaluate`: `None` when `baseline is None`. Otherwise `run = RunAgainstBaseline(comparisons=result.report.gate.cells, runs=result.outcome.observations())`, `baseline_runs = baseline.observation_runs()`, `outcomes = outcome_rows(MERGED_GROUND_TRUTH, baseline_runs, run)`, `sections = cell_grid(HONEYPOTS, baseline_runs, run)` when `result.report.gate.mode == GateMode.PAIRED` (from `evals.gate_verdict`), `[]` otherwise, and title `f"Cells against the confirmed baseline ({len(baseline.runs)} runs)"`.
     - `_record`: right before `display.print_written_recording(...)`, `display.print_recorded_grid(f"Cells of the {decision.status} baseline ({len(decision.runs)} runs)", cell_grid(HONEYPOTS, decision.observation_runs()))`.
  3. Workflows: in the `env` of the step `Run e2e evals` (`.github/workflows/evals.yml`) and `Run e2e eval` (`.github/workflows/eval-command.yml`), beside `OPENAI_API_KEY`, add `TTY_COMPATIBLE: "1"` and `TTY_INTERACTIVE: "0"`. Nothing else.
  4. Docs: `CONTRIBUTING.md`, section "Recording an e2e baseline": one sentence saying a gated run and a written recording print a grid of the cells, tools by categories, with what each box means in the legend under it. `CHANGELOG.md`, `[Unreleased]`: one line, the e2e evals print a grid of the cells (gated, unstable, missed or flagged, with this run's flips and regressions) and an outcome table with the raw observations and replays, which replaces the Cells table. No change to `README.md`, `CLAUDE.md`, `docs/`, or earlier plans.
- **Test**: no new unit test (display and composition root stay untested, as today). Manual check, no LLM: a script in the session scratchpad that loads `evals/baselines/honeypot_e2e.json` with `load_baseline`, calls `cell_grid(HONEYPOTS, baseline.observation_runs())` and `display.print_recorded_grid(...)` with the recording title, run at `COLUMNS=80`, with and without `NO_COLOR=1`: the output matches the plan's reference rendering (title, 72-column grid, honeypot heading rows, section lines between honeypots only, legend with only `gate`, `unst`, `miss`, `*`, `·`). Then build a `GateGrid` from the same baseline with fabricated outcomes (a `FLIP_NOT_REPRODUCED` on a `gate` cell with replays, a `REGRESSION`, an `INCONCLUSIVE` on an `unst` cell, an `IMPROVED` on a `miss` cell) and call `print_summary` on a report stub: the gated-run grid shows `flip`, `REGR` and `fixed`, the outcome table lists the four cells with their letters and replays, and the legend carries the gated-run line.
- **Verify**: `uv run pytest tests/unit -n auto`, `uv run pytest tests/integration -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green, and the manual rendering check above.
