# Declared flips

## Context

ADR 020 lets a change to the system under test cost cells of the honeypot gate, provided it declares them before the evals run on it: "A flip on a declared cell does not fire the gate. The baseline is then re-recorded from a green run at that commit." Its Consequences add that "the code that reads a declaration does not exist yet [...] Until then such a regression is blocked." ADR 025 requires the same declaration for the case-by-case gate of the judge isolation eval.

This plan builds the declaration: a tracked file, its reader, and its wiring into the honeypot gate, with a fault injection scenario that proves it. The judge gate does not exist yet. The plan that implements ADR 025 wires the same reader into it, by adding a `judge` suite to the file.

## Readings of the ADRs, decided here

1. **The declaration lives in a tracked, append-only file, `evals/declared_flips.json`.** ADR 020 says the change "names those cells in its commit": the commit that makes the change adds the entries to the file. A file is reviewed in the diff, validated by a model, and keeps the history of every deliberate regression in one place. Commit trailers were considered and set aside: they are read from `git log` only, and a parser of free text in commit messages is harder to validate.
2. **"The declaration applies to that commit only" is enforced through the parent commit.** Each entry records `base`, the commit the change was written on. An entry is active only when `git rev-parse HEAD~` equals its `base`, that is only at the commit that adds it. At the next commit the entry is history and the gate ignores it, with nothing to clean up. CI therefore checks out two commits (`fetch-depth: 2`).
3. **An entry is active only on a clean tree.** A tree with tracked changes measures something other than the commit that declared. Entries that would be active are ignored, and the run prints a note saying so. It is not a refusal, so iterating locally on an uncommitted change keeps working.
4. **The suite field has one value today, `honeypot`.** The judge plan adds `judge`. A value no code reads would be dead code.
5. **A declared cell that flips reads `declared`**, is not replayed, and is not a reason for red. A declared cell that does not flip is reported in the gate result under `declared_held`, and is not a reason for red either: the author's prediction was wrong, which review reads.
6. **A green run with declared flips can be recorded at that commit.** The recording code refuses a run in which a gated cell flipped (`_FLIPPED` in `evals/recording.py`). `declared` is not in that set, so the existing re-recording path accepts the run and writes a new confirmed baseline that replaces the old one (`replaces`), with the runs of that recording. That is the behavior of any re-recording from a green run today, and ADR 023 governs only the confirmation of a first, exploratory recording. Known limit, left as it is: a deliberate regression is the moment the baseline moves most, and its new baseline rests on the runs of one recording, so a cell left unstable by the change can be stored as stable. Requiring a second recording there would be a governance rule, hence a new ADR, not part of this plan. The `CONTRIBUTING.md` paragraph states the limit.
7. **Checked before any LLM call:** an active entry naming a cell outside the ground truth, and two active entries naming the same cell, refuse the run. Every entry, active or not, must parse: a non-empty `mechanism`, a `base` of 40 hexadecimal characters, a `runs_seen` list (possibly empty). Inactive entries are not checked against the current ground truth, since a later label revision may remove a cell an old entry named.
8. **Left to review, as ADR 020 says:** the order between the declaration and the runs, reverting a change after a run red on an undeclared cell, and not declaring a cell already seen flipping. The `runs_seen` field carries what the author had seen, for review to check.
9. **Instrument status.** Observations, metrics and the baseline file format do not change, so no reset. The change still moves how a flip is read by the gate, which is instrument code, so it gets an entry in `docs/labeling-log.md` answering the four questions of ADR 016, like the recording code changes before it.

## Files

### New: `evals/declared_flips.py`

```python
DECLARED_FLIPS_PATH = REPO_ROOT / "evals" / "declared_flips.json"  # REPO_ROOT from evals.honeypots

class Suite(StrEnum):
    HONEYPOT = "honeypot"

class DeclaredFlip(BaseModel):
    suite: Suite
    key: str                      # "tool/category" for the honeypot suite, as cell_key writes it
    mechanism: str                # non-empty after strip: by which mechanism the change reaches the key
    base: str                     # 40 lowercase hex characters: the parent commit of the declaring commit
    runs_seen: list[str]          # the eval runs of the change the author had seen, possibly none

class DeclaredFlipsFile(BaseModel):
    entries: list[DeclaredFlip]

@dataclass(frozen=True)
class ActiveDeclarations:
    keys: frozenset[str] = frozenset()
    ignored: frozenset[str] = frozenset()   # would be active, ignored because the tree is dirty

def load_declared_flips(path: Path) -> list[DeclaredFlip]: ...
    # missing file -> []; invalid content raises ValidationError
def entries_of_commit(entries: list[DeclaredFlip], suite: Suite, parent: str | None) -> list[DeclaredFlip]: ...
    # pure: entries of `suite` whose base == parent; parent None -> []
def declaration_problems(entries: list[DeclaredFlip], known_keys: Collection[str]) -> list[str]: ...
    # pure, called on entries_of_commit: a key outside known_keys, a key named twice
def active_declarations(entries: list[DeclaredFlip], dirty: bool) -> ActiveDeclarations: ...
    # pure, called on entries_of_commit: their keys go to `keys`, or to `ignored` when dirty
def apply_declarations(
    cells: dict[Cell, CellComparison], declared: frozenset[Cell]
) -> dict[Cell, CellComparison]: ...
    # pure: a declared cell whose outcome is FLIP becomes DECLARED, every other comparison is returned unchanged
```

`apply_declarations` lives here rather than in `evals/gate.py`, which is at 297 lines (CLAUDE.md: files should rarely exceed 300 lines, when they do, split). It imports `Cell`, `CellComparison` and `CellOutcome` from `evals.gate`.

### New: `evals/declared_flips.json`

`{"entries": []}`

### `evals/gate.py`

- `CellOutcome.DECLARED = "declared"`.
- `observe`, `classify`, `compare`, `settle` and the metrics do not change.

### `evals/gate_verdict.py`

- `GateInput.declared: frozenset[Cell] = frozenset()`.
- `GateResult.declared_held: list[str] = []`: the `cell_key` of each declared cell present in `gate_input.cells` whose outcome is not `DECLARED`, sorted. A declared cell with no comparison (no baseline, `--ungated`) is not listed: nothing was compared, so no prediction was checked.
- `_red_reasons` is unchanged: only `REGRESSION` is a paired reason, so `DECLARED` never is.

### `evals/eval_session.py`

- `EvalSession.declarations: ActiveDeclarations = ActiveDeclarations()`, last field with a default so the positional construction in `evals/fault_harness.py` keeps working.
- `open_session` loads `DECLARED_FLIPS_PATH` (a `ValidationError` becomes `Refused(REFUSED_BEFORE_ANY_LLM_CALL, ...)`, as `_load_committed_baseline` does). When the file holds no entry, it reads no git state. Otherwise it reads the parent commit with `git rev-parse --verify --quiet HEAD~` (a failure, on a root commit, a one-commit shallow clone or outside a git checkout, means no parent, never a refusal). `_git` raises `Refused` on any non-zero exit, so this read needs its own call that returns `None` on `CalledProcessError` or `FileNotFoundError`. It then computes `entries_of_commit(entries, Suite.HONEYPOT, parent)`, and reads the dirty flag as `read_tree` does only when that list is not empty. It adds `declaration_problems(those entries, known_keys)`, with the `cell_key` of every cell of `MERGED_GROUND_TRUTH`, to the reasons of `pre_run_refusals` before raising, and sets `declarations=active_declarations(those entries, dirty)`. The git reads stay in `eval_session.py`, and the three functions they feed stay pure and tested on their own. `open_session` is already 20 lines, so the file load, the parent read, `entries_of_commit` and the dirty read go into one private helper right below it (for instance `_declarations_of_head() -> tuple[list[DeclaredFlip], bool]`, the entries of the commit and the dirty flag), and the parent read into its own private helper below that one. `open_session` only adds the problems to the reasons and builds the `ActiveDeclarations` (CLAUDE.md: functions should rarely exceed 20 lines, newspaper rule).

### `evals/judging.py`

In `judge_runs`, right after `compare(...)` and before `replayer.settle_flips(...)`: `cells = apply_declarations(cells, declared)`, where `declared` is the set of `parse_cell_key(key)` for `session.declarations.keys`. Pass `declared` to `GateInput`. The early return when `session.baseline is None` passes no `declared`: there are no cells to apply it to. `Replayer.settle_flips` replays `FLIP` cells only, so declared cells are not replayed with no change to `evals/replay.py`.

### `evals/cell_grid.py` and `evals/eval_display.py`

- `CellTag.DECLARED = "decl"`, mapped from `CellOutcome.DECLARED` in `_OUTCOME_TAGS`, with a style and the meaning "gated cell wrong in this run, declared before the run: the gate does not fail".
- `outcome_rows` already lists every outcome other than `UNCHANGED`, so declared cells appear with their per-run letters.
- The summary prints one line per `declared_held` cell ("declared, did not flip"), and, when `session.declarations.ignored` is not empty, one note that the declarations of HEAD were ignored because the tree has tracked changes. `evals/run_evals.py` passes what the display needs.

### Fault injection: `evals/fault_catalog.py`, `evals/fault_harness.py`

- `Fault.declares: AuditCategory | None = None`.
- `Harness._session(mode)` becomes `_session(mode, fault)` and sets `declarations=ActiveDeclarations(keys=...)` to the `cell_key` of every fixture cell in the fault's `declares` category.
- New fault `generator_drops_error_handling_declared`: the same wrap as `generator_drops_error_handling`, `declares=AuditCategory.ERROR_HANDLING`, `Expectation(GREEN, GREEN, False, ())`. It proves that the flips `generator_drops_error_handling` turns red on are exactly the ones a declaration clears.
- `evals/fault_injection_method.md`: one paragraph on the new fault and what it pins, its row in the table of expected results, and the scenario count of the "Cost" section (nine scenarios, eight faults).

### CI

`fetch-depth: 2` on the `actions/checkout` of the `e2e-eval` job in `.github/workflows/evals.yml`, and on the checkout in `.github/workflows/eval-command.yml`, which checks out the PR head commit. The `judge-eval` job does not need it until the judge plan.

`uv sync --dev --locked` instead of `uv sync --dev` in the same two places (`.github/workflows/evals.yml` line 50, `.github/workflows/eval-command.yml` line 97). Without `--locked`, a stale `uv.lock` is rewritten during the job, the tree reads dirty, and the declarations of HEAD are ignored with only a note in the log, so the gate goes red on every declared cell for a reason that looks like a regression. With it, the job fails at the sync and names the cause.

### Living docs

- `CONTRIBUTING.md`, section "Recording an e2e baseline": a paragraph "Declaring a deliberate regression": when, the entry fields, one commit holding the change and its entries, `base` as the parent commit (`git rev-parse HEAD`, read before committing), run the evals at that commit, record from the green run, and what review checks (runs seen, no cell already seen flipping, revert after a red on an undeclared cell). Two facts it states: the new baseline rests on the runs of that one recording, and a pull request merged by squash or rebase gives the declaring commit another parent, so its entries no longer match and must be edited, or the pull request merged with a merge commit.
- `CLAUDE.md`, section "When an eval number comes back red": one bullet on the declaration file, and the command list is unchanged.
- `CHANGELOG.md`, `[Unreleased]`, `Added`: the declaration file and what the gate does with it.
- `docs/labeling-log.md`: an entry "2026-09-28, declared flips", with state, what changes, and the four questions of ADR 016.

## What stays unchanged

`evals/baselines/honeypot_e2e.json` and the `Baseline` model, `observe`, `classify`, `compare`, `settle`, every metric, the replay rule, `evals/replay.py`, `evals/recording.py` (its refusals already leave `DECLARED` out), the CVE gate and its modules, the judge isolation eval, and the product under `src/`.

## Edge cases

- No entry in the file: no git read, nothing active, the gate behaves exactly as today.
- Root commit, or a checkout with one commit: no parent, nothing active.
- Several commits pushed together: CI evaluates the head only, so only the head's entries are active. That is ADR 020's "one change at a time".
- Dirty tree with entries whose `base` is HEAD~: ignored, note printed, the run goes on.
- Declared cell whose baseline state is unstable or stable incorrect: its outcome is not `FLIP`, so it stays as `compare` set it and is listed in `declared_held`.
- Declared cell that flips because of an uncovered observation (`FlipCause.UNCOVERED`): still `DECLARED`, the cause is kept on the comparison.
- Floors-only mode against an exploratory baseline: declarations are applied, and change nothing to the verdict since that mode reads no cell outcome. Legacy mode and `--ungated` have no baseline, hence no cells: declarations are not applied and `declared_held` is empty.
- A declaring commit rewritten onto another parent (rebase, cherry-pick) no longer matches its `base`: the entry is inactive and must be edited to the new parent. History here is linear with direct pushes, so this only concerns local rewrites before pushing.
- An old entry naming a cell a label revision later removed: inactive, not checked.

## Test scenarios

Unit tests, with given/then files where they abstract something:

- `tests/unit/test_declared_flips.py`: a missing file loads as no entry; an entry with an empty or blank mechanism, a short `base`, or no `runs_seen` fails to load; `entries_of_commit` keeps only the entries whose `base` equals the parent, and none without a parent; a dirty tree moves their keys to `ignored`; an unknown key and a key named twice among the entries of the commit are problems; an entry of another commit naming an unknown key is not, since it never reaches `declaration_problems`; `apply_declarations` turns a declared `FLIP` into `DECLARED`, leaves an undeclared `FLIP` and a declared `UNCHANGED` as they are.
- `tests/unit/test_eval_gate_verdict.py`: a paired run whose only flips are declared is green; a declared cell that did not flip is in `declared_held`; a regression on an undeclared cell stays red beside a declared flip.
- `tests/unit/test_eval_judging.py`: with a declared flip, the replayer is not asked to replay that cell and the gate is green; without the declaration the same run replays it.
- `tests/unit/test_eval_recording.py`: a green gate whose cells include `DECLARED` does not refuse a recording over a confirmed baseline.
- `tests/unit/test_eval_cell_grid.py`: a declared cell shows the `decl` tag.
- `tests/unit/test_eval_session.py`: an invalid declaration file is refused before any LLM call (monkeypatching `DECLARED_FLIPS_PATH` to a temporary file, the refusal happens before any git read).
- `tests/unit/test_eval_display.py`: the summary names a `declared_held` cell, and prints the note when declarations were ignored on a dirty tree.
- `tests/integration/test_gate_fault_injection.py`: the new fault is among the pinned faults (`PINNED_FAULTS` picks it up) and meets its expectation, green in both modes. A green verdict alone does not show which cells were cleared, so one more assertion: in `paired`, the fixture's stable and correct `error_handling` cells read `declared` and no cell reads `flip`, `regression` or `flip_not_reproduced`.

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, when it ran on 2026-09-28. Later passes read it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `fetch-depth: 2` (input of `actions/checkout`, default 1, a positive number fetches that many commits, verified against github.com/actions/checkout, whose current major, `v7`, is the one both workflows already pin)
- SETTLED: `git rev-parse --verify --quiet HEAD~` exits 0 and prints the parent in a depth-2 clone and in a `git fetch --depth=2 <sha>` checkout (the way `actions/checkout` fetches a `ref` SHA), and exits 1 with no output in a depth-1 clone (verified locally with git 2.43.0 against this repository)

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest tests/unit -n auto`, `uv run pytest tests/integration -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.

### Step 1: the declaration model and the gate outcome

- **Files**: `tests/unit/test_declared_flips.py` (plus `tests/unit/test_declared_flips_given.py` / `_then.py` only where they abstract something), `tests/unit/test_eval_gate_verdict.py`, `tests/unit/test_eval_recording.py`, `evals/declared_flips.py` (new), `evals/declared_flips.json` (new), `evals/gate.py`, `evals/gate_verdict.py`.
- **Do**:
  1. Write the tests first (see Test), run them, confirm they fail.
  2. `evals/gate.py`: add `CellOutcome.DECLARED = "declared"`. Nothing else in the file changes (it is at 297 lines).
  3. `evals/declared_flips.py`: `DECLARED_FLIPS_PATH`, `Suite` (one member, `HONEYPOT`), `DeclaredFlip`, `DeclaredFlipsFile`, `ActiveDeclarations`, and the pure functions `load_declared_flips`, `entries_of_commit`, `declaration_problems`, `active_declarations`, `apply_declarations`, with the signatures and behavior of the "Files" section above. Validation lives on the pydantic model: `mechanism` non-empty after strip, `base` matching 40 lowercase hex characters, `runs_seen` required (possibly empty). A missing file loads as `[]`, invalid content raises `ValidationError`. `apply_declarations` maps a declared cell whose outcome is `FLIP` to a copy of its comparison with outcome `DECLARED` (keep the other fields, `FlipCause` included), every other comparison unchanged. Newspaper order: public functions first.
  4. `evals/declared_flips.json`: `{"entries": []}`.
  5. `evals/gate_verdict.py`: `GateInput.declared: frozenset[Cell] = frozenset()`, `GateResult.declared_held: list[str] = []`, filled with the sorted `cell_key` of each declared cell present in `gate_input.cells` whose outcome is not `DECLARED`. `_red_reasons` unchanged.
- **Test**:
  - `test_declared_flips.py`: missing file loads as no entry; empty mechanism, blank mechanism, short `base`, missing `runs_seen` each fail to load; a valid file round-trips; `entries_of_commit` keeps only the entries of the suite whose `base` equals the parent, returns none when parent is `None`; `active_declarations` puts keys in `keys` on a clean tree, in `ignored` on a dirty one; `declaration_problems` reports an unknown key and a key named twice, and reports nothing for valid entries; an entry of another commit naming an unknown key yields no problem once filtered by `entries_of_commit`; `apply_declarations` turns a declared `FLIP` into `DECLARED`, leaves an undeclared `FLIP` and a declared `UNCHANGED` unchanged.
  - `test_eval_gate_verdict.py`: a paired run whose only flips are `DECLARED` is green; a declared cell whose outcome is not `DECLARED` is listed in `declared_held`; a `REGRESSION` on an undeclared cell stays red beside a declared flip.
  - `test_eval_recording.py`: a green gate whose cells include `DECLARED` does not refuse a recording over a confirmed baseline (no change to `evals/recording.py` expected).
- **Verify**: `uv run pytest tests/unit -n auto` green, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean.

### Step 2: wiring into the session, the judging and the display

- **Files**: `tests/unit/test_eval_session.py`, `tests/unit/test_eval_judging.py`, `tests/unit/test_eval_cell_grid.py`, `tests/unit/test_eval_display.py`, `evals/eval_session.py`, `evals/judging.py`, `evals/cell_grid.py`, `evals/eval_display.py`, `evals/run_evals.py`.
- **Do**:
  1. Tests first (see Test), confirm they fail.
  2. `evals/eval_session.py`: `EvalSession.declarations: ActiveDeclarations = ActiveDeclarations()` as last field. In `open_session`, call a private helper right below it, `_declarations_of_head() -> tuple[list[DeclaredFlip], bool]`: loads `DECLARED_FLIPS_PATH` (a `ValidationError` becomes `Refused(REFUSED_BEFORE_ANY_LLM_CALL, ...)`); with no entry, returns `([], False)` without any git read; otherwise reads the parent through its own private helper (`git rev-parse --verify --quiet HEAD~`, `None` on `CalledProcessError` or `FileNotFoundError`, not through `_git` which raises `Refused`), computes `entries_of_commit(entries, Suite.HONEYPOT, parent)`, and reads the dirty flag as `read_tree` does only when that list is not empty. `open_session` adds `declaration_problems(entries, {cell_key(c) for c in MERGED_GROUND_TRUTH cells})` to the reasons of `pre_run_refusals` before raising, and sets `declarations=active_declarations(entries, dirty)`. Keep `open_session` around 20 lines.
  3. `evals/judging.py`: in `judge_runs`, after `compare(...)` and before `replayer.settle_flips(...)`, `declared = frozenset(parse_cell_key(k) for k in session.declarations.keys)`, `cells = apply_declarations(cells, declared)`, pass `declared` to `GateInput`. The early return with no baseline passes no `declared`.
  4. `evals/cell_grid.py`: `CellTag.DECLARED = "decl"`, mapped from `CellOutcome.DECLARED` in `_OUTCOME_TAGS`, with its legend meaning "gated cell wrong in this run, declared before the run: the gate does not fail" and a style in `evals/eval_display.py` where the other tags get theirs.
  5. `evals/eval_display.py`: the summary prints one line per `declared_held` cell ("declared, did not flip"), and one note when `session.declarations.ignored` is not empty (declarations of HEAD ignored because the tree has tracked changes). `evals/run_evals.py` passes what the display needs (the gate result is already there, add the ignored set or the session's declarations). Keep `eval_display.py` under ~300 lines.
- **Test**:
  - `test_eval_session.py`: an invalid declaration file (monkeypatch `DECLARED_FLIPS_PATH` to a temporary file) is refused with `REFUSED_BEFORE_ANY_LLM_CALL`, before any git read.
  - `test_eval_judging.py`: with a declared flip in `session.declarations`, the replayer is not asked to replay that cell and the gate is green; without the declaration the same run replays it.
  - `test_eval_cell_grid.py`: a declared cell shows the `decl` tag.
  - `test_eval_display.py`: the summary names a `declared_held` cell, and prints the note when declarations were ignored.
- **Verify**: `uv run pytest tests/unit -n auto` green, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean.

### Step 3: fault injection scenario, CI and living docs

- **Files**: `tests/integration/test_gate_fault_injection.py`, `tests/integration/support/test_gate_fault_injection_then.py`, `evals/fault_catalog.py`, `evals/fault_harness.py`, `evals/fault_injection_method.md`, `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`, `CONTRIBUTING.md`, `CLAUDE.md`, `CHANGELOG.md`, `docs/labeling-log.md`.
- **Do**:
  1. Test first: in `test_gate_fault_injection.py`, a test for `generator_drops_error_handling_declared` asserting, in `paired`, that the fixture's stable and correct `error_handling` cells read `DECLARED` and no cell reads `FLIP`, `REGRESSION` or `FLIP_NOT_REPRODUCED` (the assertion goes in the `then` support module). The parametrized `test_the_gate_answers_each_fault` picks the new fault up through `PINNED_FAULTS`. Confirm it fails.
  2. `evals/fault_catalog.py`: `Fault.declares: AuditCategory | None = None`, and the new fault `generator_drops_error_handling_declared` with the same wrap as `generator_drops_error_handling`, `declares=AuditCategory.ERROR_HANDLING`, `Expectation(GREEN, GREEN, False, ())`.
  3. `evals/fault_harness.py`: `_session(mode)` becomes `_session(mode, fault)` and passes `declarations=ActiveDeclarations(keys=...)` with the `cell_key` of every fixture cell in the fault's `declares` category (empty when `None`).
  4. `evals/fault_injection_method.md`: one paragraph on the new fault and what it pins, its row in the table of expected results, the "Cost" section updated to nine scenarios, eight faults.
  5. CI: `with: fetch-depth: 2` on the `actions/checkout` of the `e2e-eval` job in `.github/workflows/evals.yml` (not the `judge-eval` job), and on the checkout in `.github/workflows/eval-command.yml`. In the same two jobs, `uv sync --dev --locked` instead of `uv sync --dev` (see the "CI" section).
  6. Living docs: `CONTRIBUTING.md` paragraph "Declaring a deliberate regression" in "Recording an e2e baseline" (when, the entry fields, one commit holding change and entries, `base` = `git rev-parse HEAD` read before committing, run the evals at that commit, record from the green run, what review checks, that the new baseline rests on the runs of one recording, and that a squash or rebase merge of a pull request gives the declaring commit another parent so its entries must be edited). `CLAUDE.md`: one bullet in "When an eval number comes back red" on `evals/declared_flips.json`, command list unchanged. `CHANGELOG.md` `[Unreleased]` / `Added`: the declaration file and what the gate does with it. `docs/labeling-log.md`: entry "2026-09-28, declared flips" with state, what changes, and the four questions of ADR 016, in the format of the existing entries. No em dashes in any prose.
- **Test**: the new fault meets its expectation (green in `paired` and `floors_only`, no recording refusal), and its `error_handling` stable-correct cells read `declared` with no `flip`, `regression` or `flip_not_reproduced` anywhere.
- **Verify**: `uv run pytest tests/integration -n auto` green (the Docker test may skip), `uv run pytest tests/unit -n auto` green, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean.
