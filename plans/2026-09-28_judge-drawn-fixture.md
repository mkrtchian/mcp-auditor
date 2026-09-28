# Judge isolation eval: drawn fixture and case-by-case gate

## Context

ADR 025 replaces the judge isolation fixture, 32 cases written by hand or promoted after the judge got them wrong, and its absolute F1 threshold of 0.90. The new fixture is drawn by a rule written before the draw, from the judged cases of honeypot e2e runs and of CVE benchmark runs, and each case is labeled on its own, blind to the judge's verdict. The gate compares case by case under the rules of ADR 016, 020, 022 and 023, with the case in place of the cell, and reads the declarations of `evals/declared_flips.json` (plan `plans/2026-09-28_declared-flips.md`) for a `judge` suite.

This plan builds the code: the export of judged cases by the CVE benchmark, the draw, the new fixture format, the case gate with its baseline and recording, and the living docs. The draw, the labeling and the two recordings are human work that follows the code, in the order the section "Operating procedure" gives. They are not implementation steps.

## Readings and decisions, settled in discussion

1. **Quotas, fixed here before any draw.** Honeypot e2e: 4 cases per cell the ground truth labels FAIL (8 cells, 32 cases), 1 case per cell it labels PASS (28 cells, 28 cases). CVE benchmark: 3 cases per target (6 targets, 18 cases). About 78 cases. The derivation goes in the method note: a case drawn from a FAIL cell is often a legitimate PASS under the any-fail rule, so with p the share of failing cases in such a cell and s the chance that a failing case comes out stable and correct, 4 cases protect the cell with probability 1-(1-p·s)^4, about 0.87 at p=0.5 and 0.79 at p=0.4 with s=0.8. The honeypot gate already protects the same planted flaws end to end, so the judge gate aims lower than 0.9. One case per PASS cell covers every PASS cell. The labeling effort, about two hours with an assistant, is the bound on the total.
2. **Complement rule, fixed here before any draw.** If, once labeled, the cases labeled FAIL are 40 % or more of the cases labeled PASS or FAIL, one more case is drawn in every PASS cell with the next seed, and labeled the same way. ADR 025 notes that the precision floor only catches a judge that fails everything while the FAIL cases are under half.
3. **Source runs are fresh runs at one commit that contains this code** (in practice the commit of the rubric and brief, step 1 of the operating procedure), at the default conditions, on a clean tree: two `run_evals --ungated` invocations and one `run_cve_benchmark --ungated`, each with its own `--report` path. The old exports under `output/` are not used: they predate the rule. The fixture records, for each source file, its path, its sha256, the commit it ran at and its conditions. Neither report records a commit today, and `EvalReport` records no provider nor model: this plan adds them (see the section on the reports below).
4. **Replay audits of the CVE gate are not exported.** A replay runs only for a gated target that missed, so exporting it would add cases chosen by their outcome. Only the audits of `_run_targets` are exported.
5. **Case identity is content.** A case id is the first 16 hex characters of the sha256 of the canonical JSON of its judge inputs: `tool_name`, `tool_description`, `category`, `description`, `arguments`, `response`, `error` (`json.dumps(..., sort_keys=True, separators=(",", ":"))`). The draw drops duplicate ids before drawing. These are exactly what `build_judge_prompt` reads.
6. **The judge inputs fingerprint covers the cases, not the prompt.** It is the sha256 of the sorted case ids. The judge prompt and `category_guidance` are the system under test: a prompt change must be comparable, which is the point of the gate. Labels are left out (ADR 025), so a rubric revision re-scores the stored observations as ADR 020 does for the honeypots.
7. **Every case is judged, unspecified ones included.** Observations carry no label. The ground truth of the gate is the cases labeled `pass` or `fail`, and metrics and comparison run over it. A case later labeled out of `unspecified` then already has observations.
8. **A judge call that raises (parse failure after the adapter's attempts, provider refusal) is an `uncovered` observation**, as a missing verdict is for a honeypot cell. It can flip a gated case, cause `uncovered`, and a recording is refused when any run holds an uncovered case.
9. **Gate modes.** No baseline or an exploratory one: floors only (ADR 025: "Until a baseline is confirmed, the gate runs on the floors alone"). Confirmed baseline: paired. `--ungated`: floors only, baseline not read. There is no legacy threshold mode for the judge: `F1_THRESHOLD` goes.
10. **Floors** (ADR 022 applied to cases): recall, at least as many detections as runs, a detection being a case labeled FAIL observed FAIL in a run. Precision 0.50, averaged per run with `label_scores`. A recording is refused with no stable and correct case on either side.
11. **The generic core of `evals/gate.py` becomes generic over the key**, with PEP 695 type parameters, so a case id and a cell go through the same `observe`-free functions: `protected_cells`, `classify`, `compare`, `settle`, `count_detections`, and in `evals/metrics.py` `compute_recall`, `compute_precision`, `label_scores`, plus `apply_declarations` in `evals/declared_flips.py`. Behavior and line counts do not change, the existing tests pin them, so this is neither a reset nor a labeling log entry: no observation and no metric of the honeypot suite changes. The judge baseline, recording, session and verdict are written in their own modules, in the injected style of the CVE session (`CVEHarness`), since replaying a case is one judge call and the honeypot modules are bound to cells, servers and `EvalMetrics`.
12. **Labeling uses an assistant under a written brief**, `evals/judge_labeling_brief.md`, committed before the draw. The assistant may show and explain the case's judge inputs, the server code without its comments, the published mechanism of a CVE, the category's definition in the rubric, and the rubric. It never shows or infers the judge's verdict or justification, the source cell's label, the `correct` field or a run index, and never proposes a label. The labeling log records that the labeler was assisted, what the labeler already knew, and the questions that were asked.
13. **The rubric lives in `docs/labeling-log.md`**, as a new entry with clauses J0, J1, ..., committed before the draw. It answers ADR 025's question, whether the response or error shows a failure, planted or not, in the category tested, without reference to `src/mcp_auditor/graph/prompts.py` or `src/mcp_auditor/domain/category_guidance.py`.
14. **The drawn fixture is committed unlabeled first**, as `evals/fixtures/judge_cases_drawn.json`, so git shows the draw preceded the labels. Labels are written in that file. The commit that completes the labels replaces `evals/fixtures/judge_cases.json` by the labeled draw and deletes the drawn file. Until then the eval runs on the legacy 32 cases, converted to the new format by this plan, under floors only.

## Files

### `evals/cve_audit.py`, `evals/cve_session.py`, `evals/run_cve_benchmark.py`, `evals/export.py`

- `evals/export.py`: extract the single-step line builder so both suites use it. New `export_cve_judged_cases(audits: list[CVEAudit], report_path: Path) -> None`, writing `report_path.with_name("cve_judged_cases.jsonl")`, one line per single-step case with an `eval_result`, keys `cve_id`, `run_index`, `type="single_step"`, `tool_name`, `tool_description`, `category`, `description`, `arguments`, `response`, `error`, `verdict`, `justification`. No `expected_verdict`: a CVE target has no per-case ground truth. Chains are not exported (another prompt judges them).
- `@dataclass(frozen=True) CVEAudit(cve_id: str, run_index: int, report: AuditReport)`, in `evals/cve_session.py` or a small module beside it.
- `evals/cve_audit.py`: `_attempt` keeps the `AuditReport` of the attempt whose grade is returned, and `audit_target` returns it with the grade. Keep the retry semantics of `graded_despite_refusals` unchanged: a refused attempt's report is dropped with it.
- `evals/cve_session.py`: `AuditTarget` returns the grade and the report. `_run_targets` collects `CVEAudit` for every completed audit with its run index. `_replayed` keeps only the grade. `CVESessionResult` gains `audits: list[CVEAudit]`.
- `evals/run_cve_benchmark.py`: after `_write_reports`, call `export_cve_judged_cases(session.audits, report_path)` in the graded modes. `--calibrate` exports nothing.
- The `AuditTarget` type changes, so the fakes of `tests/unit/support/test_cve_session_given.py` and the attempts of `tests/unit/test_cve_audit.py` (`graded_despite_refusals`) change with it. `graded_despite_refusals` can become generic over the attempt's outcome so its refusal loop is untouched.

### Source run provenance: `evals/eval_report.py`, `evals/run_evals.py`, `evals/cve_oracle.py`, `evals/run_cve_benchmark.py`

Today `EvalReport` holds `config` (runs, budget, concurrency) and no commit, and `CVEBenchmarkReport` holds `conditions` and no commit. The draw needs both.

- `EvalReport` gains `commit: str`, `dirty: bool` and `conditions: BaselineConditions` (the session's `conditions`). `CVEBenchmarkReport` gains `commit: str` and `dirty: bool`. Both runners call `read_tree()` once at the start of a graded run, in every mode (`--ungated` included), and write it in the report.
- `SourceRun.conditions` keeps the scalar fields only: `runs`, `budget`, `provider`, `model`, `judge_model`, `reasoning`, `judge_reasoning`.
- **The CVE report records what the provider billed.** The honeypot report already carries `provider_usage` per run, the CVE report carries only the throttled count. `SessionThrottles` in `evals/metrics.py` also sums the `provider_usage` of every report it counts, into a `usage: ProviderUsage` field (`ProviderUsage.add` exists), so every attempt is included, refused attempts and replays too, since they are billed. `CVEBenchmarkReport` gains `provider_usage: ProviderUsage`, the session total, and the markdown report prints input and output tokens beside the throttled count. No cost is computed: `ProviderUsage` says cost is computed at report time, and no price table exists in the evals. A rename of `SessionThrottles` to a name that covers both, if the implementer finds one, is fine.

### New: `evals/judge_fixture.py`

```python
class CaseLabel(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNSPECIFIED = "unspecified"

class CaseSource(StrEnum):
    HONEYPOT = "honeypot"
    CVE = "cve"
    LEGACY = "legacy"            # the 32 hand-written cases, until the drawn fixture replaces them

class JudgeInputs(BaseModel):  # exactly what build_judge_prompt reads
    tool_name: str
    tool_description: str | None
    category: AuditCategory
    description: str
    arguments: dict[str, Any]
    response: str | dict[str, Any] | None
    error: str | None

class JudgeCase(BaseModel):
    id: str                      # case_id(inputs), checked on load
    source: CaseSource
    origin: str                  # "cell tool/category" or "cve CVE-..."; "legacy" for legacy cases
    inputs: JudgeInputs
    label: CaseLabel | None      # None only in the drawn, not yet labeled file
    clause: str | None           # the rubric clause that decided the label

class SourceRun(BaseModel):
    path: str
    sha256: str
    commit: str
    conditions: dict[str, str | int | None]

class DrawRecord(BaseModel):
    seed: int
    quotas: dict[str, int]       # "fail_cell", "pass_cell", "cve_target"
    sources: list[SourceRun]
    shortfalls: list[str]        # strata with fewer candidates than their quota
    complement_seed: int | None = None

class JudgeFixture(BaseModel):
    draw: DrawRecord | None      # None for the legacy fixture
    cases: list[JudgeCase]

def case_id(inputs: JudgeInputs) -> str: ...
def load_fixture(path: Path) -> JudgeFixture: ...           # refuses a case whose id does not match its inputs, a duplicate id, a None label
def ground_truth_of(fixture: JudgeFixture) -> dict[str, EvalVerdict]: ...   # pass and fail cases only
def inputs_fingerprint(fixture: JudgeFixture) -> str: ...  # sha256 of the sorted ids
```

`load_fixture` is used by the eval. The draw and the labeling read the drawn file with a variant that accepts `None` labels (`load_drawn(path)`).

### New: `evals/draw_judge_cases.py`

Command `uv run python -m evals.draw_judge_cases --honeypot-export PATH --honeypot-export PATH --cve-export PATH [--complement]`, writing `evals/fixtures/judge_cases_drawn.json`.

- Constants: `DRAW_SEED`, `FAIL_CELL_QUOTA = 4`, `PASS_CELL_QUOTA = 1`, `CVE_TARGET_QUOTA = 3`.
- Pure functions, tested on their own: `candidates_from_honeypot(lines, ground_truth) -> dict[Cell, list[JudgeCase]]` (single-step lines of cells in the ground truth, chains and cells outside it left out, duplicate ids dropped), `candidates_from_cve(lines) -> dict[str, list[JudgeCase]]`, `draw(strata: dict[str, list[JudgeCase]], quota: int, rng: random.Random) -> tuple[list[JudgeCase], list[str]]` (honeypot strata keyed by `cell_key(cell)`, FAIL cells and PASS cells drawn in two calls with their own quota) (each stratum sorted by id, then `rng.sample`, all candidates and a shortfall line when fewer than the quota).
- The stripped case carries the judge inputs, the id, the source and the origin only. Verdict, justification, `correct`, `expected_verdict`, `run_index` and `cve_id` beyond the origin never reach the drawn file.
- Each source file is recorded with its sha256, and the commit and conditions read from the report beside it (`eval_report.json` or `cve_report.json`). The draw refuses a source whose report says `dirty`, and sources at different commits (decision 3).
- `--complement` takes the same export paths, reads the labeled drawn file, refuses unless every case is labeled and the complement rule (decision 2) fires, draws one more case per PASS cell with `DRAW_SEED + 1` among the candidates not already drawn, appends them unlabeled, and records `complement_seed` in the `DrawRecord`.
- The draw is honeypot-first then CVE, cells in `sorted` order, so the result is a function of the seed and the source files.
- **Leak check before writing.** The drawn file is committed to a public repository with the raw responses of the audited servers. The CVE servers run confined, so what they return comes from the container, but the check costs a few lines: before writing, the draw refuses to write when any drawn case's inputs (serialized) contain the invoking user's home directory (`Path.home()`), the user name (`getpass.getuser()`, matched as a whole path segment or word so a short name does not match everywhere), or an API key pattern (`sk-[A-Za-z0-9_-]{20,}`, `AIza[0-9A-Za-z_-]{35}`, `sk-ant-[A-Za-z0-9_-]{20,}`). It names each offending case id and the kind of match, never the matched text. The check is a pure function `leaked_secrets(cases, home, user) -> list[str]` taking the home and user as arguments, so tests pass fixed values. A refused draw is not patched by hand: the source runs are inspected and rerun.

### Legacy conversion: `evals/fixtures/judge_cases.json`

One commit converts the 32 current cases to the `JudgeFixture` format (`draw: null`, `source: legacy`, `origin: legacy`, `label` from `expected_verdict`, `clause: null`), with a one-off script not kept in the repo. The eval runs on it until the drawn fixture replaces it.

### `evals/gate.py`, `evals/metrics.py`, `evals/declared_flips.py`

- PEP 695 generics over the key for `protected_cells`, `classify`, `compare`, `_flip_cause`, `count_detections` (gate.py, `_state_of` and `_compare_cell` take no key), `compute_recall`, `compute_precision`, `label_scores` and `VerdictMap` (metrics.py), `verdict_maps_of` (baseline.py, the judge gate needs it to feed `label_scores` from observations), and `apply_declarations` (declared_flips.py). `Cell`, `VerdictMap` and `GroundTruth` stay as the honeypot instantiations. No behavior change. `gate.py` is at 298 lines today: if the signatures wrap past 300, split it rather than squeeze it.
- `evals/declared_flips.py`: `Suite.JUDGE = "judge"`. Key: a case id.
- `evals/eval_session.py`: the private `_declarations_of_head` takes the suite and becomes public, `declarations_of_head(suite: Suite) -> tuple[list[DeclaredFlip], bool]`, so the judge session reuses the git reads. The honeypot call passes `Suite.HONEYPOT`.

### New: `evals/judge_baseline.py`

```python
JUDGE_BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "judge_isolation.json"

class JudgeConditions(BaseModel):
    runs: int
    provider: str
    judge_model: str
    judge_reasoning: str | None
    inputs_fingerprint: str

class JudgeBaseline(BaseModel):
    status: BaselineStatus
    conditions: JudgeConditions
    replay_rule: ReplayRule
    commit: str
    recorded_at: str
    runs: list[dict[str, Observation]]      # case id -> observation, every case of the fixture
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    disagreements: list[str] = []
    protected: ProtectedCells

def load_judge_baseline(path: Path) -> JudgeBaseline | None: ...
def write_judge_baseline(path: Path, baseline: JudgeBaseline) -> None: ...   # atomic, as write_baseline
def judge_baseline_integrity(baseline: JudgeBaseline, fixture: JudgeFixture) -> list[str]: ...
    # run count (conditions.runs, twice with confirms), and each run's keys equal the fixture ids when the fingerprint matches
def judge_condition_mismatches(recorded: JudgeConditions, candidate: JudgeConditions) -> list[str]: ...
```

### New: `evals/judge_gate.py`

Pure functions over observations:

- `observe_case(verdict: EvalVerdict | None) -> Observation`.
- `judge_ci_condition_mismatches(conditions: JudgeConditions) -> list[str]`: `runs` against the judge default (3, not `eval_session.DEFAULT_RUNS`), `provider`, `judge_model` and `judge_reasoning` against `Settings` defaults, as `ci_condition_mismatches` does for the honeypots.
- `judge_floor_breaches(runs, ground_truth) -> list[str]`: recall floor through `count_detections` and `recall_floor_breached`, precision under 0.50 through `label_scores`.
- `judge_case_gate(gate_input: JudgeGateInput) -> JudgeGateResult`, where `JudgeGateInput` is a frozen dataclass naming `runs`, `ground_truth`, `baseline_runs` (`None` outside paired mode), `mode`, `declared` and `mismatches`, as `GateInput` does for `judge_gate` in `evals/gate_verdict.py`. It reuses `GateMode`, `GateVerdict`, `CellComparison`, `CellOutcome` (`DECLARED` included) and `ProtectedCells`. `JudgeGateResult`: `mode`, `verdict`, `reasons`, `baseline_status`, `cases: dict[str, CellComparison]`, `floor_breaches`, `declared_held`, `protected`.
- Red reasons: floor breaches in every mode, and in paired mode `regression on case <id>` for each `REGRESSION`. Any mismatch makes it `NOT_COMPARABLE`.

### New: `evals/judge_recording.py`

`decide_judge_recording(existing: JudgeBaseline | None, recording: JudgeRecording, gate: JudgeGateResult) -> JudgeBaseline | RecordingRefused`, with the rules of `evals/recording.py` applied to cases: a first recording is exploratory, a second one at the same commit adds its runs and confirms (ADR 023, disagreements listed), a confirmed baseline is replaced only from a green gate with no case in `FLIP`, `REGRESSION` or `FLIP_NOT_REPRODUCED` (`DECLARED` accepted). Refusals: an uncovered case in any run, a floor breach, no stable and correct case on the FAIL side or on the PASS side, mismatched conditions, the exploratory baseline recorded at another commit.

### New: `evals/judge_session.py`

```python
@dataclass(frozen=True)
class JudgeOptions:
    runs: int
    record_baseline: bool
    ungated: bool
    concurrency: int

@dataclass(frozen=True)
class JudgeHarness:
    judge: Callable[[JudgeCase], Awaitable[EvalVerdict | None]]   # None when the call raised
    baseline_path: Path
    read_tree: Callable[[], TreeState]
    declarations: Callable[[], tuple[list[DeclaredFlip], bool]]
    clock: Callable[[], datetime]

async def run_judge_gate(options: JudgeOptions, fixture: JudgeFixture, harness: JudgeHarness) -> JudgeSessionResult: ...
```

Order: refusals before any LLM call (`--record-baseline` with `--ungated`, baseline integrity, a baseline whose rescore under the current labels leaves a side blind as `rescore_refusals` does, conditions refused when recording off the CI defaults, dirty tree when recording, an exploratory baseline recorded at another commit when recording, declaration problems against the ground truth ids of the fixture), then every case judged `runs` times side by side under `bounded(..., concurrency)`, then comparison, declarations applied, and, in paired mode with no mismatch only (as `judge_runs` does for the honeypots), flipped cases replayed one judge call at a time until `ReplayRule.decide_replays` decides, a replay that raises counting as reproduced (as an uncovered replay does in `Replayer`), then the gate, then the recording. The recording is refused at write time when `tree_drift` finds the tree or `HEAD` changed during the runs, or the baseline file changed, as in the two other suites. `JudgeSessionResult` carries the runs, the gate result, the per-run confusion matrices for display, the written baseline or the refusal, and the exit code.

### `evals/run_judge_eval.py`

- Flags: `--runs` (default 3), `--record-baseline`, `--ungated`, `--concurrency` (`positive_int`, default 15), `--report` (default `output/judge_eval_report.json`).
- Exit codes as `run_evals`: 0 green or recorded, 1 red, 3 not comparable or refused, 4 crashed.
- `F1_THRESHOLD` goes. The per-run precision, recall and F1 and the per-category table stay in the summary and the report as diagnostics, with no threshold. The report adds the gate result, the observations per run and the fixture's inputs fingerprint.
- `_judge_one_case` builds the prompt from `JudgeInputs` as `_parse_case` does today and returns `None` when the LLM call raises `UnparseableOutput` or `ProviderRefusal` (`mcp_auditor.domain.ports`) only. Any other exception (a missing key, a network failure after the adapter's retries) propagates and exits 4: caught, it would turn a crash into every case `uncovered` and a red floor.

### `evals/judge_labeling_brief.md` (new) and `evals/judge_fixture_method.md` (new)

- The method note: the draw rule (sources, strata, quotas and their derivation, seed, complement rule, what is stripped), the fixture format, how a redraw and a relabel change the gate (a redraw changes the inputs fingerprint, so the baseline is deleted in that commit and recorded again twice, only from a green gate, as ADR 025 says; a relabel re-scores), and the operating procedure below.
- The brief: what the labeling assistant may show and explain, what it must never show or infer, and that it never proposes a label (decision 12).

### CI

- `.github/workflows/evals.yml`, job `judge-eval`: `fetch-depth: 2` on its checkout and `uv sync --dev --locked`, so the declarations of HEAD are read as for the e2e job. Command unchanged.
- `.github/workflows/eval-command.yml`: the judge step gets `id: judge` and records its exit code like the e2e step (`set +e`, `exit_code` output, a `JUDGE_EXIT_CODE` env in the report step), and the report step maps judge exit codes 1, 3 and 4 to a reason, before the e2e reason.

### Living docs

- `README.md`, section "Measurement": the paragraph "The judge is calibrated on 32 fixed cases" is rewritten: cases drawn from honeypot and CVE runs by a rule written before the draw, labeled case by case blind to the verdict, a case-by-case non-regression gate, no figure published.
- `CONTRIBUTING.md`: the judge eval section (what gates, exit codes), a section "Recording the judge baseline" (clean tree, CI conditions, two recordings at one commit, a redraw deletes the baseline), and the judge suite in "Declaring a deliberate regression".
- `CLAUDE.md`, Commands: the `run_judge_eval` flags and the draw command.
- `CHANGELOG.md` `[Unreleased]`: `Changed`, the judge eval gate and fixture. `Added`, the CVE judged cases export.
- `docs/labeling-log.md`: an entry for the instrument change (the fixture is replaced and the gate changes), answering the four questions of ADR 016, written in the commit that swaps the fixture. The rubric entry is written by the operating procedure, not by the implementation.

## What stays unchanged

The honeypot baseline and every honeypot observation and metric, the CVE oracle, grammar and baselines, the product under `src/` (judge prompt and category guidance included), `evals/export.py`'s honeypot output, `evals/replay.py`, `evals/recording.py`, and the rules of ADR 016, 020, 022 and 023 for the honeypot suite.

## Edge cases

- A stratum with fewer candidates than its quota: all its candidates are drawn and a shortfall line is recorded in `DrawRecord.shortfalls`.
- The same judge inputs in two runs or two exports: one case, since the id is the content.
- A case whose `tool_description` is null: kept, `build_judge_prompt` prints "No description provided".
- A labeled `unspecified` case: judged and observed, outside the ground truth, so outside metrics, floors, protected counts and comparison.
- A rubric revision changes labels only: the inputs fingerprint does not move, the baseline is re-scored under the new labels, and a relabel that leaves a side with no stable and correct case refuses the comparison as `rescore_refusals` does for the honeypots.
- A redraw: new inputs fingerprint, so the comparison is refused as not comparable until the baseline file, deleted in the redraw commit, is recorded again.
- A judge call that raises in a baseline recording: the recording is refused. In a gated run: an `uncovered` observation, which can flip a case and be replayed.
- Declarations for the `judge` suite naming an id outside the ground truth of the fixture (absent, or labeled `unspecified`): refused before any LLM call.
- The legacy fixture in floors-only mode: 8 FAIL cases, so the recall floor asks for 3 detections over 3 runs, which a working judge meets.

## Test scenarios

Unit tests, with given/then files where they abstract something, and a `FakeLLM` or a scripted judge callable, never an LLM:

- `test_export.py`: a CVE audit list writes one line per judged single-step case with its `cve_id` and run index, skips chains and unjudged cases.
- `test_cve_session.py` / `test_cve_audit.py`: completed audits of the main runs are collected with their run index, a replayed audit is not, a refused attempt's report is dropped.
- `test_run_cve_benchmark.py` / `test_eval_session.py` or the report tests: the report carries the commit and the dirty flag of the tree it ran on.
- `test_judge_fixture.py`: `case_id` is stable under key order, a case whose id does not match its inputs is refused, a duplicate id is refused, a `None` label is refused by `load_fixture` and accepted by `load_drawn`, `ground_truth_of` leaves unspecified cases out, the fingerprint ignores labels and changes with a case.
- `test_draw_judge_cases.py`: cells outside the ground truth and chains are not candidates, duplicate ids count once, a stratum smaller than its quota yields all its cases and a shortfall, the same seed and sources give the same draw, no stripped field (verdict, justification, `correct`, `expected_verdict`, `run_index`) appears in a drawn case, `--complement` draws one new case per PASS cell among those not drawn and refuses when a case is unlabeled or the rule does not fire, a dirty source or sources at two commits are refused.
- `test_eval_gate.py` and `test_eval_metrics.py`: unchanged and green after the generics.
- `test_judge_gate.py`: a run with no detection breaches the recall floor, a judge failing every case breaches the precision floor when FAIL cases are a minority, a stable correct case that flips and reproduces 4 times out of 5 is a regression and makes the gate red, one that does not reproduce is `flip_not_reproduced` and green, a declared flip is `declared` and green, a declared case that holds is in `declared_held`, a mismatch makes it not comparable.
- `test_judge_recording.py`: first recording exploratory, second at the same commit confirmed with runs concatenated, second at another commit refused, uncovered case refused, blind side refused, replacement of a confirmed baseline refused on a flip and accepted with a declared flip.
- `test_judge_baseline.py`: integrity on run counts and keys, condition mismatches, atomic write.
- `test_judge_session.py`: refusals happen before any judge call, a recording off the CI conditions or on a dirty tree is refused, flipped cases are replayed and not the others, a judge call raising `UnparseableOutput` or `ProviderRefusal` is `uncovered` and any other exception propagates, flipped cases are not replayed outside paired mode, a recording is refused when the tree drifted during the runs, a relabel leaving a side blind is refused before any judge call, the exit codes.
- `test_declared_flips.py`: a `judge` entry naming an id outside the ground truth of the fixture is a problem.

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## Operating procedure, after the implementation (human work, not implementation steps)

1. **Rubric and brief.** The maintainer writes the rubric entry (J0, J1, ...) in `docs/labeling-log.md` and reviews `evals/judge_labeling_brief.md`. A pilot on the legacy cases, stripped of their labels, may test the rubric before it is frozen. Commit.
2. **Source runs**, clean tree, default conditions: `uv run python -m evals.run_evals --ungated --report output/judge_source/honeypot_1/eval_report.json`, the same with `honeypot_2`, and `uv run python -m evals.run_cve_benchmark --ungated --report output/judge_source/cve/cve_report.json`.
3. **Draw**: `uv run python -m evals.draw_judge_cases --honeypot-export output/judge_source/honeypot_1/judged_cases.jsonl --honeypot-export output/judge_source/honeypot_2/judged_cases.jsonl --cve-export output/judge_source/cve/cve_judged_cases.jsonl`. Commit the unlabeled `evals/fixtures/judge_cases_drawn.json`.
4. **Labeling**, with the assistant under the brief, in the drawn file. If the complement rule fires, run the draw with `--complement`, commit, and label the new cases.
5. **Swap**: the labeled draw replaces `evals/fixtures/judge_cases.json`, the drawn file is deleted, and the labeling log entry for the instrument change is written, in one commit.
6. **Recordings**: `uv run python -m evals.run_judge_eval --record-baseline` twice at that commit, then commit `evals/baselines/judge_isolation.json`.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, on 2026-09-28. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: PEP 695 type parameter syntax for the generic `gate.py`, `metrics.py`, `baseline.py` and `declared_flips.py` functions (PEP 695 is Final since Python 3.12, `pyproject.toml` requires `>=3.13`, and the repo already uses it in `evals/concurrency.py`) (verified against peps.python.org/pep-0695)
- SETTLED: `actions/checkout@v7` with `fetch-depth: 2` on the `judge-eval` job (v7 is the latest major, `fetch-depth` defaults to 1) (verified against github.com/actions/checkout)
- SETTLED: `uv sync --dev --locked` (`--locked` fails on a stale lockfile, `--dev` is redundant since the dev group syncs by default, accepted by uv 0.10.10) (verified against docs.astral.sh/uv/concepts/projects/sync and a local `uv sync --dev --locked --dry-run`)
- SETTLED: case ids through `json.dumps(..., sort_keys=True, separators=(",", ":"))` and the draw through `random.Random(seed).sample` on id-sorted strata, both deterministic in the Python standard library
- OPEN (deferred): the published mechanism of each CVE the labeling assistant may show (decision 12), gathered at labeling time from sources the plan does not name, outside the code

## Implementation steps

Verification commands, used by every step (from `CLAUDE.md`):

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto   # steps 1, 3 and 6, which touch the runners
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

The rubric entry, the brief review, the source runs, the draw, the labeling, the swap commit with its labeling log entry and the two recordings are the operating procedure, not steps below.

### Step 1: CVE benchmark exports its judged cases

- **Files**: `tests/unit/test_export.py` (+ `tests/unit/support/test_export_given.py`), `tests/unit/test_cve_audit.py`, `tests/unit/test_cve_session.py`, `tests/unit/support/test_cve_session_given.py`, `evals/export.py`, `evals/cve_audit.py`, `evals/cve_session.py`, `evals/run_cve_benchmark.py`, `CHANGELOG.md`.
- **Do**:
  - Tests first: extend `test_export.py`, `test_cve_audit.py` and `test_cve_session.py`, adapt the `AuditTarget` fakes of `test_cve_session_given.py` so they return a grade and a report.
  - `evals/cve_session.py`: `@dataclass(frozen=True) CVEAudit(cve_id: str, run_index: int, report: AuditReport)`. `AuditTarget` becomes `Callable[[CVETarget], Awaitable[tuple[RunGrade, AuditReport] | None]]` (or a small named dataclass `GradedAudit(grade, report)` if it reads better). `_run_targets` collects a `CVEAudit` for every completed outcome, with its run index within its target (0..runs-1, submission order). `_TargetRuns` keeps the grades only for gating. `_replayed` reads the grade only and never adds to the audits. `CVESessionResult` gains `audits: list[CVEAudit]`.
  - `evals/cve_audit.py`: `_attempt` returns the grade with the report of that same attempt. Make `graded_despite_refusals` generic over the attempt's outcome (PEP 695, `[T]`, outcome `T | RefusedAttempt | None`) so its refusal loop is unchanged: a refused attempt's report is dropped with it.
  - `evals/export.py`: extract the single-step line builder into a helper returning the judge-input keys (`type="single_step"`, `tool_name`, `tool_description`, `category`, `description`, `arguments`, `response`, `error`, `verdict`, `justification`), used by the honeypot line (which adds `run_index`, `expected_verdict`, `correct`, output byte-identical to today) and by the new `export_cve_judged_cases(audits: list[CVEAudit], report_path: Path) -> None` writing `report_path.with_name("cve_judged_cases.jsonl")`, one line per single-step case with an `eval_result`, prefixed by `cve_id` and `run_index`. No chains, no `expected_verdict`, no `correct`.
  - `evals/run_cve_benchmark.py`: after `_write_reports`, `export_cve_judged_cases(session.audits, Path(args.report))` in the graded modes. `--calibrate` exports nothing.
  - `CHANGELOG.md` `[Unreleased]`, `Added`: the CVE benchmark writes `cve_judged_cases.jsonl` beside its report.
- **Test**:
  - export: two audits (CVE ids, run indexes 0 and 1) with a judged case, an unjudged case and a chain write exactly the judged single-step lines, each with its `cve_id` and `run_index`, no `expected_verdict`. Existing honeypot export tests stay green unchanged.
  - cve_audit: a refused attempt followed by a graded one returns the graded attempt's report, the refused report is not returned. All attempts refused returns `None`.
  - cve_session: completed audits of the main runs are collected with their run indexes, a run that returns `None` is not, an audit made during a replay (a flipped gated target) is not in `audits`.
- **Verify**: unit, integration, ruff, pyright all green.

### Step 2: the judge fixture format and the legacy conversion

- **Files**: `tests/unit/test_judge_fixture.py` (+ given file if it abstracts case building), `evals/judge_fixture.py` (new), `evals/fixtures/judge_cases.json`, `evals/run_judge_eval.py`.
- **Do**:
  - Tests first in `test_judge_fixture.py`.
  - `evals/judge_fixture.py`, as the plan's section "New: `evals/judge_fixture.py`" gives it: `CaseLabel`, `CaseSource`, `JudgeInputs`, `JudgeCase`, `SourceRun`, `DrawRecord`, `JudgeFixture`, `case_id(inputs)` (first 16 hex of the sha256 of `json.dumps(inputs.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))`), `load_fixture(path)` (refuses an id that does not match its inputs, a duplicate id, a `None` label), `load_drawn(path)` (same checks, `None` labels accepted), `ground_truth_of(fixture) -> dict[str, EvalVerdict]` (pass and fail cases only), `inputs_fingerprint(fixture)` (sha256 of the sorted ids, joined).
  - Convert the 32 legacy cases with a one-off script in the scratchpad, not committed: `draw: null`, `source: "legacy"`, `origin: "legacy"`, `label` from `expected_verdict`, `clause: null`, `id` from `case_id`.
  - `evals/run_judge_eval.py`: load through `load_fixture`, build the tool and test case from `JudgeInputs`, expected verdict from `ground_truth_of` (the legacy fixture has no `unspecified` case). Keep the rest of the runner (F1 threshold included) untouched in this step, the gate replaces it in step 6.
- **Test**: `case_id` stable under key order of `arguments`, differs when any input changes. `load_fixture` refuses a mismatched id, a duplicate id and a `None` label, `load_drawn` accepts the `None` label. `ground_truth_of` leaves `unspecified` out. `inputs_fingerprint` ignores labels and clauses and changes when a case is added or its inputs change. The converted legacy file loads through `load_fixture` with 32 cases, 8 labeled `fail`.
- **Verify**: unit, ruff, pyright green.

### Step 3: source run provenance and the draw command

- **Files**: `tests/unit/test_draw_judge_cases.py` (+ `tests/unit/support/test_draw_judge_cases_given.py`), `tests/unit/test_run_cve_benchmark.py` and/or `tests/unit/test_eval_session.py` for the provenance, `evals/eval_report.py`, `evals/run_evals.py`, `evals/cve_oracle.py`, `evals/run_cve_benchmark.py`, `evals/metrics.py` (`SessionThrottles`) (with `render_markdown`, already listed), `evals/draw_judge_cases.py` (new), `CLAUDE.md`.
- **Do**:
  - Tests first.
  - Provenance: `EvalReport` gains `commit: str`, `dirty: bool`, `conditions: BaselineConditions`. `CVEBenchmarkReport` gains `commit: str`, `dirty: bool`. `run_evals` and `run_cve_benchmark._run_graded` call `read_tree()` once at the start of every graded run (`--ungated` included) and write it in the report. Adapt the tests or fixtures that build these reports (`grep -rn "EvalReport(\|CVEBenchmarkReport(" evals tests`).
  - CVE usage: `SessionThrottles.count` also adds the report's `provider_usage` into `usage: ProviderUsage`. `CVEBenchmarkReport` gains `provider_usage: ProviderUsage` from the session total, and `render_markdown` prints input and output tokens beside the throttled count. No cost computed.
  - Leak check: pure `leaked_secrets(cases, home, user) -> list[str]` in `evals/draw_judge_cases.py`, called before writing with `Path.home()` and `getpass.getuser()`. It refuses the write and names each offending case id and the kind of match (home path, user name as a whole segment or word, `sk-`, `sk-ant-` or `AIza` key pattern), never the matched text.
  - `evals/draw_judge_cases.py`, as the plan's section "New: `evals/draw_judge_cases.py`" gives it: constants `DRAW_SEED`, `FAIL_CELL_QUOTA = 4`, `PASS_CELL_QUOTA = 1`, `CVE_TARGET_QUOTA = 3`. Pure functions `candidates_from_honeypot(lines, ground_truth)`, `candidates_from_cve(lines)`, `draw(strata, quota, rng)` (each stratum sorted by id, `rng.sample`, all candidates plus a shortfall line when short). Honeypot first (FAIL cells then PASS cells, keyed by `cell_key`, `sorted`), then CVE. The drawn case carries id, source, origin (`"cell <tool>/<category>"` or `"cve <CVE id>"`) and inputs, `label=None`, `clause=None`. Sources: path, sha256 of the export, commit and scalar conditions (`runs`, `budget`, `provider`, `model`, `judge_model`, `reasoning`, `judge_reasoning`) read from the `eval_report.json` or `cve_report.json` beside it. Refuses a dirty source and sources at different commits. `--complement`: reads the labeled drawn file through `load_drawn`, refuses unless every case is labeled and FAIL cases are 40 % or more of the PASS or FAIL cases, draws one more case per PASS cell with `DRAW_SEED + 1` among candidates not drawn, appends them unlabeled, sets `complement_seed`. Writes `evals/fixtures/judge_cases_drawn.json`. Keep the CLI shell thin (argparse, file reads, write) over the pure functions, and split the module if it passes 300 lines.
  - `CLAUDE.md` Commands: the draw command and its `--complement` form.
- **Test**:
  - provenance: the CVE report of a graded run carries the commit and dirty flag of the tree read (through an injected or monkeypatched `read_tree` as the existing tests do).
  - usage: `SessionThrottles` sums the input and output tokens of every counted report, a refused attempt's included, and the CVE report and its markdown carry the total.
  - leak check: a case whose response holds the given home path, the given user name as a path segment, or a key pattern is named with the kind of match and the matched text is absent from the message. A user name that only appears inside a longer word does not match. Clean cases give no line.
  - draw: cells outside the ground truth and chain lines are not candidates. The same inputs in two exports count once. A stratum smaller than its quota yields all its cases and a shortfall. Same seed and sources give the same draw. No stripped field (`verdict`, `justification`, `correct`, `expected_verdict`, `run_index`) in a drawn case. `--complement` draws one new case per PASS cell among those not drawn, refuses on an unlabeled case, refuses when the rule does not fire. A dirty source is refused, sources at two commits are refused.
- **Verify**: unit, integration, ruff, pyright green.

### Step 4: generic gate core and the judge suite of declarations

- **Files**: `evals/gate.py`, `evals/metrics.py`, `evals/baseline.py`, `evals/declared_flips.py`, `evals/eval_session.py`, `tests/unit/test_declared_flips.py`.
- **Do**:
  - PEP 695 type parameters over the key for `protected_cells`, `classify`, `compare`, `_flip_cause`, `count_detections` (gate.py), `compute_recall`, `compute_precision`, `label_scores` (metrics.py, with a generic alias for `VerdictMap`), `verdict_maps_of` (baseline.py), `apply_declarations` (declared_flips.py). `Cell`, `VerdictMap` and `GroundTruth` stay the honeypot instantiations. No behavior change. If `gate.py` passes 300 lines, split it (the metric deltas and resolutions are a natural module) rather than squeeze it.
  - `Suite.JUDGE = "judge"`.
  - `evals/eval_session.py`: `_declarations_of_head()` becomes `declarations_of_head(suite: Suite)`, the honeypot call passes `Suite.HONEYPOT`.
  - Test first for the one new behavior: a `judge` entry naming an id outside given known keys is a declaration problem, and `entries_of_commit` filters the judge suite apart from the honeypot one.
- **Test**: the new `test_declared_flips.py` case. `test_eval_gate.py`, `test_eval_metrics.py`, `test_eval_baseline.py`, `test_eval_session.py` unchanged and green.
- **Verify**: unit, ruff, pyright green (pyright strict is the real check of the generics).

### Step 5: judge baseline, case gate and recording decision

- **Files**: `tests/unit/test_judge_baseline.py`, `tests/unit/test_judge_gate.py`, `tests/unit/test_judge_recording.py` (+ a shared given file under `tests/unit/support/` for observations, fixtures and baselines, if it abstracts something), `evals/judge_baseline.py` (new), `evals/judge_gate.py` (new), `evals/judge_recording.py` (new).
- **Do**:
  - Tests first, one module at a time.
  - `evals/judge_baseline.py`, as the plan's section gives it: `JUDGE_BASELINE_PATH`, `JudgeConditions`, `JudgeBaseline`, `load_judge_baseline`, `write_judge_baseline` (atomic, as `write_baseline`), `judge_baseline_integrity` (run count against `conditions.runs`, doubled with `confirms`, and each run's keys equal the fixture ids when the fingerprint matches), `judge_condition_mismatches`.
  - `evals/judge_gate.py`: `observe_case`, `judge_ci_condition_mismatches` (runs against 3, `provider`, `judge_model`, `judge_reasoning` against `Settings` defaults, as `ci_condition_mismatches`), `judge_floor_breaches` (recall through `count_detections` and `recall_floor_breached`, precision under 0.50 through `label_scores` fed by `verdict_maps_of`), `JudgeGateInput` and `JudgeGateResult` as the plan names them, `judge_case_gate` reusing `GateMode`, `GateVerdict`, `CellComparison`, `CellOutcome`, `ProtectedCells`. Red: floor breaches in every mode, `regression on case <id>` per `REGRESSION` in paired mode. Any mismatch: `NOT_COMPARABLE`.
  - `evals/judge_recording.py`: `JudgeRecording` (runs, conditions, commit, recorded_at, replay rule) and `decide_judge_recording(existing, recording, gate) -> JudgeBaseline | RecordingRefused`, with the rules of `evals/recording.py` applied to cases (plan section "New: `evals/judge_recording.py`"), plus a `judge_rescore_refusals(baseline, ground_truth)` for a relabel that leaves a side blind, as `rescore_refusals`. Reuse `RecordingRefused` and the reset wording of `evals/recording.py` where it fits.
- **Test**:
  - baseline: integrity flags a wrong run count and a run whose keys differ from the fixture ids, condition mismatches name the field, the write is atomic and round-trips.
  - gate: no detection breaches the recall floor. A judge failing every case breaches the precision floor when FAIL cases are a minority. A stable correct case that flips and reproduces 4 of 5 replays is a regression and red. One that does not reproduce is `flip_not_reproduced` and green. A declared flip is `declared` and green, a declared case that holds is in `declared_held`. A mismatch is not comparable.
  - recording: first recording exploratory, second at the same commit confirmed with runs concatenated and disagreements listed, second at another commit refused, an uncovered case refused, a blind side refused, replacing a confirmed baseline refused on a flip and accepted with a declared flip, a relabel leaving a side blind refused by the rescore check.
- **Verify**: unit, ruff, pyright green.

### Step 6: judge session and the gated runner

- **Files**: `tests/unit/test_judge_session.py` (+ `tests/unit/support/test_judge_session_given.py`, and a `then` file if the assertions abstract something), `evals/judge_session.py` (new), `evals/run_judge_eval.py`, `tests/unit/test_judge_metrics.py` only if `judge_metrics.py` changes.
- **Do**:
  - Tests first, with a scripted `JudgeHarness.judge` callable (fixed verdicts per case id, a counter of calls, an option to raise), a fake `read_tree`, `declarations` and `clock`, a temporary baseline path.
  - `evals/judge_session.py`: `JudgeOptions`, `JudgeHarness`, `JudgeSessionResult`, `run_judge_gate(options, fixture, harness)` in the order the plan's section "New: `evals/judge_session.py`" gives: refusals before any judge call (raising `Refused` from `evals.eval_session`), every case judged `runs` times under `bounded(..., concurrency)`, observations through `observe_case`, comparison, `apply_declarations`, replays of flipped cases one judge call at a time in paired mode with no mismatch only (a raising replay, i.e. `None`, counts as reproduced), the gate, then the recording with the `tree_drift` and baseline-changed check at write time.
  - `evals/run_judge_eval.py`: flags `--runs` (3), `--record-baseline`, `--ungated`, `--concurrency` (`positive_int`, 15), `--report` (`output/judge_eval_report.json`). `F1_THRESHOLD` goes. `_judge_one_case` builds the prompt from `JudgeInputs` and returns `None` on `UnparseableOutput` or `ProviderRefusal` only. The composition root wires `create_judge_llm`, `read_tree`, `declarations_of_head(Suite.JUDGE)`, `JUDGE_BASELINE_PATH` and a UTC clock. The report keeps per-run precision, recall, F1, confusion matrix and the per-category table as diagnostics, and adds the gate result, the observations per run and the inputs fingerprint. Exit codes 0 green or recorded, 1 red, 3 not comparable or refused, 4 crashed (`traceback.print_exc()` as `run_evals`). Keep the display in its own small module if the runner passes 300 lines.
- **Test**: refusals (`--record-baseline` with `--ungated`, a broken baseline, a relabel leaving a side blind, recording off the CI conditions, on a dirty tree, over an exploratory baseline of another commit, a declaration naming an id outside the ground truth) happen with zero judge calls. Flipped cases are replayed and the others are not, and nothing is replayed outside paired mode. A judge raising `UnparseableOutput` or `ProviderRefusal` gives `uncovered`, any other exception propagates. A recording is refused when the tree drifted during the runs. The exit codes of green, red, not comparable and recorded.
- **Verify**: unit, integration, ruff, pyright green. `uv run python -m evals.run_judge_eval --help` lists the new flags.

### Step 7: CI wiring, method note, labeling brief and living docs

- **Files**: `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`, `evals/judge_fixture_method.md` (new), `evals/judge_labeling_brief.md` (new), `README.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `CHANGELOG.md`.
- **Do**:
  - `evals.yml`, job `judge-eval`: `fetch-depth: 2` on its checkout, `uv sync --dev --locked`, as the e2e job. Command unchanged.
  - `eval-command.yml`: the judge step gets `id: judge`, `set +e`, an `exit_code` output, a `JUDGE_EXIT_CODE` env in the report step, which maps judge exit codes 1, 3 and 4 to a reason before the e2e reason.
  - `evals/judge_fixture_method.md`: draw rule (sources, strata, quotas with the derivation of decision 1, seed, complement rule, stripped fields), fixture format, how a redraw (new fingerprint, baseline deleted in that commit and recorded twice, only from a green gate) and a relabel (re-score) change the gate, and the operating procedure.
  - `evals/judge_labeling_brief.md`: decision 12, what the assistant may show and explain, what it never shows or infers, that it never proposes a label, and what the labeling log records about the assisted labeling.
  - `README.md` "Measurement": rewrite the paragraph on the 32 fixed cases (drawn by a rule written before the draw, labeled case by case blind to the verdict, case-by-case non-regression gate, no figure published).
  - `CONTRIBUTING.md`: judge eval section (what gates, exit codes), "Recording the judge baseline", the judge suite in "Declaring a deliberate regression".
  - `CLAUDE.md` Commands: the `run_judge_eval` flags (`--record-baseline`, `--ungated`, `--runs`, `--concurrency`).
  - `CHANGELOG.md` `[Unreleased]`, `Changed`: the judge eval gate and fixture format.
  - The labeling log entry for the instrument change is not written here: it goes in the swap commit of the operating procedure.
- **Test**: `tests/unit/test_readme_policy.py` stays green (it polices the README). No new tests.
- **Verify**: unit, ruff, pyright green. A YAML parse of both workflows (`uv run python -c "import yaml,sys; [yaml.safe_load(open(p)) for p in sys.argv[1:]]" .github/workflows/evals.yml .github/workflows/eval-command.yml`, or `actionlint` if installed).
