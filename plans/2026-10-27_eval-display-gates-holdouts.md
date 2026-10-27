# Eval display: progress, throttled total, baseline runs and a console summary for the CVE and nuisance modes

## Context

The e2e evals and the judge eval got their display work on 2026-10-05 (`plans/2026-10-05_judge-eval-paired-display.md`, `plans/2026-10-05_partial-improvements-display.md`): a progress bar, a throttled-request total with the concurrency, rich tables, baseline and run observations side by side, the verdict in a coloured panel printed last. Four modes did not:

- the CVE acceptance gate (`run_cve_benchmark`, graded modes: gated, `--record-baseline`, `--ungated`),
- the CVE holdout run (`run_holdout run`),
- the nuisance gate (`run_nuisance gate`),
- the nuisance holdout run (`run_nuisance run`).

What the operator sees in those four today:

- No progress, though each is a Docker and LLM run of many minutes. The image rebuild (`holdout_run.rebuild_images`, `subprocess.run` with no capture) and the pre-run checks take minutes with nothing on screen but docker's own output.
- Only the CVE gate prints the throttled total. The holdout run counts throttled requests in a `SessionThrottles` (`holdout_run.default_deps`) and drops the count; the nuisance run and gate count nothing (one yellow line per throttled audit, `nuisance_audit._print_incidents`, no total).
- All four print their markdown report as the end of run output (`print(markdown)`, or `console.print(markdown)` for the CVE gate, where a `[` in a detail is read as rich markup). The CVE results table has 10 columns, several of them free text: raw, it is unreadable in a terminal, and rendered through `rich.markdown.Markdown` (tried at 110 columns) it truncates the target id and the status, the two columns the reader reads for.
- The CVE gate prints its verdict twice (`Gate: red.` in the markdown, `cve_oracle._render_gate`, then a plain `Gate: [bold]red[/bold].`, `run_cve_benchmark._print_session`), neither coloured nor last: the throttled line and the recording lines come after it. A refused recording prints twice (in the markdown and as a panel). The nuisance gate prints its verdict first (`Verdict: **red**`, the raw enum value), and its recordings and orphaned baseline files twice (the markdown's `## Recording` section, then `_print_baselines`).
- The two gates list each target (server) with its candidate runs only: a target missed in every baseline run and detected in some runs of this one reads `not_gated` with nothing saying it was missed before. Replays read three ways across the six evals: `1/2` (e2e, judge), the words `reproduced, cleared` (CVE), `A.` letters (nuisance gate).
- The holdout run, the nuisance run and the nuisance gate never print where the report was written.
- Next steps after a recording: the CVE exploratory line says nothing of committing; the nuisance gate's `Run gate --record-baseline again now...` is not a runnable command.

The two holdout runs are proof-free by rule (`docs/holdout-rule.md`, "a holdout run writes and prints no proof text, no judge input and no verdict per case, only the statuses, the counts and the places"; `docs/nuisance-rule.md`, Reading). A progress bar counting audits, a throttled-request count and the report path add no per-case detail. Nothing else is added to the holdout output.

This change is display and report only. No gate decision, comparison rule, replay rule, baseline file, run condition, fingerprint or exit code changes. It is not an instrument change: no labeling log entry, no baseline reset, no declared flip.

## Decisions

- **The `.md` file is the full record, the console a summary.** The `.md` files keep their renderer and their content, with the additions below (baseline column, replay fractions, legends, throttled line, `refused:` prefix). The two gates print a console summary built with rich `Table`s, the target (server) column `no_wrap` and free-text columns `overflow="fold"`, then the verdict panel, then point to the `.md` for the rest. Rendering the whole `.md` through `rich.markdown.Markdown` was rejected: it truncates the CVE table's id and status columns at a normal terminal width, and it would force blank lines into the `.md` to keep standalone lines apart. The two holdout runs keep printing their markdown as it is: it holds headings and lists only, no table, and reads fine raw.
- **Gates: a Baseline column, no `partial` mark.** Unlike the e2e outcome table, which lists only the cells that left `unchanged`, both gates list every target (server). With the baseline letters beside the run letters, a partial or full improvement reads directly (`MMM` then `MDM`). The gate's outcome stays the one printed, no display-only label.
- **Run letters with a legend, replays as a fraction.** CVE runs and baseline runs: `D` detected, `J` reached but judged PASS, `M` missed. Nuisance runs and baseline runs: `A` an alarm on a counted tool, `.` none (today's letters). Replays, on both gates, as the e2e prints them: `k/n`, the miss (CVE) or the alarm (nuisance) reproduced in `k` of `n` replays, `-` when none. A replay is a boolean ("reproduced"), not a status: a CVE replay that came back `reached_but_judged_pass` is a reproduced miss, so status letters on replays would mislead.
- **One verdict panel for the three paired gates.** `eval_display.print_verdict(verdict, reasons)` prints the coloured panel the e2e prints today (`Gate green.`, `Gate red.`, `Not comparable.`, then the reasons as bullets), and the e2e's `print_summary` uses it with identical output. The CVE gate and the nuisance gate print it last in their summary, before any recording or refusal output. `CVEGateVerdict` has the same values as `GateVerdict`: the CVE side converts by value.
- **Progress: one bar, three tasks.** A `Preparing` task with no total from the moment the bar opens (image rebuild, pre-run checks). An `Auditing` task whose total is the audits the session is about to run, announced by the session once its pre-run check has decided which targets run; announcing removes `Preparing`. A `Replaying` task with no total, created at the first audit that completes once `Auditing` is complete (the gates' replays run strictly after every main run, so any later completion is a replay). The holdout runs never replay.
- **The image rebuild captures docker's output.** `rebuild_images` runs `docker compose build` with its output captured, so it no longer writes under the live bar. On a failed build it raises with the last 40 lines of the captured output in the message, so the crash still says why.
- **Throttled total: the e2e wording, console and JSON.** `Throttled by the model provider: N requests at concurrency C`, in yellow, printed once when N > 0, and `throttled_requests` and `concurrency` in each JSON report. The per-audit yellow lines (`_print_incidents` in `cve_audit.py` and `nuisance_audit.py`) stay: one per audit, not one per call, so they do not flood at the default concurrency of 6.
- **One console.** `cve_audit.py`, `cve_calibration.py`, `cve_layout_check.py`, `holdout_audit.py` and `nuisance_audit.py` each build their own `Console()`, and all of them print inside the bar (`check_target`, the CVE gate's and the holdout's pre-run check, prints egress warnings and calibration errors; `observe_versions`, the holdout's layout check, prints launch errors). While a `Progress` is live on another console, their lines would break the bar and lose their colour through rich's stdout redirection. They import `console` from `evals/eval_display.py` instead, and every `Progress` of these modes is built on that console. Their calibrate and survey output is unchanged. The import is `from evals.eval_display import console`, a module-level name, because the tests replace it per module with `monkeypatch.setattr(<module>, "console", ...)` (`test_cve_audit_given.captured_console`, `test_holdout_audit.py`, `test_nuisance_audit.py`); a `display.console` reference would escape those patches.
- **Report path and runnable next steps.** Every mode ends its summary with `Report written to <path> and <path>.md`. A next-step line names the full command and the commit: CVE exploratory, `Run uv run python -m evals.run_cve_benchmark --record-baseline again now, at this commit and on these images, to confirm it. Commit evals/baselines/cve/ by hand once confirmed.`; nuisance exploratory, `Run uv run python -m evals.run_nuisance gate --record-baseline again now, at this commit and on these images, to confirm it. Commit evals/baselines/nuisance/ by hand once confirmed.` The confirmed lines stay. A `--cve` or `--server` filter the run used is repeated in the command, and so is every non-default flag that enters the recorded conditions (`--runs` and `--budget` on the CVE gate, `--runs` on the nuisance gate): the confirming recording refuses on a condition mismatch (`cve_session_recording` and `nuisance_gate_session_recording` check `condition_mismatches` before the runs), so a command that drops them is not the one to run.
- **Free text never goes through rich markup.** A detail, a not-run condition or reason (a nuisance benign-call failure quotes `response.content`, a list repr starting with `[`), a flagged tool name or a not-admitted entry is printed as `Text(...)` or through `rich.markup.escape`, in the gate table cells and in the summaries' plain lines alike, as `_bullets` already does for the reasons. This is the bug the Context cites for the CVE gate's `console.print(markdown)`; a rich `Table` given a `str` cell parses it as markup too.

## Files to modify

### Shared

**`evals/audit_progress.py` (new)**

The progress of one session's audits. Composition-root code (it holds a live `rich.progress.Progress`), shared by the four modes.

```python
class AuditProgress:
    def __init__(self, progress: Progress) -> None:
        """Adds the Preparing task."""
    def announce(self, audits: int) -> None:
        """Removes Preparing and adds the Auditing task with this total. Called once, by the session."""
    def tracked[T, R](self, audit: Callable[[T], Awaitable[R]]) -> Callable[[T], Awaitable[R]]:
        """The same audit, advancing Auditing on each completion, or Replaying once Auditing is complete."""
```

- `tracked` advances after the awaited call returns, whatever it returns (a `None`, a `DroppedRun`, a graded audit). An exception propagates without advancing.
- A completion before `announce` (cannot happen in the four sessions, which announce before any audit) advances nothing rather than raising.
- `announce(0)` removes `Preparing` and adds no task (every target not run).
- The `Replaying` task is created lazily, once, with `total=None`.

**`evals/eval_display.py`**

- `print_verdict(verdict: GateVerdict, reasons: list[str]) -> None`: the panel `print_summary` prints today (`_VERDICT_STYLES` and `_bullets`). `print_summary` calls it; its output does not change.
- `gate_table(rows: Sequence[GateRow], target_header: str) -> Table`, with `GateRow` a frozen dataclass `(target: str, outcome: str, baseline: str, run: str, replays: str, detail: str)`: columns `<target_header>` (`no_wrap`), Outcome, Baseline, Run, Replays, then Detail (`overflow="fold"`), no box, as the e2e outcome table. The cells arrive already rendered (letters, fractions), so the table knows nothing of either gate. Each cell is added as `Text(cell)`, never as a markup string (a detail may hold `[`).
- `print_report_paths(report_path: Path, export: Path | None = None) -> None`: `Report written to <path> and <path with .md suffix>`, then `, judged cases exported to <export>` when the run wrote one (the two gates write `cve_judged_cases.jsonl` and `nuisance_gate_judged_cases.jsonl` beside the report, `evals/export.py`; the holdout runs export nothing).
- The module is at 264 lines; if these push it past 300, the gate table and `GateRow` go to a sibling `evals/gate_display.py`.

**`evals/cell_grid.py`**

- `_replays` becomes public `replay_fraction(replays: Sequence[bool]) -> str` (`k/n`, `-` when empty), used by `cell_grid` as today and by both gates' renderers.

**`evals/holdout_run.py`** (image rebuild only, the rest under the holdout section)

- `rebuild_images` captures the build output (`capture_output=True, text=True`). On a non-zero exit it raises `RuntimeError` naming the services, with the last 40 lines of stdout and stderr. Its three callers (holdout run, nuisance run, nuisance gate) are unchanged.

### CVE acceptance gate

**`evals/cve_gate.py`**

- `TargetComparison` gains `baseline_runs: list[CVEStatus] = []`, the statuses of the baseline's runs, empty without a baseline.
- `compare_target` fills it from `baseline.runs` whenever `baseline` is not `None` (every outcome after the `NO_BASELINE` branch, the `UNCHECKED_DECIDES` branch included when a baseline exists). No branch, outcome or detail changes. `settle` keeps it through `model_copy`.

**`evals/cve_session_model.py`**

- `CVEHarness` gains `announce_audits: Callable[[int], None]`, no default (the dataclass is frozen and built in `run_cve_benchmark.py` and `tests/unit/support/test_cve_session_given.py`, which passes a no-op).

**`evals/cve_session.py`**

- `_run_targets` calls `session.harness.announce_audits(len(targets) * count)` before its `gather`, `targets` being the ones the pre-run check let through.
- `_not_run_comparison(cve_id, conditions, baseline)` fills `baseline_runs` from the baseline when one exists, so a not-run target still shows what it was. `_gate` passes `baselines.get(target.cve_id)`.

**`evals/cve_oracle.py`** (the `.md`)

- `_render_gate` replaces the `Targets:` bullet list with a markdown table `| Target | Outcome | Baseline | Run | Replays | Detail |`, one row per comparison, then the legend line `Runs: D detected, J reached but judged PASS, M missed. Baseline: every run its file holds, both recordings once confirmed. Replays: the miss reproduced in k of n replays.` An empty letter string renders `-`, an absent detail `-`. A `|` in a detail is escaped `\|` (a not-run detail joins dead conditions, which are free text).
- New `status_letters(statuses: Sequence[CVEStatus]) -> str`, public (the console summary uses it too), placed below its caller. `_render_comparison` goes. Replays use `cell_grid.replay_fraction`.
- `_render_conditions` loses its throttled clause (`, N requests throttled by the model provider`): the throttled count gets a line of its own after the tally, `Throttled by the model provider: N requests at concurrency C`, only when N > 0, as in the other modes, so the console summary prints it once.
- The recording-refused reasons keep their section, unchanged.

**`evals/cve_console.py` (new)**

The CVE console summary, rich, from the report model alone.

```python
def print_cve_summary(report: CVEBenchmarkReport, report_path: Path) -> None: ...
```

In order:

1. `Commit: <sha>`, with ` (dirty tree)` when the tree was dirty (the report's `commit` and `dirty`, today in the JSON only; the next-step line says "at this commit"), then the conditions line (`cve_oracle._render_conditions` made public as `render_conditions`) and the measurement line when there is one.
2. A results table: CVE (`no_wrap`), Status, Detected, Miss class, Aimed, FAIL without proof. CVSS, Class, Awaited capability and Note stay in the `.md` only.
3. The `Statuses:` tally line (`cve_oracle._render_tally`, made public).
4. Under `--ungated` only, the not-run targets with their conditions (a gated run shows them in the gate table's Detail and the panel reasons already); in every mode the replay credits, as the `.md` lists them (plain lines, escaped, reusing `_render_not_run` and `_render_replay_credits` made public).
5. Under `--ungated` with costs, the title `Cost per target, all attempts, dollars at the prices as of <prices_as_of>:` then the cost table as a rich table (same columns as `cve_costs.render_cost_table`), and the large-request warnings `_print_session` prints today.
6. The throttled line, yellow, when N > 0.
7. The gate table (`gate_table(rows, "Target")`) and the legend.
8. `print_report_paths(report_path, <the judged-cases export path>)`.
9. The verdict: `print_verdict(GateVerdict(gate.verdict.value), gate.reasons)`, or the existing yellow `Ungated run: nothing compared to evals/baselines/cve/.` line.

The reasons already name each not-comparable or regressed target; the panel shows them once. The module stays under 150 lines.

**`evals/cve_audit.py`**, **`evals/cve_calibration.py`**, **`evals/cve_layout_check.py`**

- Each drops its own `Console()` and imports `console` from `evals.eval_display`.

**`evals/run_cve_benchmark.py`**

- Its own `console = Console()` goes: it imports `console` from `evals.eval_display`.
- `_run_graded` opens `with Progress(console=console) as bar:` around `run_gated(...)` (it is already `async`, so the `with` wraps the `await`), builds `AuditProgress(bar)`, and `_harness` takes it to wrap the audit: `audit=progress.tracked(bounded(audit_target(...), args.concurrency))` and `announce_audits=progress.announce`. `_harness` then takes four arguments: group what it reads of the run (`args`, `throttles`, `places`) or derive one, the implementer's choice, three arguments or fewer.
- `_write_reports` writes the two files and no longer prints. After the progress context has closed, `_run_graded` calls `print_cve_summary(report, path)`, then the recording output: orphans, written baselines and the next-step lines (`_print_session` keeps only these), then the refusal panel when the recording was refused. The `Gate:` line, the throttled line and the large-request lines of `_print_session` go (the summary prints them).
- `_NEXT_STEP` gets the runnable commands of the decision, with `--cve` repeated when the run had it and `--runs`, `--budget` when they differ from `CVE_RUNS`, `CVE_TEST_BUDGET`.
- The calibrate and survey modes are untouched.

### CVE holdout run

**`evals/holdout_results.py`**

- `HoldoutRunResult` gains `concurrency: int` and `throttled_requests: int`.

**`evals/holdout_report.py`**

- `HoldoutReport` gains `concurrency: int` and `throttled_requests: int`, copied by `build_report`.

**`evals/holdout_markdown.py`**

- After the incomplete-runs line, when `throttled_requests > 0`: `Throttled by the model provider: N requests at concurrency C`. No line at zero.

**`evals/holdout_audit.py`**

- Drops its own `Console()` and imports `console` from `evals.eval_display`.

**`evals/holdout_run.py`**

- `HoldoutDeps` gains `announce_audits: Callable[[int], None]` and `throttled_requests: Callable[[], int]`. `default_deps` fills the second with `lambda: throttles.requests` over the `SessionThrottles` it already builds, and the first with a no-op. The composition root replaces both `audit` and `announce_audits` with `dataclasses.replace` to track progress (below).
- `run_holdout` keeps its keyword `deps: HoldoutDeps | None`. The composition root builds the deps itself (`default_deps(places, holdout_overrides(conditions), concurrency)`, `_overrides` renamed public `holdout_overrides`), wraps them, and passes them, still passing `concurrency=args.concurrency` for `_RunContext.concurrency`. It builds them after `conditions.require_ready(model_ids)` in `run_holdout._run` (already there), since `holdout_overrides` asserts the three run settings are set. `run_holdout` keeps building `default_deps` when `deps` is `None` (the tests pass fakes). Building the auditor before `run_holdout`'s own refusals (tools filter, census, places) moves `build_auditor` ahead of them; it reaches no network (checked: it builds with no API key set), so `test_run_refuses_an_acceptance_target_for_its_tools_filter` still exits 3.
- `_run_all` calls `deps.announce_audits(len(surviving) * ctx.runs)` before its `gather`.
- `_RunContext` gains `concurrency: int`. `_assemble_run` fills `concurrency=ctx.concurrency` and `throttled_requests=deps.throttled_requests()`.
- The module is at 376 lines, past the 300-line limit, and this change grows it. Split: move the pre-run vetting (`_vet_all`, `_vet`, `vet_reason`, `_observe_layout`) to `evals/holdout_vetting.py`, with `vet_all` and `observe_layout` public (`default_deps` keeps using `observe_layout`). `holdout_vetting` must not import `HoldoutDeps` from `holdout_run`, which imports it back: `vet_all(targets, check, layout)` takes the two callables (`deps.check`, `deps.layout`) instead of the deps. The vetting move alone leaves the module near 345 lines, so the per-target assembly (`_assemble_target`, `_run_status`, `_detected`, `_detected_if_unchecked_missed`, `_prices`, `_run_cost`) moves too, to `evals/holdout_assembly.py` (`assemble_target` public), the mirror of `nuisance_assembly.py`. The image helpers (`rebuild_images`, `target_services`, `_backend_images`) stay, since `nuisance_run.py` and `nuisance_gate_session.py` import `rebuild_images` from here.

**`evals/run_holdout.py`**

- `_run` opens `with Progress(console=display.console) as bar:` around `asyncio.run(run_holdout(...))`, with deps built and wrapped as above (`dataclasses.replace(deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce)`), then, once the context has closed, prints the markdown as today and `display.print_report_paths(args.report)`. `_run` is already near 30 lines: put the deps building and wrapping in a helper below it.

### Nuisance holdout run

**`evals/nuisance_results.py`**, **`evals/nuisance_report.py`**, **`evals/nuisance_markdown.py`**

- Same three changes as the holdout: `NuisanceRunResult` and `NuisanceReport` gain `concurrency: int` and `throttled_requests: int`, the markdown gains the same throttled line after the incomplete-runs line, only when N > 0.

**`evals/nuisance_audit.py`**

- Drops its own `Console()` and imports `console` from `evals.eval_display`.
- Throttled requests are counted on every attempt, retried and dropped ones included, as `cve_audit.attempt_once` counts them. To stay at three arguments, group the run's fixed parts in a frozen dataclass `NuisanceAuditor(auditor: Auditor, overrides: RunOverrides, throttles: SessionThrottles)`, and `audit_once(server, auditor: NuisanceAuditor, *, backends=BACKENDS)` (the `backends` keyword stays, `test_nuisance_audit.py` passes a registry) counts `throttles.count(report)` on each `AuditReport` it returns, before `nuisance_audit` decides whether it was throttled. Both callers (`nuisance_run.default_deps`, `nuisance_gate_session.default_harness`) build the grouping.

**`evals/nuisance_run.py`**

- `NuisanceDeps` gains `announce_audits: Callable[[int], None]` and `throttled_requests: Callable[[], int]`, filled by `default_deps` as in the holdout (a `SessionThrottles` built there, a no-op announce). `_overrides` becomes public `nuisance_overrides`: the composition root builds the deps (`default_deps(nuisance_overrides(conditions), args.concurrency)`, after the `conditions.require_ready` `run_nuisance._run` already calls) to wrap them, as for the holdout, and passes them with `deps=`.
- `_run_all` announces `len(surviving) * ctx.runs`. `_RunContext` gains `concurrency`. `_assemble_run` fills the two new result fields.

**`evals/run_nuisance.py`**

- `_run`: same progress wrapping, markdown printing and `print_report_paths` as `run_holdout._run`.

### Nuisance gate

**`evals/nuisance_gate.py`**

- `ServerComparison` gains `baseline_runs: list[bool] = []`, filled by `compare_server` from `baseline.runs` whenever a baseline exists. No branch, outcome or detail changes.

**`evals/nuisance_gate_session_model.py`**

- `NuisanceGateHarness` gains `announce_audits: Callable[[int], None]` and `throttled_requests: Callable[[], int]`, no default.
- `NuisanceGateSession` gains `throttled_requests: int`.

**`evals/nuisance_gate_session.py`**

- `default_harness` builds a `SessionThrottles` and passes it through the `NuisanceAuditor` grouping, fills `throttled_requests`, and a no-op `announce_audits`.
- `_run_servers` announces `len(servers) * count` before its `gather`.
- `_not_run_comparison` fills `baseline_runs` when the server has a baseline, as for the CVE gate.
- `run_gate` fills `throttled_requests=opened.harness.throttled_requests()`.

**`evals/nuisance_gate_report.py`** (the `.md`)

- `NuisanceGateReport` gains `throttled_requests: int`.
- The servers table becomes `| Server | Outcome | Baseline | Runs | Replays | Detail |`, the baseline letters from `comparison.baseline_runs` (`-` when empty), replays as `replay_fraction`, Detail the comparison's `detail` (today shown nowhere but the JSON, so a `not_gated` server's "flagged in k of n baseline runs" or exploratory-baseline hint was lost) followed by the flagged tools per run, then the legend line `Runs: A an alarm on a counted tool, . none. Baseline: every run its file holds, both recordings once confirmed. Replays: the alarm reproduced in k of n replays.`
- After the model line, when `throttled_requests > 0`, the throttled line with the report's concurrency.
- In `## Recording`, each refused reason is prefixed `refused: `, so it does not read as one more recorded server.
- `server_letters(flagged: Sequence[bool]) -> str` public (today's `_letters`), for the console summary.

**`evals/nuisance_gate_console.py` (new)**

```python
def print_nuisance_gate_summary(report: NuisanceGateReport, report_path: Path) -> None: ...
```

In order: the commit and model line (as the `.md` header), the gate table (`gate_table(rows, "Server")`, Detail as in the `.md`: the comparison's detail then the flagged tools, folded), the legend, the not-run, not-admitted and outside-the-gate lists as plain lines when not empty, the throttled line when N > 0, `print_report_paths(report_path, <the judged-cases export path>)`, then `print_verdict(report.gate.verdict, report.gate.reasons)`. The recording and orphan lines are not in the summary: `_print_baselines` prints them once, after it.

**`evals/run_nuisance.py`**, **`evals/nuisance_gate_command.py` (new)**

- `run_nuisance.py` is at 416 lines, past the 300-line limit, and this change grows it. Split: the gate subcommand (`_gate`, `_print_empty_gate`, `_run_gate`, `_gate_options`, `_NEXT_STEP`, `_print_baselines`, and the new wrapping helper) moves to `evals/nuisance_gate_command.py`, with `gate(args)` public and still wired as the `gate` command of `run_nuisance`'s parser (`_add_gate_arguments` may move with it). The new module must not import from `run_nuisance`, which imports it back: the helpers both subcommands share (`_admission`, `_write_report`) move to the new module or to a module both import, the implementer's choice. `tests/unit/test_run_nuisance.py` drives the gate through `run_nuisance.main` and keeps doing so.
- `_run_gate`: progress wrapping of `default_harness(...)` (`dataclasses.replace` of `audit` and `announce_audits` inside `with Progress(console=console)`), in a helper below it (`_run_gate` is already 25 lines); `throttled_requests=session.throttled_requests` in the report; after the context closes, `print_nuisance_gate_summary(report, args.report)` in place of `print(markdown)`, then `_print_baselines`.
- `_NEXT_STEP` gets the runnable commands of the decision, with `--server` repeated when the run had it and `--runs` when it differs from `NUISANCE_GATE_RUNS`. `_print_baselines` prints through the shared console, the written baselines in green as the CVE side does.

## What stays unchanged

- Every gate decision: `compare_target`, `compare_server`, `settle`, `judge`, the replay rules, the exit codes.
- The baseline files, their recording, `CVERunConditions`, `NuisanceGateConditions`, the holdout conditions, every fingerprint (grammar, counter, fixture).
- The holdout and nuisance report contents beyond `concurrency` and `throttled_requests`: no per-case, per-run verdict or proof field is added to either, on file or on screen.
- The e2e and judge displays (the e2e verdict panel moves into `print_verdict` with identical output), `run_cve_benchmark --calibrate` and `--survey`, `run_holdout calibrate`, `run_nuisance calibrate`, `walk` and `nuisance-dossier`.
- The `.md` files' content, apart from the gate tables, the legends, the replay fractions, the throttled lines (the CVE one moved out of the conditions line) and the `refused:` prefix.

## Edge cases

- A gate target with no baseline: Baseline `-`, outcome `no_baseline` as today.
- A target whose fixture changed: its baseline runs still show (`fixture_changed`), they are the old fixture's, and the detail says so.
- A not-run target with a baseline: Baseline letters, Run `-`.
- Every target not run (CVE gate) or the run refused before any audit: `announce` is called with 0 (removes `Preparing`, adds no task) or never (the bar keeps `Preparing` until it closes), nothing raises.
- `--record-baseline` on the gates: same progress and summary, the recording lines after the verdict panel.
- `--ungated` CVE run: no gate table, the yellow ungated line in place of the panel, the cost table when costs exist.
- A detail with `|`: escaped in the `.md`; the rich table needs no escaping.
- A replay that does not complete (audit returns `None`): it still advances `Replaying`; the replay fraction counts completed replays only, as `settle` keeps them.
- Zero throttled requests: no console line, `throttled_requests: 0` in the JSON.
- A failed image build: the run crashes as today (exit 4 on the gates, a traceback on the holdout runs), its message now carrying the build's last lines instead of docker having printed them.

## Test scenarios

Unit tests, given/then where the setup abstracts something. Console output is checked as plain text on a `Console(file=io.StringIO(), width=200)` swapped in for the shared console, never on rich's layout. Since each module binds `console` by name at import, a summary test patches the same `Console` on the summary module (`cve_console`, `nuisance_gate_console`) and on `eval_display` (which prints the gate table, the report paths and the verdict panel); patching one alone loses half the output.

- `tests/unit/test_audit_progress.py` (new): the bar opens with `Preparing`; `announce(3)` removes it and adds `Auditing`; three tracked completions complete `Auditing` (read through `progress.tasks`); a fourth creates `Replaying` and advances it; a tracked audit returning `None` advances; one that raises propagates and does not advance; a completion before `announce` advances nothing; `announce(0)` removes `Preparing` and adds nothing.
- `test_eval_display.py` (or the e2e display test that exists): `print_verdict` prints the same text the e2e summary printed before; `gate_table` keeps a long target id whole at width 80.
- `tests/unit/test_eval_cell_grid.py`: `replay_fraction` unchanged behaviour (existing tests, renamed call).
- A `rebuild_images` test with a fake `subprocess.run`: a failed build raises with the tail of the captured output; a successful one prints nothing.
- `test_cve_gate.py`: `compare_target` carries the baseline's statuses on a held, a pending and a not-gated comparison; none without a baseline; `settle` keeps them.
- `test_cve_session.py`: the session announces targets × runs after the pre-run check (a not-run target excluded); a not-run target with a baseline carries its baseline runs.
- `test_cve_oracle.py`: the gate section renders the row `| CVE-X | not_gated | MMM | MDM | - | - |` and the legend; replays `1/2`; a `|` in a not-run detail is escaped; the throttled line stands after the tally at N > 0 with the concurrency, and the conditions line no longer carries it. Existing assertions on the `Targets:` bullets move to the table, and `test_render_states_the_throttled_requests_on_the_conditions_line` and `test_render_leaves_throttling_out_when_nothing_was_throttled` (which read line 0) are rewritten for the new line.
- `test_cve_console.py` (new): the summary shows each target id whole, the tally, the throttled line at N > 0 only, the report paths, and the verdict as the last panel; an ungated report prints the ungated line and no panel; the `Gate:` line appears nowhere in the console output; the commit line carries `(dirty tree)` on a dirty report; the not-run list appears under `--ungated` only; the cost title carries the price date; the paths line names the judged-cases export.
- `test_run_cve_benchmark.py`: the exploratory next step names the full command and the commit, with `--cve` when given and a non-default `--runs` repeated.
- A summary test (CVE or nuisance gate) with a detail or not-run reason holding `[bold]`: the text prints literally.
- `test_holdout_run.py`: the run announces surviving targets × runs; the result carries the concurrency and the throttled count the deps report.
- `test_holdout_report.py`: the throttled line appears at N > 0 with the concurrency, and not at 0.
- `test_nuisance_run.py`, `test_nuisance_report.py`: the same two pairs for the nuisance run.
- `test_nuisance_audit.py`: a throttled attempt retried, then a clean one, counts both attempts' throttled requests. `audit_once` launches through `connect` and `build_graph`, so the test fakes both on `nuisance_audit` the way `test_cve_audit_given.an_audit_reporting` fakes them on `cve_audit` (a server with no backend launches through `_single_container_launch`, which reaches no Docker), and drives `nuisance_audit(server, lambda: audit_once(server, auditor))`.
- `test_nuisance_gate.py`, `test_nuisance_gate_session.py`, `test_nuisance_gate_report.py`: baseline runs carried and rendered, announce called, throttled total in the session and the markdown, legend present, replays as a fraction, a refused reason prefixed `refused:`, a `not_gated` server's detail in the Detail column before its flagged tools.
- `test_nuisance_gate_console.py` (new): the summary has the table, the legend, the report paths and the verdict panel last, and no recording line (those stay in `_print_baselines`); the paths line names the judged-cases export.
- `test_run_nuisance.py`: the gate's exploratory next step names the full command and the commit, with `--server` and a non-default `--runs` repeated; a recorded baseline prints once.
- Test givens and helpers that build `HoldoutRunResult` (`test_holdout_report.py`, `_run_result`), `NuisanceRunResult` (`test_nuisance_report_given.py`), `NuisanceGateSession` and `NuisanceGateReport` (`test_nuisance_gate_report_given.py`), `CVEHarness`, `HoldoutDeps`, `NuisanceDeps` and `NuisanceGateHarness` gain the new fields (no-op announce, `lambda: 0` for the throttled count, or a configurable value where a test reads it). The `audit_once` calls in `test_nuisance_audit.py` build a `NuisanceAuditor`.

## Verification

```bash
uv run pytest tests/unit -n auto --maxprocesses 4
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
```

By hand, with Docker and an LLM key: `uv run python -m evals.run_cve_benchmark --ungated --cve <one target> --runs 1` shows the bar (Preparing, then Auditing), the summary tables and the ungated line. The holdout and nuisance runs are not launched to check a display: they are real measurements. The nuisance gate has no admitted acceptance server, so its summary is checked by its unit tests only.

## Living docs

- `CHANGELOG.md` `[Unreleased]`, under the heading the 2026-10-05 display entries used: the CVE acceptance gate, the CVE holdout run, the nuisance run and the nuisance gate show their progress (image builds and checks included, docker's build output no longer streamed); the two gates print a console summary in tables with the verdict panel last and the full report left to the `.md`; the two gates show each target's baseline runs beside this run's, replays as a fraction, with a legend; the two holdout runs and the nuisance gate print and record the throttled-request total with the concurrency; every mode prints where its report was written; the next-step lines after a recording name the full command.
- `CONTRIBUTING.md`: where it describes these reports' keys, the gate output or the next steps after a recording, the new keys, the Baseline column and the commands. Checked, not forced.
- `README.md`, `CLAUDE.md`: no command, flag or env var changes. Checked, left as they are if nothing is stale.

## Out of scope, for a follow-up plan

Not done here:

- The holdout and nuisance runs' exit codes: a crash exits 1 (the "red" code of the gates), and any `ValueError`, including one raised after the audits were paid for, prints "Refused: the census is malformed." with exit 3 (`run_holdout.main`, `run_nuisance.main`).
- A conditions line (commit, model and judge, runs, budget, N) in the holdout markdown, which `HoldoutReport` already carries.
- The holdout markdown prints the total cost without `prices_as_of` (holdout-rule.md:239 says list prices on the day; the JSON has the date), and the holdout report never says whether a credited place came from the catalogue or the layout (ADR 031). Both predate this plan.
- Cost or tokens in the e2e, the judge and the gated CVE run.
- The e2e per-run blocks carry no run number, and the `Run N: auditing X...` lines duplicate the progress bar.
- The in-run lines of the two holdout runs print each missed step's tool, step and provider message (and the blocked-payload pattern on the CVE side): whether to reduce them to per-target counts is a reading of `docs/holdout-rule.md` for the maintainer.

## Parallel work

Implemented in a separate git worktree merged back into `main`, in parallel with `plans/2026-10-27_nuisance-assembly-batch2.md`. That plan touches `evals/nuisance_admission.json`, possibly `evals/nuisance_fix_checks/` and `evals/nuisance_fixtures.py`, and the living docs. This one touches none of the first three. The expected conflicts are in `CHANGELOG.md` and maybe `CONTRIBUTING.md` or `CLAUDE.md`, resolved by hand at the merge. The full check runs again on `main` after the merge.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, kept so the implementation-phase fact check can read it after `/clear`. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, on 2026-10-27, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `rich` 15.0.0 is the installed version (`pyproject.toml` declares `rich>=13.0`, no pin) (verified against `importlib.metadata.version("rich")` in the project environment)

## Implementation steps

Each step closes with the full check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` (no diff left), `uv run pyright`, all green. In the loop, `uv run pytest tests/unit -n auto --maxprocesses 4` and `uv run pyright <changed files>`. Test givens live in `tests/unit/support/test_<name>_given.py` (and `_then.py`) as the existing files do. Console tests swap a `Console(file=io.StringIO(), width=200)` on every module that prints (see Test scenarios).

### Step 1: Shared display pieces and the quiet image rebuild

- **Files**: `tests/unit/test_audit_progress.py` (new), `tests/unit/test_eval_display.py` (and its given if setup grows), `tests/unit/test_eval_cell_grid.py`, `tests/unit/test_holdout_run.py`; `evals/audit_progress.py` (new), `evals/eval_display.py` (or `evals/gate_display.py` new, if `eval_display.py` would pass 300 lines), `evals/cell_grid.py`, `evals/holdout_run.py` (`rebuild_images` only).
- **Do**:
  - Tests first, then `AuditProgress(progress)` with `announce(audits)` and `tracked(audit)` exactly as the Shared section specifies (Preparing at construction, Auditing on announce, lazy Replaying with `total=None`, advance after return whatever the value, no advance on exception or before announce, `announce(0)` adds no task).
  - `eval_display.print_verdict(verdict: GateVerdict, reasons: list[str])` extracted from `print_summary` (which calls it, output identical); `GateRow` frozen dataclass and `gate_table(rows, target_header) -> Table` (target column `no_wrap`, Detail `overflow="fold"`, no box, every cell `Text(cell)`); `print_report_paths(report_path, export=None)`.
  - `cell_grid._replays` renamed public `replay_fraction(replays: Sequence[bool]) -> str`, callers updated.
  - `holdout_run.rebuild_images`: `capture_output=True, text=True`; non-zero exit raises `RuntimeError` naming the services with the last 40 lines of stdout and stderr.
- **Test**:
  - `test_audit_progress.py`: the eight scenarios of Test scenarios (Preparing at open, announce(3) swaps tasks, three completions complete Auditing, a fourth creates and advances Replaying, `None` result advances, raising audit propagates without advancing, completion before announce advances nothing, announce(0) leaves no task). Read through `progress.tasks` on a `Progress(console=Console(file=io.StringIO()))`.
  - `test_eval_display.py`: `print_verdict` output equals what the e2e `print_summary` printed before (an existing summary test keeps passing unchanged is the guard, add one direct `print_verdict` test); `gate_table` keeps a long target id whole at width 80; a cell holding `[bold]x[/bold]` prints literally; `print_report_paths` names `<path>` and `<path>.md`, and the export when given.
  - `test_eval_cell_grid.py`: existing replay tests pass with the renamed function.
  - `test_holdout_run.py`: fake `subprocess.run` (monkeypatched on `holdout_run.subprocess` or the module's import): a failed build raises with the tail of the captured output (and not lines older than the last 40); a successful one prints nothing.
- **Verify**: the step's tests red then green; full check green.

### Step 2: CVE gate model, session announce and the `.md` gate table

- **Files**: `tests/unit/test_cve_gate.py`, `tests/unit/test_cve_session.py`, `tests/unit/test_cve_oracle.py` (with `support/test_cve_gate_given.py`, `support/test_cve_session_given.py`, `support/test_cve_oracle_given.py` as needed); `evals/cve_gate.py`, `evals/cve_session_model.py`, `evals/cve_session.py`, `evals/cve_oracle.py`, `evals/run_cve_benchmark.py` (one line, see below).
- **Do**:
  - `TargetComparison.baseline_runs: list[CVEStatus] = []`, filled by `compare_target` whenever a baseline exists, kept by `settle`.
  - `CVEHarness.announce_audits: Callable[[int], None]`, no default. `test_cve_session_given` passes a recording or no-op callable. `run_cve_benchmark._harness` passes `announce_audits=lambda _: None` for now (Step 3 wires the progress).
  - `cve_session._run_targets` announces `len(targets) * count` before its `gather`; `_not_run_comparison(cve_id, conditions, baseline)` fills `baseline_runs`, `_gate` passes `baselines.get(target.cve_id)`.
  - `cve_oracle`: `_render_gate` renders the `| Target | Outcome | Baseline | Run | Replays | Detail |` table and the legend line (text in the CVE section), `-` for empty letters or detail, `|` in a detail escaped `\|`; new public `status_letters(statuses)` (D, J, M) below its caller; `_render_comparison` removed; replays through `cell_grid.replay_fraction`. The throttled clause leaves the conditions line and becomes its own line after the tally, `Throttled by the model provider: N requests at concurrency C`, only at N > 0. Make `render_conditions`, `render_tally`, `render_not_run`, `render_replay_credits` public (renames only, for Step 3).
- **Test**:
  - `test_cve_gate.py`: `baseline_runs` carried on a held, a pending and a not-gated comparison; empty without a baseline; `settle` keeps them.
  - `test_cve_session.py`: announce receives targets x runs after the pre-run check, a not-run target excluded; a not-run target with a baseline carries its baseline runs.
  - `test_cve_oracle.py`: the row `| CVE-X | not_gated | MMM | MDM | - | - |` and the legend; replays `1/2`; a `|` in a not-run detail escaped; the throttled line after the tally at N > 0 with the concurrency, absent at 0, the conditions line no longer carrying it. Move the existing `Targets:` bullet assertions to the table, rewrite `test_render_states_the_throttled_requests_on_the_conditions_line` and `test_render_leaves_throttling_out_when_nothing_was_throttled` for the new line.
- **Verify**: full check green; `uv run python -m tests.unit.support.test_cve_grammar_golden_given` must NOT be run (no grading change).

### Step 3: CVE console summary, progress and runnable next steps

- **Files**: `tests/unit/test_cve_console.py` (new, with `support/test_cve_console_given.py` if setup abstracts something), `tests/unit/test_run_cve_benchmark.py` (and its given); `evals/cve_console.py` (new), `evals/run_cve_benchmark.py`, `evals/cve_audit.py`, `evals/cve_calibration.py`, `evals/cve_layout_check.py`.
- **Do**:
  - `cve_audit.py`, `cve_calibration.py`, `cve_layout_check.py`, `run_cve_benchmark.py` drop their `Console()` for `from evals.eval_display import console` (module-level name, so existing `monkeypatch.setattr(<module>, "console", ...)` keeps working).
  - `cve_console.print_cve_summary(report, report_path)`: the nine items in order as the CVE section lists them (commit line with `(dirty tree)`, conditions and measurement lines, results table with CVE `no_wrap`, tally, not-run list under `--ungated` only and replay credits in every mode, cost table and large-request warnings under `--ungated` with costs, yellow throttled line at N > 0, `gate_table(rows, "Target")` and legend, `print_report_paths` with the judged-cases export path, then `print_verdict(GateVerdict(gate.verdict.value), gate.reasons)` or the yellow ungated line). Rows built with `status_letters` and `replay_fraction`. Free text escaped or as `Text`. Under 150 lines.
  - `run_cve_benchmark`: `_run_graded` wraps `run_gated` in `with Progress(console=console) as bar:` and `AuditProgress(bar)`; `_harness` wraps `audit` with `progress.tracked(...)` and passes `announce_audits=progress.announce`, at three arguments or fewer (group what it reads of the run). `_write_reports` stops printing; after the bar closes: `print_cve_summary`, then `_print_session` reduced to orphans, written baselines and next-step lines, then the refusal panel. The `Gate:`, throttled and large-request lines leave `_print_session`. `_NEXT_STEP` carries the runnable commands of the Decisions, repeating `--cve` when given and `--runs`, `--budget` when they differ from `CVE_RUNS`, `CVE_TEST_BUDGET`. Calibrate and survey untouched.
- **Test**:
  - `test_cve_console.py`: each target id whole; the tally; throttled line at N > 0 only; the report paths naming the judged-cases export; the verdict panel last; an ungated report prints the ungated line and no panel; `Gate:` nowhere; `(dirty tree)` on a dirty report; not-run list under `--ungated` only; the cost title carries the price date; a detail or not-run reason holding `[bold]` prints literally. Patch the console on `cve_console` and on `eval_display`.
  - `test_run_cve_benchmark.py`: the exploratory next step names the full command and the commit, with `--cve` when given and a non-default `--runs` repeated; existing tests on printed output updated to the new order (verdict once, last before the recording lines).
- **Verify**: full check green; `run_cve_benchmark.py` stays under 300 lines (it was 321, `_print_session` shrinks; if not, move the next-step rendering beside `cve_console`).

### Step 4: CVE holdout run: split, progress, throttled total

- **Files**: `tests/unit/test_holdout_run.py`, `tests/unit/support/test_holdout_run_given.py`, `tests/unit/test_holdout_report.py`, `tests/unit/test_run_holdout.py` (if its fakes build deps); `evals/holdout_run.py`, `evals/holdout_vetting.py` (new), `evals/holdout_assembly.py` (new), `evals/holdout_results.py`, `evals/holdout_report.py`, `evals/holdout_markdown.py`, `evals/holdout_audit.py`, `evals/run_holdout.py`.
- **Do**:
  - First, the pure move (tests green before and after, no behaviour change): `_vet_all`, `_vet`, `vet_reason`, `_observe_layout` to `holdout_vetting.py` with `vet_all(targets, check, layout)` and `observe_layout` public; `_assemble_target`, `_run_status`, `_detected`, `_detected_if_unchecked_missed`, `_prices`, `_run_cost` to `holdout_assembly.py` with `assemble_target` public. No import of `holdout_run` from either new module. Image helpers stay.
  - `holdout_audit.py` imports `console` from `evals.eval_display`.
  - `HoldoutRunResult` and `HoldoutReport` gain `concurrency: int` and `throttled_requests: int` (`build_report` copies them); `holdout_markdown` adds the throttled line after the incomplete-runs line at N > 0 only.
  - `HoldoutDeps` gains `announce_audits` and `throttled_requests`; `default_deps` fills them (no-op, `lambda: throttles.requests`); `_overrides` becomes public `holdout_overrides`; `_run_all` announces `len(surviving) * ctx.runs`; `_RunContext.concurrency`; `_assemble_run` fills the two fields.
  - `run_holdout._run`: a helper below it builds `default_deps(places, holdout_overrides(conditions), concurrency)` after `require_ready`, wraps with `dataclasses.replace(deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce)` inside `with Progress(console=display.console)`, passes `deps=` and `concurrency=`; after the bar closes, prints the markdown and `display.print_report_paths(args.report)`.
- **Test**:
  - `test_holdout_run.py`: the run announces surviving targets x runs (a vetted-out target excluded); the result carries the concurrency and the throttled count the deps report. Givens gain the two fields (no-op announce, configurable throttled count).
  - `test_holdout_report.py`: throttled line at N > 0 with the concurrency, absent at 0; `_run_result` gains the fields.
  - `test_run_holdout.py`: `test_run_refuses_an_acceptance_target_for_its_tools_filter` still exits 3 with `build_auditor` moved ahead.
- **Verify**: full check green; `holdout_run.py` under 300 lines after the split.

### Step 5: Nuisance audit throttle count and the nuisance run

- **Files**: `tests/unit/test_nuisance_audit.py`, `tests/unit/test_nuisance_run.py` (+ `support/test_nuisance_run_given.py`), `tests/unit/test_nuisance_report.py` (+ `support/test_nuisance_report_given.py`); `evals/nuisance_audit.py`, `evals/nuisance_results.py`, `evals/nuisance_report.py`, `evals/nuisance_markdown.py`, `evals/nuisance_run.py`, `evals/run_nuisance.py` (`_run` only), `evals/nuisance_gate_session.py` (`default_harness` builds the grouping only).
- **Do**:
  - `nuisance_audit.py`: console from `evals.eval_display`; frozen `NuisanceAuditor(auditor, overrides, throttles)`; `audit_once(server, auditor: NuisanceAuditor, *, backends=BACKENDS)` calls `throttles.count(report)` on each `AuditReport` before `nuisance_audit` decides on throttling. Both callers build the grouping (`nuisance_gate_session.default_harness` builds a `SessionThrottles` it will expose in Step 6).
  - `NuisanceRunResult`, `NuisanceReport` gain `concurrency`, `throttled_requests`; markdown throttled line after the incomplete-runs line at N > 0.
  - `NuisanceDeps` gains `announce_audits`, `throttled_requests`; `default_deps` builds the `SessionThrottles`; `_overrides` public `nuisance_overrides`; `_run_all` announces `len(surviving) * ctx.runs`; `_RunContext.concurrency`; `_assemble_run` fills both fields.
  - `run_nuisance._run`: same wrapping helper, markdown and `print_report_paths` as `run_holdout._run`.
- **Test**:
  - `test_nuisance_audit.py`: a throttled attempt retried then a clean one counts both attempts' throttled requests, faking `connect` and `build_graph` on `nuisance_audit` as `test_cve_audit_given.an_audit_reporting` does on `cve_audit`, driven through `nuisance_audit(server, lambda: audit_once(server, auditor))`; existing `audit_once` calls build a `NuisanceAuditor`.
  - `test_nuisance_run.py`: announce receives surviving servers x runs; the result carries concurrency and the throttled count.
  - `test_nuisance_report.py`: throttled line at N > 0 with the concurrency, absent at 0.
- **Verify**: full check green.

### Step 6: Nuisance gate model, session and `.md`

- **Files**: `tests/unit/test_nuisance_gate.py`, `tests/unit/test_nuisance_gate_session.py`, `tests/unit/test_nuisance_gate_report.py` (with `support/test_nuisance_gate_given.py`, `support/test_nuisance_gate_session_given.py`, `support/test_nuisance_gate_report_given.py`); `evals/nuisance_gate.py`, `evals/nuisance_gate_session_model.py`, `evals/nuisance_gate_session.py`, `evals/nuisance_gate_report.py`, `evals/run_nuisance.py` (pass `throttled_requests=session.throttled_requests` into the report only).
- **Do**:
  - `ServerComparison.baseline_runs: list[bool] = []`, filled by `compare_server` whenever a baseline exists.
  - `NuisanceGateHarness` gains `announce_audits`, `throttled_requests` (no default); `NuisanceGateSession.throttled_requests`. `default_harness` exposes the `SessionThrottles` of Step 5 and a no-op announce; `_run_servers` announces `len(servers) * count`; `_not_run_comparison` fills `baseline_runs`; `run_gate` fills `throttled_requests`.
  - `nuisance_gate_report`: `NuisanceGateReport.throttled_requests`; the `| Server | Outcome | Baseline | Runs | Replays | Detail |` table (Detail: the comparison's detail then the flagged tools per run), the legend line, the throttled line after the model line at N > 0, `refused: ` prefix on refused reasons in `## Recording`, `server_letters` public.
- **Test**:
  - `test_nuisance_gate.py`: baseline runs carried with a baseline, empty without.
  - `test_nuisance_gate_session.py`: announce called with servers x runs; throttled total in the session; a not-run server with a baseline carries its baseline runs.
  - `test_nuisance_gate_report.py`: Baseline column, legend, replays as `k/n`, throttled line at N > 0 only, `refused:` prefix, a `not_gated` server's detail before its flagged tools.
- **Verify**: full check green.

### Step 7: Nuisance gate console summary, gate command split, living docs

- **Files**: `tests/unit/test_nuisance_gate_console.py` (new), `tests/unit/test_run_nuisance.py`; `evals/nuisance_gate_console.py` (new), `evals/nuisance_gate_command.py` (new), `evals/run_nuisance.py`; `CHANGELOG.md`, `CONTRIBUTING.md` (checked), `README.md` and `CLAUDE.md` (checked only).
- **Do**:
  - Move the gate subcommand (`_gate`, `_print_empty_gate`, `_run_gate`, `_gate_options`, `_NEXT_STEP`, `_print_baselines`, possibly `_add_gate_arguments`) to `nuisance_gate_command.py` with `gate(args)` public, still wired as `run_nuisance`'s `gate` command; shared helpers (`_admission`, `_write_report`) placed where both import them without a cycle. Do the move first, tests green, then change behaviour.
  - `print_nuisance_gate_summary(report, report_path)`: commit and model line, `gate_table(rows, "Server")` with Detail as in the `.md`, legend, not-run, not-admitted and outside-the-gate lists (escaped) when not empty, throttled line at N > 0, `print_report_paths` with the judged-cases export, then `print_verdict(report.gate.verdict, report.gate.reasons)`. No recording line.
  - `_run_gate`: progress wrapping of `default_harness(...)` in a helper below it; after the bar, `print_nuisance_gate_summary` in place of `print(markdown)`, then `_print_baselines` on the shared console, written baselines in green. `_NEXT_STEP` runnable commands with `--server` and a non-default `--runs` (vs `NUISANCE_GATE_RUNS`) repeated.
  - Living docs per the Living docs section: `CHANGELOG.md` `[Unreleased]` entry covering all four modes; `CONTRIBUTING.md` updated where it describes these reports' keys, gate output or next steps.
- **Test**:
  - `test_nuisance_gate_console.py`: table, legend, report paths naming the judged-cases export, verdict panel last, no recording line; a not-run reason holding `[bold]` prints literally. Patch the console on `nuisance_gate_console` and `eval_display`.
  - `test_run_nuisance.py` (still through `run_nuisance.main`): exploratory next step names the full command and the commit, `--server` and a non-default `--runs` repeated; a recorded baseline prints once.
- **Verify**: full check green; `run_nuisance.py` and `nuisance_gate_command.py` each under 300 lines; `CLAUDE.md` Commands list unchanged (no command or flag change).
