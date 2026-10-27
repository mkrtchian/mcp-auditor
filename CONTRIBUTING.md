# Contributing

Thanks for considering a contribution. This document explains how to get started and what to expect.

## Setup

```bash
git clone https://github.com/mkrtchian/mcp-auditor.git
cd mcp-auditor
uv sync                                # install runtime + dev dependencies
uv run pytest -n auto                  # should be green before you touch anything
```

You'll need Python 3.13+. The project uses [uv](https://docs.astral.sh/uv/) for dependency management. Don't add a `requirements.txt`. Docker is needed to audit a server under the default regime, which launches it in a container, and by the CVE benchmark (below). One integration test exercises that confined path and skips when Docker does not answer; three more (`tests/integration/test_cve_planting.py`, `tests/integration/test_holdout_kit.py` and the git reference-arm check in `tests/integration/test_cve_calibration.py`) run on the CVE images: they build the images they need on first run through `docker compose -f evals/docker/compose.yml build`, which needs network access, rebuild a missing or foreign one, and skip without Docker. `CVE_PLANTING_REQUIRED=1`, set in CI, turns that skip into a failure. The Doris backend builder test (`tests/integration/test_nuisance_doris_backend.py`) runs only behind `NUISANCE_DORIS=1`: it pulls `apache/doris:all-in-one-4.1.3` and `mysql:8.0.46`, waits on the cluster and leaves it running, and under the flag it skips without Docker or fails with `CVE_PLANTING_REQUIRED=1`. The unit tests and the regular evals need none. Editing a Dockerfile under `evals/docker/` needs its fingerprint label updated in `evals/docker/compose.yml`: `tests/unit/test_cve_compose_labels.py` prints the value.

```bash
uv run pytest tests/unit               # unit tests
uv run pytest tests/integration -n auto # integration tests
uv run ruff check .                    # lint
uv run ruff format .                   # format
uv run pyright                         # type-check
uv run python -m evals.run_evals       # e2e evals (requires API key)
uv run python -m evals.run_evals --record-baseline  # record the e2e baseline (clean tree, see below)
uv run python -m evals.run_evals --ungated          # e2e evals on the floors alone, at any conditions
uv run python -m evals.run_evals --concurrency N    # e2e audits in flight at once (default 9, 1 for the old sequence)
uv run python -m evals.run_judge_eval  # judge isolation eval (requires API key)
uv run python -m evals.run_judge_eval --record-baseline  # record the judge baseline (clean tree, see below)
uv run python -m evals.run_judge_eval --ungated          # judge eval on the floors alone, at any conditions
uv run python -m evals.run_judge_eval --runs N           # judge each case N times (default 3, the baseline's conditions)
uv run python -m evals.run_judge_eval --concurrency N    # judge calls in flight at once (default 30)
```

Evals run real LLM calls and require an API key. Copy `.env.example` to `.env` and set the key of the provider you use: `OPENAI_API_KEY` (default provider), `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY`, `FIREWORKS_API_KEY`, `DASHSCOPE_API_KEY` or `OPENROUTER_API_KEY`. Unit and integration tests don't need any key.

### CVE benchmark

A separate benchmark runs the auditor against real, pinned-vulnerable MCP servers in throwaway Docker containers. It needs Docker running plus an API key. Build the images once, confirm each fixture is live (no LLM), then run the graded audit, which is the acceptance gate:

```bash
docker compose -f evals/docker/compose.yml build      # one-time, builds the pinned vulnerable and patched server images
uv run python -m evals.run_cve_benchmark --calibrate  # no LLM, checks each fixture is live on the vulnerable version and fixed on the patched one
uv run python -m evals.run_cve_benchmark --survey     # no LLM, plants every in-scope candidate place and reports what each version surfaces (no verdict)
uv run python -m evals.run_cve_benchmark              # graded run, gated against evals/baselines/cve/
uv run python -m evals.run_cve_benchmark --record-baseline  # twice at one clean commit, then commit evals/baselines/cve/ by hand
uv run python -m evals.run_cve_benchmark --ungated    # graded run with no comparison
uv run python -m evals.run_cve_benchmark --concurrency N  # audits (or calibrations) in flight at once (default 6, 1 for the old sequence)
uv run python -m evals.run_cve_benchmark --ungated --chains N --chain-steps M --tool-call-timeout T --no-tools-filter  # measurement run: forced settings on every target, per-target cost, never gates
```

The graded run compares each target to its file in `evals/baselines/cve/` ([ADR 024](docs/adr/024-cve-acceptance-gate.md)). A target detected in every run of a confirmed baseline is gated, and a miss on it is replayed alone: the gate goes red when the miss reproduces. Every detecting run is also replayed without an LLM against a fresh patched container ([ADR 030](docs/adr/030-credit-replayed-on-patched.md)): the auditor's own calls are sent again, and a proof the patched server reproduces is struck before the run is graded, since the auditor could have earned it without the flaw. A credit the replay could not check (the patched launch failed or its connection dropped after the retries) is kept but marked unchecked, and the report lists the refused and the unchecked credits (place ids) in a section after the per-target table. A run whose status rests on an unchecked credit leaves the gate not comparable whatever its baseline, and `--record-baseline` refuses it, so a gated baseline never rests on a credit the replay could not check. Before any audit, each target is checked without an LLM on both versions as `--calibrate` does, and a target that no longer passes is not run, reported with its conditions, and leaves the gate not comparable. An audit that did not detect and in which a step was missed (refused by the model provider, or an unreadable model answer) is audited again, up to three attempts, and the run does not complete when every attempt misses a step, so a missed step never reads as a miss, the struck credit included. An audit in which a step was throttled by the model provider past every retry is skipped like a crashed one, whatever it detected: it is not graded, not replayed on the patched version, and never audited again as an incomplete attempt, since a throttled step is a fact about the provider's capacity, not about the auditor. It exits `0` green, `1` red, `3` not comparable (a target that failed the pre-run check, or a run resting on an unchecked credit, included) or refused, `4` on a crash, a failed preflight (Docker unreachable, an image missing) included, under `--calibrate` and `--survey` too. `--record-baseline` refuses a dirty tree and writes every file or none. A recording refused once the runs are done still writes the report, which ends with the reasons. The first recording is exploratory, and a second at the same commit on the same images confirms it. A change to one target's fixture resets that target alone: delete its file in the commit that changes the fixture, then record it twice with `--cve`. Any other change of conditions (runs, budget, provider, models, reasoning, the grammar) resets the whole baseline: delete `evals/baselines/cve/` in a commit of its own, then record twice. A change of what the grammar grades also regenerates `tests/unit/support/cve_grammar_golden.json` in that commit, and a refactoring never does. The rules of [ADR 020](docs/adr/020-honeypot-baseline-changes.md) apply with the target in place of the cell. A baseline file of a target no longer benchmarked is reported as orphaned and not compared.

The holdout layer draws its targets from a census of public advisories, built by `uv run python -m evals.run_census` (`prefilter`, `status`, `classify-dossier`, `assemble`) from the GitHub Advisory Database, NVD and OSV exports downloaded by hand, and from the output of the census agents. The download commands, the work directory and the operating procedure are in [`evals/holdout_census_method.md`](evals/holdout_census_method.md).

All thirty drawn targets are transplanted. `uv run python -m evals.run_holdout draw-order` prints the salted-hash draw order of the draw-order candidates with each one's disclosure date, the order the draw walks once until it holds 20 targets, and that an addition resumes, up to 30 targets (`--census` defaults to `evals/holdout_census.json`, no network). `uv run python -m evals.run_holdout calibration-dossier --cve ID --out DIR` writes a self-contained, `mcp_auditor`-free calibration kit for one candidate to `DIR`, outside the repository, so the candidate is calibrated without access to the auditor's code. `uv run python -m evals.run_holdout calibrate` confirms each transplanted target is live on its vulnerable version and dead on its patched one, with every kept layout place routed (`--cve ID` restricts it to one target): it needs Docker and no LLM, exits `1` on a dead or unrouted fixture, `4` on a fixture-config error, and `0` when every target holds or nothing is drawn. `uv run python -m evals.run_holdout run` audits the drawn targets and reports the capability number: it needs the drawn targets, the chain and timeout run conditions set in `evals/holdout_conditions.json`, a cutoff with its type and source page for each of its models in `evals/holdout_conditions.json`, Docker and an LLM key, and refuses when tracing is on. It has not been run.

The nuisance admission is scaffolded, and no server is admitted. `uv run python -m evals.run_nuisance walk` prints, per server the holdout walk reached, its package, its reaching flaw and the flaws that set its version, for the maintainer to admit (no LLM, no network). `uv run python -m evals.run_nuisance nuisance-dossier --server PKG --out DIR [--backend KEY]` writes, outside the repository, the isolated admission dossier for one server (the advisories, the fixture format, the grammar and the fix-check driver), free of any `mcp_auditor` import, for the two blind admission agents (no LLM, and the fix-check driver it ships needs Docker). `--backend KEY` copies that backend's kit builder and lifecycle (`doris`). The admission session itself, the patched images and the fix check are the maintainer's deferred work. `uv run python -m evals.run_nuisance calibrate` is the maintainer's real-Docker confirmation that the committed fix-check fixtures reproduce the admission's recorded `fix_check`: it rebuilds each fixture's images, reproduces the flaw on the vulnerable and patched versions, and confirms, per flaw, that the witness surfaces on the vulnerable version and on neither patched one and that the re-run result matches the recorded `fix_check` (the `source` field excepted for a flaw recopied from the holdout calibration). It takes `--cve ID` for one flaw and `--concurrency`, needs Docker and no LLM, and exits `0` green (or when nothing is drawn) and `1` on a mismatch or a drifted fixture. Once servers are admitted, `uv run python -m evals.run_nuisance run` audits them on their patched images and reports the figure: it needs the admitted servers in `evals/nuisance_admission.json` with their compose services and any backend the fixture provisions, the run conditions of `evals/holdout_conditions.json`, Docker and an LLM key, and refuses when tracing is on. It exits `0` on a written report, and also when the admission is absent or holds no server, printing that no server is admitted. It exits `3` when it refuses or when the census or the admission is malformed.

The nuisance gate guards the acceptance servers, the servers of the current CVE targets, which a nuisance run never audits. `uv run python -m evals.run_nuisance gate` audits the admitted ones that run over stdio and under Docker on their patched images, under the nuisance run's conditions with 3 runs by default (`--runs`), and compares each to its own file under `evals/baselines/nuisance/`. A server with no alarm in any run of a confirmed baseline is gated, and an alarm on it is replayed under the replay rule of ADR 016: the gate fires when the alarm reproduces. A server with an alarm in its baseline is unstable, and a new alarm on it is reported inconclusive. A gate audit with no counted alarm in which a step was refused or came back unreadable is attempted again, up to three attempts. When every attempt stays incomplete the run does not complete, which makes the gate not comparable on a gated server only, and refuses a recording of the server whatever its baseline. `--record-baseline` records from a clean tree, twice at one commit (exploratory, then confirmed), then `evals/baselines/nuisance/` is committed by hand. A change to one server's fixture (its admission record or its patched Dockerfile) resets that server: delete its file in the commit that makes the change and record it twice with `--server PKG`. A change to the counter (`evals/nuisance_counter.py`, `evals/nuisance_counting.py`), to the grammar or to the run conditions is a whole reset: delete `evals/baselines/nuisance/` in a commit of its own and record twice. The gate writes its report JSON and markdown to `--report` (default `output/nuisance_gate_report.json`) with the flagged tools per run, and `nuisance_gate_judged_cases.jsonl` beside it, the judged cases and chains of every run. It exits `0` green, `1` red, `3` not comparable or refused (a recording refused once the runs are done included, whatever the verdict), `2` on a `--server` outside the gate set and `4` on a crash. No acceptance server is admitted yet, so it prints that no acceptance server is admitted and exits `0`.

See the README for the reproducibility rationale and the safety note (deliberately-vulnerable images, run on a non-sensitive host).

### Model probe

The probe reports the defects, cost and latency of candidate models on a frozen corpus of prompts, to inform the choice of a model. The corpus is captured once on the reference settings, `gemini-3.1-flash-lite` at `minimal` for both roles, which are no longer the default and are set explicitly below. It needs Docker, the CVE images and `GOOGLE_API_KEY`, and is committed by hand. The probe then needs the key of every candidate (`GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`):

```bash
MCP_AUDITOR_PROVIDER=google MCP_AUDITOR_MODEL=gemini-3.1-flash-lite MCP_AUDITOR_JUDGE_MODEL= MCP_AUDITOR_REASONING=minimal \
  uv run python -m evals.capture_probe_corpus  # writes evals/fixtures/probe_corpus.json
uv run python -m evals.run_probe               # writes output/probe_report.json
uv run python -m evals.run_probe --candidates "gpt-6-luna none" "gpt-6-luna low" --schema TestCaseBatch  # subset run, debugging only
```

What it measures, what it reports and its limits are in [`evals/probe_method.md`](evals/probe_method.md).

### Running evals on a pull request

The judge isolation eval runs automatically on a pull request that touches `src/**`, `evals/**`, a honeypot server, `pyproject.toml` or `uv.lock`, and it fails the check when its gate is red, not comparable or refused (see [The judge isolation eval](#the-judge-isolation-eval)). It needs an API key from repository secrets: a Dependabot pull request and a pull request from a fork both skip the job. The e2e evals never run automatically on a pull request. They run on main after merge, where they gate the build. A maintainer can run either on demand by commenting on the PR:

- `/eval` runs the judge isolation eval only (fast).
- `/eval full` also runs the e2e evals (slower, more API calls), at the baseline's conditions: 3 runs and budget 10, the defaults of `evals.run_evals`.

The workflow checks out the PR's head commit as resolved when it reads the command, so a push after the comment does not change what runs. It runs the evals against that commit and posts the outcome back as a comment, naming the commit it evaluated and, on a failure, whether the judge eval or the e2e evals failed and why (red, not comparable or refused, crashed). The trigger is restricted to repository owners, members, and collaborators. `/eval` refuses a pull request from a fork, whose code would run with the repository's API key: to evaluate one before merge, push the reviewed commit to a branch of this repository and comment `/eval` on a pull request from that branch.

Pull requests that touch the CVE benchmark (`evals/docker/**`, `evals/cve_*.py`, `evals/run_cve_benchmark.py`, the deps `pyproject.toml`/`uv.lock`, or the workflow itself) trigger a deterministic calibration gate. It builds the fixture images and runs `--calibrate` (no API key), and fails if any fixture is dead, minus any target marked CI-unstable. Today that is CVE-2025-68143, whose `git_diff_staged` hangs on GitHub-hosted runners and stays covered by local calibration. The graded detection run is the acceptance gate, run by hand on the local images (`uv run python -m evals.run_cve_benchmark`), and it has no CI workflow.

### Recording an e2e baseline

The e2e evals gate against `evals/baselines/honeypot_e2e.json`, cell by cell, with an absolute floor per metric ([ADR 016](docs/adr/016-eval-gate-governance.md), [ADR 020](docs/adr/020-honeypot-baseline-changes.md)). Without that file, the absolute thresholds stand. `uv run python -m evals.run_evals --record-baseline` writes that file, and it refuses to start on a tree with tracked modifications. A recording is refused when no planted FAIL cell, or no PASS cell, comes out stable and correct over its runs: the gate would have no cell on which to see a lost detection, or a new false positive. The first recording is exploratory: only the floors gate. A second recording at the same commit confirms it by adding its runs: the confirmed baseline holds the runs of both recordings, and only a cell that every one of those runs observes the same way is gated. From then on a flip on a stable cell is replayed and fails the build when it reproduces. A second recording refused on a floor, or for leaving no stable and correct cell on one side over the combined runs, is not made again against the same first recording. One refused for a failed run can be made again ([ADR 023](docs/adr/023-honeypot-second-recording.md)). CI never records.

The gate mode follows from the baseline file:

- **No baseline**: CI keeps the legacy absolute thresholds.
- **Exploratory baseline** (one recording): the run gates on the floors alone.
- **Confirmed baseline** (two recordings at the same commit): the run gates cell by cell, plus the floors.

A gated run and a written recording print a grid of the cells, tools by categories, with what each box means in the legend under it.

The procedure: record once, then run `--record-baseline` again right away, at the same commit and before committing anything. The exploratory file is untracked until committed, so the tree still reads clean and `HEAD` has not moved. Commit the file once the second recording has confirmed it. Committing the exploratory file first moves `HEAD`, and the confirming recording then refuses to run.

How the baseline changes afterwards depends on what changed. A label revision in `evals/ground_truth.py` re-scores the stored runs under the current labels and needs no new recording. A cell the revision adds reads `not_recorded` and stays out of the gate until a recording covers it. A revision that leaves the baseline with no stable and correct planted FAIL cell, or no stable and correct PASS cell, is not re-scored but reset: every run over that baseline, a recording included, is refused before any LLM call until the file is deleted in a commit of its own and recorded twice at that commit ([ADR 022](docs/adr/022-honeypot-recall-floor.md)). A change to a honeypot's code, a tool's name, docstring or signature, a chain setting, the scoring code, the model, `--runs` or `--budget` is a reset: delete the baseline file in the commit that makes the change, with no other change in that commit, and record twice at that commit. Under a red gate, the labeling log entry (the commit message, for a model) names the cells whose flip fired it at the last run, and each must come out stable and correct in the confirmed baseline, or the change is reverted. It is reverted too when the recording is refused for leaving no stable and correct cell on one side. Runs and budget change only from a green gate. Comments, formatting and the module docstring of a honeypot are not part of its fingerprint and change nothing. See [ADR 020](docs/adr/020-honeypot-baseline-changes.md).

A recording runs at the conditions CI runs at: the default `--runs` and `--budget`, and no `MCP_AUDITOR_PROVIDER`, `MCP_AUDITOR_MODEL`, `MCP_AUDITOR_JUDGE_MODEL` or `MCP_AUDITOR_REASONING` override in `.env` or the environment that differs from the defaults. CI sets only the API key, so a baseline recorded under other conditions would make every CI run not comparable, and `--record-baseline` refuses to start under them. It also refuses to write when the tree, `HEAD` or the baseline file changed during the runs, so two recordings started from the same baseline cannot both write, and it writes the file atomically. Every refusal, and fewer completed runs than requested in any mode, exits `3`. A pass whose report holds a step throttled by the model provider past every retry counts as a failed run, and such a replay as a failed replay, so the run is not comparable and exits `3`. A refused or unreadable step leaves the pass completed. A crash of the runner prints its traceback and exits `4`. The `/eval full` comment on a pull request names the gate mode that judged the run and the baseline status, so a pull request that edits its own baseline shows it.

**Declaring a deliberate regression.** A change to the system under test may cost gated cells on purpose, a prompt that trades one category for another for instance. It declares them in `evals/declared_flips.json`, in the commit that makes the change, before the evals run on it ([ADR 020](docs/adr/020-honeypot-baseline-changes.md)). Each entry holds `suite` (`honeypot`, or `judge` for the judge isolation eval), `key` (the cell as `tool/category`, or the case id for `judge`), `mechanism` (by which mechanism the change reaches that cell), `base` and `runs_seen` (the eval runs of the change you had seen, possibly none). One commit holds the change and its entries. `base` is the parent of that commit: read it with `git rev-parse HEAD` before committing. An entry is active only at the commit whose parent is its `base`, and only on a clean tree (a dirty tree ignores it and the run prints a note). At the next commit it is history, and nothing needs cleaning up. Run the evals at the declaring commit: a declared cell that flips reads `declared`, is not replayed and does not fail the gate, and a declared cell that did not flip is listed as "declared, did not flip". An active entry naming a cell outside the ground truth, or a cell named twice, refuses the run before any LLM call. A `judge` entry naming a case absent from the fixture or labeled `unspecified` refuses it too. From the green run, record at that commit with `--record-baseline`: the new baseline replaces the old one. Review checks the runs seen, that no cell already seen flipping went undeclared, and that a change red on an undeclared cell was reverted rather than declared after the fact. Two facts to live with. The new baseline rests on the runs of that one recording, so a cell the change left unstable can be stored as stable. The run on `main` after a merge sees the entries only when the declaring commit sits on the tip of `main` at merge time, whether the pull request is squashed, rebased or merged with a merge commit (the merge commit's first parent is then that tip). A rebase also needs the declaring commit to be the last of the pull request, since the run reads the parent of the new tip. Otherwise edit their `base` to the tip of `main` before merging.

`--ungated` runs the e2e evals on the floors alone, with no condition check and no baseline comparison, for a cheap local run at other conditions (fewer runs, a smaller budget, another model). It is never used in CI and cannot be combined with `--record-baseline`.

The fault injection on the gate is an integration test, `tests/integration/test_gate_fault_injection.py`, run by `uv run pytest tests/integration -n auto` with no API key. It audits the three real honeypot servers with a fake generator and a fake judge that reproduces the committed fixture `evals/fixtures/fault_injection_baseline.json`, plants one fault at a time (a judge that passes, fails or draws every verdict, no verdict at all, half the detections lost, a dropped category, the same category dropped with its cells declared, refused chain steps), the fault staying active in the replays, and asserts the gate's answer in the paired and the floors-only modes and the recording decision. It is the first test at the integration level to exercise the eval gate rather than an adapter. It fails first when the fixture no longer matches the ground truth. The faults, the expected results and what the test does not prove are in [`evals/fault_injection_method.md`](evals/fault_injection_method.md).

### The judge isolation eval

The judge isolation eval judges each case of `evals/fixtures/judge_cases.json` three times and gates case by case against `evals/baselines/judge_isolation.json` ([ADR 025](docs/adr/025-judge-eval-drawn-fixture.md)), under the rules of the e2e gate with the case in place of the cell. The cases are drawn from the judged cases of honeypot and CVE runs by a rule written before the draw, and labeled one by one, blind to the judge's verdict: the draw rule, the fixture format and the procedure are in [`evals/judge_fixture_method.md`](evals/judge_fixture_method.md), and the labeling brief in [`evals/judge_labeling_brief.md`](evals/judge_labeling_brief.md).

What gates:

- **Floors, in every mode**: at least as many detections as runs (a case labeled `fail` judged FAIL in a run), and a precision of 0.50 averaged over the runs.
- **Case by case, against a confirmed baseline**: a case stable and correct in every baseline run that flips is replayed, and the gate goes red when the flip reproduces. A judge call that gives no verdict (unparsable output after the adapter's attempts, a provider refusal) is an uncovered observation, which can flip a case.

With no baseline or an exploratory one, only the floors gate. A case labeled `unspecified` is judged and observed, and stays out of the floors and the comparison. The precision, recall and F1 per run and the per-category table are printed and reported (`output/judge_eval_report.json`) as diagnostics, with no threshold. The run exits `0` green or recorded, `1` red, `3` not comparable or refused, `4` on a crash, with its traceback. A run whose provider, judge model, reasoning, runs or cases differ from the baseline's is not comparable. A judgment throttled by the model provider past every retry is uncovered and listed in the report (`throttled_judgments`), and it makes the run not comparable, in a run or a replay and under `--ungated` alike: the run exits `3` with its report written, not `4`, and the later judgments are not sent. `--ungated` gates on the floors alone, at any conditions, without reading the baseline, and is never used in CI.

Against a baseline, the summary counts the cases per outcome and lists in a table those that left `unchanged`, with their baseline, run and replay observations and the cause of the flip. The table also lists as `partial` a case wrong in every baseline run and right in some runs of this one, counted apart from `unchanged`. With or without a baseline, it prints the requests the model provider throttled (HTTP 429) with the concurrency when there were any.

### Recording the judge baseline

`uv run python -m evals.run_judge_eval --record-baseline` writes `evals/baselines/judge_isolation.json` under the rules of the e2e recording above: from a clean tree, at the conditions CI runs at (the default `--runs` and no provider, judge model or reasoning override), twice at one commit (exploratory, then confirmed, the second adding its runs to the first), then committed by hand. It refuses a recording with an uncovered case in any run, a floor breach, or no stable and correct case on the FAIL side or on the PASS side, and it refuses to write when the tree, `HEAD` or the baseline file changed during the runs. A confirmed baseline is replaced only from a green run with no flipped case, a declared flip excepted.

The baseline stores observations, not labels. A label revision re-scores it and needs no new recording, unless it leaves a side with no stable and correct case: the baseline is then deleted in a commit of its own and recorded twice. A new draw changes the cases, so every run against the old baseline is not comparable: delete the baseline file in the commit of the new draw and record twice at that commit. A new draw, like a change of `--runs`, is made only from a green gate. A change of provider, judge model or reasoning is a reset, as for the e2e baseline.

## Coding, testing, and architecture standards

The project's standards are defined in [`CLAUDE.md`](CLAUDE.md). This file serves as the single source of truth, both for human contributors and for AI-assisted development.

The key points: hexagonal architecture, small pure functions, fakes over mocks. Read the full details there.

## AI-assisted development

If you're using an AI coding agent for non-trivial changes, write a plan in `plans/` before implementation. Naming convention: `YYYY-MM-DD_short_description.md`. The plan gets reviewed and approved before any code is written.

The repo ships two [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills in `.claude/skills/`:

- `/standards` reviews uncommitted changes against CLAUDE.md and fixes violations automatically.
- `/commit` stages changes and creates a conventional commit.

## Architecture decisions

Architecture decisions are documented in `docs/adr/` as immutable ADRs. To change a past decision, write a new ADR that supersedes it.

## What makes a good contribution

- Bug fixes with a regression test.
- New audit categories backed by real-world MCP failure modes.
- Eval improvements: better ground truth, new honeypot scenarios. A ground truth change follows the discipline in [ADR 016](docs/adr/016-eval-gate-governance.md): revisions go by rubric, never cell by cell. The rubric and every revision live in [`docs/labeling-log.md`](docs/labeling-log.md).
- A shipped prompt never names a honeypot's values, errors or tools: `tests/unit/test_fixture_contamination.py` checks the literals, and a rule copied as a technique rather than a string is caught only in review.
- Documentation fixes.

If you're unsure whether something fits, open an issue first.

User-facing changes (new flags, behavior changes, notable fixes) should come with an entry under the `[Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md), in the same pull request.

## Releasing (maintainers)

Publishing is automated: pushing a `v*` tag triggers `publish.yml`, which builds the package and publishes it to PyPI via trusted publishing. The manual steps are:

1. Make sure `main` is green: `uv run pytest -n auto && uv run ruff check . && uv run pyright`.
2. In `CHANGELOG.md`, rename the `[Unreleased]` section to the new version with today's date, add a fresh empty `[Unreleased]` section above it, and update the comparison links at the bottom.
3. Bump `version` in `pyproject.toml`, then run `uv lock` so the lock file picks it up.
4. Run the CVE acceptance gate on the local images: `uv run python -m evals.run_cve_benchmark`. A red gate stops the release. The release commit's message states the outcome: green, or not comparable with the reason.
5. Run the nuisance gate on the local images: `uv run python -m evals.run_nuisance gate`. A red gate stops the release. The release commit's message states the outcome: green, not comparable with the reason, or that no acceptance server is admitted.
6. Commit and push: `git commit -m "chore(release): vX.Y.Z"`.
7. Tag and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. This triggers the PyPI publication.
8. Create the GitHub release, using the changelog section for that version as the body:

   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" \
     --notes-file <(awk '/^## \[X.Y.Z\]/{f=1; next} f && (/^## \[/ || /^\[.*\]: http/){exit} f' CHANGELOG.md)
   ```

   Or paste the section by hand. The changelog is the single source of truth for release notes.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
