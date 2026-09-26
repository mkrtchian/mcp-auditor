# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Two LLM providers: `openai` (default model `gpt-6-luna` at reasoning effort `medium`, needs `OPENAI_API_KEY`) and `fireworks` (default model GLM-5.3-Flash at reasoning effort `medium`, needs `FIREWORKS_API_KEY`). Set `MCP_AUDITOR_PROVIDER` to select one. Each request to either provider is abandoned after 120 seconds, then retried like any other failed request. Their answers are capped at 8,192 output tokens, reasoning included on some providers, and an answer cut by that cap counts as unparsed: it is retried, then reported as a failure.
- The `alibaba` provider: `qwen3.8-flash` on Alibaba Cloud Model Studio's international endpoint, with thinking always off, needs `DASHSCOPE_API_KEY`. It takes no `MCP_AUDITOR_REASONING` value, and shares the timeout and output cap of `openai` and `fireworks`.
- `MCP_AUDITOR_REASONING` sets the reasoning level sent to the main and judge models (`minimal`, `low`, `medium` or `high` with `google`, `none`, `low`, `medium`, `high`, `xhigh` or `max` with `openai`, `low`, `medium` or `high` with `fireworks`, refused with `anthropic` and `alibaba`). Unset, the provider's default applies to its default model only, and a model named by `MCP_AUDITOR_MODEL` or `MCP_AUDITOR_JUDGE_MODEL` gets its API default.

### Changed

- The default Google model is now `gemini-3.5-flash-lite`, still at thinking level `minimal`, for the main model and the judge. Google has scheduled the shutdown of `gemini-3.1-flash-lite` for 2027-05-07. Its list prices are higher ($0.30 input, $2.50 output per million tokens, against $0.25 and $1.50), so a default audit costs more. Set `MCP_AUDITOR_MODEL=gemini-3.1-flash-lite` and `MCP_AUDITOR_REASONING=minimal` to keep the previous model until then.
- A generated test case batch that holds fewer cases than the budget, or fewer categories than requested, is asked for once more. A batch still missing categories after that retry is completed with the missing categories alone, each asked for its share of the budget, and only what is still missing after that is flagged, with the requested and received case counts ("7 cases generated for 10 requested") and the missing categories: a warning in the console and the dry run, a line under the tool heading in the Markdown report, and a `coverage_gap` entry on the tool report in JSON (`null` when the batch is complete).
- The test case generator keeps integer literals to 10 digits and string arguments under 1,000 characters, and probes resource exhaustion by what an argument asks the tool to do rather than by the size of the argument. A string longer than a few dozen characters is composed from varied text, never from one character repeated. It was told to use "extremely large" values, which some models answered with literals of thousands of digits that cost output tokens, could be cut by the output cap and tested the transport rather than the tool.
- Gemini's thinking level is now set explicitly to `minimal` for the default model. It is the API default, now pinned, so a change of default on the API side no longer changes the audit.
- Token usage in JSON reports gains `cached_input_tokens` (a subset of `input_tokens`) and `reasoning_tokens` (a subset of `output_tokens`).
- The honeypot eval ground truth is revised by rubric: four labels changed after the servers were written return to their creation verdict, and four cells whose planted flaw cannot be tied to a mechanism or a category leave it, which keeps 36 cells, 8 of them expected failures. Precision, its resolution and consistency now count only the cells of the ground truth. The rubric and the revision are recorded in `docs/labeling-log.md`.
- The generator, judge and chain planning prompts no longer name the values, errors or tools of this repo's test servers. A few lines written while tuning against those servers asked for them by name or described their tools one by one, and they now state the general rule instead. A unit test fails when a shipped string contains a discriminating literal of the three test servers. Audits of other servers see prompts that no longer steer toward this repo's fixtures, and the repo's own eval numbers are expected to move.
- The e2e evals gate against a recorded baseline once one exists (`evals/baselines/honeypot_e2e.json`, written by `--record-baseline`). A stable cell that flips is replayed and fails the build when the flip reproduces, and recall, precision and distribution coverage each keep an absolute floor. A run whose conditions or honeypot sources differ from the baseline's is reported not comparable and exits `3`. So is a run where fewer runs completed than were requested, in every mode, the absolute thresholds included, and a baseline file whose runs do not match its conditions or the ground truth is refused before any LLM call. A ground truth revision re-scores the baseline's stored runs under the current labels, and a cell it adds stays out of the comparison until a recording covers it. Comments, formatting and module docstrings of a honeypot are not part of its source fingerprint. A crash of the eval runner exits `4` instead of `1`, which read as a red gate. No baseline is recorded yet, so the absolute thresholds still gate. `--ungated` runs on the floors alone, at any conditions. CI runs the e2e evals at 3 runs and budget 10, the conditions a baseline is recorded at, instead of 2 runs and budget 7. See [ADR 016](docs/adr/016-eval-gate-governance.md) and [ADR 020](docs/adr/020-honeypot-baseline-changes.md).
- **Breaking.** The audited server now runs in a Docker container by default. `-- python server.py`, `-- node server.js` and `-- uv run ...` no longer launch: they stop with the ways forward, and run again as `--unconfined -- python server.py` (or with `--image IMAGE` to pick a container of your own). The quick start's `-- npx ...` form still works and now needs Docker installed and running. An audit interrupted before this release resumes only with `--unconfined` and the same command, because the thread identity of a container regime carries its regime. The container drops all capabilities, forbids privilege escalation, runs as the invoking uid and gid, bounds processes and memory, mounts each path the command names writable at the same absolute path and nothing else of the host, and keeps egress open. `--image` overrides the image chosen for the launcher, `--mount PATH[:rw]` adds a host path (read-only by default) and is the way to mount a root the auditor otherwise refuses, such as your home directory. Reports gain an `execution` entry recording the regime, the image and its digest, the mounted paths, and whether the container was killed on memory. The kill state is recorded only: no verdict is rewritten. None of the three options is a configuration-file key, since the file is read from the audited project's own directory. See ADR 017 and ADR 018.
- The CVE benchmark's filesystem, git and kubernetes fixtures now run with no network. Their images are built with everything they need and the auditor talks to them over stdio, so the only use left for egress was an exploit that succeeded and wanted out. The SSRF fixture keeps its dedicated network, since reaching the sentinel over it is the flaw under test. All six fixtures stay live under calibration.
- The CVE benchmark's containers now run with all capabilities dropped, no privilege escalation and a process bound, and the vulnerable servers whose image has no `USER` run as an unprivileged user. The images are deliberately exploitable servers and the auditor's payloads reach them, so the container was the only boundary between a successful exploit and the host running the benchmark, and it carried none of these limits. The calibration mode replays every fixture's exploit path under the new profile and all six stay live. A memory bound is not part of it yet: a server killed on memory mid-audit would be counted as a missed detection rather than a skipped run, because the benchmark does not read the container's kill state. The benchmark also warns when the Docker host cannot enforce the process bound, which Docker otherwise discards silently.
- The CVE benchmark report ends with a count per status instead of a single `Detected X/Y` ratio. That ratio pooled targets whose traces have been read with targets that have not, and the two back different claims. See ADR 015.
- The README no longer publishes the honeypot eval metrics or the judge F1 as quality numbers. A `Measurement` section replaces the thresholds table: it names what each of the three instruments answers, records that the suite was under its precision threshold at the time of the change, and names the measurement none of them makes, the false-positive rate on a healthy server. See ADR 015.
- The auditor now proves injection non-destructively: the generator is instructed to prefer benign reflected evidence, and a deterministic guard refuses to send a payload containing an enumerated destructive construct (`rm -rf`, `DROP TABLE`, a shutdown command, a fork bomb, and a handful more). A refused payload is reported as blocked with its reason in every output format, never sent to the server and never judged. Writes are still permitted: auditing a tool that writes writes. The generator is also told to prove impact by reading rather than writing, so a report can now carry a secret read from the audited server. See ADR 013 and ADR 014.
- JSON reports now always include the `owasp` key on eval results, with `null` for categories without an OWASP MCP mapping. The key used to be absent in that case. OWASP data is derived on the model itself and appears in every `EvalResult` serialization. See ADR 012.

### Fixed

- `--resume` now resumes. It was inert: a normal run stored its checkpoints under a random thread nobody could name, while `--resume` read a thread no run had ever written to, so it failed with an internal `EmptyInputError` instead of picking anything up. The thread is now derived from the audited target and wiped whenever a fresh audit starts, so re-auditing the same target cannot inherit the previous report's tools and token count. `--resume` with nothing unfinished to pick up, either because the target was never audited or because its last audit completed, says so and runs a fresh audit rather than replaying the previous report. Two consequences of keying the thread on the target are worth knowing: a resumed run is governed by the budget, chain and tool options of the run it resumes, so passing different ones alongside `--resume` has no effect, and two audits of the same target running at once now share a thread, where before they were isolated. Neither run can produce a merged report, but the one that finishes first reads the other's state, so it reports the other's result or exits claiming no report was produced. Audit a given target from one process at a time.

## [0.2.0] - 2026-07-10

### Added

- Multi-step attack chains: the auditor plans multi-step attack scenarios against a single tool, executes them step by step against the live server, and judges the outcome. Opt-in via `--chains`, rendered in all output formats. See ADR 010.
- CVE benchmark: graded runs of the auditor against real, pinned-vulnerable MCP servers in throwaway Docker containers, with a no-LLM calibration mode and a `--cve` filter. See `plans/2026-07-06_cve_benchmark.md`.
- `/eval` PR comment command: maintainers can run the judge eval (`/eval`) or the full eval suite (`/eval full`) on a pull request.
- CI gates: judge eval fails on F1 regression, CVE fixture calibration gates benchmark PRs, `ruff format --check` gates all PRs.
- Dependabot updates for uv dependencies and GitHub Actions.

### Changed

- Default Google model bumped to `gemini-3.1-flash-lite`.
- LangSmith tracing env vars migrated to the current `LANGSMITH_*` names.

### Fixed

- Audit verdicts could be attributed to a hallucinated tool name: the graph now dispatches on the tool actually under audit.
- Chain verdicts are now counted in eval aggregation.

## [0.1.0] - 2026-03-23

Initial public release on PyPI.

- Dynamic adversarial testing of live MCP servers: tool discovery, LLM-generated test cases across five categories (input validation, error handling, injection, information leakage, resource abuse), execution over the MCP protocol, LLM-as-a-judge verdicts with severity ratings.
- OWASP MCP Top 10 mapping in all output formats.
- Cross-tool learning: attack context extracted from earlier tools informs later probes.
- Config file support (`.mcp-auditor.yml`), `--tools` filter, `--budget` control, token usage reporting.
- Three-level test strategy: unit tests with fakes, integration tests against a honeypot server, LLM evals scored against planted ground truth.

[Unreleased]: https://github.com/mkrtchian/mcp-auditor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mkrtchian/mcp-auditor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mkrtchian/mcp-auditor/releases/tag/v0.1.0
