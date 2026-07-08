# CVE Validation Benchmark

**Date:** 2026-07-06
**Status:** Proposed

## Context

The honeypot evals prove the tool detects synthetic vulnerabilities. This benchmark proves it against real, published CVEs on the reference MCP servers users actually run: `@modelcontextprotocol/server-filesystem` (npm) and `mcp-server-git` (PyPI).

It is a **standing validation harness, built first**, not a one-shot report. It measures the current tool honestly and doubles as the acceptance test for future detection capabilities: when a capability lands, its CVE flips from missed to detected in this harness with no rewrite. The harness itself has no dependency on any unbuilt feature. What depends on features is how many CVEs detect, not the harness code.

### What the benchmark measures, and the philosophy line it respects

mcp-auditor is a black-box, dynamic, agentic auditor of a running server. It detects a scope bypass or an injection when the effect is reachable and observable through the protocol. A CVE that could only be caught by stepping outside that philosophy (instrumenting the host to watch silent side effects) is **out of design scope**: including it would confine the tool to an unfair failure. So the target set contains only CVEs reachable within the tool's philosophy, possibly after a philosophy-aligned capability is added.

**What it measures, stated honestly.** This benchmark measures *regression against known, published, real-world exploits*: it proves the tool still detects a fixed set of documented CVEs and tracks that detection capability as the tool and the target servers evolve. It does **not** measure discovery of unknown vulnerabilities (a published CVE is, like a honeypot case, a known issue; discovery lives in production telemetry, out of scope here). And crediting detection on a seeded sentinel is a *narrow proxy* for audit usefulness: a surfaced sentinel proves the out-of-scope secret reached the response, not that the resulting report is clear, correctly categorized, or actionable. The count this harness produces is an honest regression signal, not a measure of real-world audit quality.

### CVE selection principle

Each candidate CVE is classified by the capability it needs, and whether that capability fits the tool's black-box agentic philosophy:

- **Detectable now**: reachable by the current generator and intra-tool chains.
- **Awaiting declared-scope awareness**: needs the generator to use the scope the auditor already granted the server (its own launch args, or the server's `list_allowed_directories` tool) to construct boundary-crossing inputs. This stays black-box (the auditor uses what it configured or what a tool reveals).
- **Awaiting cross-tool chains**: needs a chain to sequence calls across different tools with shared state. Stays black-box (pure sequencing). Named as a natural extension in ADR 010.
- **Out of reach of the black-box default**: only catchable by instrumenting the host to observe a silent side effect. That gray-box mode is deferred in ADR 011, so these CVEs are excluded from this target set for now.

## Scope of this plan

Deliver the on-demand benchmark harness, the seeded fixtures, and the per-CVE target definitions with their status vocabulary. Running it against the real servers (network, package installs, API key, LLM cost) and filling a README section is a later manual step, out of this plan. The harness is on-demand, not CI-gating, consistent with the e2e eval being push-only.

## Target CVEs

| CVE | Server (pinned) | Status | Blocking capability |
|---|---|---|---|
| CVE-2025-53109 symlink traversal | filesystem npm `@0.6.2` | detectable now | none (planted symlink sits inside the allowed dir) |
| CVE-2025-53110 prefix collision | filesystem npm `@0.6.2` | missed until feature | declared-scope awareness |
| CVE-2025-68145 `--repository` bypass | git PyPI (pre-2025.9.25) | missed until feature | declared-scope awareness |
| CVE-2025-68143 `git_init` traversal | git PyPI (pre-2025.9.25) | missed until feature | cross-tool chains + declared-scope awareness |

**Tracked as out of scope (reachable only with instrumentation):**

- CVE-2025-68144 argument injection (`git_diff --output=/path`): overwrites a file silently, nothing surfaces in a tool response. Catching it needs the instrumented observation mode deferred in ADR 011. It is not run as an audit target, but it is listed in the report with an `out_of_scope` status and counted. The tally of such CVEs is the gate signal ADR 011 watches, so they are tracked, not dropped. Also recorded in the README scope note. Model this as a small `OUT_OF_SCOPE_CVES` list (id, severity, reason) that the report renderer includes alongside the run targets. The gate is not a fixed threshold encoded here: ADR 011 owns the decision to build instrumentation, and this harness only keeps the tally visible and growing so that decision stays evidence-based (today the tally is one, 68144).

Both remaining git CVEs are present in a version before 2025.9.25 (git_init still exists for 68143, the unvalidated `repo_path` still bypasses `--repository` for 68145), so one git pin covers both. Confirm the exact available PyPI version at implementation.

### Detectable-now third-party targets

The reference filesystem and git CVEs above are marquee servers but skew toward feature-gated detection. To show real detection now, add these bucket-A CVEs on popular third-party stdio servers, verified 2026-07-07 to meet the three criteria below (real CVE, pinnable vulnerable version, effect visible in the tool response):

- CVE-2025-53355, `mcp-server-kubernetes` (npm, pin `@2.4.9`, patched 2.5.0): command injection, the kubectl stdout is returned in the response.
- CVE-2026-0755, `gemini-mcp-tool` (npm, pin `@1.1.5`, patched 1.1.6): an unvalidated `@file` reference inlines file content into the ask-gemini response.
- CVE-2025-65513, `mcp-fetch-server` (npm, pin `@1.0.2`): SSRF, the fetched internal content is returned by the fetch tools.

Two swept candidates were dropped on verification: CVE-2025-66689 (Zen MCP, no pinnable npm or pypi package, only git or uvx-from-git) and CVE-2025-53967 (Framelink Figma, the injected command's output is redirected to disk and does not surface in the response, a silent effect that belongs to the deferred instrumentation class, not bucket A).

The three were verified against those criteria (stdio, pinnable vulnerable version, effect visible in the response, not silent). Re-confirm the pinned versions are still installable at implementation, since a registry can unpublish a version.

These targets reuse the same sentinel oracle: seed a sentinel the exploit surfaces (a token the injected command echoes, content at an internal URL for SSRF, or a seeded out-of-scope file), and credit detection when a FAIL evidence carries it. Crucially, the sentinel must be planted where a **generic** exfil surfaces it, because the generator is blind to targeted paths (see "Sentinel reachability"). They have `blocker=None` (conditional on that) and `tools_filter` narrowed to the vulnerable tool.

### Sentinel reachability (can the blind generator surface it?)

The oracle credits detection only if the sentinel appears in a response, and the generator is **black-box**: it knows neither the sentinel's value nor its planted path. So each target needs an explicit answer to *how a blind generator surfaces the sentinel*, a constraint easy to miss that revises some blockers.

- **53109 (solid, `blocker=None`).** The symlink `report` sits **inside** the allowed dir, so `list_directory(sandbox)` discovers it and `read_file(report)` follows it out. Nothing to guess: the attack surface is in-scope and discoverable. This is the only target reachable with zero target knowledge.
- **53110 (`declared-scope awareness`, sufficient).** The out-of-scope sibling `sandbox_secret` is not discoverable from inside `sandbox`, but it is **derivable from the boundary**: the prefix-collision attack *is* "append a suffix to the allowed prefix". §13c hands the generator the allowed dir, so it constructs `sandbox_secret` directly. §13c alone suffices here.
- **68145 (`declared-scope awareness` + derivable target).** §13c gives the boundary (`--repository <repo>`), telling the generator to aim outside it, but the specific out-of-scope repo is a somewhat arbitrary sibling it must still name. Seed that repo at a path derivable from the allowed one, or accept the reach is a run-time confirmation.
- **68143 (revised: `cross-tool chains` + `declared-scope awareness`).** Two dependencies, not one. (a) Cross-tool sequencing (§13a): `git_init(<out-of-scope dir>)` → `git_add(.)` → `git_diff_staged`. `git_add(.)` stages the whole directory, so the generator needs **no filename** (an earlier `git_add(id_rsa)` sketch was wrong: a blind generator cannot guess `id_rsa`). (b) Reaching the out-of-scope dir: a temp root has **no well-known paths** (`~/.ssh` etc. do not exist), so the generator must derive the target from the declared scope (§13c) or reach it by relative traversal (`git_init("..")`). Seed the sentinel as the content of an out-of-scope directory that is a **sibling or parent** of the repo. So 68143 awaits both capabilities, not cross-tool chains alone.
- **Third-party bucket-A (`blocker=None`, conditional on generic exfil).** Detectable now **only if** the sentinel is planted where a *generic* exfil surfaces it, since the generator won't know a targeted path:
  - *Command injection (kubernetes)*: plant the sentinel as an **env var** or a file in the server's working dir, so a generic injected dump (`; env`, `; cat ./*`) surfaces it. A targeted `cat <path>` would need the path.
  - *SSRF (fetch)*: serve the sentinel from a **well-known internal address** the generator would try (loopback, cloud-metadata IP), not an arbitrary port.
  - *`@file` inline (gemini)*: the referenced path must be one the generator would try (conventional or derivable).
  These stay `blocker=None` only if the generic-exfil path works; confirm at the run. A target that needs a specific unreachable path graduates to a declared-scope dependency like the git CVEs.

Bottom line: only **53109** is reachable with zero target knowledge. Every scope-bypass CVE (53110, 68145, 68143) needs the boundary (§13c) to aim; the injection/SSRF CVEs need the sentinel where a generic exfil hits. Exact reach is a run-time confirmation (*measure, do not assume*).

### Honest current expectation

53109 detects now, and the third-party bucket-A targets detect now conditional on the generic-exfil reach (see "Sentinel reachability"), so the benchmark shows real current detection, not an empty column. 53110, 68145, 68143 report `missed (awaiting <capability>)` until their aligned capability is built. The run may surprise us on 53110/68145 if the current generator already tries boundary-crossing paths, which is exactly what the harness is for: measure, do not assume. Each future capability then has this benchmark as its acceptance test.

## Detection semantics

Three properties make a per-CVE status trustworthy, and this section is their single locus (as `metrics.py` is for the honeypot metrics): a two-level oracle that attributes a miss to the right pipeline stage, an explicit rule for aggregating stochastic runs, and per-CVE metadata that keeps a `missed` interpretable.

### Two-level oracle: separate "generator reached" from "judge flagged"

Detection runs through two stochastic LLM nodes: the generator (does it forge an input that reaches the out-of-scope target?) and the judge (does it rate the resulting response FAIL?). A single `detected`/`missed` status collapses their two failure modes and misattributes a judge miss as a detection miss. Because the audit reads charitably (ADR 004 rule 3, the declared tool purpose), a generator can surface the out-of-scope secret while the judge still returns PASS.

So the oracle records two facts per run:

- `sentinel_surfaced`: the sentinel appears in *any* observed output (response or error), regardless of verdict. The generator reached the target.
- `sentinel_in_fail`: the sentinel appears in an output whose `eval_result.verdict == FAIL`. The full pipeline detected.

The gap between them isolates the judge, and it is what lets a miss feed the right fix: a `sentinel_surfaced` without `sentinel_in_fail` is a judge-prompt task (§5), not a generator task (§4/§13a). Both facts are already available while scanning `tool_reports`, so the second level is free.

### Aggregating across runs: capability and reliability, not one collapsed count

Detection is stochastic, so each target is audited `k` times (a `--runs` arg, default a module constant, mirroring `run_evals`), and the report carries two numbers rather than one collapsed verdict:

- **detection@k**: detected in at least one of `k` runs. The capability signal ("the tool *can* find this"), the any-hit logic proper to a detector and consistent with the FAIL-positive class choice in the eval metrics.
- **hit-rate `hits/k`**: how many of `k` runs detected. The reliability signal ("you can rely on it"), the pass^k-style consistency the honeypot harness already tracks with `--runs`.

A single-run miss is noise, not a regression: at this sample size the run-to-run variance dominates, and the tiny N also makes a Bernoulli standard error invalid, so no confidence interval is quoted on the count. A `blocker=None` regression signal is claimed only on `0/k` across `k` runs.

### Status vocabulary

Resolved per CVE from the `k` runs, most-informative first:

- `detected` — `sentinel_in_fail` in >= 1 run (report the hit-rate alongside).
- `reached_but_judged_pass` — `sentinel_surfaced` in >= 1 run but never `sentinel_in_fail`. A judge miss, not a generator miss; reported regardless of `blocker`.
- `missed` — sentinel never surfaced and `blocker is None`. A real generator/seeding miss to investigate, after ruling out a broken fixture (positive control below).
- `missed_awaiting_capability` — sentinel never surfaced and `blocker is not None` (expected until that capability lands; `blocker` names it).
- `out_of_scope` — reachable only with instrumentation (68144); tracked and counted, never run.
- `not_run` — every run failed to launch/install (infra, not a detection miss).

### Budget and positive control keep a `missed` honest

`test_budget` is applied uniformly (`CVE_TEST_BUDGET` or `--budget`), but per-CVE detection probability varies widely, so a hard-but-reachable target can miss for lack of shots rather than incapacity. The budget is carried onto every `CVEResult` and rendered next to the status, so a `missed` is read against the budget it was given.

And before any `missed` is trusted, a one-time manual exploit per detectable-now target (a raw tool call that surfaces the sentinel, no LLM) confirms the vulnerability is live in the seeded fixture. Without this reference check, a mis-seeded environment (a symlink the pinned server does not follow, a wrong allowed-dir) yields a permanent `missed` indistinguishable from a generator miss. This is a manual run-time step, not harness code.

## Approach

Mirror the structure of `evals/run_evals.py` (config dataclass + runner loop, reusing `StdioMCPClient.connect` and `build_graph`), with three differences:

- **One target per CVE**, not per server: each CVE needs its own seeded environment, and two filesystem CVEs share the read-tool cell.
- **Per-CVE reporting with a status vocabulary** (`detected`, `reached_but_judged_pass`, `missed`, `missed_awaiting_capability`, `out_of_scope`, `not_run`), resolved across `k` runs with a detection@k / hit-rate split (see "Detection semantics"), not the four aggregate honeypot metrics.
- **Setup and teardown per target** (the honeypots need no seeding).

Note: the honeypot harness reduces reports through `aggregate_verdicts` (`evals/metrics.py`), which collapses cases into a `(tool, category) -> verdict` map and discards the response text. The CVE oracle needs the raw response to match the sentinel, so it scans `report.tool_reports` directly and does not reuse `aggregate_verdicts`.

## Files to add

### `evals/cve_targets.py` (new)

```python
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3  # only consulted when chain_budget > 0


@dataclass(frozen=True)
class CVETarget:
    cve_id: str
    severity: str                      # CVSS string for the report
    sentinel: str                      # unique high-entropy token seeded out of scope
    prepare: Callable[[Path], Launch]  # seed under root, return how to launch the pinned server
    blocker: str | None                # None = detectable now; else the awaited capability
    note: str                          # one line, why detected or which capability it awaits
    tools_filter: frozenset[str] | None  # narrow build_graph to the relevant tools; None = all


CVE_TARGETS: list[CVETarget] = [ ... ]  # the 4 reference + 2-3 third-party targets
```

`CVETarget` structurally satisfies the `TargetInfo` Protocol from `cve_oracle` (it has `cve_id`/`severity`/`sentinel`/`blocker`/`note`) and adds the operational `prepare`/`tools_filter`. That split is the whole point: the pure oracle reads only the descriptive metadata, the runner owns launching and tool filtering, and neither module imports the other.

Each `prepare(root)` seeds a throwaway temp root and returns the launch:

- **53109**: create `root/sandbox`, create `root/outside/flag.txt` with the sentinel, plant a symlink `root/sandbox/report -> root/outside/flag.txt` (no MCP tool creates symlinks, so it is planted). Launch `npx -y @modelcontextprotocol/server-filesystem@0.6.2 <root/sandbox>`.
- **53110**: create `root/sandbox` (allowed) and a sibling `root/sandbox_secret/flag.txt` with the sentinel. Same server launch. Reaching the sentinel needs declared-scope awareness, so it reports missed until then.
- **68145**: `git init root/repo` (allowed) and `git init root/other` with a commit message containing the sentinel. Launch `uvx mcp-server-git@<version> --repository <root/repo>`.
- **68143**: `git init root/repo` (allowed). Seed the sentinel as the content of an out-of-scope directory that is a **sibling or parent** of the repo (reachable by relative traversal or scope-derivation, not a random hidden name). Cross-tool exploit: `git_init(<out-of-scope dir>)` → `git_add(.)` (stages the whole dir, no filename to guess) → `git_diff_staged` (surfaces the content). Same git launch. Awaits cross-tool chains **and** declared-scope awareness (see "Sentinel reachability").

### `evals/cve_seeding.py` (new)

Deterministic helpers used by `prepare`: `make_dir_with_file`, `plant_symlink`, `init_git_repo_with_commit`. Pure filesystem setup, no MCP, unit-testable.

### `evals/cve_oracle.py` (new)

Pure transformation module, mirroring the split between `evals/metrics.py` (public pure functions, exhaustively unit-tested) and `evals/run_evals.py` (private I/O orchestration, not unit-tested). All detection logic, status resolution, the `CVEResult` model, and report rendering are **public pure functions** here, so the tests exercise them as public API rather than reaching into the runner's private helpers. The runner (`run_cve_benchmark.py`) imports and orchestrates them; it owns only the I/O.

**`RunDetection`** (pydantic model, one run's facts): `sentinel_surfaced: bool`, `sentinel_in_fail: bool`, `evidence: str | None` (the matching text), `category: AuditCategory | None` (what the judge assigned).

**`TargetInfo`** (a `Protocol`, the *descriptive* slice of a target the pure oracle reads): `cve_id: str`, `severity: str`, `sentinel: str`, `blocker: str | None`, `note: str`. The concrete `CVETarget` (in `cve_targets`, Step 2) structurally satisfies it and adds the *operational* fields `prepare`/`tools_filter`. Typing the oracle against `TargetInfo` keeps `cve_oracle` free of any import from `cve_targets`, so it is pure and self-contained like `metrics.py` and can be built and unit-tested first (Step 1), before `cve_targets` exists (Step 2). No import cycle exists either way (the graph is `cve_seeding <- cve_targets <- run_cve_benchmark -> cve_oracle`); the Protocol's real payoff is this build order and the interface-segregation (the oracle never sees `prepare`/`tools_filter`).

**`CVEResult`** (pydantic model, alongside the functions as `EvalReport` sits in `metrics.py`): `cve_id`, `severity: str`, `note: str`, `status: CVEStatus`, `blocker: str | None`, `runs: int` (`k`), `hits: int` (runs with `sentinel_in_fail`), `surfaced: int` (runs with `sentinel_surfaced`), `budget: int` (the `test_budget` used), `evidence: str | None`, `category: AuditCategory | None`. Each result is **self-describing**: it snapshots `severity`/`note` from its `TargetInfo` (as `EvalResult` already snapshots `tool_name`/`category`/`severity` from its source), so `render_markdown` and the JSON both take a flat `list[CVEResult]` and render run targets, `out_of_scope`, and `not_run` rows uniformly, with no zipping against targets. `CVEStatus` is a `StrEnum` ({detected, reached_but_judged_pass, missed, missed_awaiting_capability, out_of_scope, not_run}), matching how `AuditCategory`/`EvalVerdict` are modelled in `domain/models.py`. `detection@k` is `hits >= 1`; the reliability hit-rate is `hits / runs`.

**`detect_in_report(target: TargetInfo, report: AuditReport) -> RunDetection`** (one run): scan `report.tool_reports` for the sentinel in observed output, at two levels. The observed output is not on `EvalResult` (which only carries `tool_name`, `category`, `payload`, `verdict`, `justification`, `severity`); it lives on the sibling model. For a case, check `TestCase.response`; for a chain, check each `ChainStep.response` across `AttackChain.steps`. On a tool error the text is stored in `.error` (with `.response` set to `None`), so scan `.error` as well to avoid missing a leak surfaced through an error payload. `TestCase.response` is typed `str | dict[str, Any] | None`, so coerce a dict response to text before the substring match. Record `sentinel_surfaced` (sentinel in any output, any verdict) and `sentinel_in_fail` (sentinel in an output whose `eval_result.verdict == FAIL`). Credit is on the **sentinel alone, not the category**: the sentinel is seeded only out of scope, so its appearance proves the audit surfaced the out-of-scope secret. The category the judge assigned is recorded for the report (a successful traversal read usually lands on INFO_LEAKAGE, sometimes INJECTION, per ADR 004) but does not gate detection.

**`resolve_status(target: TargetInfo, detections: list[RunDetection], budget: int) -> CVEResult`** aggregates the `k` per-run detections (see "Detection semantics"). `hits` = runs with `sentinel_in_fail`, `surfaced` = runs with `sentinel_surfaced`:

- any `sentinel_in_fail` -> `detected` (carry `hits`, `surfaced`, `runs`)
- else any `sentinel_surfaced` -> `reached_but_judged_pass` (generator reached, judge missed; regardless of `blocker`)
- else `blocker is None` -> `missed` (real generator/seeding miss to investigate, after ruling out a broken fixture)
- else `blocker is not None` -> `missed_awaiting_capability` (`blocker` names it)

Every branch snapshots `severity`/`note`/`cve_id`/`blocker` from `target` onto the `CVEResult`, so it is self-describing for the renderer. A target whose every run failed to launch is `not_run` (infra, not a detection miss), built by a public `not_run(target: TargetInfo) -> CVEResult`; `out_of_scope` results are emitted from `OUT_OF_SCOPE_CVES` via `out_of_scope_results`.

**`render_markdown(results: list[CVEResult]) -> str`** and the JSON payload are pure functions here too (a string builder, not console printing, so it is unit-testable like the "Report assembly" scenario below). The markdown table columns: CVE id, CVSS, status, hit-rate (`hits/runs`), budget, awaited capability, one-line note. The runner writes the string and the JSON to disk; the rendering itself stays pure.

### `evals/run_cve_benchmark.py` (new)

Runner mirroring `run_evals.py`: I/O orchestration only (temp roots, MCP connect, graph invoke, writing the report). It imports `detect_in_report`, `resolve_status`, `not_run`, `out_of_scope_results`, and `render_markdown` from `cve_oracle.py`.

```python
async def run_cve_benchmark(budget: int, runs: int) -> list[CVEResult]:
    results = []
    for target in CVE_TARGETS:
        detections = []
        for _ in range(runs):
            with temp_root() as root:              # throwaway, torn down after, even on failure
                try:
                    launch = target.prepare(root)
                    report = await _audit(launch, target, budget)
                except LaunchError:
                    continue                        # a failed run contributes no detection
                detections.append(detect_in_report(target, report))
        results.append(
            not_run(target) if not detections
            else resolve_status(target, detections, budget)
        )
    return results
```

`_audit` reuses the connect + `build_graph` + `ainvoke` block from `_run_single_honeypot` (keys: target, test_budget, attack_context, chain_budget, max_chain_steps), including `errlog=devnull` on `StdioMCPClient.connect` to keep the real servers' stderr from polluting the console. It loads `Settings`, builds both `create_llm`/`create_judge_llm`, and returns `result["audit_report"]`, exactly as the honeypot runner does. `chain_budget` and `max_chain_steps` come from the `Launch`; `max_chain_steps` must always be on the invoke dict since `GraphState` declares it, even when `chain_budget` is 0. `test_budget` is *not* on `Launch` (the honeypot passes it as a runner parameter) — the benchmark supplies it from a module constant `CVE_TEST_BUDGET` (or a `--budget` CLI arg mirroring `run_evals`), applied uniformly to every target. The run count `k` comes from a `--runs` arg (default a module constant `CVE_RUNS`), so each target is audited `k` times and its status resolved across those runs.

Each target carries an optional `tools_filter`, passed straight to `build_graph`. The single-tool CVEs narrow it to the tool that surfaces the leak (the filesystem read tool for 53109/53110, a git read tool such as `git_log` for 68145) to cut cost and sharpen the sentinel oracle. 68143 keeps the tools its cross-tool exploit sequences (`git_init`, `git_add`, `git_diff_staged`), so the harness is already a faithful acceptance test for cross-tool chains once they land. `None` audits all discovered tools.

The runner writes the JSON report and the `render_markdown` output to disk (under `output/`, as `run_evals` writes its report), then prints a summary. The detection, status, and rendering logic it calls all live in `cve_oracle.py`.

### README

Two touches, one now and one later:

- **Now, static, part of this plan.** Add a bullet to the existing "Scope and limitations" section stating that vulnerabilities whose only effect is a silent write, a spawned process, or out-of-band exfiltration are out of reach of the black-box tool, pointing to ADR 011. This does not depend on a run and honours the "will state" promise in ADR 011.
- **Later, deferred to the run, out of this plan.** A "CVE validation" section filled from the real report. This plan fixes its shape (CVE id, CVSS, status, awaited capability, note) plus the out-of-scope tally for 68144, so the run step only fills current statuses.

## What stays unchanged

- All of `src/` (the audited tool). The benchmark measures the existing graph, prompts, and models. No new `AuditCategory`, no prompt change, no capability added in this plan.
- The honeypot evals (`run_evals.py`, `ground_truth.py`, `metrics.py`) and their CI job. The benchmark is additive and separate.
- No change to the shipped CLI.

## Edge cases

- **Pinned package not installable / network down**: `not_run`, distinct from `missed`. An infra failure is not a detection miss.
- **Git version pins**: one pre-2025.9.25 version is expected to carry both git CVEs (see the Target CVEs note), but each git target still returns its own `Launch` with an explicit pin from `prepare`, so if that assumption breaks at implementation the targets can diverge without a harness change.
- **`blocker is None` target reports missed**: a regression signal (the generator stopped reaching a case it should), but only on `0/k` across `k` runs, never on one unlucky run; rule out a broken fixture (positive control) before blaming the generator. A `reached_but_judged_pass` on such a target points at the judge, not the generator.
- **Symlink planting**: needs a writable temp root; use `tempfile` roots, never a real user directory. Tear down (including planted symlinks) even on failure.
- **Sentinel collision**: unique high-entropy token per target so detection is never credited by coincidence.
- **Chain budget**: non-zero only where a chain is the expected path; zero elsewhere to keep runs cheap.

## Test scenarios (deterministic, no real servers or LLM)

Tests live in `tests/unit/`, exercising the **public pure functions** of `cve_seeding` and `cve_oracle` (never the runner's private I/O helpers, matching how `metrics.py` is tested and `run_evals.py` is not). Fake `AuditReport`s are constructed via a `given` support module (`tests/unit/support/test_cve_oracle_given.py`, following the `test_eval_metrics_given.py` pattern with builders like `a_report`, `a_case_with_response`, `a_chain_with_step`). Add a `given`/`then` pair only where it actually abstracts construction or assertion; inline trivial one-liners.

- **Seeding** (`cve_seeding`): `make_dir_with_file` writes the file with the sentinel; `plant_symlink` creates a link resolving to the target; `init_git_repo_with_commit` produces a repo whose log contains the sentinel. Uses `tmp_path`, asserting on observable filesystem outcomes.
- **Detection oracle** (`detect_in_report`, one run), driven by fake `AuditReport`s:
  - FAIL case whose response contains the sentinel -> `sentinel_surfaced` and `sentinel_in_fail` (regardless of the case's category).
  - FAIL case whose sentinel arrives via `.error` (response `None`) -> both true.
  - FAIL case whose `response` is a dict containing the sentinel -> both true.
  - FAIL chain whose `ChainStep.response` contains the sentinel -> both true.
  - **PASS** case whose response contains the sentinel -> `sentinel_surfaced` true, `sentinel_in_fail` **false** (the generator-vs-judge split).
  - no sentinel anywhere -> both false.
- **Status resolution** (`resolve_status`), driven by lists of `RunDetection`:
  - any run with `sentinel_in_fail` -> `detected`, `hits` = number of such runs, `surfaced` >= `hits`.
  - runs with `sentinel_surfaced` but none `sentinel_in_fail` -> `reached_but_judged_pass` (regardless of blocker).
  - no surfacing, `blocker=None` -> `missed`; `blocker="cross-tool chains"` -> `missed_awaiting_capability` (blocker recorded).
  - detection@k is any-hit: 1 of 3 runs in FAIL still resolves `detected` with `hits=1, runs=3`.
- **Report assembly** (`render_markdown`): a list of `CVEResult` renders the markdown table with the right per-CVE status, hit-rate, budget, and awaited capability, and counts detections correctly.

## Verification

- `uv run pytest tests/unit` (new deterministic tests pass).
- `uv run ruff check . && uv run ruff format --check . && uv run pyright`.
- Manual, later, out of this plan's scope: `uv run python -m evals.run_cve_benchmark` against the pinned servers with an API key, inspect the per-CVE report, draft the README "CVE validation" section. Pass `--runs k` and pin the environment: the e2e path carries environment variance on top of sampling variance, so present the result as an honest detection@k plus hit-rate, not a calibrated metric, with no confidence interval at this sample size.
- Positive control, before trusting any `missed`: for each detectable-now target, run the exploit by hand once (a raw tool call that surfaces the sentinel, no LLM) to confirm the vulnerability is live in the seeded fixture. A permanent `missed` on a mis-seeded environment is indistinguishable from a generator miss without this reference check.

## Implementation steps

### Step 1: Pure core — seeding helpers and detection oracle (test-first)

The whole pure, unit-tested surface of the benchmark. No real servers, no LLM, no I/O orchestration. Everything here is a public pure function exercised through its public API, matching how `evals/metrics.py` is tested and `run_evals.py` is not.

**Files** (write the tests and the `given` support before the production modules):

- `tests/unit/support/test_cve_oracle_given.py` (new)
- `tests/unit/test_cve_seeding.py` (new)
- `tests/unit/test_cve_oracle.py` (new)
- `evals/cve_seeding.py` (new)
- `evals/cve_oracle.py` (new)

**Do**:

1. `tests/unit/support/test_cve_oracle_given.py`: builders that construct fake `AuditReport`s carrying an out-of-scope sentinel in a FAIL case or chain, following the `test_eval_metrics_given.py` pattern (`a_report`, `a_case_with_response`, `a_chain_with_step`). Reuse the domain models directly: `AuditReport(target=..., tool_reports=[...], token_usage=TokenUsage())`, `ToolReport(tool=ToolDefinition(...), cases=[...], chains=[...])`, `TestCase(payload=AuditPayload(...), response=..., error=..., eval_result=...)`, `AttackChain(goal=ChainGoal(...), steps=[ChainStep(...)], eval_result=...)`, `EvalResult(tool_name, category, payload={}, verdict, justification, severity)`. Note the observed-output fields: `TestCase.response` is `str | dict[str,Any] | None` and `TestCase.error` is `str | None`; `ChainStep.response`/`ChainStep.error` are `str | None`. `EvalResult` itself carries no observed output, so the oracle must read the sibling `TestCase`/`ChainStep`, not `EvalResult`. Include a **PASS** case carrying the sentinel (for the surfaced-but-not-flagged split) and lists of `RunDetection` for the `resolve_status` tests. Extract a builder only where it abstracts real construction; inline trivial one-liners.

2. `evals/cve_seeding.py`: three deterministic filesystem helpers, pure setup, no MCP. `make_dir_with_file(dir_path: Path, filename: str, content: str) -> Path` (creates the dir, writes the file, returns the file path); `plant_symlink(link: Path, target: Path) -> None` (creates a symlink `link -> target`, parents created); `init_git_repo_with_commit(repo: Path, commit_message: str) -> None` (runs `git init`, adds a seed file, commits with the given message so the log carries it). Use `subprocess.run` for git with an explicit env that sets author/committer identity so the commit succeeds in a bare CI environment.

3. `evals/cve_oracle.py`: the public pure detection surface (see "Detection semantics" for the rationale). Newspaper order:
   - `CVEStatus(StrEnum)`: `detected`, `reached_but_judged_pass`, `missed`, `missed_awaiting_capability`, `out_of_scope`, `not_run` (model it like `AuditCategory`/`EvalVerdict` in `domain/models.py`).
   - `TargetInfo(Protocol)`: the descriptive slice the oracle reads — `cve_id: str`, `severity: str`, `sentinel: str`, `blocker: str | None`, `note: str`. Structurally satisfied by `CVETarget` (Step 2); keeps this module importing nothing from `cve_targets`.
   - `RunDetection(BaseModel)`: one run's facts — `sentinel_surfaced: bool`, `sentinel_in_fail: bool`, `evidence: str | None`, `category: AuditCategory | None`.
   - `CVEResult(BaseModel)`: `cve_id: str`, `severity: str`, `note: str`, `status: CVEStatus`, `blocker: str | None`, `runs: int`, `hits: int`, `surfaced: int`, `budget: int`, `evidence: str | None`, `category: AuditCategory | None`.
   - `detect_in_report(target: TargetInfo, report: AuditReport) -> RunDetection`: scan `report.tool_reports`. For each `TestCase` with `eval_result` and each `AttackChain` with an `eval_result`, look for `target.sentinel` in the observed output. Observed output for a case = `case.response` (coerce a dict to text before the substring match, e.g. `str(response)` or JSON) plus `case.error`; for a chain = each `step.response` and `step.error` across `chain.steps`. Set `sentinel_surfaced` if the sentinel appears anywhere (any verdict), `sentinel_in_fail` if it appears in an output whose result verdict is `EvalVerdict.FAIL`. Credit is on the sentinel alone, not the category; `evidence`/`category` come from the matching (preferably FAIL) output. `target` is typed against the `TargetInfo` Protocol (above), not the concrete `CVETarget`, so this pure module imports nothing from `cve_targets` and stays buildable and testable in this step, before `cve_targets` exists.
   - `resolve_status(target: TargetInfo, detections: list[RunDetection], budget: int) -> CVEResult`: aggregate the `k` runs. `hits` = runs with `sentinel_in_fail`, `surfaced` = runs with `sentinel_surfaced`. Any `sentinel_in_fail` -> `detected`; else any `sentinel_surfaced` -> `reached_but_judged_pass`; else `blocker is None` -> `missed`; else -> `missed_awaiting_capability` (record `blocker`). Carry `runs`/`hits`/`surfaced`/`budget`, snapshot `severity`/`note`/`cve_id`/`blocker` from `target`, and keep a representative `evidence`/`category`, so the `CVEResult` is self-describing.
   - `not_run(target: TargetInfo) -> CVEResult`: public builder returning a `not_run` result (infra failure, not a detection miss).
   - `out_of_scope_results(cves) -> list[CVEResult]`: public builder mapping each `OUT_OF_SCOPE_CVES` entry (id, severity, reason) to an `out_of_scope` `CVEResult` (reason -> `note`, zeroed run counts), so the renderer counts them.
   - `render_markdown(results: list[CVEResult]) -> str`: pure string builder (no console printing). Markdown table columns: CVE id, CVSS/severity, status, hit-rate (`hits/runs`), budget, awaited capability (the blocker), one-line note. Detection count in a summary line. Because every `CVEResult` is self-describing (it carries its own `severity`/`note`), `render_markdown` and the JSON both take a flat `list[CVEResult]` — no zipping with targets, and `out_of_scope`/`not_run` rows render the same way as run targets.

**Test**:

- Seeding (`tests/unit/test_cve_seeding.py`, use `tmp_path`, assert on filesystem):
  - `make_dir_with_file` writes the file containing the sentinel content.
  - `plant_symlink` creates a link that resolves to the target path.
  - `init_git_repo_with_commit` produces a repo whose `git log` output contains the commit message sentinel.
- Detection oracle (`tests/unit/test_cve_oracle.py`, fake `AuditReport`s via `given`):
  - `detect_in_report`, FAIL case whose `response` contains the sentinel -> `sentinel_surfaced` and `sentinel_in_fail`; `evidence`/`category` populated.
  - FAIL case whose sentinel arrives via `.error` (response `None`) -> both true.
  - FAIL case whose `response` is a dict containing the sentinel -> both true.
  - FAIL chain whose `ChainStep.response` contains the sentinel -> both true.
  - PASS case whose `response` contains the sentinel -> `sentinel_surfaced` true, `sentinel_in_fail` false.
  - no sentinel -> both false.
  - `resolve_status`, any `sentinel_in_fail` -> `detected` with the right `hits`/`surfaced`/`runs`; detection@k any-hit (1 of 3 -> `detected`).
  - surfaced-only across all runs -> `reached_but_judged_pass` (regardless of blocker).
  - no surfacing, `blocker=None` -> `missed`; `blocker="cross-tool chains"` -> `missed_awaiting_capability`, `blocker` recorded.
  - `not_run(target)` -> status `not_run`; `out_of_scope_results` maps `OUT_OF_SCOPE_CVES` to `out_of_scope`.
- Report assembly: a list of `CVEResult` renders the markdown table with the right per-CVE status, hit-rate, budget, and awaited capability, and the detection count is correct.

**Verify**:

- `uv run pytest tests/unit/test_cve_seeding.py tests/unit/test_cve_oracle.py` — all new tests pass (confirm they were red before the production code existed).
- `uv run ruff check . && uv run ruff format --check . && uv run pyright` — clean.

### Step 2: Target definitions and the on-demand runner (I/O)

The composition layer: the four `CVETarget` definitions that seed each environment, and the runner that connects, audits, and writes the report. Pure-transformation logic already lives in step 1; this step is data + I/O orchestration, so it carries no new unit tests (mirroring `run_evals.py` being untested).

**Files**:

- `evals/cve_targets.py` (new)
- `evals/run_cve_benchmark.py` (new)
- `README.md` (modify: one scope-limitation bullet)

**Do**:

1. `evals/cve_targets.py`: the `Launch` and `CVETarget` frozen dataclasses exactly as sketched in "Files to add" (`Launch`: `command`, `args`, `chain_budget=0`, `max_chain_steps=3`; `CVETarget`: `cve_id`, `severity`, `sentinel`, `prepare: Callable[[Path], Launch]`, `blocker: str | None`, `note`, `tools_filter: frozenset[str] | None`). Then `CVE_TARGETS: list[CVETarget]` with the reference and third-party targets, each `prepare(root)` seeding a throwaway root via `cve_seeding` helpers and returning the pinned `Launch`:
   - **CVE-2025-53109** (detectable now, `blocker=None`, `tools_filter={filesystem read tool}`): create `root/sandbox`, create `root/outside/flag.txt` with a unique sentinel, plant symlink `root/sandbox/report -> root/outside/flag.txt`. Launch `npx` with args `["-y", "@modelcontextprotocol/server-filesystem@0.6.2", str(root/"sandbox")]`.
   - **CVE-2025-53110** (`blocker="declared-scope awareness"`, same tools_filter): create `root/sandbox` (allowed) and sibling `root/sandbox_secret/flag.txt` with its own sentinel. Same filesystem server launch on `root/sandbox`.
   - **CVE-2025-68145** (`blocker="declared-scope awareness"`, `tools_filter` narrowed to a git read tool such as `git_log`): `init_git_repo_with_commit(root/"repo", ...)` (allowed) and `init_git_repo_with_commit(root/"other", <sentinel commit message>)`. Launch `uvx` with args `["mcp-server-git@<pinned>", "--repository", str(root/"repo")]`.
   - **CVE-2025-68143** (`blocker="cross-tool chains + declared-scope awareness"`, `chain_budget` non-zero e.g. 3 with `max_chain_steps` 3-5, `tools_filter={"git_init","git_add", "git_diff_staged"}`): `init_git_repo_with_commit(root/"repo", ...)`, seed the sentinel as the content of an out-of-scope directory sibling/parent of the repo (reachable by traversal or scope-derivation). The exploit chain is `git_init(<out-of-scope dir>)` → `git_add(.)` → `git_diff_staged`. Same git launch. See "Sentinel reachability".
   - **Third-party bucket-A targets** (`blocker=None`, `tools_filter` narrowed to the vulnerable tool): the 2-3 confirmed in "Detectable-now third-party targets". Each `prepare` installs the pinned third-party server, seeds the sentinel the exploit surfaces (echoed command output, internal URL content, or out-of-scope file), and returns the `Launch`.
   - Confirm the exact installable pre-2025.9.25 `mcp-server-git` PyPI version at implementation (`pip index versions mcp-server-git` or PyPI); one pin is expected to cover both git CVEs, but each git target returns its own explicit pin so they can diverge without a harness change. Use a unique high-entropy sentinel per target (`secrets.token_hex`) to rule out coincidental credit.

2. `evals/run_cve_benchmark.py`: I/O runner mirroring `run_evals.py`, importing `detect_in_report`, `resolve_status`, `not_run`, `out_of_scope_results`, `render_markdown` from `cve_oracle` and `CVE_TARGETS`, `OUT_OF_SCOPE_CVES` from `cve_targets`. Structure:
   - `main()` with argparse `--budget` (default `CVE_TEST_BUDGET`), `--runs` (default `CVE_RUNS`), and `--report` path, `asyncio.run(run_cve_benchmark(budget, runs))`, then append the `out_of_scope` results built from `OUT_OF_SCOPE_CVES`, write the JSON report and the `render_markdown` string under `output/` (as `run_evals` writes its report), print a summary.
   - `async def run_cve_benchmark(budget, runs) -> list[CVEResult]`: loop over `CVE_TARGETS`; for each, run `k = runs` throwaway audits (`tempfile.TemporaryDirectory`, torn down after — including planted symlinks — even on failure), collecting a `RunDetection` per successful run. A run whose launch/install fails contributes no detection; if *every* run failed, append `not_run(target)`, else `resolve_status(target, detections, budget)`.
   - `_audit`: reuse the connect + `build_graph` + `ainvoke` block from `_run_single_honeypot` — `create_llm`/`create_judge_llm` from `Settings`, `StdioMCPClient.connect(launch.command, launch.args, errlog=devnull)`, `build_graph(llm, mcp_client, judge_llm=judge_llm, tools_filter=target.tools_filter)`, invoke with keys `target`, `test_budget=budget`, `attack_context=AttackContext()`, `chain_budget=launch.chain_budget`, `max_chain_steps=launch.max_chain_steps` (always present since `GraphState` declares it, even when `chain_budget` is 0), return `result["audit_report"]`. Catch launch/install exceptions here and raise a `LaunchError` the loop maps to a skipped run.

3. `evals/cve_targets.py` also defines `OUT_OF_SCOPE_CVES` (id, severity, reason), holding CVE-2025-68144. `main()` maps them through `out_of_scope_results` (step 1) into `CVEResult`s with `status=out_of_scope` and appends them to the results list, so `render_markdown` renders and counts them uniformly with the run targets. This tally is the gate signal ADR 011 watches.

4. `README.md`: add one bullet to the existing "Scope and limitations" section. Vulnerabilities whose only effect is a silent write, a spawned process, or out-of-band exfiltration are out of reach of the black-box tool, deferred to a future instrumented mode (link ADR 011). Static text, no run needed.

**Test**: no new unit tests (data + I/O composition). Detection, status, and rendering are already covered by step 1's tests.

**Verify**:

- `uv run ruff check . && uv run ruff format --check . && uv run pyright` — clean (strict mode; the runner and targets type-check).
- `uv run pytest tests/unit` — the full unit suite still passes.
- Do NOT run the real e2e benchmark (network, package installs, API key, LLM cost); that is the deliberately out-of-scope manual step in "Verification".
