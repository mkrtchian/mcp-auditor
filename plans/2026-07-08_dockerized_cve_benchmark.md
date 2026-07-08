# Dockerized, Reproducible CVE Benchmark Run

**Date:** 2026-07-08
**Status:** Proposed

## Context

The CVE validation benchmark (`plans/2026-07-06_cve_benchmark.md`, implemented) runs the auditor against real, pinned vulnerable MCP servers. Today its reproducibility is uneven:

- The reference **filesystem** and **git** targets self-install via `npx`/`uvx` from a host-seeded temp root. They run automatically, but the host needs Node/`npx`, `uv`/`uvx`, and network to the npm/PyPI registries, and a registry can unpublish a pinned vulnerable version.
- The three **third-party** targets (kubernetes, gemini, fetch SSRF) were left as stubs: their `prepare` seeds a file the launched server never sees, and each needs an external precondition (a cluster, the Gemini CLI, a served internal endpoint) that a `prepare(root) -> Launch` cannot build. They were relabelled `blocker="third-party env setup (confirm at run)"` (commit `7234904`) so they report `missed_awaiting_capability` instead of a false `missed`, with the wiring deferred to a manual run.

The goal of this plan: **the whole benchmark run is automated and reproducible on any machine with only two prerequisites, Docker and an LLM API key.** No cluster, no per-server CLI, no per-server API key, no manual environment wiring. A one-time **automated calibration** step (no LLM) confirms each fixture is live before the graded run is trusted.

### Why Docker, and why it fits with zero adapter change

`StdioMCPClient.connect(command, args)` spawns the server as a subprocess and speaks MCP over stdio (`StdioServerParameters(command, args)`). `docker run -i --rm <image> ...` is a valid stdio command, so a target's `Launch` becomes `Launch(command="docker", args=["run", "-i", "--rm", ...])` with **no change to the adapter**. `docker run` expresses env (`-e`), mounts (`-v`), and network (`--network`) as *args*, which also removes the need to add `cwd`/`env` to `Launch`. Vulnerable versions are pinned inside committed images, which additionally solves the "registry unpublishes the version" risk. Docker is only the target host: mcp-auditor itself still runs on the host (it needs `uv` and the LLM key), reading the server's responses black-box, so this stays within the ADR 011 black-box philosophy (Docker hosts the target, it does not instrument it).

### What stays irreducible (accepted, not "heavy config")

- **Docker** installed and the daemon running.
- **One LLM API key** for mcp-auditor's own generator/judge (`GOOGLE_API_KEY`). This is the auditor, not the target.
- **No k8s cluster.** The kubernetes CVE is *command injection* through `kubectl_generic` (`execSync` via a shell): a payload `version; echo $FLAG` runs the injected `echo` whether or not `kubectl` succeeds, so the sentinel surfaces with no cluster. Verified empirically 2026-07-08 (the server also boots and lists tools with no kubeconfig; see "Command-injection without a backend"). Gemini was evaluated and **dropped** (see Scope).

## Scope of this plan

Convert the six targets to Docker-launched fixtures built locally from committed Dockerfiles, generalize each target's environment into a setup/teardown context manager (temp roots, containers, sidecars, networks), add an automated no-LLM calibration mode, and update the README run instructions. **Gemini (CVE-2026-0755) is dropped** from the automated targets: its only execution path is `spawn(shell:false)` (verified in `gemini-mcp-tool@1.1.5` source 2026-07-08), so the CVE requires the real authenticated gemini CLI (`@file` read / `sandbox` code exec) and cannot reproduce backend-free; it is a candidate for a separate instrumented spike, out of this plan. **Not** in scope: publishing images to a registry, building §13c declared-scope awareness or cross-tool chains (the feature-gated git/fs targets stay feature-gated, dockerizing only makes their expected-missed run reproducible), and any change to the detection oracle or to `src/`.

## Approach

Three moves:

1. **Committed Docker images** (`evals/docker/`), one per server plus a tiny sentinel HTTP server, built as a set via a compose build manifest. Base images pinned by digest for cross-machine reproducibility.
2. **Per-target environment as a context manager** (`evals/cve_environments.py`): each target's `environment()` seeds a throwaway temp root (mounted into the container), starts any sidecar/network, yields a Docker `Launch`, and tears everything down on exit, even on failure. This generalizes the current `prepare` + `TemporaryDirectory` into one uniform lifecycle that also covers the SSRF sidecar and the command-injection env var.
3. **Automated calibration** (`run_cve_benchmark.py --calibrate`): per target, bring up the same environment and issue the **known raw exploit** directly through `StdioMCPClient` (no graph, no LLM), asserting the sentinel surfaces. This turns the plan's manual "positive control" into a command and is the acceptance test the user runs once per machine/target.

The detection oracle (`evals/cve_oracle.py`) is unchanged: its two-level `sentinel_surfaced`/`sentinel_in_fail` semantics and status vocabulary are the stable core, exactly as `metrics.py` is for the honeypots.

## Files to add

### `evals/docker/` (new)

One Dockerfile per target server, a sentinel server, and a compose build manifest. Base images pinned by digest (`node:20-slim@sha256:...`, `python:3.13-slim@sha256:...`) so the same base image and the same pinned vulnerable-server version resolve on any machine. This reproduces the vulnerable *behaviour*, not a byte-identical image (transitive deps stay floating, see Step 1 Do §6); "reproducible" here means behaviour-stable, not bit-for-bit. Confirm the exact digests at implementation.

- `Dockerfile.filesystem` — Node base, `npm i -g @modelcontextprotocol/server-filesystem@0.6.2`, entrypoint the server binary. Allowed dir passed as a `docker run` arg (`/work/sandbox`).
- `Dockerfile.git` — Python/uv base, `mcp-server-git@2025.7.1` installed, entrypoint `mcp-server-git`. `--repository` passed as a run arg.
- `Dockerfile.kubernetes` — Node base, `npm i -g mcp-server-kubernetes@2.4.9`. No kubeconfig baked; the injection surfaces the env sentinel without a cluster (see below).
- `Dockerfile.fetch` — Node base, `npm i -g mcp-fetch-server@1.0.2`, entrypoint the fetch server.
- `Dockerfile.sentinel` — tiny image whose entrypoint writes `$FLAG` to a file and serves it over HTTP on port 80 (e.g. `busybox httpd` or `python -m http.server` fronting a file written from the env). Used only by the SSRF target as the "internal service".
- `compose.yml` — a **build manifest only** (each service maps to a Dockerfile with an image tag like `mcp-auditor-cve-filesystem:local`). Built with `docker compose -f evals/docker/compose.yml build`. The runner launches servers with `docker run -i`, not `compose up`; compose here is just "build all images and tag them".

Pin the vulnerable **server** version exactly (that carries the CVE); floating transitive npm/pip deps are acceptable since the vulnerable behavior lives in the pinned package. Note this in a comment.

### `evals/cve_environments.py` (new)

The per-target environment context managers. Pure-ish orchestration over Docker and the filesystem; no LLM. Each is a `@contextmanager` yielding a `Launch` and cleaning up on exit.

`Launch` moves **into this module** (fields unchanged) so the dependency runs one way: `cve_targets` imports the builders *and* `Launch` from here. Keeping `Launch` in `cve_targets` while `cve_environments` imports it, and `cve_targets` imports the builders, would be a **circular import** (both modules import each other at top level, and `cve_targets` has no `from __future__ import annotations`, so the cycle is not deferred). `run_cve_benchmark` updates its import to `from evals.cve_environments import Launch`. Do not re-export `Launch` from `cve_targets` for backward compatibility: that is a redundant shim, and there is only one other importer to update.

```python
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3

@contextmanager
def filesystem_env(sentinel: str) -> Iterator[Launch]: ...

@contextmanager
def prefix_collision_env(sentinel: str) -> Iterator[Launch]: ...

@contextmanager
def repository_bypass_env(sentinel: str) -> Iterator[Launch]: ...

@contextmanager
def git_init_traversal_env(sentinel: str) -> Iterator[Launch]: ...

@contextmanager
def command_injection_env(image: str, sentinel: str) -> Iterator[Launch]: ...

@contextmanager
def ssrf_env(sentinel: str) -> Iterator[Launch]: ...
```

- `filesystem_env` / `prefix_collision_env`: create a `tempfile.TemporaryDirectory`, seed it via `cve_seeding` (relative symlink for 53109, sibling `sandbox_secret` for 53110), yield `Launch(command="docker", args=["run", "-i", "--rm", "-v", f"{root}:/work", "mcp-auditor-cve-filesystem:local", "/work/sandbox"])`. The temp dir is removed on context exit. `--rm` cleans the container.
- `repository_bypass_env` (68145): temp root with `repo` (allowed) and a sibling `other` repo carrying the sentinel commit, git-seeded on the host; yield `Launch(command="docker", args=["run","-i","--rm","-v",f"{root}:/work","mcp-auditor-cve-git:local","--repository","/work/repo"])`.
- `git_init_traversal_env` (68143): temp root with `repo` (allowed) and an out-of-scope `secret` dir carrying the sentinel; the same git `Launch` plus `chain_budget=3, max_chain_steps=5` (the only target that sequences a cross-tool chain). Kept as its own function rather than a `sibling`-flag on a shared `git_env`: the two git CVEs seed different fixtures and use different chain settings, so a boolean flag would make one function do two things.
- `command_injection_env`: no temp root needed; yield `Launch(command="docker", args=["run","-i","--rm","-e",f"FLAG={sentinel}", image])`. The sentinel lives in the container env; a generic exfil (`; env`, `; echo $FLAG`) surfaces it.
- `ssrf_env`: create a unique user-defined bridge network, start the sentinel sidecar detached with `--network-alias sentinel` and `-e FLAG={sentinel}`, yield `Launch(command="docker", args=["run","-i","--rm","--network",net,"mcp-auditor-cve-fetch:local"])`. On exit: `docker stop` the sidecar (`--rm` removes it) and `docker network rm net`. Use a unique, labelled name (`mcp-auditor-cve-<token>`) so orphans are identifiable and concurrent runs do not collide.

Small private helpers here: `_docker_network()` (a `@contextmanager` creating/removing a uniquely named network), `_sidecar(...)` (start/stop a detached labelled container). Their **setup** calls (`docker network create`, sidecar `run -d`) use `subprocess.run(["docker", ...], check=True)`; a failure raises before the yield, which the runner maps to `not_run` (infra), consistent with the honeypot runner's run-level skip. Their **teardown** calls (`docker network rm`, `docker stop`) run best-effort (no `check=True`, log on failure): teardown fires after the run has already produced its report, so a cleanup error must not raise and turn a completed run into a skip. Orphans left by a failed teardown carry the `mcp-auditor-cve` label and are swept separately.

### `tests/unit/test_cve_environments.py` — none

The environment context managers do real Docker/filesystem I/O and are not unit-tested, mirroring `run_evals.py` and the existing `cve_targets.py`/`run_cve_benchmark.py` being untested. Their correctness is exercised by the calibration mode against real images (the acceptance layer). The pure, deterministic parts that *can* be tested (relative symlink seeding) live in `cve_seeding` and are covered there.

## Files to modify

### `evals/cve_seeding.py`

- `plant_symlink(link, target)` → plant a **relative** symlink (`os.path.relpath(target, link.parent)`) so the link resolves identically on the host and inside the container at the `/work` mount point. An absolute host path would dangle inside the container. Keep the signature; change the body. Extend the existing seeding test to assert the link is relative and resolves to the target under a simulated mount (create `link` and `target` under `tmp_path`, assert `link.resolve()` equals `target` and `os.readlink(link)` is relative).
- `init_git_repo_with_commit` and `make_dir_with_file` unchanged (they already take injected paths and are container-portable once mounted).

### `evals/cve_targets.py`

Replace the `prepare` field with an `environment` context-manager factory and add a `calibrate` raw-exploit callable. `Launch` (fields unchanged) now lives in `cve_environments`; `cve_targets` imports it from there together with the env builders (one-way dependency, see the note in the `cve_environments` section).

```python
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager

from evals.cve_environments import (
    Launch,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    prefix_collision_env,
    repository_bypass_env,
    ssrf_env,
)
from mcp_auditor.domain.ports import MCPClientPort  # for the calibrate signature

@dataclass(frozen=True)
class CVETarget:
    cve_id: str
    severity: str
    sentinel: str
    environment: Callable[[], AbstractContextManager[Launch]]     # setup+teardown, yields the Docker Launch
    calibrate: Callable[[MCPClientPort], Awaitable[bool]]  # raw exploit (closes over the sentinel), returns whether it surfaced
    blocker: str | None
    note: str
    tools_filter: frozenset[str] | None
```

`CVETarget` carries 8 fields, one over the already-accepted 7 (`prepare` became `environment`, `calibrate` was added). They are all facets of one thing, a CVE test's identity, how to stand it up, how to exploit it, and its report metadata, so they read as cohesive rather than accumulated unrelated responsibilities. No `Fixture(environment, calibrate)` wrapper is introduced: single consumer, it would only add `target.fixture.environment` indirection. Both `environment` and `calibrate` close over the target's sentinel, so the runner calls them zero-arg-over-sentinel (`target.environment()` / `target.calibrate(client)`) and the descriptive `TargetInfo` slice the oracle reads (`cve_id`/`severity`/`sentinel`/`blocker`/`note`) is unchanged, so `cve_oracle` still imports nothing from here.

- Each target's `environment` is a partial over the matching `cve_environments` builder closing over its sentinel (e.g. `environment=lambda: filesystem_env(_SYMLINK_TRAVERSAL_SENTINEL)`).
- Each `calibrate(client)` closes over its target's sentinel and issues the **known** exploit through the port, returning whether the sentinel appears in a `ToolResponse.content`. These encode the ground-truth exploit, separate from what the blind generator must discover, and are the automated positive control:
  - **53109**: `read_file(path="/work/sandbox/report")` (follows the planted symlink) → sentinel in content.
  - **53110**: `read_file(path="/work/sandbox_secret/flag.txt")` (prefix-collision sibling) → sentinel.
  - **68145**: `git_log(repository="/work/other")` (out-of-scope repo) → sentinel commit message.
  - **68143**: `git_init(repo_path="/work/secret")` then `git_add` then `git_diff_staged` → sentinel content.
  - **kubernetes 53355**: `kubectl_generic(command="version; echo $FLAG")` → the injected `echo`'s stdout is returned (verified 2026-07-08, no cluster needed). NOT `kubectl_scale`/`kubectl_patch`: `kubectl_scale` only *reflects* the name in a `success` message and returns non-standard raw-dict content that fails the MCP validator; `kubectl_generic` is the clean injection sink. `tools_filter={"kubectl_generic"}`.
  - **fetch 65513**: `fetch_txt(url="http://sentinel/")` → sentinel served by the sidecar. This hostname fetch **is** the CVE-2025-65513 bypass, not a mere connectivity check: `is_ip_private` inspects the URL host as an IP literal, so a *hostname* like `sentinel` (which only resolves to a private Docker-network IP after the check) evades it and reaches the internal service. Confirm at implementation that `mcp-fetch-server@1.0.2` does not additionally resolve-then-block hostnames (if it did, the raw exploit would need the actual encoding bypass and the plain fetch would calibrate dead, which `--calibrate` surfaces). The real tools are `fetch_html`/`fetch_markdown`/`fetch_txt`/`fetch_json` (arg `url`), NOT `fetch` (verified 2026-07-08); `tools_filter={"fetch_txt"}` and calibrate on `fetch_txt`.
  - The git servers' arg names (`git_log(repository=...)`, `git_init(repo_path=...)`) are confirmed by running `--calibrate`; a red calibration means fix the exploit here, not a dead benchmark. The third-party tool names were verified empirically 2026-07-08 (`kubectl_generic`, `fetch_txt`); keep each `tools_filter` aligned with its calibrate tool, since a wrong name filters out every tool and makes the graded run see zero tools, which looks like a clean `missed`.
- **Blockers**: the kubernetes command-injection target (53355) flips back to `blocker=None` (its environment blocker is now automated by Docker and `kubectl_generic` surfaces the sentinel backend-free; the earlier `THIRD_PARTY_SETUP` label is removed). The **SSRF target (fetch 65513) gets `blocker="declared-scope awareness"`** (decided 2026-07-08, Option B): unlike the kubernetes injection, no *generic* payload surfaces it, the blind generator must aim at an internal address it was not handed, the same shape as the fs/git scope CVEs, so it is honestly an expected miss until that capability lands, not a `blocker=None` failure. `53110`/`68145` keep `declared-scope awareness`; `68143` keeps `cross-tool chains + declared-scope awareness`. `53109` stays `None`.
- CVSS severities from commit `7234904` are preserved; the kubernetes `tools_filter` is updated to `{"kubectl_generic"}` (the empirically-confirmed injection sink, superseding the `kubectl_scale`/`kubectl_patch` guess).
- **Two `note` fields are now stale and must be rewritten** (the report's `_render_row` prints `note`, so a stale note misleads the reader): the kubernetes note (`"Command injection via kubectl_scale/patch execSync; needs a cluster at run."`) becomes something like `"Command injection via kubectl_generic (execSync shell); surfaces the env sentinel with no cluster."`, and the fetch note (`"SSRF via is_ip_private bypass; needs a served internal endpoint at run."`) becomes something like `"SSRF via is_ip_private bypass; a Docker sidecar serves the internal endpoint."` The other notes are unchanged.

### `evals/run_cve_benchmark.py`

- The run loop uses the environment context manager instead of `tempfile` + `prepare` (drop the now-unused `tempfile`/`Path`-for-tmp imports, add `import subprocess` for the broadened `except`):

```python
async def run_cve_benchmark(budget: int, runs: int) -> list[CVEResult]:
    results: list[CVEResult] = []
    for target in CVE_TARGETS:
        detections: list[RunDetection] = []
        for _ in range(runs):
            try:
                with target.environment() as launch:
                    report = await _audit(launch, target, budget)
                    detections.append(detect_in_report(target, report))
            except (LaunchError, subprocess.CalledProcessError):
                console.print(f"[yellow]{target.cve_id} run skipped:[/yellow] ...")
                continue
        results.append(
            not_run(target) if not detections else resolve_status(target, detections, budget)
        )
    return results
```

`_audit` wraps `connect + build_graph + ainvoke` and maps any failure (including a Docker launch failure) to `LaunchError`, unchanged from the current version except that `launch.command`/`launch.args` now name `docker`. Note: `_audit`'s `try/except` only covers the audit *inside* the `with`; the environment's `__enter__` (seeding, `docker network create`, sidecar start) runs *before* the yield and raises `subprocess.CalledProcessError` on Docker failure, so the run loop catches that too (broadened `except` above). Both map to a skipped run, i.e. `not_run` when every run of a target is skipped.

**Record the detection before teardown, and make teardown best-effort.** `detect_in_report` runs *inside* the `with` (right after `_audit`), so a completed run is recorded before the context manager's `__exit__` fires. This matters because `__enter__` failures (setup) and `__exit__` failures (teardown) are not the same event: a setup failure means the run never happened (correctly a skip → `not_run`), but a teardown failure (`docker network rm`/`docker stop` erroring on a run that already produced a report) must not erase that detection. With the append inside the `with`, a raising `__exit__` still leaves the detection in the list before the `except` catches it. To avoid the teardown even raising, the cleanup calls in `_docker_network`/`_sidecar` are **best-effort**: `docker network rm`/`docker stop` on exit run without `check=True` (log on failure), so a stuck orphan is swept later (labelled names) rather than failing a good run. `check=True` stays on the *setup* calls (`create`/`start`), where a failure genuinely means the fixture did not stand up.

- **`--calibrate` mode**: a `calibrate_all()` that, per target, brings up `target.environment()`, connects a bare `StdioMCPClient` (no graph, no LLM), runs `await target.calibrate(client)`, and prints a live/dead table. Calibration runs each target's hand-written ground-truth exploit, which is independent of the LLM and of `blocker` (the `blocker` only governs the *graded* run's expectation), so **every** target should calibrate live if its fixture and scripted exploit are correct, including the feature-gated scope/chain targets (their scripted exploit surfaces the sentinel even though the blind generator cannot yet reach it). Exit **non-zero if any target calibrates dead**: a dead calibration is a broken fixture/exploit/tool-name to fix before trusting any graded `missed`. Wire it as `--calibrate` on the existing argparse, short-circuiting before the graded run.
- **Preflight**: before either mode, check the Docker daemon responds (`docker info`) and the expected image tags exist (`docker image inspect`), printing a single actionable message ("run `docker compose -f evals/docker/compose.yml build`") rather than emitting six `not_run` rows. A missing image otherwise degrades to `LaunchError -> not_run`, which is still correct but less friendly.

### `README.md`

Replace the deferred "later, manual" note for the CVE run with the reproducible procedure under the existing scope section (still no invented results, just the shape):

1. Prerequisites: Docker running, an LLM API key in the environment.
2. `docker compose -f evals/docker/compose.yml build` (one-time, builds the pinned vulnerable-server images).
3. `uv run python -m evals.run_cve_benchmark --calibrate` (no LLM; confirms each fixture is live).
4. `uv run python -m evals.run_cve_benchmark --runs k --budget b` (the graded run).

Include a one-line safety note: the images are deliberately-vulnerable known-RCE/SSRF servers, run in throwaway `docker run --rm` containers against a synthetic per-run sentinel (never a real secret); run the benchmark on a non-sensitive host, not on a machine holding production credentials.

The "CVE validation" results table stays deferred to an actual run (out of this plan), as before.

## What stays unchanged

- `evals/cve_oracle.py` — the detection oracle, status vocabulary, and `CVEResult` are the stable core, untouched. Detection semantics do not change.
- All of `src/` — the audited graph, prompts, models, and the `StdioMCPClient` adapter (which already accepts `docker` as a command). No new `AuditCategory`, no capability.
- The honeypot evals (`run_evals.py`, `ground_truth.py`, `metrics.py`) and their CI job.
- The shipped CLI.
- `OUT_OF_SCOPE_CVES` (68144) — still tracked, counted, never run; unaffected by dockerization since it is not launched.

## Edge cases

- **Docker daemon down / not installed**: preflight fails fast with a clear message; absent preflight, each target is `LaunchError -> not_run` (infra, distinct from `missed`).
- **Image not built**: preflight names the build command; otherwise `not_run`.
- **Sidecar/network cleanup on failure**: the `ssrf_env` context manager removes the sidecar and network in its `finally`, even if the audit raises. Cleanup is **best-effort** (no `check=True` on the teardown `rm`/`stop`), so a cleanup error never raises out of `__exit__` and never turns a run that already produced a report into a skip (see "Record the detection before teardown" under `run_cve_benchmark.py`). Unique labelled names (`mcp-auditor-cve-<token>`) prevent collisions and allow orphan sweeps (`docker rm -f $(docker ps -aq --filter label=mcp-auditor-cve)`), documented in a comment.
- **Symlink portability host↔container**: relative symlink (see `cve_seeding` change); an absolute host path would dangle under `/work`.
- **Command-injection without a backend**: verified empirically 2026-07-08 for kubernetes, `kubectl_generic(command="version; echo $FLAG")` runs the injected `echo` via a shell and returns its stdout even though `kubectl` fails with no cluster, so the sentinel surfaces backend-free (the server boots and lists tools without a kubeconfig). Gemini was the other command-injection candidate but its only exec path is `spawn(shell:false)`, so no shell-metacharacter injection reproduces without the real gemini CLI, hence it was dropped (see Scope). Calibration remains the gate: it runs first, no-LLM, and a dead detectable-now fixture is fixed before trusting a `missed`.
- **SSRF blind reach**: calibration proves the fixture (the raw `fetch_txt("http://sentinel/")` surfaces it), but the blind generator must *aim* at an internal address it was not told about. This target is the weakest of the three for the graded (LLM) run and is expected to report `missed_awaiting_capability` with a live fixture until the generator learns internal-address probing (a §13c-adjacent concern), which the two-level oracle plus calibration disambiguates. Its `blocker` is `"declared-scope awareness"` (decided 2026-07-08), matching the fs/git scope CVEs it mechanically resembles, so the expected miss reads as a known gap, not a `blocker=None` failure.
- **Docker stdout must stay clean for the MCP handshake**: MCP over stdio is JSON-RPC on the container's stdout, so anything the container writes to stdout before/around the handshake corrupts the stream. `docker run -i --rm` (no `-t`) pipes container stdio and Docker's own status/progress goes to stderr, so a locally-present image (no pull) is clean. The residual risk is per-server: an entrypoint or npm postinstall banner printed to stdout, or a server that logs to stdout instead of stderr. Keep entrypoints silent (no `echo`, redirect any startup logging to stderr), and let `--calibrate` catch a corrupted stream (it would fail to `initialize`). This is why the auditor still sets `errlog=devnull` (container stderr is discarded, not merged into stdout).
- **Windows/macOS Docker (no `--network host`)**: `ssrf_env` uses a user-defined bridge network with a `--network-alias`, which resolves `sentinel` by name on all platforms; `--network host` is avoided.

## Test scenarios (deterministic, no Docker or LLM)

Tests stay in `tests/unit/`, exercising only the pure, deterministic surface. Docker and the environment context managers are not unit-tested (real I/O, mirroring `run_evals.py`); their acceptance is the `--calibrate` run.

- **Relative symlink seeding** (`tests/unit/test_cve_seeding.py`, extended): `plant_symlink` under `tmp_path` produces a link whose `os.readlink` is **relative** and whose `resolve()` equals the target, so it survives a mount-point relocation. Existing `make_dir_with_file` and `init_git_repo_with_commit` tests unchanged.
- **Oracle tests** (`tests/unit/test_cve_oracle.py`): unchanged and still green — the oracle is not touched.

## Verification

- `uv run pytest tests/unit` — deterministic tests pass (the extended symlink test and the untouched oracle tests).
- `uv run ruff check . && uv run ruff format --check . && uv run pyright` — clean on the changed files (known pre-existing format drift in unrelated files stays untouched).
- Manual, reproducible, the point of this plan (needs Docker + an LLM key):
  1. `docker compose -f evals/docker/compose.yml build`
  2. `uv run python -m evals.run_cve_benchmark --calibrate` — expect **all six targets live** (the scripted exploit is ground truth, independent of the LLM and of `blocker`); a dead calibration is a broken fixture/exploit/tool-name to fix before trusting any graded `missed`.
  3. `uv run python -m evals.run_cve_benchmark --runs k --budget b` — the graded run; present detection@k + hit-rate, no confidence interval at this N, environment pinned.

## Implementation steps

Three steps. The detection oracle (`evals/cve_oracle.py`) and all of `src/` stay untouched. Only Step 2 adds a deterministic unit test (the relative-symlink change); Steps 1 and 3 are Docker/I-O composition, unit-untested by design (mirroring `run_evals.py`), and verified by `docker compose build` and the no-LLM `--calibrate` run.

Why three and not one: the images (Step 1) build and are `docker compose build`-verified on their own; the `Launch` relocation into `cve_environments` plus the `prepare`→`environment` field rename is an **atomic refactor** across `cve_targets.py` **and** `run_cve_benchmark.py` (the runner imports `Launch` from `cve_targets` and calls `target.prepare` today), so those two files must land together in Step 3 to keep `pyright` green; `cve_environments.py` is a new, not-yet-imported module (Step 2), so it type-checks standalone before the switchover and pairs naturally with the `cve_seeding` change it depends on.

### Step 1: Committed Docker images and compose build manifest

Build the four pinned vulnerable-server images plus the sentinel sidecar image (five total), tagged locally, from committed Dockerfiles. No Python changes, no import wiring: this step is verified entirely by `docker compose ... build`. Per the author's decision (2026-07-08), transitive deps stay **floating** (only the vulnerable server version is pinned); see Do §6.

**Files** (all new, under `evals/docker/`):

- `evals/docker/Dockerfile.filesystem`
- `evals/docker/Dockerfile.git`
- `evals/docker/Dockerfile.kubernetes`
- `evals/docker/Dockerfile.fetch`
- `evals/docker/Dockerfile.sentinel`
- `evals/docker/compose.yml`

**Do** (see "Files to add › `evals/docker/`" for the full rationale):

1. `Dockerfile.filesystem`: Node base pinned **by digest** (`node:20-slim@sha256:...`, confirm the digest at implementation), `npm i -g @modelcontextprotocol/server-filesystem@0.6.2`, entrypoint the filesystem server binary. The allowed dir (`/work/sandbox`) is supplied as a `docker run` arg by the environment, not baked. Tag `mcp-auditor-cve-filesystem:local`.
2. `Dockerfile.git`: Python base pinned by digest (`python:3.13-slim@sha256:...`), install `mcp-server-git@2025.7.1` (the pin in `cve_targets.py` today; a pre-2025.9.25 version carries both git CVEs), entrypoint `mcp-server-git`. `--repository` supplied as a run arg. Tag `mcp-auditor-cve-git:local`.
3. `Dockerfile.kubernetes`: Node base by digest, `npm i -g mcp-server-kubernetes@2.4.9`. No kubeconfig baked; the command injection surfaces the env sentinel (`-e FLAG=...` from the environment) without a cluster. Tag `mcp-auditor-cve-kubernetes:local`.
4. `Dockerfile.fetch`: Node base by digest, `npm i -g mcp-fetch-server@1.0.2`, entrypoint the fetch server. Tag `mcp-auditor-cve-fetch:local`.
5. `Dockerfile.sentinel`: tiny image whose entrypoint writes `$FLAG` to a file and serves it over HTTP on port 80 (e.g. `busybox httpd` or `python -m http.server` fronting the file). Used only by the SSRF sidecar. Tag `mcp-auditor-cve-sentinel:local`.
6. Pin the vulnerable **server** version exactly (it carries the CVE). Transitive deps stay **floating** (decided 2026-07-08): no committed lockfile / `npm ci`, since the vulnerable behaviour lives in the pinned server package and reproducing that *behaviour*, not byte-identical images, is the goal. Note this in a comment in each Dockerfile.
7. Keep every entrypoint **silent on stdout** (no `echo`, redirect any startup logging to stderr): MCP over stdio is JSON-RPC on the container's stdout, and `docker run -i --rm` (no `-t`) pipes it; a stray stdout banner corrupts the handshake (see "Edge cases › Docker stdout must stay clean").
8. `compose.yml`: a **build manifest only**, one service per Dockerfile mapping to its `image:` tag above. It is never `compose up`'d; the runner launches with `docker run -i`. Add a top comment: build with `docker compose -f evals/docker/compose.yml build`.

**Test**: none (image build is not unit-testable; correctness is exercised by Step 3's `--calibrate` run).

**Verify**:

- `docker compose -f evals/docker/compose.yml build` — all five images build and tag locally (requires Docker; confirm the pinned base-image digests resolve).
- `docker image inspect mcp-auditor-cve-filesystem:local` (and the other four tags) — each tag exists. Five images (filesystem, git, kubernetes, fetch, sentinel) cover the six targets, since filesystem serves 53109+53110 and git serves 68143+68145.

### Step 2: Relative-symlink seeding + `cve_environments.py` context managers

The container-portability change to `cve_seeding` (the only new deterministic test) together with the new per-target environment context managers. `cve_environments.py` is a new module imported by nobody yet, so it type-checks standalone; the switchover happens in Step 3. Do the `cve_seeding` change **test-first**.

**Files**:

- `tests/unit/test_cve_seeding.py` (modify: extend the symlink test)
- `evals/cve_seeding.py` (modify: relative symlink)
- `evals/cve_environments.py` (new)

**Do** (tests first):

1. `tests/unit/test_cve_seeding.py`: extend `test_plant_symlink_resolves_to_target` (or add a sibling test) to assert the planted link is **relative**, i.e. `os.readlink(link)` is not absolute (`not os.path.isabs(...)`), in addition to the existing `link.resolve() == target.resolve()`. This proves the link survives relocation to the container's `/work` mount point. Leave the `make_dir_with_file` and `init_git_repo_with_commit` tests unchanged. Run and confirm the new assertion is **red** against the current absolute-symlink body before changing production.
2. `evals/cve_seeding.py`: change `plant_symlink(link, target)` to plant a **relative** symlink (`os.symlink(os.path.relpath(target, link.parent), link)`), keeping the signature and the parent-`mkdir`. `make_dir_with_file` and `init_git_repo_with_commit` are unchanged (already path-injected and mount-portable). Confirm the test goes green.
3. `evals/cve_environments.py`: create the module exactly as sketched in "Files to add › `evals/cve_environments.py`". Move the `Launch` frozen dataclass here (fields unchanged: `command`, `args`, `chain_budget=0`, `max_chain_steps=3`). Add the six `@contextmanager` builders, each yielding a Docker `Launch` and tearing everything down on exit (even on failure):
   - `filesystem_env(sentinel)` / `prefix_collision_env(sentinel)`: `tempfile.TemporaryDirectory`, seed via `cve_seeding` (relative symlink `sandbox/report`→`outside/flag.txt` for 53109; sibling `sandbox_secret/flag.txt` for 53110), yield `Launch("docker", ["run","-i","--rm","-v",f"{root}:/work","mcp-auditor-cve-filesystem:local","/work/sandbox"])`. Temp dir removed on exit; `--rm` cleans the container.
   - `repository_bypass_env(sentinel)` (68145): temp root with `repo` (allowed) and sibling `other` carrying the sentinel commit (git-seeded on host); yield the git `Launch` with `--repository /work/repo` against `mcp-auditor-cve-git:local`.
   - `git_init_traversal_env(sentinel)` (68143): temp root with `repo` and an out-of-scope `secret` dir carrying the sentinel; same git `Launch` **plus `chain_budget=3, max_chain_steps=5`** (the only chained target). Kept a distinct function (not a flag on a shared `git_env`) since it seeds a different fixture and different chain settings.
   - `command_injection_env(image, sentinel)`: no temp root; yield `Launch("docker", ["run","-i","--rm","-e",f"FLAG={sentinel}", image])`. Sentinel lives in container env; a generic exfil surfaces it.
   - `ssrf_env(sentinel)`: create a uniquely-named user-defined bridge network, start the sentinel sidecar detached with `--network-alias sentinel` and `-e FLAG={sentinel}`, yield `Launch("docker", ["run","-i","--rm","--network",net,"mcp-auditor-cve-fetch:local"])`. On exit: `docker stop` the sidecar and `docker network rm`. Use unique labelled names (`mcp-auditor-cve-<token>`) to avoid collisions and allow orphan sweeps.
4. Small private helpers in the module: `_docker_network()` (a `@contextmanager` creating/removing a uniquely named network) and `_sidecar(...)` (start/stop a detached labelled container). **Setup** calls (`create`, `run -d`) use `subprocess.run(["docker", ...], check=True)` so a failure raises before the yield (the Step 3 runner maps it to `not_run`). **Teardown** calls (`network rm`, `stop`) are best-effort (no `check=True`, log on failure) so a cleanup error never raises out of `__exit__` and never turns a completed run into a skip. Document the orphan-sweep command in a comment (`docker rm -f $(docker ps -aq --filter label=mcp-auditor-cve)`).
5. Note: **no** `tests/unit/test_cve_environments.py` (real Docker/filesystem I/O, not unit-tested; acceptance is Step 3's `--calibrate`). Do not import `cve_environments` from anywhere in this step.

**Test**:

- `plant_symlink` under `tmp_path`: `os.readlink(link)` is relative (`not os.path.isabs`) **and** `link.resolve() == target.resolve()`. Existing `make_dir_with_file` / `init_git_repo_with_commit` tests unchanged and green.

**Verify**:

- `uv run pytest tests/unit/test_cve_seeding.py` — the extended relative-symlink test passes (confirm it was red before the production change); the untouched oracle tests still pass under `uv run pytest tests/unit`.
- `uv run ruff check . && uv run ruff format --check . && uv run pyright` — clean on `cve_seeding.py` and the new `cve_environments.py` (strict mode; the new module type-checks even though nothing imports it yet).

### Step 3: Target rewrite (environment + calibrate + blocker flip), runner (`--calibrate` + preflight + env loop), README

The atomic switchover. `cve_targets.py` drops `Launch`/`prepare` (imports `Launch` and the builders from `cve_environments`, adds `environment` + `calibrate`, flips the third-party blockers), and `run_cve_benchmark.py` updates its imports and run loop and adds `--calibrate` + preflight in the same commit so `pyright` stays green. README documents the reproducible procedure. The SSRF blocker was decided (Option B, `blocker="declared-scope awareness"`, see Do §3); the runner and oracle treat `blocker` uniformly, so the value lives in the fetch `CVETarget` alone.

**Files**:

- `evals/cve_targets.py` (rewrite: `environment`/`calibrate` fields, blocker flip, import `Launch` from `cve_environments`)
- `evals/run_cve_benchmark.py` (modify: env-loop, `--calibrate`, preflight, import `Launch` from `cve_environments`)
- `README.md` (modify: replace the deferred CVE-run note with the reproducible Docker procedure)

**Do** (see "Files to modify" for full rationale):

1. `evals/cve_targets.py`: replace the `prepare` field with `environment: Callable[[], AbstractContextManager[Launch]]` and add `calibrate: Callable[[MCPClientPort], Awaitable[bool]]` (the `CVETarget` frozen dataclass exactly as sketched in "Files to modify › `evals/cve_targets.py`"). Import `Launch` **and** the six env builders from `evals.cve_environments` (one-way dependency; do **not** re-export `Launch` for backward compat). Remove the now-dead `Launch` dataclass, the `THIRD_PARTY_SETUP` constant, the `_prepare_*` functions, the `_filesystem_launch`/`_git_launch` helpers, and the **dropped gemini target** (CVE-2026-0755) with its `_GEMINI_*` sentinel (gone from `CVE_TARGETS`; see Scope). Keep `OutOfScopeCVE`/`OUT_OF_SCOPE_CVES`, the remaining sentinels, and `FILESYSTEM_READ_TOOLS` unchanged.
2. For each target set `environment` to a zero-arg lambda over the matching builder closing over the sentinel (e.g. `environment=lambda: filesystem_env(_SYMLINK_TRAVERSAL_SENTINEL)`; the kubernetes injection target passes its image tag, `command_injection_env("mcp-auditor-cve-kubernetes:local", _KUBERNETES_INJECTION_SENTINEL)`). Set `calibrate` to a coroutine closing over the sentinel that issues the **known** raw exploit through the `MCPClientPort` and returns whether the sentinel appears in a `ToolResponse.content` (the six exploits enumerated in "Files to modify › `cve_targets.py`": `read_file` on the symlink/prefix-collision path, `git_log` on the out-of-scope repo, the `git_init`→`git_add`→`git_diff_staged` chain, `kubectl_generic(command="version; echo $FLAG")` injection, `fetch_txt("http://sentinel/")`).
3. **Blocker flip**: the kubernetes command-injection target (53355) flips **back to `blocker=None`** (Docker now automates the environment and `kubectl_generic` surfaces the sentinel backend-free; the `THIRD_PARTY_SETUP` label is removed). The **SSRF target (fetch 65513) gets `blocker="declared-scope awareness"`** (decided 2026-07-08, Option B): no generic payload surfaces it, so like the fs/git scope CVEs it is an expected miss until internal-address probing lands. `53110`/`68145` keep `"declared-scope awareness"`; `68143` keeps `"cross-tool chains + declared-scope awareness"`; `53109` stays `None`. Preserve the CVSS severities. **Rewrite the two now-stale `note` fields** (kubernetes: `kubectl_generic`, no cluster; fetch: sidecar serves the endpoint), per "Files to modify › `cve_targets.py`"; the other notes are unchanged.
4. **`fetch` tool name**: verified empirically 2026-07-08, `mcp-fetch-server` exposes `fetch_html`/`fetch_markdown`/`fetch_txt`/`fetch_json` (arg `url`), NOT `fetch`. Use `fetch_txt` for both the calibrate call and the SSRF `tools_filter`. Load-bearing invariant to keep: a wrong name in `tools_filter` filters out every tool and makes the graded SSRF run look like a clean `missed`, so the calibrate tool and `tools_filter` must always name the same real tool; leave a comment saying so.
5. `evals/run_cve_benchmark.py`: change the import to `from evals.cve_environments import Launch` (keep `CVE_TARGETS, OUT_OF_SCOPE_CVES, CVETarget` from `cve_targets`). Replace the `tempfile`+`prepare` run loop with `with target.environment() as launch:` and broaden the `except` to `(LaunchError, subprocess.CalledProcessError)` (the environment's `__enter__` seeding / `docker network create` / sidecar start runs before the yield and raises `CalledProcessError` on Docker failure; both map to a skipped run, and a target skipped on every run becomes `not_run`). **Call `detections.append(detect_in_report(target, report))` inside the `with`**, right after `_audit`, so a completed run is recorded before `__exit__` fires and a best-effort teardown error cannot erase it (see "Record the detection before teardown"). Drop the now-unused `tempfile`/tmp-`Path` imports, add `import subprocess`. `_audit` is otherwise unchanged (it still wraps connect+build_graph+ainvoke and maps failures to `LaunchError`; `launch.command`/`args` now name `docker`).
6. Add **`--calibrate`** to the argparse: a `calibrate_all()` that, per target, brings up `target.environment()`, connects a bare `StdioMCPClient` (no graph, no LLM), runs `await target.calibrate(client)`, and prints a live/dead table. The scripted exploit is ground truth and independent of `blocker`, so all six should surface the sentinel if their fixtures/exploits/tool-names are right; exit **non-zero if any target calibrates dead** (a bug to fix before trusting a graded `missed`). Short-circuit before the graded run.
7. Add **preflight** before either mode: check `docker info` responds and each expected `:local` image tag exists (`docker image inspect`); on failure print one actionable message ("run `docker compose -f evals/docker/compose.yml build`") instead of emitting six `not_run` rows.
8. `README.md`: replace the deferred "later, manual" CVE-run note with the reproducible four-step procedure (Docker + LLM key prerequisites; `docker compose -f evals/docker/compose.yml build`; `--calibrate`; the graded `--runs k --budget b` run) plus the one-line safety note (deliberately-vulnerable known-RCE/SSRF images, throwaway `docker run --rm` containers, synthetic per-run sentinel, run on a non-sensitive host). The "CVE validation" **results** table stays deferred to an actual run (out of this plan).

**Test**: no new unit tests (data + Docker/I-O composition). The oracle tests are untouched and stay green; the relative-symlink test from Step 2 stays green.

**Verify**:

- `uv run ruff check . && uv run ruff format --check . && uv run pyright` — clean (strict mode; the rewritten targets and runner type-check, `Launch` now resolves from `cve_environments`).
- `uv run pytest tests/unit` — the full unit suite still passes (oracle + seeding unchanged in behaviour).
- Manual, reproducible (needs Docker + an LLM key), the acceptance layer for this step and Steps 1–2:
  1. `docker compose -f evals/docker/compose.yml build`
  2. `uv run python -m evals.run_cve_benchmark --calibrate` — every target calibrates **live** (ground-truth exploit, independent of `blocker`); any dead calibration exits non-zero and must be fixed (adjust the raw exploit / tool name here, per Do §4) before trusting a `missed`.
  3. `uv run python -m evals.run_cve_benchmark --runs k --budget b` — the graded run; no confidence interval at this N.
