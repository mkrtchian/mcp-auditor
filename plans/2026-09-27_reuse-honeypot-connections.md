# One connection per honeypot for a whole fault scenario

## Context

Each fault injection test (`tests/integration/test_gate_fault_injection.py`) audits the three honeypots 3 times, then replays the flipped servers, and every audit goes through `evals.honeypots.audit_honeypot`, which starts a fresh server process (`StdioMCPClient.connect(ServerLaunch.unconfined("uv", honeypot.args))`). A scenario starts about 24 servers.

Measured on 2026-09-27 on a 16-core machine:

- A cProfile of the random judge scenario (10.8 s wall): the test process spends 9.0 s in `epoll`, waiting on the server subprocesses. The graph, the fakes and the gate account for the rest.
- One server start, up to the first `list_tools` answer, takes about 0.36 s, through `uv run` or through `python` directly alike. It is the import of the MCP SDK in the server, not `uv`.
- 24 starts × 0.36 s ≈ 8.6 s, about 80% of a scenario.

So the fault injection spends most of its time starting servers. Reusing a server across audits cannot change a verdict here: `ScriptedAuditModel` writes one case per category without reading any response, and `FixtureJudge` returns the fixture's observation whatever the server answered. Only the tool list and the server staying alive matter, and a change in either fails the test loudly. The reuse would stay safe even if a honeypot one day held state (today their data, `USERS`, `PROJECTS`, `USERS_DB`, `SENSITIVE_CONFIG`, ..., is never mutated). Opening one connection per honeypot at the start of a scenario and keeping it for the runs and the replays of that scenario removes about 21 starts out of 24.

`pytest-xdist` stays (decided in discussion): it still parallelizes the other integration tests and the eight scenarios.

## Approach

- In `evals/honeypots.py`, split `audit_honeypot` in two: connecting to a honeypot, and auditing a honeypot already connected. `audit_honeypot` keeps its signature and behavior (connect, audit, disconnect) for its other callers (`evals/run_evals.py`, `evals/capture_probe_corpus.py`).
- In `evals/fault_harness.py`, `Harness.inject` connects the three honeypots once, with an `AsyncExitStack`, and `FaultedAudit` audits through those connections for the runs and the replays.
- Servers are shared within one scenario, one test, only. No connection is shared between tests, so the isolation of the previous change holds. The other integration tests do not change.

## `evals/honeypots.py`

```python
@dataclass(frozen=True)
class ConnectedHoneypot:
    config: HoneypotConfig
    client: MCPClientPort


async def audit_honeypot(models: AuditModels, honeypot: HoneypotConfig, budget: int) -> AuditReport:
    async with connected(honeypot) as server:
        return await audit_connected(models, server, budget)


@asynccontextmanager
async def connected(honeypot: HoneypotConfig) -> AsyncIterator[ConnectedHoneypot]:
    """Starts the honeypot's server, its stderr silenced, and stops it on exit."""
    # today's devnull + StdioMCPClient.connect(ServerLaunch.unconfined("uv", honeypot.args), errlog=devnull)


async def audit_connected(models: AuditModels, honeypot: ConnectedHoneypot, budget: int) -> AuditReport:
    # today's body: build_graph(models.llm, AuditedServer(honeypot.client), judge_llm=models.judge_llm),
    # ainvoke with target, test_budget, attack_context, chain_budget, max_chain_steps from honeypot.config
```

The three functions go where `audit_honeypot` sits today, in the order shown: the caller first, then `connected` and `audit_connected` in the order it calls them. `MCPClientPort` comes from `mcp_auditor.domain.ports`. `ConnectedHoneypot` names the pairing a connected audit needs, so `audit_connected` stays at three arguments. A new `AuditedServer` and a new graph are built for every audit, as today: only the server process is reused. The `devnull` handling moves into `connected` unchanged (opened before the connection, closed after it, in a `finally`).

## `evals/fault_harness.py`

- `Harness.inject(fault)`: opens `AsyncExitStack`, enters `connected(honeypot)` for each of `HONEYPOTS`, builds `{honeypot.name: server}`, then does what it does today (runs, replays, two `judge_runs`, recording) inside the stack, and closes the three servers at the end. `inject` stays under about 20 lines: if it does not, extract the connection of the three honeypots into a private helper (for example an `@asynccontextmanager` `_connected_honeypots() -> AsyncIterator[dict[str, ConnectedHoneypot]]` below it).
- `FaultedAudit` gains `servers: Mapping[str, ConnectedHoneypot]` (or `dict`) and keeps `fault`, `models`, `budget`, `audits`. `servers` has no default, so it goes before `audits` (the only field with a `default_factory`), or the dataclass fails at import. `_report(honeypot)` becomes `audit_connected(self.models, self.servers[honeypot.name], self.budget)`. `runs()` and `replay()` do not change: `audit_honeypots` and `Replayer` still receive a `HoneypotConfig -> AuditReport` callable.
- The `FaultedAudit` docstring gains one clause: the servers are shared by the runs and the replays of a scenario.
- The `audit_honeypot` import goes, `audit_connected`, `connected` and `ConnectedHoneypot` come in.

## `evals/fault_injection_method.md`

- The "what the test does not prove" part gains one sentence: each scenario audits servers already started, one per honeypot shared by its runs and replays, so the audit of a freshly started server is not exercised here. The other integration tests and the evals start their own servers. The reuse changes no verdict, because the verdicts come from the fixture through the fake judge, not from the servers' responses.
- `## Cost`: each scenario is its own test, starts one server per honeypot, and reuses it for its runs and replays, with the durations remeasured after the change (scenarios under `-n auto` and one after the other, integration suite under `-n auto`), dated, with the core count. The previous figures (19 s, 59 s, 29 s) are replaced, not kept beside the new ones.

## What stays unchanged

- `audit_honeypot`'s signature and behavior, and its callers `evals/run_evals.py` and `evals/capture_probe_corpus.py`: each of their audits still starts its own server. The real-model evals are out of scope.
- `audit_honeypots`, `Replayer`, `judge_runs`, the gate, the recording, the fault catalog, the fakes, the fixture.
- The honeypot servers (`tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`): they are ground truth, never touched.
- The test module and its given/then modules: the change is inside `Harness.inject`, which they call.
- `pytest-xdist`, the CI workflow, `CLAUDE.md`, `CONTRIBUTING.md`.
- `src/`: nothing changes in the product.

## Edge cases

- A server that dies during a scenario (a tool call that kills it) now fails the remaining audits of that scenario, not only one. `StdioMCPClient.call_tool` turns any exception into an error `ToolResponse`, so the rest of the audit in progress judges error responses silently, and the next audit on that server raises from `list_tools`. In `runs()` that exception reaches the test. In a replay, `Replayer.settle_flips` catches it and records "a replay of <name> failed", which changes the gate's reasons, so the test fails on its expectation rather than on the connection error. Today no honeypot tool exits its process, and the fake generator sends `{}` arguments. Acceptable: the failure is visible and confined to one test.
- A tool call that times out (`_DEFAULT_TOOL_CALL_TIMEOUT = 30` s in `src/mcp_auditor/adapters/mcp_client.py`) may keep running on the shared server while the next audit sends its calls. Every honeypot tool answers in milliseconds, so this does not happen today. If it did, the verdicts would not move (they come from the fixture), only the duration.
- An exception inside `inject` still closes the three servers, because they are entered in the `AsyncExitStack`.
- The random judge's draws depend on the order of judge calls within a scenario. The audits of a scenario already run one after the other (`audit_honeypots` loops over the honeypots in turn), and reusing the servers does not change that order.
- The half-loss draws depend on the audit index (`FaultedAudit.audits`), which this change does not touch.

## Test scenarios

No new test. The eight fault injection tests are the check: the healthy test proves the observations of each run still equal the fixture's through the shared servers, and the fault tests prove the gate's answers are unchanged. A unit test on `audit_connected` would need a real MCP server, which is the integration level.

## Verification

- Before any change, record the baseline: `uv run pytest tests/integration/test_gate_fault_injection.py -n auto --durations=10` and `uv run pytest tests/integration/test_gate_fault_injection.py -p no:xdist`.
- After: the same two commands, 8 passed each, with the durations. Expected, not a pass criterion: each scenario drops from about 7 to 14 s to about 2 to 4 s, and the scenarios one after the other from about 59 s to about 20 s.
- `uv run pytest tests/integration -n auto --durations=10`: all pass, duration recorded for the method note.
- `uv run pytest -n auto`, `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all pass.

## Commit message

The fault injection opens one server per honeypot for a whole scenario instead of one per audit, because starting a server was about 80% of a scenario's time and the fake judge's verdicts do not depend on the servers' responses. `audit_honeypot` is unchanged for the evals. Name no plan, step or phase.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, written so that later passes (the implementation-phase fact check among them) can read it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `-n auto` (pytest-xdist `--numprocesses`, verified against the installed pytest `--help`, pytest-xdist>=3.8.0 in `pyproject.toml`)
- SETTLED: `-p no:xdist` (verified by running it on the installed pytest: the plugin is disabled and the 8 tests still collect)
- SETTLED: `--durations=10` (verified against the installed pytest `--help`)

## Implementation steps

### Step 1: Share one server per honeypot across a fault scenario

- **Files**: `evals/honeypots.py`, `evals/fault_harness.py`, `evals/fault_injection_method.md`
- **Do**:
  1. Record the baseline before touching code: `uv run pytest tests/integration/test_gate_fault_injection.py -n auto --durations=10` and `uv run pytest tests/integration/test_gate_fault_injection.py -p no:xdist`. Note the per-scenario durations and totals.
  2. No new test (see "Test scenarios"): the eight existing fault injection tests are the regression check, and they must stay green through the refactor.
  3. `evals/honeypots.py`: add the frozen dataclass `ConnectedHoneypot(config: HoneypotConfig, client: MCPClientPort)` (`MCPClientPort` from `mcp_auditor.domain.ports`). Replace the body of `audit_honeypot` (signature unchanged) with `async with connected(honeypot) as server: return await audit_connected(models, server, budget)`. Below it, in this order: `connected(honeypot) -> AsyncIterator[ConnectedHoneypot]` (`@asynccontextmanager`, carries today's `devnull` open / `StdioMCPClient.connect(ServerLaunch.unconfined("uv", honeypot.args), errlog=devnull)` / `finally: devnull.close()` unchanged), then `audit_connected(models, honeypot: ConnectedHoneypot, budget) -> AuditReport` (today's graph build with a new `AuditedServer(honeypot.client)` per audit and the `ainvoke` payload read from `honeypot.config`). Imports: `asynccontextmanager`, `AsyncIterator`.
  4. `evals/fault_harness.py`: `FaultedAudit` gains `servers: Mapping[str, ConnectedHoneypot]`, placed before `audits` (no default). `_report` calls `audit_connected(self.models, self.servers[honeypot.name], self.budget)`. Add one clause to its docstring: the servers are shared by the runs and the replays of a scenario. `Harness.inject` connects the three `HONEYPOTS` in an `AsyncExitStack` and runs today's body inside it; if `inject` passes about 20 lines, extract a private `@asynccontextmanager` `_connected_honeypots() -> AsyncIterator[dict[str, ConnectedHoneypot]]` right below its caller. Swap the `audit_honeypot` import for `audit_connected`, `connected`, `ConnectedHoneypot`. `runs()`, `replay()`, `audit_honeypots`, `Replayer` stay as they are.
  5. Rerun the two commands of item 1 and `uv run pytest tests/integration -n auto --durations=10`, then update `evals/fault_injection_method.md`: in the "does not prove" paragraph, one sentence saying each scenario audits servers already started (one per honeypot, shared by its runs and replays), so the audit of a freshly started server is not exercised here, while the other integration tests and the evals start their own, and the reuse changes no verdict because the verdicts come from the fixture through the fake judge, not from the servers' responses. In `## Cost`, rewrite the paragraph: each scenario is its own test, starts one server per honeypot and reuses it for its runs and replays, with the new measured durations (scenarios under `-n auto`, one after the other, integration suite under `-n auto`), dated 2026-09-27, 16-core machine. Replace the old figures (19 s, 59 s, 29 s), do not keep them.
  6. Do not touch the honeypot servers, the test module and its given/then, `src/`, `CLAUDE.md`, `CONTRIBUTING.md`, the CI workflow, `evals/run_evals.py`, `evals/capture_probe_corpus.py`.
- **Test**: the eight tests of `tests/integration/test_gate_fault_injection.py` pass unchanged (healthy scenario: observations equal the fixture's through the shared servers; fault scenarios: gate answers unchanged).
- **Verify**:
  - `uv run pytest tests/integration/test_gate_fault_injection.py -n auto --durations=10`: 8 passed (expected, not a criterion: each scenario about 2 to 4 s).
  - `uv run pytest tests/integration/test_gate_fault_injection.py -p no:xdist`: 8 passed (expected about 20 s).
  - `uv run pytest tests/integration -n auto --durations=10`: all pass.
  - `uv run pytest -n auto`, `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all pass.
  - Commit message per the plan's "Commit message" section, no plan, step or phase named.
