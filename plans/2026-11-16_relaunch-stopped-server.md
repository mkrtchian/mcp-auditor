# Relaunching an audited server that stops answering

## Context

[ADR 036](../docs/adr/036-stopped-server-relaunched.md) decides what the auditor does when the audited server stops answering: it relaunches the server, stops calling a tool that keeps timing out, bounds the relaunches, and reports the calls it did not send. The same ADR has the replay of the detection suite relaunch the patched version after the same calls as the run. This plan implements that decision and does not reopen it.

Today a tool call that times out is recorded as an ordinary response and the next call is sent (`StdioMCPClient.call_tool`, `src/mcp_auditor/adapters/mcp_client.py`). A lost connection is an ordinary response too. Nothing in the product tells a timeout or a lost connection from any other error: the only classification lives in `evals/cve/server_health.py`. The replay reads a timeout on the patched version as a response (`_sent_again`, `evals/cve/detection/replay.py`).

The change touches the system under test (the product), then two instruments (the detection suite's replay, the reports of both suites). The product change goes first, in its own commits, with its justification under ADR 016. The instrument changes follow in theirs.

## Decisions taken with the maintainer

- **The full decision of ADR 036 is implemented**, not only the stage where a server that stops answering is taken as down.
- **A relaunch that fails is a failure to launch in the detection and nuisance suites.** Their rules already retry a failure to launch at most twice, then report the target or the server as not run. An entry in each suite log records it. No rule version opens.
- **The suites name each server's container at audit time**, in `evals/cve/launch_audit.py` and in the replay, so the auditor can remove a blocked server before it relaunches. Neither file is in a fixture fingerprint. The audited launch then differs from the calibrated launch by that one option, which each suite log records with its reason. The name is a random token under the suite's label (`mcp-auditor-cve-audit-<token>`) and says nothing of the server or the flaw: a container name resolves by DNS on a user-defined Docker network, so it must carry nothing, neither a flaw ID nor a package name.
- **The bounds** are constants of the product with no flag: 3 timeouts in a row for a tool on a server that answers the ping, 2 relaunches in a row for a tool, 10 seconds for a ping. They live in the module of the policy.
- **The vet and the calibration check report, per server, whether it answers a ping**, without changing their verdict or their exit code.

## What was measured before this plan

Trials on 2026-11-16 (Docker Engine 29.9.3, mcp 1.30.0), which the tests below make permanent:

- `docker run --name X` exits 125 with a name conflict while X exists, running or stopped without `--rm`.
- Without `--init`, a container whose PID 1 is blocked is still running after the SDK ends its client (stdin closed, SIGTERM, SIGKILL). With `--init`, the confined regime's case, it exits and keeps its name.
- `docker rm -f` removes a blocked container at once, and a launch under the same name right after it succeeds, with or without `--rm`.
- Closing an MCP session from another task than the one that opened it raises `RuntimeError: Attempted to exit cancel scope in a different task`. With one task that owns both SDK context managers, a relaunch asked from any task works: 2.4 s for a blocked server, 0.3 s for one that exited.
- A server whose one tool never returns but leaves the loop free answers the ping and serves the next call.
- The 65 nuisance servers all answer a ping sent right after the handshake, in 0.04 s at most.

## Approach

Four layers, built in this order. Each one leaves the tree green.

1. **The policy and its vocabulary in the domain**, with a client that cannot relaunch yet. `MCPClientPort` gains `ping` and `relaunch`. The real client implements `ping` and answers `False` to `relaunch`. A server that stops answering is then taken as down at once: the remaining calls are not sent, the tools left have a coverage gap, the report is written. This layer is the whole decision except the relaunch itself, and it holds alone.
2. **The relaunch in the adapter**: one task owns the session, `relaunch` ends the old server and opens a new session, under the three execution regimes.
3. **The suites**: the container named at audit time, the relaunches recorded beside the exchanges, a server taken as down turned into a failure to launch, the counters in both reports, the ping in the vet and the calibration check.
4. **The replay**: relaunches at the run's points, a new failure cause for a patched version that stops answering elsewhere.

## Part 1: the product

### Vocabulary and predicates

New module `src/mcp_auditor/domain/server_liveness.py` (`models.py` is already past 300 lines):

```python
class RelaunchCause(StrEnum):
    LOST_CONNECTION = "lost_connection"
    UNANSWERED_PING = "unanswered_ping"
    STUCK = "stuck"

class UnsentCause(StrEnum):
    TOOL_TIMING_OUT = "tool_timing_out"
    RELAUNCHES_IN_A_ROW = "relaunches_in_a_row"
    SERVER_DOWN = "server_down"

@dataclass(frozen=True)
class UnsentPayload:
    cause: UnsentCause

class Relaunch(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    cause: RelaunchCause
    succeeded: bool
```

This module imports nothing from `models.py`, because `models.py` imports it: `CoverageGap.unsent_cause` and `AuditReport.relaunches` name its types. What needs `ToolResponse` or `BlockedPayload` lives in `server_watch.py` (below), which imports both modules:

```python
# server_watch.py
@dataclass(frozen=True)
class CallAttempt:
    outcome: ToolResponse | BlockedPayload | UnsentPayload
    relaunch: Relaunch | None = None

def is_timeout(response: ToolResponse) -> bool: ...
def is_lost_connection(response: ToolResponse) -> bool: ...
```

`UnsentPayload` shares no field name with `ToolResponse` or `BlockedPayload`, for the reason the comment on `BlockedPayload` gives: an outcome a caller forgets to handle is a type error. `is_timeout` reads `error_type == "TimeoutError"`, which only the adapter sets. `is_lost_connection` and its table move to `server_watch.py` from `evals/cve/server_health.py`, which imports them, and the replay imports the new name, so the product and the suites read one definition.

### The policy

New module `src/mcp_auditor/domain/server_watch.py`: a state machine with no I/O, tested without a fake.

```python
TIMEOUTS_IN_A_ROW: Final = 3
RELAUNCHES_IN_A_ROW: Final = 2
PING_TIMEOUT_SECONDS: Final = 10  # read by the adapter's ping

class WatchStep(StrEnum):
    NOTHING = "nothing"
    PING = "ping"
    RELAUNCH = "relaunch"

class ServerWatch:
    @property
    def taken_as_down(self) -> bool: ...
    def unsent_cause(self, tool_name: str) -> UnsentCause | None: ...
    def control_ping_answered(self, answered: bool) -> None: ...
    def after_response(self, tool_name: str, response: ToolResponse) -> WatchStep: ...
    def after_ping(self, tool_name: str, answered: bool) -> WatchStep: ...
    def relaunch_cause(self) -> RelaunchCause: ...
    def after_relaunch(self, tool_name: str, succeeded: bool) -> None: ...
```

Its rules, each with one unit test:

- A lost connection asks for a relaunch at once.
- A timeout on a server that answered the control ping asks for a ping. No answer asks for a relaunch, cause `UNANSWERED_PING`.
- A timeout on a server silent to the control ping asks for no ping, and counts as a timeout on a server that answers.
- When a tool reaches `TIMEOUTS_IN_A_ROW` on a server that answers, the tool is stopped: `unsent_cause` returns `TOOL_TIMING_OUT` for it. If the tool audited just before this one was itself stopped for `TOOL_TIMING_OUT`, the watch asks for a relaunch instead, cause `STUCK`, and this second tool goes on being called.
- A relaunch, whatever its cause, resets the timeout count of the tool whose call led to it. Its relaunch count goes on.
- A relaunch of cause `STUCK` clears the memory of the tool stopped before it: if the tool that led to it again times out `TIMEOUTS_IN_A_ROW` times on a server that answers the ping, it is stopped for `TOOL_TIMING_OUT`, with no second `STUCK` relaunch.
- When the calls of a tool lead to `RELAUNCHES_IN_A_ROW` relaunches in a row, the tool is stopped, cause `RELAUNCHES_IN_A_ROW`.
- The relaunch count of a tool is reset only by a call that gets a real response, neither a timeout nor a lost connection. A timeout on a server that answers the ping leaves it as it is.
- A call that gets a real response resets the tool's two counts and clears the memory of the tool stopped before it. The counts are keyed by the name of the tool called, so a chain step counts for the tool it calls.
- A relaunch that fails takes the server as down: `taken_as_down` is true and `unsent_cause` returns `SERVER_DOWN` for every tool from then on.

### The port and `AuditedServer`

`MCPClientPort` (`domain/ports.py`) gains two methods that never raise:

```python
async def ping(self) -> bool: ...      # True on any response, an error response included
async def relaunch(self) -> bool: ...  # ends the old server and opens a new session, False when it could not
```

The port's docstring, which says the adapter manages the lifecycle, is corrected. Every implementation follows: `StdioMCPClient`, `studio._StudioMCPPlaceholder`, `tests/fakes/mcp_client.py` (the doubles of `test_checkpointing_given.py` and `test_nuisance_benign_call_given.py` inherit it), `GatedClient` in `tests/unit/evals/support/test_honeypot_fault_harness_given.py`, which does not, `evals/cve/exchange_log.py`, and any other test double typed as the port.

The control ping is sent in three places: by `AuditedServer.list_tools()` after it lists the tools, on the new session right after each relaunch that succeeds, and before a call only when none was sent yet for the current session, which is the case of a resumed audit, since it skips `list_tools` (under redaction, the `list_tools()` that `attempt` makes for a resumed audit sends it).

`AuditedServer.attempt` returns a `CallAttempt`. Its order: the destructive-payload guard first, as today, then `watch.unsent_cause`, then the `list_tools()` a resumed audit under redaction already makes today to learn the original tool names (`audited_server.py`), which sends the control ping itself, then the control ping when none was sent yet for this session, then `call_tool`, then the watch's step (a ping, a relaunch followed at once by a control ping on the new session, or nothing), then the redaction of the response. The function is split into helpers that stay under 20 lines. `AuditedServer` also exposes the watch's answers, which the routers read (see below): the property `taken_as_down` and `unsent_cause(tool_name) -> UnsentCause | None`. It carries the policy, so no state key repeats it.

The honeypot suite opens one connection per audit (`connected` in `evals/honeypots.py`). The fault injection harness (`evals/honeypot/fault_harness.py`) opens one connection per honeypot and shares it across its runs and retests, and its unit tests drive it with fake clients (`GatedClient`). Both are left as they are: no honeypot tool blocks or exits, so no relaunch happens there.

### The graph

A call not sent never enters `processed_cases`, `ToolReport.cases` or `AttackChain.steps`. It is counted apart. This is what keeps every prompt and the grammar's units unchanged: `_format_cases_for_extraction` and `_format_single_step_summary` skip only a blocked case, and `evals/cve/report_units.py` reads `blocked_reason`.

`graph/nodes.py` (277 lines) and `graph/chain_nodes.py` (233) cannot take this section's additions under the 300-line bound of CLAUDE.md. The three new nodes (the reports of the tools left when the server is taken as down, the count of the chains a stopped tool does not plan, the count of a chain whose first step is not sent) and the bookkeeping of calls not sent go in a new module `graph/unsent_calls.py`, on the model of `graph/missed_model_calls.py`. The same bound applies to `domain/rendering.py` (278) and `console.py` (275): the relaunch lines go in a module of their own where an addition would take either past it.

No state key says that the server is down or that a tool is stopped. Writing to a resumed thread makes the interrupted subgraph start again from its beginning, and such a key would survive in the subgraph's state. The routers ask the `AuditedServer` instead, which carries the policy: `AuditedServer.taken_as_down` and `AuditedServer.unsent_cause(tool_name)`. The state keeps only what the report needs.

- `graph/state.py`: `relaunches: Annotated[list[Relaunch], operator.add]` in the three states, on the model of `missed_model_calls`, so a relaunch survives `--resume`. For the report, `unsent_cases: int`, `unsent_chains: int` and `unsent_cause: UnsentCause | None`, and in the chain state `unsent_step_cause: UnsentCause | None` and `chain_cut_by_relaunch: bool`.
  Each key sits in `GraphState` and in the subgraph state that writes it, so the subgraphs hand it back to the parent: `unsent_cases` and `unsent_cause` in `AuditToolState` (written by `execute_tool`), `unsent_cause` and `unsent_chains` in `ChainAuditState` (written by `execute_step` and `count_unsent_chain`), and all three in `GraphState`, where `count_chains_not_planned` writes `unsent_chains` and `unsent_cause`. `prepare_tool` resets `unsent_cases`, `unsent_chains` and `unsent_cause` with `coverage_gap`.
  `unsent_cause` is written only when a call is in fact not sent (an `UnsentPayload` received) or by `count_chains_not_planned`, so no execute node ever writes it to `None`.
  The routers read every remaining new key with `.get` and its default, so a checkpoint written before this change resumes and routes as it does today.
- `make_execute_tool` (`graph/nodes.py`): on an `UnsentPayload`, the case is dropped from `pending_cases`, counted in `unsent_cases`, not judged, and its cause written to `unsent_cause`. It is routed on `current_case is None` as a blocked payload is, but it never enters `processed_cases`. On a `CallAttempt` with a relaunch, the relaunch is appended and the case is judged as today, on its timeout or its lost connection.
- `build_tool_report`: the tool's `CoverageGap` carries the cases and the chains not sent. `CoverageGap` gains `unsent_cases: int = 0`, `unsent_chains: int = 0` and `unsent_cause: UnsentCause | None = None`. A gap from generation and a gap from calls not sent merge into one. A tool has a gap for calls not sent only when `unsent_cases + unsent_chains > 0`, so a tool stopped at its last call with no chain budget has none. Such a gap keeps `requested_cases` and `received_cases` as generation left them, and an empty `missing_categories` when generation found none missing. A tool that `report_tools_left` reports has `requested_cases = test_budget`, `received_cases = 0`, `unsent_cases = 0`, `unsent_chains = chain_budget` and the cause `SERVER_DOWN`.
- `route_to_chains_or_report` (`graph/chain_nodes.py`) becomes `make_route_to_chains_or_report(server)`, wired in `build_graph` (`graph/builder.py`) on the conditional edge of `audit_tool`. It reads `server.unsent_cause(tool_name)` for the current tool, so a tool stopped at its last case is known before chains are planned. A cause present plans no chains and goes to the node `count_chains_not_planned` of `graph/unsent_calls.py`, then to `build_tool_report`. A router cannot write state, so that node writes `completed_chains: []`, `unsent_chains: chain_budget` and `unsent_cause` with that cause. Without it, the report of a stopped tool that comes after a tool with chains would carry that tool's chains and its count.
- `make_execute_step`: an `UnsentPayload` sets its own state key (`unsent_step_cause`, reset by `prepare_chain`), never `blocked_step_reason`, and writes its cause to `unsent_cause`. `route_after_execute_step` stays a plain router fed by the keys `execute_step` writes for the current step. It sends a step not sent to `judge_chain` when steps were made. With no step made, the chain is not recorded at all: the node `count_unsent_chain` counts it in `unsent_chains` and goes to the next chain, since `abandon_chain` would record an empty chain with no `blocked_reason`, which the context and grammar would read as a chain that ran. A step followed by a relaunch sets `chain_cut_by_relaunch` (reset by `prepare_chain`) and ends the chain: `route_after_execute_step` reads it and sends the chain to `judge_chain` without `observe_step`, and `judge_chain` reads it to set `AttackChain.cut_by_relaunch: bool = False` for the rendering. `blocked_reason` is not reused: the blocked count, the honeypot metrics and the grammar read it.
- `route_tools` (`graph/nodes.py`) becomes `make_route_tools(server)`, wired in `build_graph` on the conditional edge of `extract_attack_context`. It reads `server.taken_as_down`: once the server is taken as down, the pure node `report_tools_left` of `graph/unsent_calls.py` gives each tool not yet audited a `ToolReport` with the gap above, then the graph goes to `generate_report`.
- `generate_report` copies `relaunches` into `AuditReport.relaunches: list[Relaunch] = []`.
- A resumed audit starts with a fresh policy on a server just launched: nothing is reset in the checkpoint, and `resume_or_reset` and `checkpointing.py` do not change.

`AuditReport.is_complete` is unchanged: a coverage gap already makes an audit incomplete, and a relaunch does not.

### Rendering and the console

- `domain/rendering.py`: a `**Relaunches**` line in the summary, each relaunch under its tool with the arguments of the call before it and its cause, `describe_coverage_gap` extended to the cases and chains not sent, a label on a chain cut by a relaunch. The JSON report follows from the models.
- `console.py`, `stream_handler.py`, `progress.py`: a line per relaunch, and the progress bar advances on a case not sent, or a stopped tool would never reach its end. The label "blocked, not sent" of `progress.py` is reworded so that "not sent" names one thing.
- `cli.py`: `ci_exit_code` is unchanged. Its help text for exit 3 names the calls not sent.

### The session owner and the relaunch

New module `src/mcp_auditor/adapters/session_owner.py`. One task, the owner, holds the `AsyncExitStack` of the current session (`stdio_client`, then `ClientSession`), runs `initialize` under its timeout, and is the only task that enters or exits the SDK's context managers. Its interface has three operations, each asked from any task and carried out by the owner, which hands back the open session or the exception of the opening:

- `open()`: opens the first session.
- `replace()`: closes the current session and opens the next.
- `close()`: closes the current session and ends the owner.

```python
async def _own(self) -> None:
    stack = AsyncExitStack()
    try:
        while True:
            request = await self._requests.get()
            if request.kind is not RequestKind.OPEN:  # REPLACE and CLOSE end the current session
                await self._closed(stack)  # `_only_broken_streams` applies here
                stack = AsyncExitStack()
            if request.kind is RequestKind.CLOSE:
                request.answer.set_result(None)
                return
            try:  # stdio_client, ClientSession, initialize under its timeout
                request.answer.set_result(await self._opened(stack))
            except Exception as error:
                request.answer.set_exception(error)
    finally:
        with anyio.CancelScope(shield=True):  # the caller's cancellation leaves nothing running
            await self._closed(stack)
```

A failed opening unwinds its stack with the exception (`await stack.__aexit__(*sys.exc_info())`), so the caller gets the group the SDK's task groups raise today, and no half-open session stays.

On the caller's cancellation, which the suites use to stop audits in flight (`evals/cve/run_interruption.py`), the exit of `connect` cancels the owner, and the owner closes the current session before it ends, so no process and no container is left.

`StdioMCPClient.connect` keeps its signature for its positional arguments and `initialize_timeout`, because `evals/cve/environments.py` calls it and is in every fixture fingerprint. It gains one keyword, `teardown: ServerTeardown | None = None`:

```python
class ServerTeardown(Protocol):
    async def end_server(self) -> None: ...
```

- `ping()`: `session.send_ping()` under the ping timeout. An `McpError` whose code is not the SDK's connection-closed code is an answer. A timeout, a closed connection or a stream error is silence.
- `relaunch()`: the client ends the old server, then the owner replaces the session. Any exception gives `False`.
- Ending the old server has one implementation of the named declared container rule, in the client. Under the declared-container regime, the client always applies it first: a container whose command sets a `--name` (read with `declared_container_name`) is removed by that name with `docker rm -f -v`, as the suites' container hygiene removes, so a relaunch leaves no anonymous volume behind. Then it calls the injected `teardown`, when one is given. Under the unconfined regime the end of the session is enough, since it ends the process group. This is what lets the suites, which launch declared containers through `environments.connect`, relaunch without a change to that module.
- The removal runs through `asyncio.to_thread`, its Docker subprocess with the environment `os.environ | client_env`. A `docker rm` that exits non-zero is not by itself a failed relaunch, since the container may already be gone (a `--rm` container whose server exited): the opening of the next session decides. The whole teardown is bounded by `TEARDOWN_TIMEOUT_SECONDS` (30, in the adapter), and a teardown past it gives `False`.
- A transport error raised inside the owner by a write to a dead server marks the session dead, so the next calls return a lost connection. It neither cancels the audit nor passes in silence.

`ServerExecution` (`server_execution.py`) implements `end_server` for the confined regime only: it reads `oom_killed` for the container, keeps the state, and removes the container, whose name the relaunch reuses. Under the two other regimes it does nothing, since the client carries the declared container rule. `Audit._probe_the_server` passes it as `teardown`. `ExecutionRecord.oom_killed` stays one value, true when any container of the audit was killed on memory, `None` only when no read succeeded. The Docker calls go through `asyncio.to_thread` (`ContainerRuntime` stays synchronous), and `DockerRuntime.remove` gains `-v`.

A pure function `declared_container_name(args) -> str | Undecidable | None` joins `domain/confinement.py`, for `--name X` and `--name=X` before the image. It has three outcomes: a name, no name, or undecidable, the last when an option the table does not know comes before any `--name`. `Undecidable` is a one-member enum, so a caller cannot read it as a name. Telling the image apart needs the `docker run` options that take a value, pinned in that module as a table: the scan stops at the first argument that is neither an option nor an option's value. A `--name` the server's own arguments carry after the image is never read, so the auditor cannot remove a container the command did not name. In the product, undecidable is read as no name: the container is left, as ADR 036 says of a declared container the command does not name.

### Exception shapes

With the owner, the body of `connect` no longer runs inside the SDK's task groups, so an exception the graph raises reaches `Audit` bare where it came wrapped in a group. One place reads that shape and is changed, with a test:

- `audit.py`: `Audit.run` catches today `ConnectionError`, `OSError` and `BaseExceptionGroup`, and every exception the graph raises reaches it in a group. A bare exception from the graph gets the outcome the group gets today: `CheckpointFromEarlierVersion` keeps its own message, and any other one ends in `_give_up` with the message and the exit code it has now. No traceback reaches the user that did not before. `tests/integration/test_resume_earlier_checkpoint.py` keeps pinning the first outcome, and a new test pins the second with a graph that raises. Its comment that the refusal comes wrapped by the session's task group (lines 9-10) becomes false and is corrected.

`evals/cve/detection/calibration_check.py` (`_root_cause`) and `evals/cve/failure_text.py` (`_original_errors`) already read a bare exception as well as a group (`tests/unit/cve/test_cve_failure_text.py` covers the second), so neither changes.

The shapes that do not change, pinned by the tests that exist: the timeout of `initialize` inside an `ExceptionGroup` (`tests/integration/test_mcp_client_transport.py`), the group of `BrokenResourceError` swallowed on a noisy shutdown. The common path gets characterization tests, written before the owner and green before it, that the owner leaves unchanged: a command not found (the bare `OSError` and what `Audit.run` prints), a server that exits before `initialize`, a server that dies under `list_tools` (the message, the exit code and the stderr shown), and a cancellation of the caller that ends the server's process.

### What does not change in the product

Nothing a model reads: the text `Tool call timed out after {N}s`, `JUDGING_RULES`, the category guidance, every prompt builder, the six schemas sent to a model and the Anthropic wire models. `tests/unit/auditor/test_model_inputs_golden.py` stays green with no regeneration, since the fake client answers the ping and never times out. The destructive-payload guard keeps running first. The unconfined thread id is untouched.

### Tests of the product (written first, red before the change)

- `tests/unit/auditor/test_server_watch.py`: one test per rule of the policy above.
- `tests/unit/auditor/test_audited_server.py`: the guard still runs before anything else, `list_tools` sends the control ping, a payload not sent makes no call, a relaunch is returned with the tool and the arguments of the call before it, a control ping follows each relaunch at once, a first call with no control ping yet for the session sends one, the response is still redacted.
- `tests/unit/auditor/test_nodes.py`, `test_chain_nodes.py`, `test_graph.py`: a stopped tool and its gap, a server taken as down with the report written and the tools left in gaps, chains not planned and counted (a tool stopped at its last case included), a tool stopped at its last call with no chain budget left with no gap, a stopped tool that comes after a tool with chains carrying neither that tool's chains nor its count, a chain whose first step is not sent counted and not recorded, a chain cut by a relaunch judged on its steps and left with no gap, relaunches kept through a resume, an audit interrupted during the judgment of the call whose relaunch failed and then resumed auditing the remaining tools with no `SERVER_DOWN` gap among them, a checkpoint without the new keys routed as today. `test_resuming_a_crashed_audit_finishes_without_reauditing` (`tests/unit/auditor/test_checkpointing.py`) stays the guard of the resume. `then.one_case_blocked_unjudged_and_unsent` is renamed, since "unsent" now names another outcome.
- `tests/unit/auditor/test_rendering.py`, `test_export.py`, `test_console_display.py`, `test_cli.py`: the relaunch lines, the extended gap, and `ci_exit_code` at 0 on relaunches alone and 3 on calls not sent.
- `tests/unit/auditor/test_server_execution.py`, `test_confinement.py`: `end_server` under each regime (the confined container removed, nothing under the two others), the memory state kept across containers, `declared_container_name` (both spellings, no name, a `--name` after the image ignored, an unknown option before the name giving undecidable).
- `tests/fakes/mcp_client.py` learns scripted response sequences, a timeout and a lost connection helper, a scripted `ping` and `relaunch`, and counts them. Its default answers the ping.
- The characterization tests of the common path (see "Exception shapes"), in `tests/integration/test_mcp_client_transport.py` and beside `tests/integration/test_resume_earlier_checkpoint.py`.
- `tests/integration/test_mcp_client_transport.py`, with a new stdio server `tests/integration/support/stalling_server.py` (a synchronous tool that blocks the loop, an asynchronous one that leaves it free, one that exits, a mode that ignores the ping, and a mode that answers the ping with a JSON-RPC error): the ping answered and silent, an error response to the ping read as an answer, a relaunch after a blocked loop with the old process group gone, a relaunch after an exit, a relaunch that fails, a named declared container removed by the client before the injected teardown runs, a declared container with no `--name` relaunched with no `rm`, and one audit run through `Audit` under `astream` whose report names the relaunch. This last test is the proof that a relaunch asked from a graph node works.
- `tests/integration/test_confined_launch.py` (Docker): under the confined regime, a blocked server is replaced under the same name and the memory state of the first container is kept.
- `tests/integration/test_relayed_environment.py`: a relaunch under `--env` writes no value. The relaunch path logs no exception text from the server.

### Commit message and declared flips

The product commits carry the four questions of ADR 016. The justification holds with no mention of a measurement: an auditor that goes on sending calls to a server that cannot answer reports tools as tested when they were not. No flip is declared: no honeypot tool blocks or exits, so no gated cell is expected to move. The honeypot gate runs on the last product commit.

## Part 2: the suites

### The audit of a launch (`evals/cve/launch_audit.py`, not fingerprinted)

- `named(launch) -> Launch` inserts `--name <name>` after `run`, where the name is `f"{LABEL}-audit-{secrets.token_hex(6)}"`, on the model of the names `evals/cve/planting_docker.py` gives (`LABEL` from `evals/cve/planting_base.py`, `mcp-auditor-cve`). A container name resolves by DNS on a user-defined Docker network, so the name carries nothing, neither a flaw ID nor a package name. When `declared_container_name` reads a name in the arguments, that name is kept: Doris, the CKAN holdout target and every nuisance server with a backend already carry one. When it reads undecidable, `named` raises `UndecidableLaunch`, defined in this module, so a second `--name` is never inserted. It is a configuration error, never a failure to launch, and it stops the run as a `planting_spec` refusal does: `_audit` (`evals/cve/detection/audit.py`) re-raises it beside `AuditFailed`, so `attempt_once` lets it pass, and `audit_once` (`evals/cve/nuisance/audit.py`) and `_run_patched` (`evals/cve/detection/replay.py`) re-raise it before their `except Exception`. The `server_command` given to the graph is built from the launch as the fixture wrote it.
- `ExchangeLog` (`evals/cve/exchange_log.py`) forwards `ping` without recording it, forwards `relaunch`, and keeps `relaunched_after: list[int]`, the number of exchanges recorded at each relaunch. `Exchange` stays a tuple: the calibration check and the kit read it as it is.
- After the graph returns, an audit whose report holds a relaunch that failed (`any(not relaunch.succeeded for relaunch in report.relaunches)`) raises `ServerTakenAsDown`, defined in this module. The test is on the relaunches, not on a `SERVER_DOWN` gap, so a relaunch that fails after the last call is covered too. The detection suite turns it into `LaunchError` and the nuisance suite into `LaunchFailed`, by the handlers that exist. The holdout and nuisance runs retry it, and the acceptance layer reports the run as skipped, as it does for any failure to launch.
- `LaunchAudit` carries `relaunched_after`, which the detection suite passes on to `RunToCheck` (a new field with an empty default, so the existing givens that build a `RunToCheck` stay valid).

### Server health and the reports

`ServerHealth` (`evals/cve/server_health.py`) gains `relaunches` and `unsent_calls`, summed like its two counts, read from the audit report: `health_of` takes the report as well as the client and the exchanges, and `NO_INCIDENTS` gains the two zeros. Its other readers follow: `audit_attempts.py`, `detection/holdout_audit.py`, `detection/session_model.py`. They are report-only, on the precedent of the entries of 2026-10-28 in both logs: no statistic, grading or retry reads them. The result and markdown modules of the holdout run and of the nuisance run print them per target or per server: `detection/holdout_results.py`, `holdout_assembly.py`, `holdout_report.py`, `holdout_markdown.py`, and `nuisance/results.py`, `assembly.py`, `report.py`, `markdown.py`. No per-case output is added.

### The ping in the vet and the calibration check

The return types of `check_target` and `benign_call` do not change. The ping reaches the two commands through an optional callback, a callable parameter absent by default, which only `vet` and `calibration-check` pass. Every other caller is left as it is.

- `nuisance/vetting.py`: `benign_call` gains `on_ping: Callable[[AdmittedServer, bool], None] | None = None`, called with whether the server answered a ping sent after the handshake. A server that never connects never calls it, and its line reads `answers the ping: unknown`. `VetDeps` (`nuisance/vet_command.py`) gains `ping_answers: dict[str, bool]`, keyed by server package, with an empty default (`field(default_factory=dict)`) so the given that builds it stays valid. `default_vet_deps` passes a callback that fills it, `vet` passes it to `_print_vet_results` (same module), which adds `answers the ping: yes`, `no` or `unknown` to each server's line. The nuisance run and the nuisance gate, which share `benign_call`, pass none and print nothing more.
- `detection/calibration_check.py`: `check_target` gains `on_ping: Callable[[TargetVersion, bool], None] | None = None`. When given, the ping is sent right after the handshake of each version, before the benign call, and its answer handed to it. `passes_calibration_check`, which both calibration-check commands share through `calibration_check_exit.py`, passes a callback that prints it per target and version. The pre-run checks, of a holdout run (`holdout_run.py`) and of a graded run of the acceptance layer (`run_detection.py`), which call `check_target`, pass none and print nothing more, as the entry of 2026-10-28 in the detection log promises.
- The verdicts and exit codes do not move. The kit under `evals/cve/kit/` is not touched: it is copied into the blind dossiers.

### The Docker shim of the integration tests

`tests/integration/support/detection_fake_targets.py` replaces `docker` with a shim that runs the command after `run`. It changes with the relaunch, at step 7, before the suites name their containers. It learns to skip `--name <value>`, and its `rm` appends its arguments to a file the test reads, so a test sees the removal happen before the injected teardown, and sees a launch without `--name` call no `rm`.

### What does not change in the suites

No file of `GRAMMAR_PATHS` or `ENVIRONMENT_PATHS` (`evals/cve/detection/baseline.py`) is touched in its code: `grammar.py`, `proofs.py`, `units.py`, `report_units.py`, `environments.py`, `holdout_environments.py`, the planting modules, `closed_network.py`. Neither are `nuisance/confinement.py`, `counter.py`, `counting.py` and the backend modules under `evals/cve/backends/`. The fingerprint check of "Verification", run at the end of every step, compares each of them to the base commit through `fingerprint_source`, and checks that the Dockerfiles, the stand-ins, the admission and the places file are the same. No permanent test pins the fingerprints: one would break on every later fixture change. `tests/unit/nuisance/admission/test_nuisance_admission_loads.py` already fails when a module of `ENVIRONMENT_PATHS` moves, through the holdout calibration copies. The module docstring of `environments.py`, which the fingerprint ignores, is corrected (see the living docs).

### Tests of the suites

- `tests/unit/cve/test_cve_launch_audit.py`: a name added under the suite's label with a random token, a name kept, an undecidable launch raising `UndecidableLaunch`, `server_command` without the added name, the relaunch points recorded, `ServerTakenAsDown` raised on a relaunch that failed, after the last call included.
- Every launch the suites build reads, with `declared_container_name`, to its own name or to none, never to undecidable. The criterion is every function that returns the `run` argv of an audited server: the builder parametrization of `tests/unit/cve/test_cve_launches.py` (`_LAYOUT_BUILDERS`), the pure `*_server_args` functions of the backends (`doris_server_args`, `ckan_server_args`, `jenkins_server_args` and the others under `evals/cve/backends/`), the method `Responder.server_args` (`evals/cve/backends/responder.py`), `_server_args` of `evals/cve/backends/ckan_holdout.py`, `kubernetes_injection_env` (`evals/cve/backends/kubernetes_detection.py`), `doris_db_env` (`evals/cve/detection/holdout_environments.py`), and `single_container_run_args` and `single_container_launch_args` (`evals/cve/nuisance/confinement.py`). None of these files is changed: the test reads what they return.
- `tests/unit/cve/test_cve_exchange_log.py`, `test_cve_server_health.py`: the ping forwarded and not recorded, the new counts and their sum.
- `tests/unit/detection/test_detection_audit.py`, `tests/unit/nuisance/test_nuisance_audit_once.py`: a server taken as down is a run skipped, and a launch failure. `attempt_once` and `audit_once` let `UndecidableLaunch` pass.
- The report and markdown tests of both suites for the two counts.
- `tests/unit/nuisance/test_nuisance_vetting.py`, `test_run_nuisance_vet.py`, and `tests/integration/test_detection_calibration_check.py`: the ping line, with the exit codes unchanged.

## Part 3: the replay

`evals/cve/detection/replay.py` is not fingerprinted (ADR 030 keeps the replay outside the grammar).

- `_run_patched` connects to `named(planted.launch)` and sends a control ping. It re-raises `UndecidableLaunch` before its `except Exception`, so a launch `named` cannot read stops the run instead of reading as `LAUNCH_FAILED`.
- At a relaunch point, a call the run relaunched after, the patched version's response, even a lost connection or a timeout, is kept as the output of that call. Then the patched version is relaunched, through the client's `relaunch`, and the replay goes on with the next call. This rule is evaluated before any other. The replay relaunches nowhere else. A relaunch that fails is `LAUNCH_FAILED`.
- At any other call, a lost connection fails the attempt as today. A timeout on a version that answered the control ping is followed by a ping, and no answer fails the attempt with a new cause, `ReplayAttemptFailure.STOPPED_ANSWERING`. An answer leaves the call as answered, the limit ADR 036 states. The failed attempt is made again within `REPLAY_ATTEMPTS`, then the credit stays unchecked through `NO_ATTEMPT_DECIDED`.
- The truncation rule ("a server gone on both versions stops the replay there") stays as defensive code, reset at each relaunch point so that it reads the connection lost since the last relaunch. A real run no longer reaches it: under the new product, a lost connection in the run is always followed by a relaunch, or the run is discarded as a failure to launch. Its existing tests stay.
- `_sent_a_call` becomes `bool(step.outputs)`, the same today, so no future representation of a call not sent can make `arguments_agree` fail.
- `replay_with_causes` takes its `connect` as a dependency, as `Auditor` does, so the unit tests need no Docker.
- The module docstring and the comments that describe one container and no relaunch are rewritten.

The new cause appears in the holdout report beside the two that exist.

### Tests of the replay

- `tests/unit/detection/test_detection_replay.py`: relaunches at the run's points and nowhere else, a lost connection and a timeout at a relaunch point kept as the call's output and followed by the relaunch, `STOPPED_ANSWERING` at another call, a timeout with an answered ping left as answered, a relaunch that fails, the truncation reset, `UndecidableLaunch` raised out of `_run_patched`.
- `tests/integration/test_detection_replay.py`, with `hang_on_call=N` added to `support/detection_replay_read_server.py`: the same three main cases against a real stdio server.

### Labeling log

One entry in `docs/labeling-log.md`, on the form of the entries about the replay: the state, what changes (the relaunch at the run's points, the rule at a relaunch point evaluated first, the new cause, the truncation rule kept as defensive code that a real run no longer reaches, `_sent_a_call`), what the replay cannot see (a patched version silent to the control ping has every timeout read as a response), that no fingerprint moves and no baseline is reset since no detection baseline is recorded, and the four questions of ADR 016.

## Part 4: the relaunch exercised on real fixtures

A graded run rarely meets a server that stops answering, so the relaunch is exercised on purpose, with no LLM, in `tests/integration/test_cve_relaunch.py`. It runs only behind `CVE_RELAUNCH=1`, on the model of `NUISANCE_DORIS=1`, so `uv run pytest -n auto` does not stand a Kubernetes control plane on every run. It needs Docker too.

- The acceptance Kubernetes target, launched through its fixture, receives the recorded blocking call, `kubectl_generic` with the arguments `{"command": "get", "resourceType": "events", "flags": {"watch": true, "request-timeout": "2147483647s"}}`, through an `AuditedServer`, with a short tool call timeout. The test first asserts that the call times out and that the ping after it gets no answer, so a call that does not block fails the test where it would otherwise pass without a relaunch. It then asserts the old container gone, the next call answered by the new one, and the nonces still planted.
- A launch that joins a namespace holder is relaunched and reaches its sentinel again.
- A launch that already carries a name and `--rm` is relaunched under that name.
- A launch that carries a name and `--rm`, whose container ends without the auditor's removal (the test stops it with `docker kill`), is relaunched at once: the `docker rm` that finds nothing or races the `--rm` removal does not fail the relaunch, and the new container starts under the same name.

The test builds no image: it uses the images the preflight expects, and skips, naming the build command, when one of them is absent (unlike the five image tests that build what they need on first run).

## Living docs and text that becomes false

- `README.md`: the audit phases (relaunches and calls not sent in the report), the container removed before a relaunch as well as at the end, and the consequence ADR 036 states for a command that is not pinned: under the confined regime a relaunch fetches the server package again, so an `npx` or `uvx` command without a pinned version can launch another version of the server than the one audited before it. On the declared-container side, one sentence: a declared container is removed before a relaunch only when its command sets a `--name`, and is left otherwise. Also `MCP_AUDITOR_TOOL_CALL_TIMEOUT`, exit code 3, the replay's unchecked causes.
- `CONTRIBUTING.md`: the same sentence on the replay.
- `CHANGELOG.md`, `[Unreleased]`, each line written by the step that makes it true: the calls not sent (step 5), the relaunch and the container removal (step 7), the ping line of the vet and the calibration check (step 11). Under Changed, as a change of behavior: a tool whose calls time out three times in a row is no longer called, its audit is incomplete and `--ci` exits 3 where it exited 0, and before a relaunch the auditor removes its container, or a declared container the command names, with its logs, its files and its anonymous volumes.
- `CLAUDE.md`: the `vet`, `--calibration-check` and `run_detection_holdout calibration-check` lines for the ping (both calibration-check commands print it through `calibration_check_exit.py`), the integration tests line for `test_cve_relaunch.py` (runs only behind `CVE_RELAUNCH=1`, needs Docker and the preflight's images, skips without them, builds nothing), and two landmines, the session owner (a session is closed only by the task that opened it) and the name added at audit time with the shim that skips it.
- `docs/glossary.md`: relaunch, taken as stuck and taken as down are already there (ADR 036's commit). Two terms this plan writes in code and in the suite logs enter in the first product commit: **control ping** (the ping sent after each handshake, which decides whether a timeout is followed by a ping, Code: `control_ping_answered`), and **call not sent** (a tool call the auditor withholds because the tool is stopped or the server taken as down, counted in the tool's coverage gap, Code: `UnsentPayload`, `UnsentCause`, `unsent_cases`, `unsent_chains`, Not: blocked payload, which the guard stops, and missed model call). Any other term the implementation needs enters in the same commit.
- `docs/detection-suite-log.md` and `docs/nuisance-suite-log.md`: one entry per step that writes one, never an edit of an entry an earlier step wrote.
  - Step 8, one entry in each: the bounds and the control ping as constants of the product, a relaunch that fails as a failure to launch, the container named at audit time and why (a random token under the suite's label, which says nothing of the server or the flaw), and the reversal of the detection log entry of 2026-11-16, which says a server killed on memory counts as missed unless a nonce surfaced before: it is now relaunched and the audit goes on. The nuisance entry refers to that reversal. It also states two limits: a counted tool the auditor stops can raise no more alarm and counts as not flagged, and the count of calls not sent is per server.
  - Step 10, one entry in each: the two report-only counts, `relaunches` and `unsent_calls`, which that step prints.
  - Step 12, one entry in the detection log: the replay's new cause.
- `docs/labeling-log.md`: one entry at step 8, on the form of the entry of 2026-11-16 on the memory bound (Commit, State, What changes, Fingerprint, the four questions of ADR 016), since the audited launch and the membership of N change: the name added at audit time, a server taken as down turned into a failure to launch. One entry at step 12, described under "Labeling log".
- Docstrings and comments: `ServerExecution` ("nothing is touched"), `ExecutionRecord.oom_killed`, `MCPClientPort`, `AuditedServer`, the `body_error` comment of `mcp_client.py`, the comment of `audit.py` on the wrapped error, the module docstring of `evals/cve/environments.py` and its comment on the replay's timeout, `server_health.py`, `exchange_log.py`, `launch_audit.py`, `replay.py`. In the tests, the comment of `tests/integration/test_resume_earlier_checkpoint.py` on the refusal wrapped by the session's task group (lines 9-10) and the docstring of `FakeConnect` (`tests/unit/cve/support/test_cve_launch_audit_given.py`) on an error that comes out in nested groups, both corrected at step 7, where the owner changes that shape.

## Edge cases

- **A server silent to the control ping.** It is never pinged after a timeout. Its timeouts are counted, so a tool is stopped at the third, and the server is relaunched only if the next tool reaches the same count.
- **An error response to the ping.** It is an answer: the loop ran.
- **A lost connection at the last call of an audit.** The server is relaunched like any other, and the replay mirrors it.
- **A resumed audit.** It starts with a fresh policy on a server just launched: no tool is stopped, the server is not taken as down, the watch's counts start again from zero, and the control ping is sent before the first call, since a resumed audit skips `list_tools` (under redaction, by the `list_tools()` that the first attempt makes). Nothing in the checkpoint is reset. A tool reported before the interruption keeps its gap and its cause. The relaunches already recorded stay in the report. A checkpoint written before this change lacks the new keys, and the routers read them with `.get`.
- **A chain step that calls a stopped tool.** It is not sent. With steps made, the chain is judged on them. With none, the chain is not recorded and counts in `unsent_chains`.
- **A declared container with no name, in the product.** It is left, and the report names the relaunch. An undecidable `docker run` (an option the table does not know before any `--name`) is read the same way. Under the suites every container has a name, and an undecidable launch is a configuration error, `UndecidableLaunch`, raised by `named`.
- **No bound on the relaunches of an audit.** The bound is per tool (`RELAUNCHES_IN_A_ROW`), so an audit of many tools that each lead to relaunches can relaunch the server many times. No global bound is built.
- **The state a relaunch loses.** The server's memory and what earlier calls wrote inside its container are gone, so the attack context can name things that no longer exist. A mounted path, a backend and the planted nonces stay.
- **A relaunch that raises inside the adapter.** `relaunch` returns `False`, the server is taken as down, the audit ends normally and writes its report.
- **A patched version that does not stop where the vulnerable one did.** The replay relaunches it at that call all the same, so both versions start again from the same state.

## Not in scope

- Telling the judge that the server stopped answering (ADR 036, Consequences).
- The replay's tool call timeout when a measurement run forces another than the default.
- A flag for the bounds.

## Verification

```bash
uv run pytest tests/unit -n auto --maxprocesses 6
uv run pytest -n auto
uv run ruff check .
uv run pyright
uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given   # must leave the golden unchanged: git diff shows nothing
uv run python -m evals.run_honeypot_suite                                    # the honeypot gate, on the last product commit
uv run python -m evals.run_judge_eval                                        # the judge gate, unchanged prompts
uv run python -m evals.run_detection --calibration-check                     # acceptance targets, with the ping line
uv run python -m evals.run_detection_holdout calibration-check               # every holdout target live and fixed, with the ping line
uv run python -m evals.run_nuisance vet                                      # every server answers its benign calls, with the ping line
CVE_RELAUNCH=1 uv run pytest tests/integration/test_cve_relaunch.py -n 0      # the relaunch on real fixtures (Docker and the preflight's images, builds nothing)
```

### The fingerprint check

Run at the end of every step, from step 1. It compares, through the repository's fingerprint function, the source of every fingerprinted module at the base commit `0bc2043` with its source in the tree, then checks that the Dockerfiles, the stand-ins, the admission and the places file are the same as at the base commit. It stops at the first part that fails: the script names every fingerprinted module that moved, `git diff --stat` names every one of those files that changed, and the last line fails on an untracked file under `evals/docker` or `evals/stand_ins`.

```bash
set -e
uv run python - <<'EOF'
import subprocess
import sys
from pathlib import Path

from evals.baseline import fingerprint_source
from evals.cve.detection.baseline import ENVIRONMENT_PATHS, GRAMMAR_PATHS
from evals.cve.nuisance.counter import _COUNTER_PATHS

BASE = "0bc2043"
root = Path.cwd()
watched = {
    *GRAMMAR_PATHS,
    *ENVIRONMENT_PATHS,
    *_COUNTER_PATHS,
    root / "evals/cve/nuisance/confinement.py",
    *(root / "evals/cve/backends").glob("*.py"),
}
moved = []
for path in sorted(watched):
    relative = path.resolve().relative_to(root)
    at_base = subprocess.run(
        ["git", "show", f"{BASE}:{relative}"], capture_output=True, text=True, check=True
    ).stdout
    if fingerprint_source(at_base) != fingerprint_source(path.read_text()):
        moved.append(str(relative))
print("\n".join(moved) or "no fingerprinted module moved")
sys.exit(1 if moved else 0)
EOF
git diff --exit-code --stat 0bc2043 -- evals/docker evals/stand_ins evals/nuisance_admission.json evals/detection_places.json
test -z "$(git status --porcelain --untracked-files=all -- evals/docker evals/stand_ins)"
```

The backend modules are all those of `evals/cve/backends/`, which covers every module a fixture fingerprint serves (`backend_sources` of the detection fixtures, `_served` in `evals/cve/nuisance/backend_registry.py`).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, one line each, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, on 2026-11-16, not what is true now. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- SETTLED: `mcp==1.30.0` is the installed SDK, and `ClientSession.send_ping()` exists in it, returning `EmptyResult` (verified against the installed package, `mcp/client/session.py`).
- SETTLED: `CONNECTION_CLOSED = -32000`, the code of the SDK's `McpError` with message `"Connection closed"` raised for a request in flight when the connection closes (verified against the installed package, `mcp/types.py` and `mcp/shared/session.py`).
- SETTLED: `[a-zA-Z0-9][a-zA-Z0-9_.-]` is Docker's container name character set, under the pattern `^` + that + `+$`, so a name has at least two characters (verified against moby `daemon/names/names.go`, master). The name `named` builds, `mcp-auditor-cve-audit-` and twelve hexadecimal digits, is inside it, so no character of a name needs replacing.
- SETTLED: on a user-defined Docker network, a container resolves another by its name through Docker's embedded DNS (docs.docker.com, networking overview). This is why the name `named` gives carries a random token and nothing of the server or the flaw.
- SETTLED: `LABEL` (`evals/cve/planting_base.py`, `mcp-auditor-cve`) and `secrets.token_hex(6)` are what `evals/cve/planting_docker.py` builds its container names from (verified in the repository).
- SETTLED: `docker rm -f -v <name>` kills a running container with SIGKILL, removes it, and removes its anonymous volumes, never a named one (verified against docs.docker.com, `docker container rm` reference).
- OPEN (unverified): the trials of 2026-11-16 (Docker Engine 29.9.3: exit 125 on a name conflict, `--init` behavior, `docker rm -f` then a relaunch under the same name), measured locally by the maintainer, not re-run since this pass does not run Docker. The plan's tests make them permanent.
- SETTLED: the option table of `declared_container_name` is built from the `docker run` reference of the Docker CLI in use. It lists the options that take a value and the flags that take none, and it reads grouped short flags such as `-it`. An option outside it before any `--name` gives undecidable, which the product reads as no name and `named` raises `UndecidableLaunch` on. Tests pin that every function returning the `run` argv of an audited server in either suite (listed under "Tests of the suites") parses to the expected name or to none. The README carries no `docker run` example, so none is pinned.
- SETTLED: no state key says that the server is down or that a tool is stopped, since a write to a resumed thread makes the interrupted subgraph start again from its beginning and the key would survive in the subgraph's state. The routers read `AuditedServer.taken_as_down` and `AuditedServer.unsent_cause`, and `checkpointing.py` does not change (decided with the maintainer, current router wiring verified in `graph/builder.py`, `graph/nodes.py` and `graph/chain_nodes.py`).
- SETTLED: `UndecidableLaunch` passes through `attempt_once` (its `except` names `AuditFailed`, `LaunchError`, `PlantingFailed` and `subprocess.CalledProcessError` only) once `_audit` re-raises it, and `audit_once` and `_run_patched` must re-raise it before their `except Exception` (verified in the repository).
- SETTLED: `VetDeps` (`evals/cve/nuisance/vet_command.py`) is a dataclass of callables today, and `_print_vet_results` takes the servers and the `VetResult`, so the ping answers reach it only through the new `ping_answers` field (verified in the repository).
- SETTLED: the arguments of the recorded blocking `kubectl_generic` call are written out in Part 4, and the test asserts the timeout and the unanswered ping before anything else.
- SETTLED: the fingerprint check compares against the base commit `0bc2043` through `fingerprint_source` (`evals/baseline.py`), over `GRAMMAR_PATHS` and `ENVIRONMENT_PATHS` (`evals/cve/detection/baseline.py`), `_COUNTER_PATHS` (`evals/cve/nuisance/counter.py`), `evals/cve/nuisance/confinement.py` and the modules of `evals/cve/backends/` (names verified in the repository). It runs under `set -e`, so the Python part failing stops it, and it fails on an untracked file under `evals/docker` or `evals/stand_ins`, which `git diff` alone does not see.
- SETTLED: the suites cancel audits in flight (`first_failure` and `sibling_runs` in `evals/cve/run_interruption.py`), which is why the session owner closes its session on the caller's cancellation.
- SETTLED: the honeypot suite opens one connection per audit (`connected` in `evals/honeypots.py`), and the fault injection harness shares one per honeypot (`_connected_honeypots` in `evals/honeypot/fault_harness.py`) (verified in the repository).

## Implementation steps

Rules that hold for every step:

- Each step is one commit. Steps 1 to 7 change the product (the system under test): their commit messages answer the four questions of ADR 016, with the justification of "Commit message and declared flips" above, and declare no flip. Steps 8 to 13 change instruments: they touch no file of `src/mcp_auditor/` and no file of `GRAMMAR_PATHS` or `ENVIRONMENT_PATHS` beyond a module docstring or a comment (`evals.baseline.fingerprint_source` leaves those two out, a function docstring is not left out).
- Tests first, red before the code. The given/then split of CLAUDE.md applies to every new test file.
- Docker: do not build or pull an image and do not grow Docker disk usage. A Docker test whose image is absent locally skips or is left to the maintainer, and the step's report says so.
- Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright` (no file argument), all green, and with the fingerprint check of "Verification", which must report that nothing moved. Steps 3, 4 and 5 also run `uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given` and check that `git diff` shows no change to the golden.
- A docstring or comment the plan lists under "Docstrings and comments" is corrected in the step that changes the code it describes.
- A suite log or labeling log entry is written by the step named for it under "Living docs", and no step edits an entry an earlier step wrote.

### Step 1: the liveness vocabulary and the watch policy (product)

- **Files**: `tests/unit/auditor/test_server_watch.py` (+ given/then if they abstract something), `src/mcp_auditor/domain/server_liveness.py` (new), `src/mcp_auditor/domain/server_watch.py` (new), `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/domain/__init__.py` (exports, if the existing pattern re-exports model types), `docs/glossary.md`.
- **Do**:
  - Write `test_server_watch.py` first, one test per rule of "The policy", plus `is_timeout` and `is_lost_connection`.
  - `server_liveness.py`: `RelaunchCause`, `UnsentCause`, `UnsentPayload`, `Relaunch` exactly as in "Vocabulary and predicates". It imports nothing from `models.py`.
  - `server_watch.py`: `CallAttempt`, `is_timeout`, `is_lost_connection` (with its own copy of the `LOST_CONNECTION_RESPONSES` table and its comment, taken from `evals/cve/server_health.py`, which is left untouched here: step 9 makes it import this one), the constants `TIMEOUTS_IN_A_ROW = 3`, `RELAUNCHES_IN_A_ROW = 2`, `PING_TIMEOUT_SECONDS = 10`, `WatchStep`, and `ServerWatch` with the six methods and the property `taken_as_down` of the plan. Pure, no I/O. The watch remembers the control ping's answer (`control_ping_answered`), per-tool timeout and relaunch counts keyed by tool name, the tool stopped last for `TOOL_TIMING_OUT`, and whether the server is taken as down, which `taken_as_down` reads. `relaunch_cause()` returns the cause of the relaunch the last step asked for.
  - `models.py`: `CoverageGap` gains `unsent_cases: int = 0`, `unsent_chains: int = 0`, `unsent_cause: UnsentCause | None = None`. `AuditReport` gains `relaunches: list[Relaunch] = []`. `AttackChain` gains `cut_by_relaunch: bool = False`. `is_complete` unchanged. Check that the existing `CoverageGap` description helpers and the JSON export still load an old report (defaults).
  - `docs/glossary.md`: the entries **control ping** and **call not sent** as worded in "Living docs" (check `docs/glossary-log.md` first).
- **Test** (`test_server_watch.py`, about 13 cases):
  - a lost connection returns `RELAUNCH` with cause `LOST_CONNECTION`.
  - control ping answered, a timeout returns `PING`. `after_ping(answered=False)` returns `RELAUNCH`, cause `UNANSWERED_PING`. `after_ping(answered=True)` returns `NOTHING`.
  - control ping silent, a timeout returns `NOTHING` and the third timeout stops the tool.
  - three timeouts in a row on tool A (ping answered each time) make `unsent_cause("A") == TOOL_TIMING_OUT`, other tools `None`.
  - A stopped for timing out, then three timeouts on B: the third returns `RELAUNCH` with cause `STUCK`, and B is not stopped.
  - after that `STUCK` relaunch, three more timeouts on B (ping answered) stop B for `TOOL_TIMING_OUT`, with no second `STUCK` relaunch.
  - a relaunch resets the timeout count of the tool that led to it (two more timeouts after it do not stop the tool) while its relaunch count goes on.
  - two relaunches in a row from tool A stop A with `RELAUNCHES_IN_A_ROW`.
  - a relaunch from A, then a timeout of A on a server that answers the ping, then a second relaunch from A: A is stopped with `RELAUNCHES_IN_A_ROW`, since the timeout did not reset the relaunch count.
  - a real response resets both counts and clears the memory of the tool stopped before (A stopped, B answers once, then C's three timeouts stop C instead of relaunching).
  - `after_relaunch(succeeded=False)` makes `taken_as_down` true and gives `SERVER_DOWN` for every tool.
  - `is_timeout` true only on `error_type == "TimeoutError"`. `is_lost_connection` on each row of the table, false on another `McpError` text.
- **Verify**: `uv run pytest tests/unit/auditor/test_server_watch.py -n 0` red then green, then the short loop, then the closing checks and the fingerprint check.

### Step 2: the ping on the port and in the real client (product)

- **Files**: `tests/integration/support/stalling_server.py` (new), `tests/integration/test_mcp_client_transport.py` (+ its given), `src/mcp_auditor/domain/ports.py`, `src/mcp_auditor/adapters/mcp_client.py`, `src/mcp_auditor/studio.py`, `tests/fakes/mcp_client.py`, `tests/unit/evals/support/test_honeypot_fault_harness_given.py` (`GatedClient`), `evals/cve/exchange_log.py` (forwarding only), `tests/unit/cve/test_cve_exchange_log.py`.
- **Do**:
  - `stalling_server.py`: a stdio MCP server with an asynchronous tool that never returns but leaves the loop free, a synchronous tool that blocks the loop, a mode (a command-line flag) that leaves every ping unanswered, and a mode that answers the ping with a JSON-RPC error. Step 6 adds the modes the characterization tests need, and step 7 the tool that exits.
  - `MCPClientPort` gains `ping() -> bool` and `relaunch() -> bool`, both never raising, with the docstring corrected (the adapter opens the first session, `relaunch` ends the server and opens another).
  - `StdioMCPClient.ping()`: `session.send_ping()` under `asyncio.timeout(PING_TIMEOUT_SECONDS)` (imported from `domain/server_watch.py`). An `McpError` whose code is not `CONNECTION_CLOSED` (-32000) is an answer. A timeout, that code, or a stream error (`anyio.ClosedResourceError`, `anyio.BrokenResourceError`) is `False`. `relaunch()` returns `False` (step 7 implements it).
  - `_StudioMCPPlaceholder`, `GatedClient`: both methods. `FakeMCPClient`: scripted response sequences per tool (a list consumed in order, the last repeated), helpers building a timeout response (`error_type="TimeoutError"`, the adapter's text) and a lost-connection response, a scripted `ping` answer (default `True`) and `relaunch` answer (default `True`), and counters `pings` and `relaunches`. Keep its current constructor valid so `test_checkpointing_given.py` and `test_nuisance_benign_call_given.py`, which inherit it, need no change.
  - `ExchangeLog`: forward `ping` and `relaunch` to the inner client, recording nothing. Nothing calls them yet, and `relaunched_after` comes in step 8. The commit message says that this change to an instrument file is type conformance to the port only.
- **Test** (integration, against `stalling_server.py`):
  - the ping is answered right after the handshake.
  - the ping is answered while the asynchronous tool is in flight (its call timed out), and the next call is served.
  - the ping is unanswered after the synchronous tool blocked the loop (the call timed out first).
  - the ping is unanswered under the ignore-ping mode.
  - an error response to the ping is an answer (`ping()` returns `True` under the error-ping mode).
  - `relaunch()` returns `False`.
  - unit, `test_cve_exchange_log.py`: `ExchangeLog` forwards `ping` and `relaunch` to the inner client and records no exchange for either.
- **Verify**: `uv run pytest tests/integration/test_mcp_client_transport.py tests/unit/cve/test_cve_exchange_log.py -n 0`, the short loop, the closing checks, the fingerprint check. A test that waits out the 10 s ping timeout is acceptable.

### Step 3: `AuditedServer` drives the watch, the execute nodes take a call not sent (product)

- **Files**: `tests/unit/auditor/test_audited_server.py`, `tests/unit/auditor/test_nodes.py`, `tests/unit/auditor/test_chain_nodes.py` (+ their given/then), `tests/unit/auditor/test_graph.py` and `tests/unit/auditor/support/test_graph_then.py` (the rename), `tests/unit/detection/test_detection_targets.py` and `tests/integration/support/test_relayed_environment_given.py` (both read `attempt.outcome`), `src/mcp_auditor/domain/audited_server.py`, `src/mcp_auditor/graph/state.py`, `src/mcp_auditor/graph/unsent_calls.py` (new), `src/mcp_auditor/graph/nodes.py`, `src/mcp_auditor/graph/chain_nodes.py`, `src/mcp_auditor/graph/builder.py`.
- **Do**:
  - `AuditedServer` owns a `ServerWatch`. `list_tools()` sends the control ping after it lists the tools. `attempt` returns a `CallAttempt` in the order of "The port and `AuditedServer`": guard, `watch.unsent_cause` (an `UnsentPayload`, no call), the `list_tools()` a resumed audit under redaction already makes (which sends the control ping itself), the control ping only when none was sent yet for the current session (a resumed audit), `call_tool` on the original name, the watch's step (a `ping` then `after_ping`, or a `relaunch` then `after_relaunch` and, on success, a control ping at once on the new session), then the redaction. The `Relaunch` it returns carries the tool name and the arguments of the call before it (the redacted ones the graph sees) and the watch's cause. Expose the property `taken_as_down` and `unsent_cause(tool_name)`, both read from the watch. Helpers under 20 lines, docstring updated. With the real client still answering `False` to `relaunch`, the first relaunch takes the server as down.
  - The callers of `attempt` outside the graph read `attempt.outcome`: `tests/unit/detection/test_detection_targets.py` (its `assert not isinstance(outcome, BlockedPayload)` would otherwise pass on any `CallAttempt`) and `tests/integration/support/test_relayed_environment_given.py` (its `assert isinstance(response, ToolResponse)` would otherwise fail).
  - `state.py`: `relaunches: Annotated[list[Relaunch], operator.add]` in `GraphState`, `AuditToolState`, `ChainAuditState`. `unsent_cases: int` and `unsent_cause: UnsentCause | None` in `GraphState` and `AuditToolState`, `unsent_chains: int` in `GraphState`. `unsent_cause`, `unsent_chains`, `unsent_step_cause: UnsentCause | None` and `chain_cut_by_relaunch: bool` in `ChainAuditState`, so the subgraphs hand them back. No key says that the server is down or that a tool is stopped.
  - `unsent_calls.py` (on the model of `missed_model_calls.py`): the bookkeeping of a case not sent (the update dict that drops it from `pending_cases`, counts it in `unsent_cases` and writes the payload's cause to `unsent_cause`), and the node `count_unsent_chain` for a chain whose first step is not sent (counts it in `unsent_chains`, records no chain, moves to the next chain).
  - `nodes.py`: `prepare_tool` resets `unsent_cases`, `unsent_chains` and `unsent_cause`. `make_execute_tool`: an `UnsentPayload` is dropped, counted, not judged, never in `processed_cases`, routed on `current_case is None`, and its cause written to `unsent_cause`. A `CallAttempt` with a relaunch appends it and the case is judged as today. A call that is sent writes nothing to `unsent_cause`.
  - `chain_nodes.py`: `prepare_chain` resets `unsent_step_cause` and `chain_cut_by_relaunch`. `make_execute_step`: an `UnsentPayload` sets `unsent_step_cause` (never `blocked_step_reason`) and writes its cause to `unsent_cause`, a relaunch is appended and sets `chain_cut_by_relaunch`. `route_after_execute_step` reads `unsent_step_cause` and `chain_cut_by_relaunch` with `.get`: a step not sent with steps made, or a step followed by a relaunch, goes to `judge_chain` without `observe_step`, and a step not sent with no step made goes to `count_unsent_chain`. `judge_chain` reads `chain_cut_by_relaunch` to set `AttackChain.cut_by_relaunch`. `builder.py` wires `count_unsent_chain` in `_build_chain_audit_subgraph`: the path map of `execute_step` gains it, and it routes on to the next chain as `abandon_chain` does (`route_after_judge`).
  - Rename `then.one_case_blocked_unjudged_and_unsent` (`tests/unit/auditor/support/test_graph_then.py`, called from `tests/unit/auditor/test_graph.py`) to a name without "unsent", for instance `one_case_blocked_unjudged_and_not_called`.
- **Test** (about 14 cases):
  - `test_audited_server.py`: the guard runs before the control ping and the watch (a blocked payload makes no ping and no call). `list_tools` sends the control ping, and the first call after it sends none. A first call with no control ping yet for the session sends one. A payload of a stopped tool makes no call. A lost connection returns a `CallAttempt` whose relaunch names the tool and the arguments. A control ping follows each successful relaunch at once. A failed relaunch makes `taken_as_down` true and every later attempt an `UnsentPayload` with `SERVER_DOWN`. The response is still redacted under `--env`.
  - `test_nodes.py`: a case not sent is counted and not judged, never in `processed_cases`, and its cause is in `unsent_cause`. A case followed by a relaunch is judged and the relaunch is in the state. A case that is sent leaves `unsent_cause` as it was.
  - `test_chain_nodes.py`: a step not sent after steps were made goes to `judge_chain`. A first step not sent leaves no chain and counts one in `unsent_chains`. A step followed by a relaunch skips `observe_step` and the chain is `cut_by_relaunch`. A step not sent writes its cause to `unsent_cause`.
- **Verify**: the test files with `-n 0`, the short loop, the golden check, the closing checks, the fingerprint check.

### Step 4: stopped tools, a server taken as down, and the report (product)

- **Files**: `tests/unit/auditor/test_nodes.py`, `tests/unit/auditor/test_chain_nodes.py`, `tests/unit/auditor/test_graph.py`, `tests/unit/auditor/test_checkpointing.py` (+ given/then), `src/mcp_auditor/graph/nodes.py`, `src/mcp_auditor/graph/chain_nodes.py`, `src/mcp_auditor/graph/unsent_calls.py`, `src/mcp_auditor/graph/builder.py`.
- **Do**:
  - `build_tool_report`: the tool's `CoverageGap` carries `unsent_cases`, `unsent_chains` and `unsent_cause`. A gap from generation and a gap from calls not sent merge into one `CoverageGap`. A tool has a gap for calls not sent only when `unsent_cases + unsent_chains > 0`. That gap keeps `requested_cases` and `received_cases` as generation left them, and an empty `missing_categories` when generation found none missing.
  - `route_to_chains_or_report` becomes `make_route_to_chains_or_report(server)`: it reads `server.unsent_cause(tool_name)` for the current tool, and a cause present plans no chains and goes to the node `count_chains_not_planned` of `unsent_calls.py`, which writes `completed_chains: []`, `unsent_chains: chain_budget` and `unsent_cause` with that cause, then to `build_tool_report` (a tool stopped at its last case included). `builder.py` wires it in `build_graph` on the conditional edge of `audit_tool`, whose path map gains `count_chains_not_planned`, and adds the edge from that node to `build_tool_report`.
  - `unsent_calls.py`: a pure node `report_tools_left` that gives each tool not yet audited a `ToolReport` whose gap has `requested_cases = test_budget`, `received_cases = 0`, `unsent_cases = 0`, `unsent_chains = chain_budget` and the cause `SERVER_DOWN`. `route_tools` becomes `make_route_tools(server)`: it reads `server.taken_as_down` and sends a graph whose server is down to `report_tools_left`, then `generate_report`. `builder.py` wires it in `build_graph` on the conditional edge of `extract_attack_context`. The dry-run graph keeps its own routers.
  - The existing tests that call `route_tools` (`test_nodes.py`) and `route_to_chains_or_report` (`test_chain_nodes.py`) build them through the factories, with an `AuditedServer` over the fake client.
  - `generate_report` copies `relaunches` into `AuditReport.relaunches`.
  - `resume_or_reset` and `checkpointing.py` do not change: a resumed audit starts with a fresh `AuditedServer`, so a fresh policy, on a server just launched.
- **Test** (about 12 cases):
  - two gaps merged into one (generation short and calls not sent).
  - a tool stopped at its last call with no chain budget has no gap.
  - `make_route_to_chains_or_report` with a stopped tool and with the server down, and the chain budget counted with the cause.
  - a stopped tool that comes after a tool with chains carries neither that tool's chains nor its count of chains not sent.
  - `test_graph.py` through the fake client: a tool whose calls time out three times is stopped with its gap and no chains, and the next tool is audited. A server whose relaunch fails ends the audit with a report, the tools left in `SERVER_DOWN` gaps of the shape above and `is_complete` false. A relaunch that succeeds is in `AuditReport.relaunches` and the audit is complete. A chain cut by a relaunch leaves its tool with no gap. Relaunches recorded before an interruption are still in the report after `--resume` (on the pattern of the existing resume tests).
  - resume (`test_checkpointing.py`): an audit interrupted during the judgment of the call whose relaunch failed, then resumed, audits the remaining tools, and none of them receives a `SERVER_DOWN` gap. A checkpoint without the new keys resumes and routes as today. `test_resuming_a_crashed_audit_finishes_without_reauditing` stays green unchanged, as the guard of the resume.
- **Verify**: as step 3.

### Step 5: the report, the console and the CLI show relaunches and calls not sent (product)

- **Files**: `tests/unit/auditor/test_rendering.py`, `test_export.py`, `test_console_display.py`, `test_progress.py`, `test_stream_handler.py`, `test_cli.py` (+ given/then), `src/mcp_auditor/domain/rendering.py` (and a new `domain/relaunch_rendering.py` if the additions take it past 300 lines), `src/mcp_auditor/console.py` (and a new module for the relaunch lines if they take it past 300), `src/mcp_auditor/stream_handler.py`, `src/mcp_auditor/progress.py`, `src/mcp_auditor/cli.py`, `README.md`, `CHANGELOG.md`.
- **Do**:
  - Rendering: a `**Relaunches**` line in the summary, each relaunch under its tool with the arguments of the call before it and its cause, `describe_coverage_gap` naming the cases and chains not sent and why, a label on a chain cut by a relaunch.
  - Console and stream handler: a line per relaunch as it is recorded. Progress: the bar advances on a case not sent. Reword the "blocked, not sent" label so that "not sent" names only a call not sent (for instance "blocked by the guard").
  - `cli.py`: `ci_exit_code` unchanged, its exit-3 help names the calls not sent.
  - `README.md`: the audit phases (relaunch reporting and calls not sent), exit code 3, `MCP_AUDITOR_TOOL_CALL_TIMEOUT` (a slow tool can be given more time before it counts as a timeout). `CHANGELOG.md` `[Unreleased]`: under Added, the calls not sent in the report. Under Changed, a tool whose calls time out three times in a row is no longer called, its audit is incomplete and `--ci` exits 3 where it exited 0. The relaunch itself, the container removal and the unpinned command are written in step 7.
- **Test** (about 9 cases): the relaunch line and its cause in markdown. The gap text with cases and chains not sent. The cut-chain label. The JSON export carries `relaunches` and the new gap fields, and an old report without them still loads. A console line per relaunch. The progress bar reaches its end for a stopped tool. `ci_exit_code` 0 on relaunches alone, 3 on calls not sent.
- **Verify**: as step 3.

### Step 6: ending the old server, and the net under the common path (product)

- **Files**: `tests/integration/test_mcp_client_transport.py` (+ given), `tests/integration/support/stalling_server.py` (a mode that exits before `initialize`, a mode that exits under `list_tools`), the characterization test of `Audit.run` beside `tests/integration/test_resume_earlier_checkpoint.py` (with its given), `tests/unit/auditor/test_confinement.py`, `tests/unit/auditor/test_server_execution.py` (+ given/then), `src/mcp_auditor/domain/confinement.py`, `src/mcp_auditor/domain/models.py` (the docstring of `ExecutionRecord.oom_killed`), `src/mcp_auditor/server_execution.py`, `src/mcp_auditor/adapters/docker.py`, `src/mcp_auditor/audit.py`.
- **Do**:
  - Write the characterization tests of the common path first. They are green before any code of this step and of step 7, and step 7 leaves them unchanged: a command not found (the bare `OSError`, and what `Audit.run` prints), a server that exits before `initialize`, a server that dies under `list_tools` (the message, the exit code and the stderr shown), and a cancellation of the caller that ends the server's process (on the model of the suites' cancellation of audits in flight, `evals/cve/run_interruption.py`).
  - `confinement.py`: `declared_container_name(args) -> str | Undecidable | None`, with `Undecidable` a one-member enum, and the pinned table of `docker run` options that take a value and the flags that take none (grouped short flags such as `-it` read), for `--name X` and `--name=X` before the image. The scan stops at the image. An option the table does not know before any `--name` gives undecidable. A `--name` after the image is never read.
  - `ServerExecution.end_server()` (async, Docker calls through `asyncio.to_thread`): confined, read `oom_killed`, keep it (true when any container of the audit was killed on memory, `None` only when no read succeeded) and remove the container. The two other regimes, nothing: the client carries the declared container rule (step 7). `__aexit__` folds the kept state into `ExecutionRecord`. `DockerRuntime.remove` gains `-v`. Docstrings of `ServerExecution` and `ExecutionRecord.oom_killed` corrected.
  - `audit.py` `Audit.run`: a bare exception from the graph gets the outcome a group gets today (`CheckpointFromEarlierVersion` keeps its message, any other ends in `_give_up` with today's message and exit code). `ServerExecution` is not passed to the client yet (step 7 adds the `teardown` keyword).
- **Test** (about 16 cases): the four characterization tests, green from the start. `declared_container_name` for `--name X`, `--name=X`, no name, a name after the image, an unknown option before the name (undecidable), grouped flags. `end_server` under each regime (the confined container removed with its kill state kept across two containers and folded into the record, nothing under the two others). The bare-exception outcome of `Audit.run`.
- **Verify**: the test files with `-n 0`, the short loop, the closing checks, the fingerprint check.

### Step 7: the session owner and the relaunch (product, last product commit)

- **Files**: `tests/integration/support/stalling_server.py` (the tool that exits), `tests/integration/test_mcp_client_transport.py` (+ given), `tests/integration/test_confined_launch.py` (+ given/then), `tests/integration/test_relayed_environment.py`, `tests/integration/support/detection_fake_targets.py` (the Docker shim), `tests/integration/test_resume_earlier_checkpoint.py` (its comment), `tests/unit/cve/support/test_cve_launch_audit_given.py` (the docstring of `FakeConnect`), `src/mcp_auditor/adapters/session_owner.py` (new), `src/mcp_auditor/adapters/mcp_client.py`, `src/mcp_auditor/audit.py`, `README.md`, `CHANGELOG.md`, `CLAUDE.md`.
- **Do**:
  - `session_owner.py` as in "The session owner and the relaunch": the three operations `open`, `replace` and `close`, asked from any task and carried out by the owner task, which holds the `AsyncExitStack` (`stdio_client`, then `ClientSession`), runs `initialize` under its timeout, applies `_only_broken_streams` at each close, and hands back the open session or the exception of the opening. A failed opening unwinds its stack with the exception (`await stack.__aexit__(*sys.exc_info())`), so the caller gets the group the SDK's task groups raise today and no half-open session stays. On the caller's cancellation, it closes the current session before it ends.
  - `StdioMCPClient.connect` keeps its positional arguments and `initialize_timeout`, gains `teardown: ServerTeardown | None = None` (`ServerTeardown` protocol in the adapter). `relaunch()`: under the declared-container regime, the client removes a container whose command sets a `--name` (`declared_container_name`, undecidable read as no name) with `docker rm -f -v` through `asyncio.to_thread`, its subprocess run with `os.environ | client_env`, a non-zero exit not failing the relaunch by itself. Then it calls the injected `teardown` when one is given, then the owner replaces the session. The whole teardown is bounded by `TEARDOWN_TIMEOUT_SECONDS`. Any exception, or the bound passed, gives `False`. A transport error raised inside the owner by a write to a dead server marks the session dead, so later calls return a lost connection. Keep the shapes listed in "Exception shapes" (the `initialize` timeout in an `ExceptionGroup`, the swallowed `BrokenResourceError` group) and the characterization tests of step 6 unchanged. Update the `body_error` comment.
  - `audit.py` `_probe_the_server` passes `self._execution` as `teardown`. Update the comment on the wrapped error.
  - The Docker shim of `detection_fake_targets.py` skips `--name <value>`, and its `rm` appends its arguments to a file the test reads, as in "The Docker shim of the integration tests".
  - The comment of `test_resume_earlier_checkpoint.py` (lines 9-10) and the docstring of `FakeConnect`, which describe an error the session's task groups wrap, are corrected to the shape the owner gives.
  - Docs: `README.md` (the container removed before a relaunch as well as at the end, a declared container removed before a relaunch only when its command sets a `--name` and left otherwise, and the unpinned `npx` or `uvx` command that can launch another version after a relaunch under the confined regime), `CHANGELOG.md` (Added: the relaunch. Changed: before a relaunch the auditor removes its container, or a declared container the command names, with its logs, files and anonymous volumes), `CLAUDE.md` landmine: a session is closed only by the task that opened it, which is why the session owner exists.
- **Test** (about 10 cases): a relaunch after a blocked loop with the old process group gone. A relaunch after the server exits. A relaunch that fails returns `False`. A teardown past its bound returns `False`. A write to a dead server gives a lost connection and does not cancel the caller. A named declared container is removed by the client before the injected teardown runs, as the shim's `rm` file shows. A declared container with no `--name` is relaunched with no `rm` call. One audit through `Audit` under `astream` with the fake LLM whose report names the relaunch (the proof that a relaunch asked from a graph node works). The characterization tests of step 6 and the existing shape tests pass unchanged. Under `--env` a relaunch writes no value and logs no server exception text. `test_confined_launch.py` (Docker): a blocked server replaced under the same name with the first container's kill state kept, run only if its image is present locally.
- **Verify**: the integration files with `-n 0`, the short loop, the closing checks, the fingerprint check. The maintainer then runs the honeypot gate and the judge eval on this commit (LLM cost, not run by the implementer).

### Step 8: the suites name the container and turn a server down into a failure to launch (instrument)

- **Files**: `tests/unit/cve/test_cve_launch_audit.py`, `tests/unit/cve/test_cve_exchange_log.py`, `tests/unit/cve/test_cve_launches.py`, a test over the other functions that return the `run` argv of an audited server (beside the existing backend tests under `tests/unit/cve/backends/`), `tests/unit/detection/test_detection_audit.py`, `tests/unit/nuisance/test_nuisance_audit_once.py` (+ given/then), `evals/cve/launch_audit.py`, `evals/cve/exchange_log.py`, `evals/cve/detection/audit.py`, `evals/cve/nuisance/audit.py`, `evals/cve/environments.py` (module docstring only), `docs/detection-suite-log.md`, `docs/nuisance-suite-log.md`, `docs/labeling-log.md`, `CLAUDE.md`.
- **Do**:
  - `launch_audit.py`: `named(launch) -> Launch` inserts `--name` with `f"{LABEL}-audit-{secrets.token_hex(6)}"` after `run` (`LABEL` from `evals/cve/planting_base.py`), keeps a name `declared_container_name` reads, and raises `UndecidableLaunch` (defined in this module) on undecidable, a configuration error never caught as a failure to launch. The audit connects to the named launch and gives the graph the `server_command` of the launch as the fixture wrote it. `ServerTakenAsDown` is raised after the graph returns when `any(not relaunch.succeeded for relaunch in report.relaunches)`. `LaunchAudit.relaunched_after`. Docstring updated.
  - `ExchangeLog`: `relaunched_after: list[int]`, the number of exchanges recorded at each relaunch it forwards. `Exchange` stays a tuple.
  - `detection/audit.py` turns `ServerTakenAsDown` into `LaunchError`, `nuisance/audit.py` into `LaunchFailed`, through the existing handlers. `_audit` (`detection/audit.py`) re-raises `UndecidableLaunch` beside `AuditFailed`, so `attempt_once` lets it pass, and `audit_once` (`nuisance/audit.py`) re-raises it before its `except Exception`: it stops the run as a `planting_spec` refusal does.
  - `environments.py`: the module docstring only (the launch named at audit time, the relaunch).
  - Suite logs, one entry each (dated the day of the commit), as listed for step 8 under "Living docs": the bounds and the control ping as constants of the product, a relaunch that fails as a failure to launch, the container named at audit time and why (a random token under the suite's label, which says nothing of the server or the flaw, since a container name resolves by DNS on a user-defined network), and the reversal of the detection log entry of 2026-11-16 on a server killed on memory. The nuisance entry refers to that reversal, and also states that a counted tool the auditor stops can raise no more alarm and counts as not flagged, and that the count of calls not sent is per server.
  - `docs/labeling-log.md`: one entry on the form of the entry of 2026-11-16 on the memory bound (Commit, State, What changes, Fingerprint, the four questions of ADR 016): the audited launch gains the name, and a server taken as down becomes a failure to launch, which changes which targets and servers are in N.
  - `CLAUDE.md` landmine: the name added at audit time, and the shim that skips it (changed at step 7).
- **Test** (about 13 cases): a name added under the label with a random token, a name kept, an undecidable launch raising `UndecidableLaunch`, `server_command` without the added name. Every function that returns the `run` argv of an audited server, as listed under "Tests of the suites", reads with `declared_container_name` to its own name or none, never undecidable: a case in the `_LAYOUT_BUILDERS` parametrization of `test_cve_launches.py`, and a case over the others (the backends' `*_server_args`, `Responder.server_args`, `_server_args` of `ckan_holdout.py`, `kubernetes_injection_env`, `doris_db_env`, `single_container_run_args` and `single_container_launch_args`), none of whose modules changes. Relaunch points recorded by `ExchangeLog`. `ServerTakenAsDown` raised on a failed relaunch, one after the last call included. A server taken as down is a run skipped in the detection acceptance layer and a launch failure retried in the holdout and nuisance runs. `attempt_once` and `audit_once` let `UndecidableLaunch` pass.
- **Verify**: the test files with `-n 0`, the short loop, the closing checks, the fingerprint check.

### Step 9: the relaunches and calls not sent in `ServerHealth` (instrument)

- **Files**: `tests/unit/cve/test_cve_server_health.py`, `tests/unit/detection/test_detection_holdout_audit.py` (+ given/then as needed), `evals/cve/server_health.py`, `evals/cve/launch_audit.py`, `evals/cve/audit_attempts.py`, `evals/cve/detection/holdout_audit.py`, `evals/cve/detection/session_model.py`, `evals/cve/detection/replay.py` (import only).
- **Do**: `ServerHealth` gains `relaunches` and `unsent_calls` (defaults 0 so the givens that build it stay valid), summed by `__add__`. `NO_INCIDENTS` gains the two zeros. `health_of` takes the audit report as well (relaunches from `AuditReport.relaunches`, calls not sent from the gaps' `unsent_cases` plus `unsent_chains`). `server_health.py` drops its copy of the lost-connection table and imports `is_lost_connection` from `mcp_auditor.domain.server_watch`, and `replay.py` imports the new name. Update the module docstring. The readers (`audit_attempts.py`, `holdout_audit.py`, `session_model.py`) carry the counts through, and no statistic, grading or retry reads them. The suite log entries on the two counts are written at step 10, which prints them.
- **Test** (about 5 cases): the two counts read from a report. Their sum. `NO_INCIDENTS`. A holdout audit attempt carries them. The lost-connection table read from the product.
- **Verify**: the test files with `-n 0`, the short loop, the closing checks, the fingerprint check.

### Step 10: both suites print the two counts (instrument)

- **Files**: the report and markdown tests of both suites (`tests/unit/detection/test_detection_holdout_report.py`, which tests the holdout markdown too, `tests/unit/nuisance/test_nuisance_report.py` and `test_nuisance_assembly.py`, with `support/test_nuisance_report_given.py`), `evals/cve/detection/holdout_results.py`, `holdout_assembly.py`, `holdout_report.py`, `holdout_markdown.py`, `evals/cve/nuisance/results.py`, `assembly.py`, `report.py`, `markdown.py`, `docs/detection-suite-log.md`, `docs/nuisance-suite-log.md`.
- **Do**: the run result and the markdown of the holdout run and of the nuisance run print `relaunches` and `unsent_calls` per target or per server, beside the two counts of 2026-10-28, report-only. No per-case output. Suite logs, one entry each: the two report-only counts, on the precedent of the entries of 2026-10-28. `holdout_report.py` is at 299 lines: move what the addition needs out of it rather than pass 300.
- **Test** (about 6 cases): each result carries the two counts, each markdown prints them, an old result without them still loads if the result files are read back anywhere.
- **Verify**: the test files with `-n 0`, the short loop, the closing checks, the fingerprint check.

### Step 11: the ping in the calibration check and the vet (instrument)

- **Files**: `tests/unit/detection/test_detection_calibration_check.py`, `tests/integration/test_detection_calibration_check.py`, `tests/unit/nuisance/test_nuisance_vetting.py`, `tests/unit/nuisance/test_run_nuisance_vet.py` (+ givens), `evals/cve/detection/calibration_check.py`, `evals/cve/nuisance/vetting.py`, `evals/cve/nuisance/vet_command.py`, `CLAUDE.md`, `CHANGELOG.md`.
- **Do**:
  - `calibration_check.py`: `check_target` keeps its return type and gains `on_ping: Callable[[TargetVersion, bool], None] | None = None`. When given, a ping is sent right after the handshake of each version, before the benign call, and its answer handed to the callback. `passes_calibration_check` passes a callback that prints it per target and version (both calibration-check commands reach it through `calibration_check_exit.py`, which needs no change). The pre-run checks pass none and print nothing more. Verdicts and exit codes unchanged.
  - `vetting.py`: `benign_call` keeps its return type and gains `on_ping: Callable[[AdmittedServer, bool], None] | None = None`, called after the handshake. `vet_command.py`: `VetDeps` gains `ping_answers: dict[str, bool] = field(default_factory=dict)`, keyed by server package, `default_vet_deps` passes a callback that fills it, and `vet` passes it to `_print_vet_results`, which adds `answers the ping: yes`, `no` or `unknown` (a server that never connected). The run and the gate pass none and print nothing more.
  - `CLAUDE.md`: the `vet`, `--calibration-check` and `run_detection_holdout calibration-check` lines name the ping line. `CHANGELOG.md` `[Unreleased]`: the ping line of the vet and the calibration check.
  - The kit under `evals/cve/kit/` is not touched.
- **Test** (about 8 cases): the callback of `check_target` called per version. The ping printed by `passes_calibration_check`. A target out of calibration keeps its exit code. `benign_call` with ping answered and silent, and no callback call for a server that never connected. `VetDeps.ping_answers` filled by the callback of `default_vet_deps`. The vet line with each of the three answers. The vet exit codes unchanged. The integration calibration check prints the ping line.
- **Verify**: the test files with `-n 0`, the short loop, the closing checks, the fingerprint check.

### Step 12: the replay relaunches where the run did (instrument)

- **Files**: `tests/unit/detection/test_detection_replay.py` (+ given/then), `tests/integration/test_detection_replay.py` (+ given/then), `tests/integration/support/detection_replay_read_server.py` (`hang_on_call=N`), `evals/cve/detection/replay.py`, `evals/cve/detection/audit.py`, `evals/cve/environments.py` (the comment on the replay's timeout only), `docs/labeling-log.md`, `docs/detection-suite-log.md`, `README.md`, `CONTRIBUTING.md`.
- **Do**: everything listed in Part 3. `RunToCheck.relaunched_after` (empty default) filled by `detection/audit.py` from `LaunchAudit`. `_run_patched` connects to `named(planted.launch)`, sends a control ping, and re-raises `UndecidableLaunch` before its `except Exception`. In `_sent_again`, the rule at a relaunch point is evaluated before any other: the patched version's response, even a lost connection or a timeout, is kept as the call's output, then the patched version is relaunched and the replay goes on (a failed relaunch is `LAUNCH_FAILED`). Nowhere else does it relaunch. Elsewhere a lost connection fails the attempt as today, and a timeout on a version that answered the control ping is followed by a ping, no answer failing with `ReplayAttemptFailure.STOPPED_ANSWERING`. The truncation rule stays as defensive code, reset at each relaunch point, with its existing tests, and a comment says a real run no longer reaches it. `_sent_a_call` becomes `bool(step.outputs)`. `replay_with_causes` takes `connect` as a dependency. The module docstring and comments rewritten. Check that the new cause reaches the holdout report beside the two others (add it there if the causes are listed by hand). The labeling log entry as in "Labeling log", with the patched version silent to the control ping whose timeouts all count as responses. A new entry in the detection suite log for the replay's new cause. The replay sentence of `README.md` and `CONTRIBUTING.md`.
- **Test** (about 10 cases): unit, through the injected `connect` and the fake client: relaunches at the run's points and nowhere else. A lost connection and a timeout at a relaunch point kept as the call's output, then the relaunch, then the next call sent. `STOPPED_ANSWERING` at another call. A timeout with an answered ping left as answered. A relaunch that fails is `LAUNCH_FAILED`. The truncation reset at a relaunch point. `UndecidableLaunch` raised out of `_run_patched`, not read as `LAUNCH_FAILED`. Integration, with `hang_on_call`: the same three main cases against a real stdio server.
- **Verify**: the test files with `-n 0`, the short loop, the closing checks, the fingerprint check.

### Step 13: the relaunch on real fixtures (instrument tests)

- **Files**: `tests/integration/test_cve_relaunch.py` (+ given/then), `CLAUDE.md`.
- **Do**: the four cases of Part 4 (the acceptance Kubernetes target with the recorded `kubectl_generic` call, asserting first the timeout and the unanswered ping. A launch that joins a namespace holder reaching its sentinel again. A launch that already carries a name and `--rm` relaunched under that name. A named `--rm` launch whose container ends without the auditor's removal, relaunched at once), through an `AuditedServer` with a short tool call timeout. The file runs only behind `CVE_RELAUNCH=1`, on the model of `NUISANCE_DORIS=1`. The test builds nothing: it skips without Docker and skips, naming the build command, when an image the preflight expects is absent. `CLAUDE.md`: the integration tests line names `test_cve_relaunch.py` (runs only behind `CVE_RELAUNCH=1`, needs Docker and the preflight's images, skips without them, builds nothing).
- **Test**: the four cases. Without `CVE_RELAUNCH=1`, or on a machine without the images, all skip.
- **Verify**: `CVE_RELAUNCH=1 uv run pytest tests/integration/test_cve_relaunch.py -n 0` (it skips unless the images are present, never build them), the closing checks, the fingerprint check. The maintainer then runs the calibration checks and the vet of "Verification" (Docker, no LLM).
