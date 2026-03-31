# Multi-step attack chains (§11)

**ADR:** `docs/adr/010-multi-step-attack-chains.md`

## Context

Single-payload testing can't express attacks that require reconnaissance before exploitation — e.g., probing a tool to discover internal paths, then using that knowledge to attempt traversal. Multi-step chains add a bounded observe-decide-act loop as a second phase within each tool's audit, after the existing single-step testing.

Chains call the same tool multiple times with different arguments. Each step's payload depends on the previous step's response. The chain ends when the agent decides there's nothing more to exploit (dead end) or hits the max depth.

## Approach

1. **Domain model**: new types (`ChainStep`, `ChainGoal`, `StepObservation`, `AttackChain`) separate from `TestCase`. `ToolReport` extended with an optional `chains` field.
2. **Prompts**: four new pure functions — chain planning, step planning, step observation, chain judgment.
3. **Chain subgraph**: a new subgraph with two nested loops — outer loop over chains, inner loop over steps within a chain.
4. **Main graph wiring**: chain subgraph inserted between `audit_tool` and `build_tool_report`, with conditional edge to skip when chains are disabled.
5. **CLI**: `--chains N` flag (default 0 initially — opt-in until evals validate the feature).
6. **Rendering**: chains displayed as a separate section per tool in markdown and JSON.
7. **Honeypot + evals**: new `chain_server.py` with tools that require multi-step exploitation, ground truth, chain delta recall metric.

## Domain model

### New types in `src/mcp_auditor/domain/models.py`

```python
class StepObservation(BaseModel):
    """LLM output after observing a chain step's response."""
    observation: str
    should_continue: bool
    next_step_hint: str = ""

class ChainStep(BaseModel):
    """A single step in a multi-step attack chain."""
    payload: AuditPayload
    response: str | None = None
    error: str | None = None
    observation: str = ""

class ChainGoal(BaseModel):
    """LLM-generated plan for one attack chain."""
    description: str
    category: AuditCategory          # informative — the judge's EvalResult.category is authoritative
    first_step: AuditPayload

class ChainPlanBatch(BaseModel):
    """Wrapper for structured output (same pattern as TestCaseBatch)."""
    chains: list[ChainGoal]

class AttackChain(BaseModel):
    """A completed multi-step attack chain with a final verdict."""
    goal: ChainGoal
    steps: list[ChainStep]
    eval_result: EvalResult | None = None
```

Place after `TestCase`, before `TokenUsage`.

### `ToolReport` extension

```python
class ToolReport(BaseModel):
    tool: ToolDefinition
    cases: list[TestCase]
    chains: list[AttackChain] = []
```

Default `[]` means all existing code that creates `ToolReport(tool=..., cases=...)` continues to work without changes.

### `AuditReport.findings`

Update the `findings` property to include chain findings:

```python
@property
def findings(self) -> list[EvalResult]:
    results = []
    for tr in self.tool_reports:
        for case in tr.cases:
            if case.eval_result and case.eval_result.verdict == EvalVerdict.FAIL:
                results.append(case.eval_result)
        for chain in tr.chains:
            if chain.eval_result and chain.eval_result.verdict == EvalVerdict.FAIL:
                results.append(chain.eval_result)
    return results
```

## Prompts

Four new functions in a new `src/mcp_auditor/graph/chain_prompts.py` file (`prompts.py` is 198 lines; four prompt functions with helpers would push it well past 300).

### `build_chain_planning_prompt`

```python
def build_chain_planning_prompt(
    tool: ToolDefinition,
    single_step_cases: list[TestCase],
    attack_context: AttackContext,
    chain_budget: int,
) -> str:
```

The prompt:
- Describes the tool (name, description, schema).
- Summarizes single-step results: what errors were observed, what paths/values appeared, which categories failed. Uses a helper `_format_single_step_summary(cases)` that extracts interesting signals (errors, response snippets, verdicts) — not the full case dump.
- Includes attack context if non-empty (reuse `build_context_section` — rename from `_build_context_section` in `prompts.py` since it's now shared across modules).
- Asks the LLM to produce up to `chain_budget` chain plans, each with a goal description, a target category, and a first step (AuditPayload). Instructs the LLM to focus on vulnerabilities that require multiple steps — probing then exploiting, discovering internal state then using it.
- Explicitly says: "Do not plan chains for things that can be tested with a single request."

### `build_step_planning_prompt`

```python
def build_step_planning_prompt(
    tool: ToolDefinition,
    goal: ChainGoal,
    chain_history: list[ChainStep],
    observation_hint: str,
) -> str:
```

The prompt:
- Describes the tool and the chain's goal.
- Lists the chain history: each previous step's payload, response/error, and observation.
- Includes the previous observation's `next_step_hint` if non-empty.
- Asks for the next `AuditPayload` — what to call the tool with next, and why.

Output schema: `AuditPayload` (reused from single-step).

### `build_step_observation_prompt`

```python
def build_step_observation_prompt(
    tool: ToolDefinition,
    goal: ChainGoal,
    chain_history: list[ChainStep],
    latest_response: str | None,
    latest_error: str | None,
) -> str:
```

The prompt:
- Shows the chain's goal and full history.
- Shows the latest step's response/error.
- Asks two questions: (1) What did this response reveal? (2) Is there a promising next step, or is this a dead end?
- Does NOT ask for a PASS/FAIL verdict.

Output schema: `StepObservation`.

### `build_chain_judge_prompt`

```python
def build_chain_judge_prompt(
    tool: ToolDefinition,
    chain: AttackChain,
) -> str:
```

The prompt:
- Describes the tool.
- Shows the chain goal and the full step sequence (payload → response/error → observation for each step).
- Asks: "Considering the entire sequence of interactions, was a vulnerability demonstrated?"
- Uses the same verdict rules as `build_judge_prompt` (FAIL/PASS, severity, category-specific guidance) but adapted for multi-step context.
- Key instruction: "Judge the chain as a whole. Individual steps may appear benign — the vulnerability is in the progression."

Output schema: `EvalResult` (reused — same fields as single-step judgment). The `payload` field should contain the arguments from the final (most significant) step in the chain, since `EvalResult.payload` is typed `dict[str, Any]` (a single argument set). The `tool_name` comes from the chain's tool.

**Decision**: Reuse `EvalResult` (no `ChainEvalResult`). The `payload` field holds the final step's arguments. Per-step detail lives in `AttackChain.steps`, which is always available in rendering and JSON output. `AuditReport.findings` returns `EvalResult` objects — consumers that need chain context should iterate `ToolReport.chains` directly. This keeps the findings aggregation and exit-code logic unchanged.

## Graph state

### `ChainAuditState` in `src/mcp_auditor/graph/state.py`

```python
class ChainAuditState(TypedDict):
    current_tool: ToolDefinition
    judged_cases: list[TestCase]             # single-step results, read-only context
    attack_context: AttackContext
    chain_budget: int
    max_chain_steps: int
    pending_chains: list[ChainGoal]
    current_chain_goal: ChainGoal | None
    current_chain_steps: list[ChainStep]
    current_step_payload: AuditPayload | None
    current_observation: StepObservation | None
    completed_chains: Annotated[list[AttackChain], operator.add]
    token_usage: Annotated[list[TokenUsage], operator.add]

class ChainAuditInput(TypedDict):
    current_tool: ToolDefinition
    judged_cases: list[TestCase]
    attack_context: AttackContext
    chain_budget: int
    max_chain_steps: int
```

### `GraphState` additions

```python
class GraphState(TypedDict):
    # ... existing fields ...
    chain_budget: int
    max_chain_steps: int
    completed_chains: list[AttackChain]      # no reducer — overwritten per tool
```

**Reducer asymmetry by design**: `ChainAuditState.completed_chains` uses `operator.add` so that each `make_judge_chain` call appends to the list within a single subgraph invocation. `GraphState.completed_chains` has no reducer — it is overwritten wholesale by the subgraph output each time a new tool is processed (same pattern as `judged_cases`).

## Chain subgraph nodes

New file: `src/mcp_auditor/graph/chain_nodes.py`. Keeps `nodes.py` under 300 lines.

### `make_plan_chains(llm: LLMPort)`

Reads tool, judged_cases, attack_context, chain_budget from state. Calls `build_chain_planning_prompt` → `llm.generate_structured(prompt, ChainPlanBatch)`. Returns `{"pending_chains": batch.chains, "token_usage": [usage]}`.

### `prepare_chain`

Synchronous pure function. Pops first from `pending_chains`, sets `current_chain_goal`, clears `current_chain_steps`, and sets `current_step_payload` to `goal.first_step`. The first step skips `plan_step` (the payload comes from the chain plan); subsequent steps go through `plan_step → execute_step → observe_step`.

```python
def prepare_chain(state: dict[str, Any]) -> dict[str, Any]:
    pending = list(state["pending_chains"])
    goal = pending.pop(0)
    return {
        "pending_chains": pending,
        "current_chain_goal": goal,
        "current_chain_steps": [],
        "current_step_payload": goal.first_step,
    }
```

Note: `prepare_chain` is synchronous — it's a pure function with no I/O.

### `make_execute_step(mcp_client: MCPClientPort)`

Reads `current_step_payload` from state. Calls `mcp_client.call_tool(payload.tool_name, payload.arguments)`. Creates a `ChainStep` with the payload + response/error (observation empty for now). Appends to `current_chain_steps`.

```python
def make_execute_step(mcp_client: MCPClientPort):
    async def execute_step(state: dict[str, Any]) -> dict[str, Any]:
        payload = state["current_step_payload"]
        tool = state["current_tool"]
        if payload.tool_name != tool.name:
            payload = payload.model_copy(update={"tool_name": tool.name})
        response = await mcp_client.call_tool(payload.tool_name, payload.arguments)
        step = ChainStep(payload=payload)
        if response.is_error:
            step = step.model_copy(update={"error": response.content})
        else:
            step = step.model_copy(update={"response": response.content})
        steps = list(state["current_chain_steps"]) + [step]
        return {"current_chain_steps": steps}
    return execute_step
```

Chains are intra-tool: if the LLM produces a payload targeting a different tool, `execute_step` corrects the `tool_name` to the current tool. This enforces the "same tool, different arguments" invariant without crashing.

### `make_observe_step(llm: LLMPort)`

Reads the latest step (last in `current_chain_steps`), the goal, and chain history. Calls `build_step_observation_prompt` → `llm.generate_structured(prompt, StepObservation)`. Updates the latest step's `observation` field. Returns the observation for routing.

```python
def make_observe_step(llm: LLMPort):
    async def observe_step(state: dict[str, Any]) -> dict[str, Any]:
        steps = list(state["current_chain_steps"])
        latest = steps[-1]
        goal = state["current_chain_goal"]
        tool = state["current_tool"]
        prompt = build_step_observation_prompt(
            tool=tool, goal=goal, chain_history=steps[:-1],
            latest_response=latest.response, latest_error=latest.error,
        )
        obs, usage = await llm.generate_structured(prompt, StepObservation)
        updated_step = latest.model_copy(update={"observation": obs.observation})
        steps[-1] = updated_step
        return {
            "current_chain_steps": steps,
            "current_observation": obs,
            "token_usage": [usage],
        }
    return observe_step
```

### `make_plan_step(llm: LLMPort)`

Reads goal, chain history, and current observation hint. Calls `build_step_planning_prompt` → `llm.generate_structured(prompt, AuditPayload)`. Returns `{"current_step_payload": payload, "token_usage": [usage]}`.

### `make_judge_chain(llm: LLMPort)`

Builds an `AttackChain(goal=goal, steps=steps)`, calls `build_chain_judge_prompt` → `llm.generate_structured(prompt, EvalResult)`. Attaches the eval_result and appends to `completed_chains`.

```python
def make_judge_chain(llm: LLMPort):
    async def judge_chain(state: dict[str, Any]) -> dict[str, Any]:
        goal = state["current_chain_goal"]
        steps = state["current_chain_steps"]
        tool = state["current_tool"]
        chain = AttackChain(goal=goal, steps=steps)
        prompt = build_chain_judge_prompt(tool=tool, chain=chain)
        eval_result, usage = await llm.generate_structured(prompt, EvalResult)
        judged_chain = chain.model_copy(update={"eval_result": eval_result})
        return {
            "completed_chains": [judged_chain],
            "current_chain_goal": None,
            "current_chain_steps": [],
            "token_usage": [usage],
        }
    return judge_chain
```

### Routing functions

```python
def route_after_planning(state: dict[str, Any]) -> str:
    if state["pending_chains"]:
        return "prepare_chain"
    return END

def route_after_observe(state: dict[str, Any]) -> str:
    obs = state["current_observation"]
    steps = state["current_chain_steps"]
    max_steps = state["max_chain_steps"]
    if obs.should_continue and len(steps) < max_steps:
        return "plan_step"
    return "judge_chain"

def route_after_judge(state: dict[str, Any]) -> str:
    if state["pending_chains"]:
        return "prepare_chain"
    return END
```

## Chain subgraph builder

New function in `src/mcp_auditor/graph/builder.py`:

```python
def _build_chain_audit_subgraph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    judge_llm: LLMPort,
) -> CompiledStateGraph:
```

Uses `llm` for planning and observation, `judge_llm` for `make_judge_chain` (same separation as single-step audit where `judge_llm` handles `make_judge_response`).

Topology:

```
START → plan_chains → prepare_chain → execute_step → observe_step
                          ↑                              |
                          |      [continue] → plan_step → execute_step (loop)
                          |      [stop] → judge_chain
                          |                    |
                          └── [more chains] ←──┘
                              [done] → END
```

Edges:
- `START → plan_chains`
- `plan_chains → route_after_planning` (if no chains planned → END, else → prepare_chain)
- `prepare_chain → execute_step`
- `execute_step → observe_step`
- `observe_step → route_after_observe` (→ plan_step or → judge_chain)
- `plan_step → execute_step`
- `judge_chain → route_after_judge` (→ prepare_chain or → END)

### Main graph update

```python
# In build_graph:
chain_subgraph = _build_chain_audit_subgraph(llm, mcp_client, effective_judge)

builder.add_node("chain_audit_tool", chain_subgraph)
# Replace: builder.add_edge("audit_tool", "build_tool_report")
# With:
builder.add_conditional_edges("audit_tool", route_to_chains_or_report)
builder.add_edge("chain_audit_tool", "build_tool_report")
# route_to_chains_or_report returns "chain_audit_tool" or "build_tool_report"
```

Note: `_build_chain_audit_subgraph` needs `effective_judge` (the judge LLM) for `make_judge_chain`, same pattern as the audit subgraph passing `judge_llm` to `make_judge_response`.

Routing function (in `chain_nodes.py` — keeps all chain logic in one module, avoids importing chain types into `nodes.py`):

```python
def route_to_chains_or_report(state: dict[str, Any]) -> str:
    if state.get("chain_budget", 0) > 0:
        return "chain_audit_tool"
    return "build_tool_report"
```

### `build_tool_report` update (in `nodes.py`, where it currently lives)

```python
async def build_tool_report(state: dict[str, Any]) -> dict[str, Any]:
    tool = state["current_tool"]
    cases = state["judged_cases"]
    chains = state.get("completed_chains", [])
    report = ToolReport(tool=tool, cases=cases, chains=chains)
    return {"tool_reports": [report]}
```

### Dry-run graph

No chains in dry-run. The `chain_budget` field exists in state but is 0 by default. No changes to dry-run graph builder.

## CLI

In `src/mcp_auditor/cli.py`:

```python
@click.option("--chains", default=0, type=click.IntRange(min=0), help="Attack chains per tool (0 = disabled). Each chain adds several LLM calls.")
```

Add to `ExecutionConfig`:

```python
@dataclass(frozen=True)
class ExecutionConfig:
    budget: int
    chains: int
    resume: bool
    dry_run: bool
```

Pass to initial state:

```python
initial_state = {
    "target": target_str,
    "test_budget": config.execution.budget,
    "chain_budget": config.execution.chains,
    "max_chain_steps": 3,
    "attack_context": AttackContext(),
}
```

`max_chain_steps` is hardcoded at 3 initially (not a CLI flag). Can be exposed later if needed.

**LLM cost note**: each chain uses up to `1 (planning) + max_chain_steps × 2 (plan_step + observe) + 1 (judge)` LLM calls. Plus the shared `plan_chains` call. With `--chains 2` and `max_chain_steps=3`, that's up to 17 LLM calls per tool. The `--chains` help text should mention this: `"Attack chains per tool (0 = disabled). Each chain adds several LLM calls."`

## Rendering

### Markdown (`render_markdown`)

After the single-step results section for each tool, add a chains section:

```python
def _render_chain_section(chain: AttackChain) -> str:
    # "### CHAIN: [goal description]"
    # "**Category**: [category]"
    # "**Steps**:"
    # "  1. [payload] → [response snippet] — [observation]"
    # "  2. [payload] → [response snippet] — [observation]"
    # "**Verdict**: FAIL (high)"
    # "**Justification**: ..."
```

### JSON (`render_json`)

`model_dump(mode="json")` already handles `chains: list[AttackChain]` since it defaults to `[]`. `_inject_owasp_into_json` needs to also iterate `tool_report["chains"]` and inject OWASP mapping on each chain's `eval_result` (same pattern as cases).

### `_summarize_tool_report` (in `rendering.py`)

The private function `_summarize_tool_report` currently counts only `cases`. Update it to also count chain verdicts:

```python
def _summarize_tool_report(tool_report: ToolReport) -> ToolSummary:
    judged_cases = [c for c in tool_report.cases if c.eval_result is not None]
    judged_chains = [ch for ch in tool_report.chains if ch.eval_result is not None]
    all_results = (
        [c.eval_result for c in judged_cases if c.eval_result]
        + [ch.eval_result for ch in judged_chains if ch.eval_result]
    )
    passed = sum(1 for r in all_results if r.verdict == EvalVerdict.PASS)
    severity_counts = Counter(
        r.severity for r in all_results if r.verdict == EvalVerdict.FAIL
    )
    return ToolSummary(
        name=tool_report.tool.name,
        judged=len(all_results),
        passed=passed,
        failed=len(all_results) - passed,
        severity_counts=severity_counts,
    )
```

Also update `_render_summary_section` to count chains in `total_cases`:

```python
total_cases = sum(len(tr.cases) + len(tr.chains) for tr in report.tool_reports)
```

### Console / stream handler

`AuditProgressReporter` handles events by `(namespace, node_name)`. The chain subgraph is nested inside the main graph as `"chain_audit_tool"`, so its events arrive with a two-level namespace (the outer per-tool subgraph + `"chain_audit_tool"`). Concretely, chain node events have `len(namespace) >= 2`.

Add a `_on_chain_event` handler in `AuditProgressReporter`:

```python
def _on_chain_event(self, node_name: str, state_update: dict[str, Any]) -> None:
    if node_name == "plan_chains":
        pending = state_update.get("pending_chains", [])
        if pending:
            self._display.print_info(f"Planning {len(pending)} attack chain(s)")
    elif node_name == "execute_step":
        steps = state_update.get("current_chain_steps", [])
        if steps:
            self._display.print_info(f"  Chain step {len(steps)} executed")
    elif node_name == "judge_chain":
        chains = state_update.get("completed_chains", [])
        if chains:
            last = chains[-1]
            verdict = last.eval_result.verdict if last.eval_result else "?"
            self._display.print_info(f"  Chain judged: {verdict}")
```

Update `on_stream_event` to dispatch based on namespace depth:

```python
if namespace == ():
    self._on_parent_event(node_name, state_update)
elif len(namespace) == 1:
    self._on_subgraph_event(node_name, state_update)
else:  # len >= 2: chain subgraph events
    self._on_chain_event(node_name, state_update)
```

`AuditDisplay` does not have a `print_info` method — add one as a thin wrapper: `def print_info(self, message: str) -> None: self._console.print(message)`. Chain progress does not use the spinner/advance pattern — it's plain log lines, because chains are fewer and slower than single-step cases.

## Honeypot

### `tests/chain_server.py`

Two tools designed for intra-tool multi-step exploitation:

```python
# Non-guessable base path — only revealed by action="list".
# This ensures single-step blind traversal cannot succeed by guessing the prefix.
BASE_DIR = "/srv/app-7f3a9c2e/workspace"

@app.tool()
def file_manager(action: str, path: str = ".") -> str:
    """Manage files: list directory contents or read a file."""
    # action="list": returns directory listing that reveals BASE_DIR:
    #   "Directory listing of /srv/app-7f3a9c2e/workspace:\n  config.yml\n  data/\n  logs/"
    # action="read": requires path to start with BASE_DIR. Rejects anything else
    #   ("Access denied: path must be within the workspace directory").
    #   BUT: does not normalize ".." segments, so:
    #     path="/srv/app-7f3a9c2e/workspace/../../etc/hostname" → reads /etc/hostname (traversal!)
    #   Single-step blind traversal ("../../etc/passwd", "/etc/passwd") is rejected
    #   because neither starts with BASE_DIR.
    # Multi-step: list → discover BASE_DIR → read with BASE_DIR + "/../../etc/hostname".

@app.tool()
def key_value_store(operation: str, key: str = "", value: str = "") -> str:
    """Simple key-value store: list_keys, get, set."""
    # operation="list_keys": reveals key names including "admin_token"
    # operation="get" with key="admin_token": returns sensitive data
    # Single-step with guessed keys fails (returns "key not found").
    # Multi-step: list_keys → discover admin_token → get it.
```

### Ground truth

In `evals/ground_truth.py`:

```python
CHAIN_GROUND_TRUTH: GroundTruth = {
    # file_manager: traversal only via multi-step (INPUT_VALIDATION: ".." not normalized)
    ("file_manager", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL, # chain-only
    ("file_manager", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,    # chain-only
    ("file_manager", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("file_manager", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("file_manager", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    # key_value_store: info leak only via multi-step
    ("key_value_store", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL, # chain-only
    ("key_value_store", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("key_value_store", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("key_value_store", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("key_value_store", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
}
```

Mark entries that are chain-only in a separate set or with a comment. The eval runner measures:
- **Single-step recall** on chain honeypot (should be low — these vulns aren't detectable single-step).
- **Chain recall** on chain honeypot (should catch the chain-only findings).
- **Chain delta recall** = chain recall - single-step recall.

### Eval runner updates

Add `CHAIN_SERVER` path and `CHAIN_GROUND_TRUTH` to `run_evals.py`. Add a new `HoneypotConfig` for the chain server with `chain_budget` parameter. Update `_run_single_honeypot` to accept and pass `chain_budget` and `max_chain_steps` in the initial state (currently hardcoded without these fields — they must be added for chain honeypot runs, and set to 0 for existing honeypots to preserve current behavior). Compute standard metrics + chain delta recall.

## Files to modify

| File | Change |
|------|--------|
| `src/mcp_auditor/domain/models.py` | Add `StepObservation`, `ChainStep`, `ChainGoal`, `ChainPlanBatch`, `AttackChain`. Add `chains` field to `ToolReport`. Update `AuditReport.findings`. |
| `src/mcp_auditor/domain/__init__.py` | Export new types |
| `src/mcp_auditor/graph/state.py` | Add `ChainAuditState`, `ChainAuditInput`. Add `chain_budget`, `max_chain_steps`, `completed_chains` to `GraphState`. |
| `src/mcp_auditor/graph/prompts.py` | Rename `_build_context_section` → `build_context_section` (now shared with `chain_prompts.py`). |
| `src/mcp_auditor/graph/chain_prompts.py` | **New file.** `build_chain_planning_prompt`, `build_step_planning_prompt`, `build_step_observation_prompt`, `build_chain_judge_prompt` + helpers. |
| `src/mcp_auditor/graph/chain_nodes.py` | **New file.** All chain nodes, routing functions, and `route_to_chains_or_report`. |
| `src/mcp_auditor/graph/builder.py` | Add `_build_chain_audit_subgraph`. Wire into main graph with conditional edge (replace `audit_tool -> build_tool_report` edge with `audit_tool -> conditional -> chain_audit_tool / build_tool_report`). |
| `src/mcp_auditor/graph/nodes.py` | Update `build_tool_report` to include chains. |
| `src/mcp_auditor/cli.py` | Add `--chains` flag, `chain_budget` / `max_chain_steps` in initial state and config. |
| `src/mcp_auditor/config_file.py` | Add `"chains"` to `KNOWN_KEYS` so it can be set in `.mcp-auditor.yml`. |
| `src/mcp_auditor/domain/rendering.py` | Add chain rendering in markdown. Update JSON OWASP injection for chains. Update `summarize_tools` for chains. |
| `src/mcp_auditor/console.py` | Add `print_info` method to `AuditDisplay`. |
| `src/mcp_auditor/stream_handler.py` | Handle chain subgraph events. |
| `tests/chain_server.py` | **New file.** Honeypot for multi-step exploitation. |
| `evals/ground_truth.py` | Add `CHAIN_GROUND_TRUTH`. |
| `evals/run_evals.py` | Add chain honeypot config, chain delta recall metric. |
| Tests (multiple files) | See test scenarios below. |

## What stays unchanged

- `src/mcp_auditor/domain/ports.py` — no new port, chains use `LLMPort` and `MCPClientPort`
- `src/mcp_auditor/domain/category_guidance.py` — category definitions are orthogonal
- `src/mcp_auditor/adapters/` — no adapter changes
- `src/mcp_auditor/config.py` — no new settings (chain budget is a CLI flag, config file support via `config_file.py`)
- Existing single-step nodes and tests — untouched except `build_tool_report` and the `_build_context_section` → `build_context_section` rename in `prompts.py`
- Existing evals and ground truth — chain evals are additive

## Edge cases

- **`--chains 0` (default)**: conditional edge skips chain subgraph entirely. Zero overhead. `completed_chains` stays `[]`. `ToolReport.chains` stays `[]`. All rendering, findings, exit codes behave exactly as today.
- **Chain planner returns 0 chains**: `plan_chains` produces an empty `ChainPlanBatch`. Routing goes to END. No wasted LLM calls beyond the planning call.
- **All chain steps are dead ends**: `observe_step` returns `should_continue=False` on step 1. Chain goes straight to `judge_chain`. The judge likely returns PASS (no vulnerability demonstrated). This is correct behavior, not a failure.
- **Max steps reached without clear exploit**: `observe_step` would continue, but step count equals `max_chain_steps`. Routing forces `judge_chain`. The judge evaluates what was found — partial progress may still constitute a finding.
- **Tool call timeout during chain**: `execute_step` uses the same `MCPClientPort` as single-step. Timeout produces `ToolResponse(is_error=True)`. The observe step sees this and likely stops the chain.
- **Single tool server**: chains still run (if budget > 0). The single tool is called multiple times — this is the intended behavior.
- **`--resume`**: `chain_budget` and `max_chain_steps` are in `GraphState`, so the LangGraph checkpointer persists them. The chain subgraph has its own `ChainAuditState` which is also checkpointed. No special resume handling needed — the graph resumes mid-chain if interrupted. Note: the chain subgraph is doubly nested (main → audit_tool → chain_audit_tool), which is a less-common LangGraph checkpoint path — a dedicated resume mid-chain test validates this (see "Unit: resume mid-chain" in test scenarios).

## Test scenarios

New chain node tests go in `tests/unit/test_chain_nodes.py` with corresponding `tests/unit/support/test_chain_nodes_given.py` and `tests/unit/support/test_chain_nodes_then.py` (per CLAUDE.md Given/When/Then pattern). Chain model tests go in the existing `test_models.py`. Chain prompt tests go in the existing `test_prompts.py`. Chain rendering tests go in the existing `test_rendering.py` with its existing given/then files.

### Unit: domain models

- `ChainStep`, `ChainGoal`, `AttackChain` construct and serialize correctly.
- `ToolReport` with non-empty `chains` serializes/deserializes.
- `AuditReport.findings` includes chain FAIL verdicts.
- `AuditReport.findings` excludes chain PASS verdicts.
- `StepObservation` parses with and without `next_step_hint`.
- `ChainPlanBatch` wraps a list of `ChainGoal`.

### Unit: prompts

- `build_chain_planning_prompt`: includes tool name, single-step summary, attack context, chain budget.
- `build_step_planning_prompt`: includes goal, chain history with observations, hint.
- `build_step_observation_prompt`: includes goal, chain history, latest response/error.
- `build_chain_judge_prompt`: includes tool, full chain steps, asks for PASS/FAIL.

### Unit: chain nodes

- `make_plan_chains`: given FakeLLM returning `ChainPlanBatch` with 2 goals → state has `pending_chains` of length 2.
- `prepare_chain`: pops first goal, sets `current_chain_goal`, clears steps, sets `current_step_payload` to `goal.first_step`.
- `make_execute_step`: calls MCP, records response/error in `ChainStep`, appends to `current_chain_steps`.
- `make_execute_step` with wrong tool_name: if payload targets a different tool, `execute_step` corrects `tool_name` to the current tool and the call still goes through.
- `make_observe_step`: calls LLM, updates latest step's observation, sets `current_observation`.
- `make_plan_step`: calls LLM, returns `current_step_payload`.
- `make_judge_chain`: calls LLM, creates `AttackChain` with `eval_result`, appends to `completed_chains`.

### Unit: routing

- `route_after_observe`: returns `"plan_step"` when `should_continue=True` and steps < max.
- `route_after_observe`: returns `"judge_chain"` when `should_continue=False`.
- `route_after_observe`: returns `"judge_chain"` when steps == max (even if `should_continue=True`).
- `route_after_judge`: returns `"prepare_chain"` when pending chains remain.
- `route_after_judge`: returns END when no pending chains.
- `route_to_chains_or_report`: returns `"chain_audit_tool"` when `chain_budget > 0`.
- `route_to_chains_or_report`: returns `"build_tool_report"` when `chain_budget == 0`.

### Unit: graph integration

- Single tool with `chain_budget=0` → graph completes, `ToolReport.chains` is `[]`.
- Single tool with `chain_budget=1` and a FakeLLM sequence for one 2-step chain → `ToolReport.chains` has one `AttackChain` with 2 steps and an `eval_result`.
- Token usage includes chain LLM calls.

### Unit: rendering

- Markdown with chains: chain section appears after single-step section.
- Markdown without chains: no chain section.
- JSON with chains: `chains` field present in tool reports.
- `summarize_tools` includes chain findings in counts.

### Unit: resume mid-chain

- Single tool with `chain_budget=1`: run graph with a checkpointer, interrupt after `execute_step` (first chain step), resume from checkpoint. After resume, the chain completes with observation → judgment. Verifies that doubly-nested subgraph state (main graph → audit_tool → chain_audit_tool) survives checkpoint round-trip.

### Integration: chain honeypot

- Connect to `chain_server.py`, call `file_manager` and `key_value_store` with known payloads. Verify the tools behave as designed (reject blind traversal, allow discovery-based traversal).

## Verification

```bash
uv run pytest tests/unit -x                     # All unit tests
uv run pytest tests/integration -x              # Integration tests
uv run ruff check .                             # Lint
uv run ruff format .                            # Format
uv run pyright                                  # Type check
uv run pytest                                   # All tests
uv run python -m evals.run_evals                # E2E evals (after honeypot is ready)
```

## Implementation steps

### Step 1: Domain model, prompts, and their tests

Add the new chain types to the domain layer, extend `ToolReport` and `AuditReport.findings`, update exports, and add the four new chain prompt functions. Write tests first for both models and prompts.

**Files**:
- `tests/unit/test_models.py` (modify -- add chain model tests)
- `tests/unit/test_prompts.py` (modify -- add chain prompt tests)
- `src/mcp_auditor/domain/models.py` (modify -- add `StepObservation`, `ChainStep`, `ChainGoal`, `ChainPlanBatch`, `AttackChain`; add `chains` field to `ToolReport`; update `AuditReport.findings`)
- `src/mcp_auditor/domain/__init__.py` (modify -- export new types)
- `src/mcp_auditor/graph/prompts.py` (modify -- rename `_build_context_section` → `build_context_section`)
- `src/mcp_auditor/graph/chain_prompts.py` (new -- prompts.py is 198 lines; four new prompt functions with helpers would push it well past 300, so chain prompts go in a separate file)

**Do**:

*Tests (write first)*:

In `test_models.py`, add tests for the new chain types:
- `AttackChain` constructs with goal, steps list, and optional `eval_result`.
- `ToolReport` with non-empty `chains` serializes and deserializes via `model_dump`/`model_validate`.
- `AuditReport.findings` includes chain FAIL verdicts (create a `ToolReport` where `chains` has one `AttackChain` with `eval_result.verdict == FAIL`).
- `AuditReport.findings` excludes chain PASS verdicts.
- `StepObservation` parses with and without `next_step_hint`.
- `ChainPlanBatch` wraps a list of `ChainGoal`.

In `test_prompts.py`, add tests for each of the four chain prompt functions:
- `build_chain_planning_prompt`: assert it includes tool name, a summary of single-step results (not full dump), attack context when non-empty, chain budget number.
- `build_step_planning_prompt`: assert it includes goal description, chain history with observations, observation hint from previous step.
- `build_step_observation_prompt`: assert it includes goal description, latest response/error text, chain history.
- `build_chain_judge_prompt`: assert it includes tool name, full chain steps with payloads and responses, asks for verdict.

*Production code*:

In `models.py`, add `StepObservation`, `ChainStep`, `ChainGoal`, `ChainPlanBatch`, `AttackChain` after `TestCase` and before `TokenUsage` (exact field definitions in the plan's "Domain model" section). Add `chains: list[AttackChain] = []` to `ToolReport`. Update `AuditReport.findings` to also iterate `tr.chains` and include chain FAIL verdicts (see plan's `AuditReport.findings` code block).

In `__init__.py`, export `StepObservation`, `ChainStep`, `ChainGoal`, `ChainPlanBatch`, `AttackChain`.

Create `src/mcp_auditor/graph/chain_prompts.py` with the four prompt functions. Exact signatures are in the plan's "Prompts" section. Key helpers to extract into private functions:
- `_format_single_step_summary(cases: list[TestCase]) -> str`: extracts interesting signals (errors, response snippets, verdicts) from single-step cases -- not the full case dump.
- `_format_chain_history(steps: list[ChainStep]) -> str`: renders each step's payload, response/error, and observation.
Rename `_build_context_section` → `build_context_section` in `graph/prompts.py` (drop the underscore — it's now shared across modules). Update the single existing call site in `prompts.py`. Import `build_context_section` in `chain_prompts.py`.

**Test**: Run model and prompt tests to confirm they fail first (red), then pass after implementation (green).

**Verify**:
```bash
uv run pytest tests/unit/test_models.py tests/unit/test_prompts.py -x
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

---

### Step 2: Chain nodes, state, routing, and their tests

Build the chain subgraph nodes, state types, and routing functions. Write tests using fakes for each node and routing decision.

**Files**:
- `tests/unit/test_chain_nodes.py` (new -- chain node + routing tests)
- `tests/unit/support/test_chain_nodes_given.py` (new -- Given helpers)
- `tests/unit/support/test_chain_nodes_then.py` (new -- Then helpers)
- `src/mcp_auditor/graph/state.py` (modify -- add `ChainAuditState`, `ChainAuditInput`; add `chain_budget`, `max_chain_steps`, `completed_chains` to `GraphState`)
- `src/mcp_auditor/graph/chain_nodes.py` (new -- all chain node factories and routing functions)

**Do**:

*Tests (write first)*:

Create `test_chain_nodes.py` with Given/When/Then pattern. Use `FakeLLM` from `tests/fakes/llm.py` and `FakeMCPClient` from `tests/fakes/mcp_client.py`.

Node tests:
- `make_plan_chains`: Given a `FakeLLM` returning `ChainPlanBatch` with 2 goals, when invoked with state containing `current_tool`, `judged_cases`, `attack_context`, `chain_budget=2`, then result has `pending_chains` of length 2.
- `prepare_chain`: Given state with `pending_chains=[goal_a, goal_b]`, when invoked, then result has `current_chain_goal=goal_a`, `current_chain_steps=[]`, `current_step_payload=goal_a.first_step`, and `pending_chains=[goal_b]`.
- `make_execute_step`: Given `FakeMCPClient` returning `ToolResponse(content="found /data/projects")`, when invoked with `current_step_payload`, then `current_chain_steps` has one `ChainStep` with `response="found /data/projects"` and no error.
- `make_execute_step` with error: Given `FakeMCPClient` returning `ToolResponse(is_error=True, content="denied")`, then step has `error="denied"` and no response.
- `make_execute_step` with wrong tool_name: Given payload with `tool_name="other_tool"` but `current_tool.name="file_manager"`, then the executed step's `payload.tool_name` is corrected to `"file_manager"`.
- `make_observe_step`: Given `FakeLLM` returning `StepObservation(observation="found path", should_continue=True, next_step_hint="try traversal")`, when invoked, then latest step's `observation` is updated, `current_observation.should_continue` is `True`.
- `make_plan_step`: Given `FakeLLM` returning `AuditPayload(...)`, when invoked, then result has `current_step_payload` matching.
- `make_judge_chain`: Given `FakeLLM` returning `EvalResult(verdict=FAIL, ...)`, when invoked with 2 steps, then `completed_chains` has one `AttackChain` with `eval_result.verdict == FAIL` and 2 steps.

Routing tests:
- `route_after_observe`: `should_continue=True` and `len(steps) < max` returns `"plan_step"`.
- `route_after_observe`: `should_continue=False` returns `"judge_chain"`.
- `route_after_observe`: `len(steps) == max` (even if `should_continue=True`) returns `"judge_chain"`.
- `route_after_judge`: pending chains remain returns `"prepare_chain"`.
- `route_after_judge`: no pending chains returns `END`.
- `route_after_planning`: pending chains exist returns `"prepare_chain"`, empty returns `END`.
- `route_to_chains_or_report`: `chain_budget > 0` returns `"chain_audit_tool"`, `chain_budget == 0` returns `"build_tool_report"`.

Given helpers (`test_chain_nodes_given.py`): `a_chain_goal(...)`, `a_chain_step(...)`, `a_step_observation(...)`, `a_chain_audit_state(...)`, plus wrappers for fake LLM/MCP setup.
Then helpers (`test_chain_nodes_then.py`): `pending_chains_count(result, n)`, `current_chain_goal_is(result, goal)`, `completed_chains_count(result, n)`, `chain_has_steps(chain, n)`, `chain_verdict_is(chain, verdict)`.

*Production code*:

In `state.py`: add `ChainAuditState` and `ChainAuditInput` as specified in the plan's "Graph state" section. Add `chain_budget: int`, `max_chain_steps: int`, `completed_chains: list[AttackChain]` to `GraphState` (no reducer on `completed_chains` -- overwritten per tool, same pattern as `judged_cases`).

Create `src/mcp_auditor/graph/chain_nodes.py` with all node factory functions and routing functions as specified in the plan's "Chain subgraph nodes" section:
- `make_plan_chains(llm)`, `prepare_chain`, `make_execute_step(mcp_client)`, `make_observe_step(llm)`, `make_plan_step(llm)`, `make_judge_chain(llm)`
- `route_after_planning`, `route_after_observe`, `route_after_judge`, `route_to_chains_or_report`

Import chain prompts from `graph/chain_prompts.py`.

**Test**: Run chain node tests.

**Verify**:
```bash
uv run pytest tests/unit/test_chain_nodes.py -x
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

---

### Step 3: Graph wiring, CLI, rendering, stream handler, config, and integration tests

Wire the chain subgraph into the main graph, add the CLI flag, update `build_tool_report`, add chain rendering in markdown/JSON, update stream handler for chain events, add config file support, and write graph integration tests. Many of these files need only small changes (1-5 lines for CLI, config_file, stream_handler, nodes.py), so they group naturally into one step.

**Files**:
- `tests/unit/test_rendering.py` (modify -- add chain rendering tests)
- `tests/unit/support/test_rendering_given.py` (modify -- add chain test data helpers)
- `tests/unit/support/test_rendering_then.py` (modify -- add chain assertions if needed)
- `tests/unit/test_graph.py` (modify -- add chain graph integration tests)
- `tests/unit/support/test_graph_given.py` (modify -- add chain-aware initial state and FakeLLM sequence helpers)
- `tests/unit/support/test_graph_then.py` (modify -- add chain assertions)
- `tests/unit/test_cli.py` (modify -- add `--chains` flag test if existing tests cover other flags)
- `tests/unit/test_config_file.py` (modify -- add `chains` to known keys test)
- `src/mcp_auditor/graph/builder.py` (modify -- add `_build_chain_audit_subgraph`, wire conditional edge)
- `src/mcp_auditor/graph/nodes.py` (modify -- update `build_tool_report` to include chains)
- `src/mcp_auditor/cli.py` (modify -- add `--chains` option, update `ExecutionConfig`, pass `chain_budget`/`max_chain_steps` in initial state)
- `src/mcp_auditor/config_file.py` (modify -- add `"chains"` to `KNOWN_KEYS`)
- `src/mcp_auditor/domain/rendering.py` (modify -- add chain rendering in markdown/JSON, update summary counts)
- `src/mcp_auditor/console.py` (modify -- add `print_info` method to `AuditDisplay`)
- `src/mcp_auditor/stream_handler.py` (modify -- handle chain subgraph events)

**Do**:

*Tests (write first)*:

In `test_rendering.py`:
- Markdown with chains: create `ToolReport` with one chain that has a FAIL verdict. Assert the markdown output contains the goal description, step payloads, and the verdict.
- Markdown without chains: existing `ToolReport` with `chains=[]` produces no chain section.
- JSON with chains: assert `chains` field is present in tool report JSON with OWASP injection on chain eval results.
- `summarize_tools` with chains: a `ToolReport` with 1 case PASS + 1 chain FAIL should have `failed=1` from the chain.

In `test_graph.py`:
- Single tool with `chain_budget=0`: graph completes, `ToolReport.chains` is `[]`. Reuse existing helper pattern but add `chain_budget=0` and `max_chain_steps=3` to initial state.
- Single tool with `chain_budget=1`: FakeLLM sequence includes: (1) test case generation, (2) judge response, (3) attack context extraction, (4) chain planning returning 1 `ChainGoal`, (5) step observation returning `StepObservation(should_continue=False)`, (6) chain judgment returning `EvalResult`. After graph completes, `ToolReport.chains` has one `AttackChain`. Token usage includes chain LLM calls.
- Resume mid-chain: single tool with `chain_budget=1`, using `MemorySaver` checkpointer. Configure `interrupt_after=["execute_step"]` on the chain subgraph (via `builder.add_node("chain_audit_tool", chain_subgraph)` — LangGraph supports `interrupt_after` on subgraph nodes). First `ainvoke` stops after `execute_step`. Second `ainvoke` with same `thread_id` resumes and completes through `observe_step` → `judge_chain`. Assert `ToolReport.chains` has one `AttackChain` with an `eval_result`. This validates checkpoint round-trip through the doubly-nested subgraph (main → audit_tool → chain_audit_tool).

In `test_config_file.py`: verify `"chains"` is accepted in config validation (not rejected as unknown key).

In `test_cli.py`: verify `--chains 3` is parsed correctly.

*Production code*:

In `builder.py`:
- Add `_build_chain_audit_subgraph(llm, mcp_client, judge_llm)` using `StateGraph(ChainAuditState, input_schema=ChainAuditInput)`. Wire the topology from the plan's "Chain subgraph builder" section: `START -> plan_chains -> route_after_planning -> (prepare_chain / END)`, `prepare_chain -> execute_step -> observe_step -> route_after_observe -> (plan_step / judge_chain)`, `plan_step -> execute_step`, `judge_chain -> route_after_judge -> (prepare_chain / END)`.
- In `build_graph`: add the chain subgraph as a node `"chain_audit_tool"`. Replace `builder.add_edge("audit_tool", "build_tool_report")` with `builder.add_conditional_edges("audit_tool", route_to_chains_or_report)` mapping to `{"chain_audit_tool": "chain_audit_tool", "build_tool_report": "build_tool_report"}` and `builder.add_edge("chain_audit_tool", "build_tool_report")`. Import `route_to_chains_or_report` from `chain_nodes`.

In `nodes.py`: update `build_tool_report` to read `chains = state.get("completed_chains", [])` and pass `chains=chains` to `ToolReport`.

In `cli.py`: add `--chains` click option (default 0, `IntRange(min=0)`). Add `chains: int` field to `ExecutionConfig`. In initial state dict, add `"chain_budget": config.execution.chains` and `"max_chain_steps": 3`.

In `config_file.py`: add `"chains"` to the `KNOWN_KEYS` set.

In `rendering.py`:
- Add `_render_chain_section(chain: AttackChain) -> str` that renders each chain as a subsection: goal, category, numbered steps (payload -> response snippet -> observation), verdict, justification.
- Update `_render_tool_section` to call `_render_chain_section` for each chain in `tool_report.chains` after single-step results.
- Update `_inject_owasp_into_json` to also iterate `tool_report["chains"]` and inject OWASP mapping on chain eval results.
- Update `_summarize_tool_report` to count chain verdicts in `judged`, `passed`, `failed`, and `severity_counts`.

In `stream_handler.py`: chain subgraph events arrive with `len(namespace) >= 2` (outer per-tool subgraph + `"chain_audit_tool"` nesting). Add `_on_chain_event` handler as specified in the "Console / stream handler" section above. Update `on_stream_event` to dispatch to `_on_chain_event` when `len(namespace) >= 2`. Chain progress uses plain `print_info` lines, not the spinner/advance pattern (chains are fewer and slower than single-step cases). Verify `AuditDisplay` has a `print_info` method — if not, add one as a thin wrapper around `console.print`.

**Test**: Run all unit tests.

**Verify**:
```bash
uv run pytest tests/unit -x
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

---

### Step 4: Chain honeypot server, ground truth, and eval runner updates

Add the chain honeypot server, its ground truth, integration tests for the server, and update the eval runner to support chain honeypots.

**Files**:
- `tests/chain_server.py` (new -- honeypot MCP server with `file_manager` and `key_value_store` tools)
- `tests/integration/test_chain_server.py` (new -- integration tests for chain server tools)
- `evals/ground_truth.py` (modify -- add `CHAIN_GROUND_TRUTH`)
- `evals/run_evals.py` (modify -- add chain honeypot config, `chain_budget`/`max_chain_steps` params, chain delta recall metric)

**Do**:

*Tests (write first)*:

In `tests/integration/test_chain_server.py` (follow the pattern from existing `test_mcp_client.py` / `test_subtle_server.py` for server subprocess fixtures):
- Connect to `chain_server.py` via `StdioMCPClient`. Verify `file_manager(action="list")` returns directory contents including the base path `/srv/app-7f3a9c2e/workspace`.
- Verify `file_manager(action="read", path="../../etc/passwd")` is rejected (blind traversal fails).
- Verify `file_manager(action="read", path="/etc/hostname")` is rejected (absolute path without base prefix fails).
- Verify `file_manager(action="read", path="/srv/app-7f3a9c2e/workspace/../../etc/hostname")` succeeds (discovery-based traversal works).
- Verify `key_value_store(operation="list_keys")` returns key names including `admin_token`.
- Verify `key_value_store(operation="get", key="guessed_key")` returns "key not found".
- Verify `key_value_store(operation="get", key="admin_token")` returns sensitive data.

*Production code*:

Create `tests/chain_server.py` as a valid MCP stdio server (same pattern as `tests/dummy_server.py` — uses `FastMCP`, runs via `app.run()`). Two tools:
- `file_manager(action: str, path: str = ".")`: Uses a non-guessable base path constant `BASE_DIR = "/srv/app-7f3a9c2e/workspace"`. `action="list"` returns simulated directory listing that reveals `BASE_DIR` in the output. `action="read"` validates `path.startswith(BASE_DIR)` but does **not** normalize `..` segments — so `BASE_DIR + "/../../etc/hostname"` bypasses the check. Rejects any path that doesn't start with `BASE_DIR` (blind traversal like `"../../etc/passwd"` or `"/etc/passwd"` is rejected).
- `key_value_store(operation: str, key: str = "", value: str = "")`: `operation="list_keys"` reveals key names including `admin_token`. `operation="get"` with unknown key returns "key not found". `operation="get"` with `admin_token` returns a sensitive token value.

In `evals/ground_truth.py`: add `CHAIN_GROUND_TRUTH` dictionary as specified in the plan (10 entries across 2 tools and 5 categories).

In `evals/run_evals.py`:
- Add `chain_budget: int = 0` and `max_chain_steps: int = 3` to `HoneypotConfig`.
- Add chain server to `HONEYPOTS` list with `chain_budget=2`.
- Update `_run_single_honeypot` to pass `chain_budget` and `max_chain_steps` from `HoneypotConfig` into the initial state dict (existing honeypots keep `chain_budget=0`).
- Add chain delta recall computation: for the chain honeypot, compare recall with chains enabled vs. baseline (chains disabled). Display in summary.

**Test**: Run integration tests for the chain server. Run full test suite to confirm nothing is broken.

**Verify**:
```bash
uv run pytest tests/integration/test_chain_server.py -x
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -x
```
