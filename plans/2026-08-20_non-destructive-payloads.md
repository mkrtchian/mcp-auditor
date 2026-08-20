# Non-destructive attack payloads

## Context

The auditor generates its own attack payloads and sends them to a live server. A
graded CVE benchmark run against the kubernetes target showed that one of the two
injection attempts per run was **destructive**: `rm -rf /`, landing in a different
argument each run (`command`, then `name`, then `flags`). Nothing in the codebase
prevents that payload from reaching the server.

Two distinct harms:

1. **Damage to the audited server.** The benchmark is only safe because its
   fixtures run under `docker run --rm`. A user pointing the auditor at a real
   server with a mounted volume or persistent state gets the destructive payload
   executed for real. `ADR 004` models the server as the subject under test,
   possibly flawed, with the attacker acting through the LLM client. What has no
   counterpart anywhere in the code is the reverse duty: not being hostile *to*
   the server we were pointed at.
2. **Self-sabotage of the measurement.** A destructive payload that lands early
   in a run breaks the probes that follow it in the same run, so the auditor
   corrupts its own evidence.

**The destructive payload never had detection value.** Both cases are covered:

- If the injection is **observable in the response**, a benign reflected marker
  (`echo mcp-auditor-probe`, `id`, `whoami`, `SELECT`/`UNION SELECT`) proves it
  just as well. Destroying state adds nothing to the evidence.
- If the injection is observable **only through a silent effect** (an unechoed
  write, a spawned process, out-of-band exfiltration), the destructive payload
  did not reveal it either. A black-box auditor reads the response and nothing
  else, which is exactly the class `ADR 011` documents and defers behind the
  `ExecutionObserver` seam.

So this change removes payloads that were pure downside. It does **not** create a
new capability ceiling, and it does not narrow what `ADR 011` already scoped.

Checked against the eval ground truth: **no ground-truth cell requires a
destructive payload.** All eleven `FAIL` cells in `evals/ground_truth.py` are
establishable non-destructively. The load-bearing ones:

- `execute_query` returns `Executed: {query}` for *any* query
  (`tests/honeypot_server.py:31`), so `SELECT sqlite_version()` or `' OR '1'='1`
  triggers the same FAIL as `DROP TABLE`.
- `project_manager` x `injection` is a path traversal in **read** mode
  (`path.startswith("/data/admin/")` returns the sensitive config).
- `delete_record` x `input_validation` and x `error_handling`
  (`tests/subtle_server.py`) come from a negative `record_id` and an ignored
  confirmation flag, not from destroying anything. Worth naming explicitly
  because it is the one honeypot tool whose *name* contains a destructive verb.
- On `CVE-2025-53355`, the finding is established by the read-only exfiltration
  of `/etc/passwd`, not by the destructive attempt.

**Say "requires", not "costs nothing", and the distinction is not pedantic.** The
guard drops a blocked case rather than substituting a benign one, so a cell can
still be *lost in a given run* if the generator's only probe for it was
destructive. That is a run-level risk, visible in the metrics and addressed in
Verification, not a ground-truth dependency. Overstating it as "zero detection
cost" is exactly the kind of claim this repo's credibility depends on not making.

Caveat to keep in mind: the honeypots are written in this repo, so the statement
holds for the measured substrate, not universally.

## Approach

Two layers, because this is a **safety** property and a prompt is a probabilistic
constraint. The measured failure mode (the same destructive command improvised
into three different argument names) is precisely what a prompt instruction alone
does not reliably prevent.

1. **Prompt.** Rewrite the injection guidance at all three generation sites so the
   generator proves injection non-destructively.
2. **Deterministic guard.** A pure function in `domain/` that inspects generated
   argument values and refuses unambiguously destructive constructs before any
   call reaches the server.

### What the guard is, and is not

The guard is **not** a security boundary against a hostile LLM. A denylist can be
bypassed, and it does not need to resist bypass here: the generator is not trying
to evade us. It is a guard against our own generator's exuberance, and stating
that plainly is what keeps the claim defensible.

Its mandate is **destructive to state, or dangerous to the host and the run**.

### Asymmetry of the two error directions

- A false block costs recall, and shows up in the evals.
- A false allow destroys a user's server.

So: aggressive on unambiguous constructs, permissive on ambiguous ones, with the
prompt carrying the bulk of the work.

### Enforcement location: a named door, not a remembered call

Enforcement lives in a domain service, `AuditedServer`, which becomes the
**only** reach the graph has into the server under audit. Its sending method
returns a union, `ToolResponse | BlockedPayload`.

**The hard constraint** is that a refusal must never be able to look like
something the server said. This is not hypothetical: the `tool_name` bug made the
auditor call a nonexistent tool, the server replied `Unknown tool: <category>`,
the judge graded that auditor error as an `error_handling` finding, and the same
false conclusion then poisoned the cross-tool `AttackContext` that feeds later
generations.

**Why a plain decorator over `MCPClientPort` fails that constraint**, and why the
union does not. A decorator has to answer with `ToolResponse`, whose fields are
`content` / `is_error` / `error_type`, so a refusal is indistinguishable from a
server error. Widening the return type removes that objection entirely: a refusal
becomes a **different variant**, not an error-shaped response. `BlockedPayload`
deliberately shares **no attribute name** with `ToolResponse`, so no code path can
turn one into the other. That non-overlap is the load-bearing property, and it is
invisible unless written down.

**Why the service rather than a call inside each node.** Calling
`destructive_reason` from the two execution nodes is complete today, since those
are the only two `call_tool` sites in `src/`. But it holds by convention: a future
execution path that forgets the call breaks nothing, produces no type error and
fails no test, and destructive payloads reach the server again in silence. The
plan's own "Not in scope" names two candidate future paths, the `ExecutionObserver`
seam reserved by `ADR 011` and a corrective regeneration loop. When two future
paths are already written down, the invariant should stop depending on their
authors' memory.

The missing concept this names is not "a guard the nodes remember to call", it is
**the audited server as the auditor is allowed to touch it**, owning both the
decision and the delegation. Two independent locks follow:

- **Capability.** A new node receives an `AuditedServer` and nothing else.
  Obtaining an unguarded `call_tool` requires changing `build_graph`'s signature
  and every composition site, a deliberate reviewable edit rather than an
  omission. Omission is the failure mode being closed.
- **Type.** `attempt` is the only sending method and its return is the union, so
  ignoring the refusal is a type error under the repo's strict `pyright`.

Honest limit: the type forces an author to **acknowledge** the variant, not to
handle it well. Someone can narrow and discard it. But silence, not misuse, was
the smell.

Note also what this relocation is **not**: the call to `destructive_reason` exists
either way, and the node bodies do not grow. The only question was whether it sits
where it can be skipped or where it cannot.

### Fate of a blocked case

Marked as not executed, carrying its reason, visible in the report, **not judged**.

- Not silently dropped: the budget would quietly shrink and distribution coverage
  would drift, so the metrics would lie about what was actually exercised.
- Not regenerated: that costs an LLM call and is a different feature (a corrective
  generation loop).

Every metric in `evals/metrics.py` already guards on `eval_result is None`
(`aggregate_verdicts`, `compute_distribution_coverage`), and so does
`evals/export.py`. A blocked case therefore contributes nothing to recall,
precision or consistency, which is correct: we neither claim a detection nor a
false positive for a payload we never sent.

One consequence is intended, not a bug: if the only `injection` case for a tool is
blocked, that tool's **distribution coverage drops**, because the category was
genuinely not exercised. That visibility is the point. If blocks turn out to be
frequent, that is a prompt-compliance signal we want to see rather than absorb.

## Files to modify

### `src/mcp_auditor/domain/payload_safety.py` (new)

The pure predicate. No I/O, no LLM, no clock. Hexagon interior, exhaustively
unit-testable.

```python
def destructive_reason(arguments: dict[str, Any]) -> str | None:
```

No docstring: the name and the signature say it. Reserve a comment for the
non-obvious *why* (the residual, below).

Contract:

- Walks the argument values recursively (values can be `str`, `int`, `list`,
  `dict`, `None`), and inspects **string values only**. Argument *names* are never
  inspected: the tool's own function is legitimate, only injected content is not.
- Returns the first matching reason, so the message names one concrete construct
  (`"destructive filesystem command: rm -rf"`), never a generic refusal.
- Case-insensitive matching, tolerant of surrounding whitespace.

Shape of the module, newspaper order: the public `destructive_reason` first,
then the private helpers right below it (`_first_destructive_string` for the
recursive walk, `_matching_construct` for the group lookup), then the table of
constructs. Keeping the walk and the matching in named helpers is what holds the
public function under the 20-line rule.

The group is a missing concept, so name it rather than pairing two parallel
constants:

```python
@dataclass(frozen=True)
class DestructiveConstruct:
    reason: str
    patterns: tuple[str, ...]
```

The same shape as `OwaspMapping` in `domain/models.py`. The reason string is
derived from the construct, never duplicated at the match site.

**The table invariant, which is the whole design.** No pattern may be a bare
word. A destructive command always carries an argument or a flag (`rm -rf /`,
`shutdown -h now`, `chmod -r 000 /work`, `dd of=/dev/sda`), so writing the
pattern with that argument attached makes it **self-delimiting**. This removes
the entire incidental-match class without a regex engine, a shell parser or a
second matching mode.

Word boundaries would not have been enough, and this is the reason the mechanism
stays literal: `\bshutdown\b` still matches `get_service_status(service="shutdown")`,
which `tests/subtle_server.py` already ships. Separating that from
`command="shutdown"` would require inspecting the argument **name**, which comes
from the server's own `inputSchema`. The guard's rule is to inspect injected
*content*, never the tool's declared interface, and a name cannot execute. Note
the distinction that makes this more than a preference: the generator already
relies on those names to build payloads, which is best-effort and self-correcting,
whereas letting them decide what counts as dangerous would make a safety property
depend on input the audited server controls. The discrimination is therefore
unavailable at this function's signature, the choice is forced, and the stated
asymmetry assigns bare words to the permissive side.

Blocked constructs, grouped by intent (one `DestructiveConstruct` each). All
patterns are lowercase, matched against a lowercased value:

| Group | Patterns | Reason |
|---|---|---|
| Filesystem destruction | `rm -rf`, `rm -fr`, `rm -r `, `rm -f `, `rm /`, `rm ~`, `rmdir `, `shred `, `unlink `, `mv /` | `destructive filesystem command` |
| Clobbering redirect | `> /`, `>> /`, `> ~`, `>> ~` | `output redirect overwriting a file` |
| Permission destruction | `chmod -r`, `chown -r` | `recursive permission change` |
| Disk / device writes | `mkfs.`, `mkfs `, `dd of=`, `of=/dev/`, `truncate -s` | `destructive disk operation` |
| SQL state destruction | `drop table`, `drop database`, `truncate table`, `delete from ` | `destructive SQL statement` |
| Forced VCS write | `push --force`, `push -f `, `checkout --force`, `reset --hard`, `clean -fd` | `forced version-control write` |
| Host availability | `shutdown -`, `shutdown now`, `sudo shutdown`, `reboot -`, `sudo reboot`, `sudo poweroff`, `init 0`, `init 6`, `kill -9 1` | `host availability command` |
| Fork bomb | `:(){`, `:|:&`, `:(){:|:&};:` | `fork bomb` |

Deltas worth knowing, each closing a concrete defect:

- `halt` is **deleted**. It is the one construct with no argument form to hang a
  boundary on, and it is what matches `/opt/halted`.
- `shutdown` and `reboot` keep only argument-carrying forms.
- `shred`, `unlink `, `rmdir `, `rm -r ` take a trailing space, which kills
  `shredder` and `unlinked`.
- `mv ` becomes `mv /`. `mv` is the highest-false-positive entry left, and the
  only one whose blocked example is a *mutation* sitting on the exact line this
  plan draws. Requiring an absolute source keeps it on the destruction side.
- `delete from ` is **added**. `'; DELETE FROM users--` is the second most likely
  destructive SQL form an LLM writes, and blocking `DROP` and `TRUNCATE` without
  it was a gap.
- Patterns are lowercase **and the test suite asserts it**, see below. Written as
  `chmod -R` against a lowercased value, the pattern would never match: a
  fail-open in the catastrophic direction, invisible without the assertion.

**One carve-out, before matching.** `> /` also matches `2> /dev/null`, an idiom
the generator emits routinely, and blocking it would corrupt the very instrument
this plan protects. Strip harmless sinks first, in a named
`_without_harmless_sinks` helper:

```python
_HARMLESS_SINKS = ("/dev/null", "/dev/stdout", "/dev/stderr")
```

This also removes an inconsistency the literal space would otherwise create,
where `> /dev/null` blocks and `>/dev/null` does not.

Explicitly **not** blocked. The full rationale lives in `ADR 013`, not in the
module: a one-line header comment naming the mandate and pointing at the ADR,
matching how `category_guidance.py` heads itself and how `EvalResult.owasp`
carries `(ADR 012)`. Duplicating the argument in both places invites drift.

- Shell metacharacters and injection syntax: `;`, `|`, `&&`, `$()`, backticks,
  `--`, `' OR '1'='1`. They are the substance of the `injection` category, and
  blocking them would gut it.
- A **bare** `>` or `>>`. A redirect is only matched when followed by an absolute
  path or the home directory, because `WHERE price > 5` and any XML or HTML
  payload contain a bare `>`. Blocking it would violate the asymmetry stated
  above: ambiguous constructs stay permitted and the prompt handles them.
- A **bare command word**: `shutdown`, `reboot`, `mv` on their own. This is a
  deliberate false *allow*, and it rests on a bet worth naming as a bet in
  `ADR 013` rather than passing for a fact: an LLM writes `shutdown -h now`, not
  a bare `shutdown`. Two things make it acceptable. The prompt still forbids host
  shutdown, so the residual needs the generator to disobey **in its least likely
  phrasing**, a conjunction rather than a single event. And the alternative is
  not "block both", it is unavailable, per the argument-name reasoning above. If
  the bet is wrong, the fix is one string in one tuple.
- A bare `delete` / `drop` word. `delete_record(record_id=1)` is the subtle
  honeypot's legitimate function and must pass;
  `delete_record(record_id="1; rm -rf /")` is caught by the `rm -rf` rule, on the
  injected content, not on the tool's purpose.
- Writes as such. `git_init`, `git_add`, `write_file`, `create_*` and any other
  mutating call go through. See the policy decision below: the guard forbids
  destruction, not mutation.
- Large or unbounded values (`limit=999999999`, oversized strings, wildcards).
  They are the substance of the `resource_abuse` category and are already bounded
  by the 30s tool-call timeout.

**The list is enumerated, not complete**, and the module's header comment says so
in one line. Constructs such as an obscure destructive binary, or a clobbering
redirect to a relative path, pass. That is the accepted residual: the guard is a
denylist aimed at our own generator's exuberance, not a bypass-resistant
boundary. The README and `ADR 013` must therefore describe an enumerated
enforcement, never a guaranteed property. Widening the list later is cheap and
needs no new decision.

The fork bomb sits in this module rather than being left to `resource_abuse`
because it is dangerous under the second half of the mandate (host and run), and
because `resource_abuse` is exercised through large *argument values*, never
through a self-replicating shell construct. Blocking it removes no legitimate
`resource_abuse` test.

### `src/mcp_auditor/domain/models.py`

- `TestCase` gains `blocked_reason: str | None = None`. A case with a
  `blocked_reason` was never sent: `response`, `error` and `eval_result` all stay
  `None`. This is what distinguishes it from both a server error and a
  not-yet-judged case.
- `AttackChain` gains `blocked_reason: str | None = None`, recording that the
  chain was cut short by the guard.
- `ChainStep` is **unchanged**. A blocked step is deliberately never appended to
  the chain's steps, so the chain judge only ever sees steps that really executed.
- New `BlockedPayload`, a frozen dataclass beside `ToolResponse`, same shape as
  `OwaspMapping`:

```python
@dataclass(frozen=True)
class BlockedPayload:
    reason: str
```

  It carries a one-line comment on the class recording the invariant, because the
  property is load-bearing and invisible otherwise: **no field is named like a
  `ToolResponse` field**. No `content`, no `is_error`, no `error_type`. That
  non-overlap is what turns an unhandled refusal into a type error rather than a
  silent success, and what makes it structurally impossible for a refusal to be
  mistaken for something the server said.

  It never crosses serialization: the reason is copied onto
  `TestCase.blocked_reason` or `AttackChain.blocked_reason` immediately.

### `src/mcp_auditor/domain/audited_server.py` (new)

The named door. Roughly 22 lines, inside the hexagon: it imports `MCPClientPort`
from `domain/ports.py` and the pure `destructive_reason`, and imports nothing
from `adapters/`.

```python
class AuditedServer:
    def __init__(self, client: MCPClientPort) -> None:
        self._client = client

    async def list_tools(self) -> list[ToolDefinition]:
        return await self._client.list_tools()

    async def attempt(
        self, tool: ToolDefinition, payload: AuditPayload
    ) -> ToolResponse | BlockedPayload:
        reason = destructive_reason(payload.arguments)
        if reason is not None:
            return BlockedPayload(reason=reason)
        return await self._client.call_tool(tool.name, payload.arguments)
```

**Not a `Protocol`.** There is one implementation, and tests inject a
`FakeMCPClient` *underneath* it, so the real guard runs in every node test rather
than being faked away. Making it a Protocol with its own fake would be the actual
over-engineering here.

Taking a `ToolDefinition` rather than a name string costs nothing (both nodes
already hold `state["current_tool"]`) and incidentally makes the `tool_name`
hallucination class harder to reproduce.

### Composition root

`build_graph` and `build_dry_run_graph` take an `AuditedServer` instead of an
`MCPClientPort`. After this change, `grep -rn MCPClientPort src/mcp_auditor/graph/`
returns nothing: the hexagon interior no longer holds any object able to call
`call_tool`. That is the capability lock.

Seven one-line edits wrap the client where it is built: `cli.py` (the audit path
and `_run_dry_run`, whose parameter type changes), `studio.py`,
`evals/run_evals.py`, `evals/run_cve_benchmark.py`, and
`tests/unit/support/test_graph_given.py`.

**`evals/cve_targets.py` keeps the raw `MCPClientPort`, deliberately.** Its
calibration exploits are hand-written ground truth, not generated `AuditPayload`s,
so the guard does not apply to them. Record this in `ADR 013` or someone will
"fix" it later and break the calibration gate.

**The dry-run path keeps the wrapper, also deliberately, and for the opposite
reason.** `build_dry_run_graph` has no `execute_tool` node, so the guard is never
consulted there and the wrap looks pointless. It is not: it is what keeps
`AuditedServer` the *only* server-facing type the graph builders accept. Unwrap
it and `build_dry_run_graph` takes a raw port again, which reopens the capability
hole for whoever later adds an execution node to that graph. The two exceptions
pull in opposite directions and both need their line in `ADR 013`: calibration
keeps the raw port because the guard does not apply, dry run keeps the wrapper
because the type is the lock.

### `src/mcp_auditor/graph/nodes.py`

`make_discover_tools(server: AuditedServer, tools_filter=None)` calls
`server.list_tools()`.

`make_execute_tool(server: AuditedServer)` sends through `attempt` and narrows the
union. About 14 lines:

```python
outcome = await server.attempt(tool, case.payload)
if isinstance(outcome, BlockedPayload):
    blocked = case.model_copy(update={"blocked_reason": outcome.reason})
    return {"judged_cases": [blocked], "current_case": None, "pending_cases": pending}
if outcome.is_error:
    case = case.model_copy(update={"error": outcome.content, "response": None})
else:
    case = case.model_copy(update={"response": outcome.content})
return {"current_case": case, "pending_cases": pending}
```

The blocked case goes straight into the `judged_cases` accumulator with
`eval_result` left as `None`, and `current_case` is set to `None` to signal the
skip to the router.

**What the type checker enforces**, verified against this repo's pinned `pyright`
in `strict` mode rather than assumed. Omitting the `isinstance` narrowing
produces, at severity Error:

```
Cannot access attribute "is_error" for class "BlockedPayload"
Cannot access attribute "content" for class "BlockedPayload"
```

and passing the outcome on unnarrowed produces `Argument of type
"ToolResponse | BlockedPayload" cannot be assigned to parameter of type
"ToolResponse"`. The narrowed version above produces **zero** diagnostics, so the
design adds no false friction. `uv run pyright` is already in the `CLAUDE.md`
command list, so this is enforced by the existing gate with nothing new to wire.

New router, placed next to `route_test_cases` (newspaper rule, right below its
caller's concern):

```python
def route_after_execute(state: dict[str, Any]) -> str:
    if state["current_case"] is None:
        return route_test_cases(state)
    return "judge_response"
```

### `src/mcp_auditor/graph/chain_nodes.py`

`make_execute_step(server: AuditedServer)`: same door, same narrowing, before the
`ChainStep` is built. A blocked step is **not** appended to
`current_chain_steps`; it sets `blocked_step_reason` in the state and ends the
chain there.

```python
outcome = await server.attempt(tool, payload)
if isinstance(outcome, BlockedPayload):
    return {"blocked_step_reason": outcome.reason}
```

Everything downstream is unchanged by the union: it alters how the reason
arrives, not what the chain does with it.

`make_judge_chain`: when `blocked_step_reason` is set, stamp it onto the chain
(`chain.model_copy(update={"blocked_reason": reason})`) and clear it from the
state alongside the other per-chain fields. The judge prompt still receives only
the executed steps, so the LLM never sees the auditor's refusal.

New node `abandon_chain`, placed with the other node functions (right after
`make_judge_chain`, before the routers, per the newspaper rule) for the case
where the **first** step is blocked and nothing executed. Judging an empty chain would waste an LLM call and invite a
garbage verdict, so instead it records an unjudged chain and moves on:

```python
def abandon_chain(state: dict[str, Any]) -> dict[str, Any]:
    chain = AttackChain(
        goal=state["current_chain_goal"],
        steps=[],
        blocked_reason=state["blocked_step_reason"],
    )
    return {
        "completed_chains": [chain],
        "current_chain_goal": None,
        "current_chain_steps": [],
        "blocked_step_reason": None,
    }
```

Because `eval_result` stays `None`, `ToolReport.eval_results` skips it, so the
metrics and the export skip it too, with no extra guard to write.

New router:

```python
def route_after_execute_step(state: dict[str, Any]) -> str:
    if state["blocked_step_reason"] is None:
        return "observe_step"
    if state["current_chain_steps"]:
        return "judge_chain"
    return "abandon_chain"
```

### `src/mcp_auditor/graph/state.py`

- `ChainAuditState` gains `blocked_step_reason: str | None`.
- `prepare_chain` resets it to `None` when starting a new chain, so a block on
  one chain never leaks into the next.

### `src/mcp_auditor/graph/builder.py`

In `_build_audit_tool_subgraph`, replace the plain edge with a conditional one:

```python
builder.add_conditional_edges(
    "execute_tool",
    route_after_execute,
    {"judge_response": "judge_response", "execute_tool": "execute_tool", END: END},
)
```

In `_build_chain_audit_subgraph`, register `abandon_chain`, replace the
`execute_step -> observe_step` edge with `route_after_execute_step`, and route
`abandon_chain` through the existing `route_after_judge` so it continues to the
next chain or ends.

### `src/mcp_auditor/graph/prompts.py`

Rewrite the `injection` line of `build_attack_generation_prompt`. It currently
reads:

```
- injection: Craft payloads that attempt SQL injection, command injection, or code
  execution through the tool's arguments. Use the tool's expected input types.
```

The replacement has two distinct halves, and the distinction is the whole policy
(see "Destruction, not mutation" below).

**A prohibition, co-extensive with the guard.** Never destroy state and never
affect host availability: no deleting or overwriting files, no `DROP` or
`TRUNCATE`, no recursive permission change, no forced version-control write, no
shutdown, no fork bomb. This half must not forbid more than
`destructive_reason` can enforce, so that the guard remains its deterministic
backstop.

**A preference, with no guarantee attached.** When a benign reflected marker
proves the same thing, prefer it: `echo mcp-auditor-probe`, `id`, `whoami`,
read-only reads, `SELECT` / `UNION SELECT` rather than DDL or DML. Phrase it as
a preference, not a rule, because for a mutating tool there is no read-only way
to probe it, and a rule the generator cannot satisfy is a rule it learns to
ignore.

Give the reason in one clause, because a rule with a reason is followed more
reliably than a bare interdiction: a destructive payload proves nothing more than
a benign marker, and it corrupts the rest of the audit.

Keep the wording generic. Do not name a honeypot literal or a benchmark target.

### Destruction, not mutation (policy decision)

The prohibition covers **destruction of state and host availability**. It does
**not** cover writes. `git_init`, `git_add`, `write_file` and any other mutating
call are permitted.

Three reasons, in decreasing order of force.

1. **Auditing a write tool requires writing.** Proving injection on
   `write_file`, `create_pod` or `execute_query` means calling the tool, and the
   call mutates because mutating is the tool's declared function. A read-only
   policy does not merely cost one benchmark target: its honest consequence is
   "the auditor does not test write tools for injection", which is not a
   property anyone wants and which the benchmark already contradicts.
2. **A read-only promise would be unverifiable by this tool's own admission.**
   `ADR 011` records that the auditor cannot observe a call's side effects. A
   tool that has documented it cannot see writes cannot promise it causes none.
   The claim would be falsified the first time an injection probe against a
   write tool succeeded.
3. **It would move a benchmark denominator for a self-imposed rule.**
   `CVE-2025-68143` has the graded path `git_init(out-of-scope) -> git_add(.) ->
   git_diff_staged`, whose first two steps are writes. Under a read-only policy
   it would have to move into `OUT_OF_SCOPE_CVES` with a reason of "out of reach
   by policy", while its `awaited_capability` field still says
   `"cross-tool chains + declared-scope awareness"`. Reclassifying a target for a
   rule we chose, not for a capability we lack, is the worst kind of benchmark
   movement to have to explain.

Rejected alternatives, recorded here and in `ADR 013`:

- **A `--read-only` flag defaulting to strict.** Its guarantee would be
  prompt-only, since the auditor cannot determine whether a given call writes.
  That is precisely the probabilistic constraint this plan exists to stop relying
  on, dressed as a setting. It would also fork the eval matrix and make the
  published CVE numbers describe a non-default mode.
- **Permitting writes only inside the path the server declares.** Circular:
  the declared scope is the very property under test, so it cannot also be the
  boundary that keeps us safe while we test it: `declared-scope awareness` is the `awaited_capability` of four of the six
  CVE targets, and path traversal is the confirmation that the boundary does not
  hold. Using it as a guard would forbid the category's central probe.

**The general rule this contributes**, and the reason it belongs in an ADR rather
than a comment: the prompt must never forbid more than the guard can enforce.
Beyond that line the guard stops being a backstop and the surplus prohibition
becomes an unbacked promise.

### `src/mcp_auditor/graph/chain_prompts.py`

The same constraint at the two chain generation sites, since a chain step is an
LLM-generated payload like any other and `--chains` against a real server is
exactly the scenario this change protects.

- `build_chain_planning_prompt`: the `first_step` payload.
- `build_step_planning_prompt`: every subsequent step.

Extract the shared constraint into a single module-level constant in
`graph/prompts.py` and import it in `chain_prompts.py`, which already imports
`build_context_section` and `format_tool_header` from there. Three copies of a
safety rule would drift.

### Blocked cases in the downstream prompts

Two prompt builders iterate `tool_report.cases` / `judged_cases` and would render a
blocked case as a bare heading with no response, no error and no verdict:

- `_format_cases_for_extraction` in `graph/prompts.py`, feeding
  `build_context_extraction_prompt`.
- `_format_single_step_summary` in `graph/chain_prompts.py`, feeding
  `build_chain_planning_prompt`.

Skip a case with a `blocked_reason` in both. A case we never sent carries no
evidence about the server, so including it can only invite the LLM to invent one.
This is the same rule as the chain judge only seeing executed steps.

### `src/mcp_auditor/domain/category_guidance.py`

**No prohibition goes here.** This module is consumed only by the judge prompt
(its header comment says so, fixed in `78ba64d`), and the judge generates nothing.

One change is needed, for a different reason. Now that injection is proven by a
benign reflected marker, the judge must recognise that as injection. The
`INJECTION` entry's "What counts" line already covers it (`user input is executed
as code, SQL, or commands`), but its "What does NOT count" line reads:

```
- The tool echoing input in an error message (that's error_handling or
  info_leakage, not injection)
```

A reflected marker risks being read as a mere echo. Sharpen the exclusion so it
distinguishes an echo *inside an error message* from output that **evidences
execution**: a marker that comes back as command output, or a query result, is
execution, not an echo.

The tension already exists (`execute_query` literally echoes, and the ground truth
says FAIL on injection), so this is a clarification of a live edge, not a new
rule. Measure it: the judge isolation eval runs in about four seconds.

### `src/mcp_auditor/domain/rendering.py`

`_render_tool_section` currently skips any case with `eval_result is None`, which
would make a blocked case invisible. Render it instead, so the report states what
was not sent:

```
### BLOCKED -- injection
**Payload**: `{...}`
**Reason**: destructive filesystem command: rm -rf
```

`_render_chain_section` renders `chain.blocked_reason` when set, so a chain cut
short says so rather than looking like it merely ended.

`_render_summary_section` counts `Test cases` from `len(tr.cases) + len(tr.chains)`
and needs no change: a blocked case is still a generated case. Add a `Blocked`
line when the count is above zero, so the summary never implies every case was
executed. Count **both** sources, cases with a `blocked_reason` and chains with
one, since both are rendered as blocked further down and a partial count would be
worse than none.

### `src/mcp_auditor/stream_handler.py` and `src/mcp_auditor/progress.py`

The live display counts judged cases. A blocked case never reaches
`judge_response`, so the progress bar would stall one tick short per block.
Advance the progress on a block and print a one-line notice naming the reason.
Blocking is a decision the user must see while the audit runs, not something to
discover in the JSON afterwards.

Two concrete edits, because the advance is not where the file list first suggests:

- `stream_handler.py` is the site that drives the bar. `AuditProgressReporter.
  _on_tool_audit_event` currently only reacts to `judge_response`, reading
  `state_update["judged_cases"][-1].eval_result`. It must also react to
  `execute_tool`, which now emits `judged_cases` when it blocks. Guard on
  `blocked_reason` being set, so a normal `execute_tool` update (which carries
  `current_case`, not `judged_cases`) changes nothing.
- `progress.py`: `ToolProgress.advance` and `CIProgress.advance` take an
  `EvalResult`, which a blocked case does not have. Add a separate
  `advance_blocked(reason: str)` on both rather than widening `advance` to
  `EvalResult | None` — `_ResultTracker` only knows how to record verdicts, and a
  block is not a verdict. `ToolProgress.advance_blocked` prints the notice through
  `self._progress.console` and advances the task, `CIProgress.advance_blocked`
  prints a plain line.

`console.py` needs no change: `AuditDisplay` exposes the progress objects but does
not count cases itself, and `_build_summary_table` already derives its `Tests`
column from `eval_results`, which correctly excludes a blocked case.

### `tests/fakes/mcp_client.py`

`FakeMCPClient` currently records nothing: it holds `_tools` and `_responses` and
returns a canned `ToolResponse`. The test scenarios below assert that a blocked
payload produced **no** tool call, which is unobservable today. Give the fake a
public `calls: list[tuple[str, dict[str, Any]]]` appended in `call_tool`.

That is an observable-outcome assertion, not an implementation one: "the auditor
did not touch the server" is precisely the behavior this change exists to
guarantee, and a fake recording its own inputs is the standard way to see it.

### `README.md`

Two distinct edits: the scope bullet, and the two architecture diagrams.

#### The architecture diagrams

Both published mermaid diagrams become wrong with this change and must move in
the same commit, per the living-docs rule. They already draw conditional branches
(`S3 -->|more cases| S2`, `O -->|continue| S`), so a block branch belongs at
exactly that level of detail.

- The `audit_tool` subgraph currently draws `S2[execute_tool] --> S3[judge_response]`
  as a plain edge. It becomes conditional: judged when the payload was sent,
  straight to the next case or the end when it was blocked.
- The `chain_audit_tool` subgraph draws `C --> E --> O` with no abandon path. It
  gains the `abandon_chain` node and the branch out of `execute_step`.

This is the file an outsider is most likely to read, so a diagram that misstates
the graph costs more here than anywhere else.

#### The scope bullet

In `Scope and limitations`, add a bullet stating the policy. Open it with a bold
lead-in phrase like every other bullet in that section (`**Transport: local stdio
only.**`, `**Observable effects only.**`). It has two halves and **both must be
present**, adjacent, or the bullet over-promises.

The promise: the auditor never aims to destroy. Its generator is instructed to
prove injection with benign reflected evidence, and a deterministic guard refuses
a payload before it leaves the auditor when it contains one of a short, literal
list of destructive command forms (`rm -rf`, `mkfs`, `DROP TABLE`, a shutdown
command, a fork bomb, and a handful more). A refused payload is reported as
blocked, never sent, never judged.

**Describe the mechanism, not eight category names.** Writing "file deletion" or
"host shutdown" names a *property* the substring list does not enforce, and a
reader would reasonably conclude every deletion is caught. Name the shape of the
list instead, and give one concrete thing it lets through so the boundary is
visible rather than discovered: the repo already documents one, `CVE-2025-68144`
in `evals/cve_targets.py`, where `git_diff --output=/path` overwrites a file
silently and `--output=` is not in the table.

The limit, in the same bullet: it still calls the server's own tools with
adversarial arguments, so **if a tool writes, auditing it writes**. And the
auditor cannot observe a call's side effects (`ADR 011`), so it cannot promise
their absence. Point it at a server whose state you can restore.

**Must not claim**: "read-only", "no side effects", "safe against production",
"will not modify your server", or that the guard is a sandbox or a security
boundary. Say "enumerated constructs", never a guaranteed property. The existing
"Not in scope" note stands and stays reachable from here: the audited server runs
as a subprocess with the user's privileges whatever our payloads contain.

Link the new `ADR 013`, matching how every other bullet in that section and in
`Design decisions` links its ADR. Reference `ADR 011` for the silent-effect class
rather than restating it, so the two documents do not drift.

### `CLAUDE.md`

Two lines of the Coding standards section stop being true once `build_graph`
takes an `AuditedServer`, and `CLAUDE.md` is a living doc, so its own workflow
rule ("a feature isn't done until the living docs match it") applies.

- "Graph nodes are built via factory functions (`make_node(port)`) [...] Ports are
  `Protocol` classes in `domain/`." Two node factories now take a concrete domain
  service, not a Protocol. Reword so the rule still reads as the injection rule it
  is, and name the exception rather than deleting the rule.
- The example block in Testing standards calls
  `build_graph(llm=fake_llm, mcp_client=FakeMCPClient([tool]))`, which no longer
  type-checks. Update it to wrap the fake.

### `CHANGELOG.md`

An entry under `[Unreleased]`, `### Changed`, describing the user-facing behavior:
the auditor now proves injection non-destructively, and refuses to send a payload
it judges destructive, reporting it as blocked. Reference the new ADR.

### `docs/adr/013-non-destructive-payloads.md` (new)

Short ADR. Its thesis is a **safety policy**, not a capability boundary.

- **Context**: the auditor generates and sends its own payloads; a graded run
  produced `rm -rf /`; nothing prevented it from reaching the server.
- **Decision**: the auditor proves injection without destructive mutation, through
  a prompt constraint plus a deterministic guard, enforced behind a single named
  door. A blocked payload is reported, never disguised as a server response.
- **`AuditedServer` and the union return.** Record why the guard is a domain
  service owning the send rather than a call the nodes remember to make: the
  hexagon interior holds no object able to call `call_tool`, so a future
  execution path cannot bypass the guard by omission, only by a deliberate
  signature change. And record the invariant that makes it work, because it is
  invisible in the code: **`BlockedPayload` shares no attribute name with
  `ToolResponse`**, which is what makes an unhandled refusal a type error instead
  of a silent success, and what makes it structurally impossible for a refusal to
  be read as server behavior. Name the `Unknown tool` incident as the precedent.
- **`evals/cve_targets.py` calibration keeps the raw port on purpose**: its
  exploits are hand-written ground truth, not generated payloads, so the guard
  does not apply. Without this line someone will "fix" the inconsistency and
  break the calibration gate.
- **Why no ground-truth cell requires a destructive payload**: the two-case argument from the Context
  section of this plan. State it, since it is the load-bearing claim.
- **Scope of the policy, in one line**: destruction of state and host
  availability. **Not** writes. Record the three reasons from "Destruction, not
  mutation": auditing a write tool requires writing, so a read-only policy would
  mean not testing write tools for injection; a read-only promise would be
  unverifiable under `ADR 011`; and it would reclassify `CVE-2025-68143` for a
  self-imposed rule rather than a capability limit.
- **Prompt and guard are deliberately co-extensive.** State it as a decision, not
  a coincidence: the prompt must never forbid more than the guard can enforce, or
  the guard stops being the deterministic backstop and the surplus prohibition
  becomes an unbacked promise. This is the general rule the ADR contributes
  beyond the immediate fix.
- **The read-only preference that survives**, and that it is generator guidance
  with no guarantee attached, never a claim made to the user.
- **The guard's honest limit**: an enumerated denylist aimed at our own
  generator's exuberance. Not bypass-resistant, not claiming completeness. Name
  what still passes (an obscure destructive binary, a clobbering redirect to a
  relative path) rather than leaving the reader to discover it.
- **The bare-word bet, recorded as a bet, not as a fact.** No pattern is a bare
  command word, so a bare `shutdown` or `reboot` passes. The reasoning: the
  discrimination that would block it is unavailable, since `command="shutdown"`
  and `service="shutdown"` are identical at the guard's signature and only the
  argument *name* separates them, which comes from a server `ADR 004` declares
  hostile. The bet is that an LLM writes `shutdown -h now`, not a bare
  `shutdown`. It is not measured. If it is wrong, the fix is one string in one
  tuple.
- **Why literal substring matching, and not something that looks more rigorous.**
  Record the rejections so nobody re-opens them: a regex per construct (the fork
  bomb pattern `:|:&` read as a regex matches every string and would block the
  whole suite, and a denylist that cannot be audited by eye defeats its own
  purpose); `shlex` or shell-grammar parsing (payload values are routinely not
  valid shell, `' OR '1'='1` raises, so the fallback path *is* substring matching
  and half the mandate is not shell at all); an allowlist (wrong polarity, the
  benign side is the unbounded one); a second LLM call (a probabilistic backstop
  under a probabilistic constraint is not a backstop); a per-category decision
  (no category makes destruction legitimate); `destructiveHint` (describes the
  tool not our payload, and is server-supplied). The property that decides is
  that the adversary is our own generator writing canonical forms, so
  bypass-resistance buys nothing.
- **Relation to ADR 011**, which is load-bearing here rather than merely
  referenced: the unobservability of side effects is *both* the reason this ADR
  cannot promise the absence of writes *and* the reason a destructive payload
  never carried detection value. This ADR adds no capability exclusion of its
  own; the residual silent-effect class stays exactly where `ADR 011` put it,
  behind the deferred `ExecutionObserver` seam. Same relationship style as
  `ADR 011`'s own closing paragraph about `ADR 004`.
- **Alternatives considered**: prompt only (rejected: a safety property must not
  depend on LLM compliance, and the measured failure mode is the model improvising
  the payload into three different argument names); a `MCPClientPort` decorator
  (rejected: it would disguise an auditor refusal as a server error, the
  `Unknown tool` false-positive class); silently dropping a blocked case
  (rejected: the budget would shrink and distribution coverage would drift, so
  the metrics would lie); read-only proof only, a `--read-only` flag, and a
  server-declared-scope boundary (all three rejected in "Destruction, not
  mutation", with their reasons).

  On the decorator specifically, be precise rather than dismissive: the objection
  was never the choke point, it was `ToolResponse`'s shape. Widening the return
  type to a union removes that objection, which is exactly what `AuditedServer`
  does. Recording this matters, because a reader who sees only "decorator
  rejected" will conclude the choke point was the problem and rebuild the wrong
  thing.

## What stays unchanged

- `AuditPayload` keeps its shape. The guard reads it, nothing is added to what the
  LLM must emit.
- `ChainStep` keeps its shape.
- The judge prompt's structure, its rules 1 to 3, and the four non-`INJECTION`
  entries of `CATEGORY_GUIDANCE`.
- `evals/metrics.py`, `evals/export.py`, `evals/ground_truth.py`. They already
  guard on `eval_result is None` and need no change. The ground truth is not
  touched: no cell depends on a destructive payload.
- The honeypot servers. Fixing an apparent bug there would silently degrade the
  eval suite.
- The four other categories' generator guidance. Only `injection` changes.
- The `resource_abuse` category's ability to send large and unbounded values.
- `--dry-run`, which never executes and therefore never blocks.
  `build_dry_run_graph` routes `generate_test_cases -> collect_generated_cases`
  with no `execute_tool` node, so the guard is never consulted and no case ever
  carries a `blocked_reason`. Consulting it there would be cosmetic consistency:
  the guard protects the send, and a dry run sends nothing.

  **Consequence to keep in mind when verifying.** A dry-run JSON report still
  contains whatever the generator produced, `rm -rf /` included, with no
  `blocked_reason` on it. The verification step below says to grep the report for
  `rm -rf`; that grep is only meaningful on a **real run**. Run against a
  dry-run report it hits, and reads as a failed fix.
- `evals/cve_targets.py`. No field, note or `awaited_capability` changes.
  `CVE-2025-68143` stays reachable, and nothing moves into `OUT_OF_SCOPE_CVES`.
  This is a consequence of the destruction-not-mutation decision and is worth
  asserting: the change costs no benchmark target.
- The auditor's ability to call mutating tools. Writes are how a write tool is
  audited at all.

## Edge cases

| Case | Expected behavior |
|---|---|
| Payload with `;` or `$()` but no destructive verb | Sent. Injection syntax is the point of the category. |
| `delete_record(record_id=1)` | Sent. The tool's own function is legitimate. |
| `delete_record(record_id="1; rm -rf /")` | Blocked on `rm -rf`, found in the injected content. |
| Destructive string nested in a list or dict argument | Blocked. The walk is recursive. |
| Destructive string in an argument *name*, not a value | Sent. Names are never inspected; a name cannot execute. |
| Non-string values only (ints, booleans, `None`) | Sent. Nothing to match. |
| Every case for a tool blocked | Tool report has cases, no `eval_result`, distribution coverage drops for that tool. Intended and visible. |
| First chain step blocked | `abandon_chain`: chain recorded with `blocked_reason`, no verdict, no LLM call. |
| Mid-chain step blocked | Chain ends; `judge_chain` judges the executed prefix and stamps `blocked_reason`. |
| Block on one chain, next chain fine | `prepare_chain` resets `blocked_step_reason`; no leak between chains. |
| `RESOURCE_ABUSE` payload with a huge `limit` | Sent. Bounded by the tool-call timeout. |
| `RESOURCE_ABUSE` payload containing a fork bomb | Blocked. Dangerous to host and run. |
| `git_init(repo_path="/out/of/scope")`, `git_add(".")` | Sent. Writes, not destruction. Keeps `CVE-2025-68143` reachable. |
| `write_file(path=..., content="; echo marker")` | Sent. Auditing a write tool writes. |
| SQL payload containing `WHERE price > 5` | Sent. A bare `>` is not a redirect. |
| XML or HTML payload containing `>` | Sent. Same reason. |
| `echo evil > /etc/hosts` | Blocked. Redirect to an absolute path. |
| `echo evil > notes.txt` | **Sent.** Relative-path redirect is part of the accepted residual. |
| `chmod -R 000 /work` | Blocked. Recursive permission change. |
| `git push --force` | Blocked. Forced version-control write. |
| `cat log 2> /dev/null` | Sent. Harmless sinks are stripped before matching. |
| `service="shutdown"` on a status tool | **Sent.** Bare command word, the named bet. |
| `command="shutdown -h now"` | Blocked. Argument-carrying form. |
| Value containing `/opt/halted` | Sent. `halt` is not a pattern. |
| `'; DELETE FROM users--` | Blocked. Destructive SQL. |
| `mv notes.txt /tmp/` | **Sent.** `mv /` requires an absolute source. |

## Test scenarios

Written **test-first**: each scenario below goes in and is run red before the
code that makes it pass.

Unit tests reuse the existing `tests/unit/support/test_<name>_given.py` and
`_then.py` pairs where the setup or the assertion actually abstracts something.
Where it does not, inline it: `test_payload_safety.py` calls a pure function with
a literal dict and asserts on the returned string, so it gets **no** given/then
pair.

### `tests/unit/test_payload_safety.py` (new)

Exhaustive on the pure function, no fakes needed.

- Each blocked group returns a reason naming that group: `rm -rf /`, `mv /data /data.bak`,
  `echo x > /etc/hosts`, `chmod -R 000 /work`, `mkfs.ext4 /dev/sda`, `dd of=/dev/sda`,
  `DROP TABLE users`, `TRUNCATE TABLE users`, `'; DELETE FROM users--`,
  `git push --force`, `shutdown -h now`, `:(){ :|:& };:`.
- Case-insensitivity: `drop table` and `DROP TABLE` both blocked.
- **The table's own invariants**, asserted in one loop over
  `DESTRUCTIVE_CONSTRUCTS`:

  ```python
  assert pattern == pattern.lower()   # else the pattern can never fire
  assert not pattern.isalnum()        # else it matches incidental words
  ```

  This is a structural test, and it is the one place where that is the right
  call. It guards the exact maintenance moment at which the mechanism fails
  **silently**: an uppercase pattern matched against a lowercased value never
  fires, which is a fail-open in the catastrophic direction that no behavioral
  test would reveal, and a bare-word pattern reintroduces the incidental-match
  class. Both failures recur every time a construct is added, which is precisely
  what makes the invariant worth pinning rather than remembering.
- Harmless sinks are stripped before matching: `cat log 2> /dev/null` returns
  `None`, while `echo x > /etc/hosts` is blocked.
- Allowed payloads return `None`: `' OR '1'='1`, `; SELECT sqlite_version()`,
  `$(id)`, `` `whoami` ``, `../../etc/passwd`, `UNION SELECT null, null`,
  `echo mcp-auditor-probe`.
- **Writes are allowed**, which is the policy decision made executable:
  `git_init` with an out-of-scope `repo_path`, `git_add(".")`, and a
  `write_file`-shaped payload all return `None`. Without these cases a later
  refactor could tighten the guard into a mutation guard and silently make
  `CVE-2025-68143` unreachable.
- **The bare `>` is not a redirect**: `WHERE price > 5` and a payload containing
  `<script>` return `None`, while `> /etc/hosts` is blocked. This pins the
  deliberate ambiguity boundary so it cannot be widened without a failing test.
- Every accepted residual is asserted, not merely documented, each named in the
  test as known-permitted so anyone tightening the rule meets a decision rather
  than a gap: `echo evil > notes.txt`, a bare `shutdown`, a bare `reboot`,
  `mv notes.txt /tmp/`, and a value containing `/opt/halted`. The last two exist
  specifically because `mv /` and the deletion of `halt` are the entries most
  likely to be "fixed" back by someone who has not read `ADR 013`.
- `delete_record(record_id=1)` allowed; `delete_record(record_id="1; rm -rf /")` blocked.
- Recursive walk: destructive string inside a list, and inside a nested dict.
- Argument name containing `rm -rf` with benign values: allowed.
- Empty arguments, and arguments with only non-string values: allowed.

### `tests/unit/test_audited_server.py` (new)

Three tests, with a `FakeMCPClient` underneath so the real guard runs:

- `attempt` with a destructive payload returns a `BlockedPayload` carrying the
  reason, and `FakeMCPClient.calls` is **empty**. That is the whole point of the
  change stated as one assertion: the auditor did not touch the server.
- `attempt` with a benign payload returns the client's `ToolResponse`.
- `list_tools` delegates.

### `tests/unit/test_nodes.py`

- A blocked case is recorded with its `blocked_reason`, and `FakeMCPClient`
  received **no call** for it. Assert on the observable outcome, not on internals.
- A blocked case has `eval_result is None` and `response is None` and
  `error is None`.
- A safe case still executes and is judged, unchanged.
- `route_after_execute` returns `judge_response` after a normal execution,
  and continues to the next pending case or ends after a block.

These get strictly better with `AuditedServer`: the fake is injected underneath
it, so the real guard is live in every node test instead of being stubbed out.

### `tests/unit/test_chain_nodes.py`

- First step blocked: chain lands in `completed_chains` with `blocked_reason`,
  `eval_result is None` and `steps == []`. Assert the outcome, not that the judge
  was skipped: `FakeLLM` records nothing, and an absent `eval_result` is the
  observable form of "no verdict was produced".
- Mid-chain step blocked: the executed prefix is judged, the chain carries
  `blocked_reason`, and the blocked step is absent from `chain.steps`.
- `blocked_step_reason` does not leak into the next chain.

### `tests/unit/test_graph.py`

- End-to-end through the compiled graph with a `FakeLLM` that emits one
  destructive and one safe payload: the report contains both cases, one blocked
  and unjudged, one judged, and the fake MCP client saw exactly one call.

### `tests/unit/test_prompts.py`

- `build_attack_generation_prompt` contains the non-destructive constraint.
- The same constraint appears in both chain prompts, asserted through the shared
  constant so the three sites cannot drift.
- The constraint states a prohibition on destruction and a *preference* for
  benign reflected proof, and does **not** contain a blanket prohibition on
  writing or mutating. Assert the absence, not only the presence: a later
  well-meaning edit that hardens the preference into a rule is exactly the
  regression that would make write tools untestable and `CVE-2025-68143`
  unreachable, and nothing else in the suite would catch it.

### `tests/unit/test_rendering.py`

- A blocked case renders a `BLOCKED` section with its reason.
- A chain with `blocked_reason` renders it.
- The summary reports a `Blocked` count when above zero, and omits it at zero.

### `tests/unit/test_progress.py`

- `ToolProgress.advance_blocked` prints a line naming the reason and does not
  count the case as a failure in the tool summary.
- `CIProgress.advance_blocked` prints the reason in CI mode.

Both write through the console captured by `given.a_display()` in
`tests/unit/support/test_console_given.py`, the same setup the existing display
tests use.

### `tests/unit/test_stream_handler.py` (new)

`stream_handler.py` has no test module today, and `test_console_display.py`
covers `console.py`, not the reporter. One test file per module, so this is a new
file.

- The stream handler advances on an `execute_tool` update carrying a blocked case,
  and does nothing on a normal `execute_tool` update. Without this, the bar stalls
  one tick short per block and the notice never prints, which is exactly the
  regression the two-file split above exists to prevent.

### `tests/unit/test_prompts.py` and `tests/unit/test_chain_prompts.py`

- `build_context_extraction_prompt` omits a blocked case.
- `build_chain_planning_prompt` omits a blocked case from the single-step summary.

### `tests/unit/test_readme_policy.py` (new)

One test, on the `README.md` text itself. The scope bullet's promise and its
limit must stay in the **same** bullet: assert that the paragraph containing the
promise also contains the "if a tool writes, auditing it writes" clause and the
`ADR 011` reference.

The reason this is worth a test rather than review discipline: the two halves are
what keep the claim truthful, and separating them is a plausible tidy-up edit
that no other test would catch. A README that promises a safety guard without its
limit is how a reader ends up pointing the auditor at production. This is the
only assertion in the suite on documentation text, and it is scoped to that one
invariant, not to the wording.

### `tests/unit/test_eval_metrics.py`

- A report containing a blocked case yields the same recall, precision and
  consistency as the same report without it. Guards the claim that a payload we
  never sent is neither a detection nor a false positive.
- Distribution coverage **drops** when the only case of a category is blocked.
  This asserts the intended visibility, so a later refactor cannot quietly
  restore a misleading full-coverage number.

## Verification

```bash
uv run pytest                    # unit + integration
uv run ruff check .
uv run ruff format .
uv run pyright                   # strict
```

Then, cheapest first:

```bash
uv run python -m evals.run_judge_eval    # ~4s, F1 >= 0.90 gate
uv run python -m evals.run_evals         # recall / precision / consistency / distribution
```

The judge eval is the one that answers the `CATEGORY_GUIDANCE` question: if
sharpening the echo-versus-execution exclusion broke a case, it shows here in
seconds. Step 3 carries the decision rule for when it fails.

**How to read the e2e run, and the interaction nobody else will warn you about.**

`run_evals` gates on four thresholds and exits non-zero below any of them. One of
them interacts directly with this change: **a block can fail the distribution
gate for a correct reason.** `compute_distribution_coverage` counts the
categories covered by cases that carry an `eval_result`, and a blocked case has
none. So if the generator emits a destructive `injection` payload during an eval
run, that tool loses the `injection` category and its coverage falls from 1.00 to
0.80 on five categories. The threshold is 0.80 and the published figure is 1.00,
so **one block sits exactly on the threshold and two fall below it.**

The response is not to lower the threshold. A block during an eval run means the
prompt did not hold, which is precisely the signal this design was built to make
visible. Fix the prompt.

Hence the reading order when the gate fails:

1. **Attribute before diagnosing.** Check the reports for blocked cases first. A
   distribution failure explained by blocks is a prompt-compliance finding, not a
   detection regression, and the two have opposite fixes.
2. **Re-run before concluding.** Recall rests on 11 ground-truth `FAIL` cells over
   3 runs. At that sample size the minimum detectable effect is large, so a small
   move is not evidence of anything. One re-run costs minutes; a wrong conclusion
   costs a prompt tuned against noise.
3. **If a recall cell genuinely disappeared, read its transcript** and answer one
   question: did the generator stop producing the payload that used to establish
   that cell, which is a real capability cost of the constraint and must be
   written down, or did the judge change its verdict on an equivalent payload,
   which is unrelated to this change?
4. **Never tune the prompt to bring a number back.** The number is the
   measurement, not the target. If the constraint genuinely costs a cell, the
   honest outcome is a recorded cost, not a reworded prompt that games the eval.

**If the numbers move, the README table moves with them.** `README.md` publishes
Recall 0.88 / Precision 0.85 / Consistency 0.97 / Distribution 1.00, all measured
before this guard existed. If the run lands on different figures and the move
survives the reading order above, republish the table in the same commit. Leaving
a measured table that no longer describes the shipped tool is the failure this
repo's credibility is least able to afford. If the figures hold, say nothing and
change nothing.

Then the CVE target that motivated the change:

```bash
docker compose -f evals/docker/compose.yml build
uv run python -m evals.run_cve_benchmark --calibrate
uv run python -m evals.run_cve_benchmark --cve CVE-2025-53355 --runs 3 --budget 10
```

**How to read that run.** The check is that the auditor still returns a critical
`injection` FAIL on **`kubectl_generic`**, 3 runs out of 3. It is **not** the
oracle status: the sentinel oracle only credits the exfiltration of a specific
planted secret, which lives in an environment variable, while the generator
exfiltrates `/etc/passwd`. It therefore reports this CVE as `missed` even though
detection works. That under-crediting is a known property of the oracle and is
out of scope here. Reading the oracle status instead of the verdicts would
produce a false regression signal.

The tool name is spelled out above on purpose. The GHSA advisory for this CVE
names `kubectl_scale`, `kubectl_patch` and `explain_resource`, not
`kubectl_generic`, so opening the advisory mid-triage invites the wrong
conclusion that the fixture targets the wrong tool. It does not: the advisory
also notes that similar patterns exist elsewhere in the codebase, and
`_calibrate_kubernetes_injection` (`evals/cve_targets.py`) proves this fixture
live by running `kubectl_generic({"command": "version; echo $FLAG"})`.

Also confirm no destructive payload is emitted any more. **Watch where you look**:
neither eval runner exposes a blocked case in its report file.

- `run_cve_benchmark` discards the `AuditReport` entirely, keeping only
  `CVEResult` records (`_write_reports`), so `output/cve_report.json` cannot show
  a blocked case or a payload.
- `run_evals` writes `judged_cases.jsonl` through `export_judged_cases`, which
  `continue`s on `case.eval_result is None` — that skip is what makes a blocked
  case metric-neutral, and it also means it never reaches the JSONL.

So the two observable channels are: the **live console notice** added in
`stream_handler.py` / `progress.py` during the run, and a direct
`mcp-auditor run -o <path>` against the kubernetes fixture, whose JSON report
serializes `blocked_reason` on the case. Grep that JSON for `rm -rf` and for
`blocked_reason`.

**Do not run that grep against a `--dry-run` report.** A dry run never executes,
so the guard is never consulted and the report still contains whatever the
generator produced. The grep would hit and read as a failed fix. It is only
meaningful on a real run.

**Decided: `export_judged_cases` does not emit blocked cases.** Making block
frequency measurable across eval runs is a real want, but `judged_cases.jsonl`
feeds the judge fixture pipeline (`ADR 007`): every line is a verdict a human
reviews and may promote into `judge_cases.json`. A blocked case has no verdict,
so it is not judge material, and adding a line type would invite a consumer to
count it as a judged case. Block frequency is observable where it belongs, on the
report and in the live console. If it later needs to be tracked across runs, the
right place is a counter on `EvalReport`, which is separate work.


## Not in scope

- **Sandboxing the audited server.** The auditor spawns the target as a raw
  subprocess with the user's privileges. Untrusted server code runs on the host
  regardless of how benign our payloads are. That is a separate and heavier piece
  of work, and this change does not claim to address it.
- **Instrumented observation.** No host-state snapshot or diff. `ADR 011` stands.
- **Widening the exfiltration repertoire** (environment dump and similar). It
  would change a published benchmark number and needs its own justification on
  the merits.
- **Regenerating a blocked case.** A corrective generation loop is a different
  feature.
- **The judge's remaining domain overfit.** Sharpening one exclusion line in the
  `INJECTION` entry is the minimum this change requires. Rewriting the guidance
  for server-type awareness is separate work.

## Implementation steps

Verification commands for this repo (from `CLAUDE.md` and `pyproject.toml`):
`uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`,
`uv run ruff format .`, `uv run pyright` (strict, `line-length = 100`).

### Step 1: the pure guard and the named door

**Files**

- `tests/unit/test_payload_safety.py` (new)
- `tests/unit/test_audited_server.py` (new)
- `tests/fakes/mcp_client.py` (modify)
- `src/mcp_auditor/domain/payload_safety.py` (new)
- `src/mcp_auditor/domain/models.py` (modify)
- `src/mcp_auditor/domain/__init__.py` (modify)
- `src/mcp_auditor/domain/audited_server.py` (new)

**Do** (tests and fixtures first, then production code)

1. `tests/unit/test_payload_safety.py` — no given/then pair. Each test calls
   `destructive_reason({...})` with a literal dict and asserts on the returned
   `str | None`. Import `DESTRUCTIVE_CONSTRUCTS` for the table-invariant test.
2. `tests/unit/test_audited_server.py` — no given/then pair, three tests, a
   `FakeMCPClient` injected underneath a real `AuditedServer` so the real guard
   runs.
3. `tests/fakes/mcp_client.py` — add a public `calls: list[tuple[str, dict[str, Any]]]`
   initialised in `__init__` and appended in `call_tool` before returning. Nothing
   else changes.
4. `src/mcp_auditor/domain/payload_safety.py` — new module, hexagon interior, no
   I/O. One-line header comment naming the mandate (destructive to state, or
   dangerous to the host and the run) and pointing at `ADR 013`, plus one line
   saying the list is enumerated, not complete. Same heading style as
   `domain/category_guidance.py`. No docstring on the public function.

   Newspaper order: public function first, private helpers below it, table last.

   ```python
   def destructive_reason(arguments: dict[str, Any]) -> str | None:
   ```

   - Walks the argument *values* recursively (`str`, `int`, `list`, `dict`,
     `None`, ...) and inspects string values only. Argument *names* are never
     inspected.
   - Lowercases the value and strips the harmless sinks
     (`_HARMLESS_SINKS = ("/dev/null", "/dev/stdout", "/dev/stderr")`) in a named
     `_without_harmless_sinks` helper **before** matching, so `2> /dev/null` and
     `2>/dev/null` behave alike.
   - Returns the first matching construct's `reason`, formatted so the message
     names one concrete construct, e.g.
     `"destructive filesystem command: rm -rf"`. The reason string comes from the
     `DestructiveConstruct`, never duplicated at the match site.
   - Private helpers: `_first_destructive_string` (recursive walk),
     `_matching_construct` (group lookup). Public function stays under 20 lines.

   ```python
   @dataclass(frozen=True)
   class DestructiveConstruct:
       reason: str
       patterns: tuple[str, ...]
   ```

   `DESTRUCTIVE_CONSTRUCTS: tuple[DestructiveConstruct, ...]` holds exactly the
   eight groups of the plan's table, all patterns lowercase, none a bare word.
   Copy the patterns verbatim from the table (note the trailing spaces on
   `rm -r `, `rmdir `, `shred `, `unlink `, `push -f `, `delete from `). `halt`
   is deliberately absent.

5. `src/mcp_auditor/domain/models.py` —
   - `TestCase` gains `blocked_reason: str | None = None`.
   - `AttackChain` gains `blocked_reason: str | None = None`.
   - `ChainStep` unchanged.
   - New frozen dataclass `BlockedPayload` beside `ToolResponse`, with a one-line
     comment recording the invariant: no field is named like a `ToolResponse`
     field (`content`, `is_error`, `error_type`), which is what makes an
     unhandled refusal a type error rather than a silent success.

   ```python
   @dataclass(frozen=True)
   class BlockedPayload:
       reason: str
   ```

6. `src/mcp_auditor/domain/__init__.py` — export `BlockedPayload` (import list and
   `__all__`, both alphabetical).
7. `src/mcp_auditor/domain/audited_server.py` — new module, ~22 lines, exactly the
   class in the plan's "Files to modify" section. Imports `MCPClientPort` from
   `domain/ports.py`, `destructive_reason` from `domain/payload_safety.py`,
   `AuditPayload` / `BlockedPayload` / `ToolDefinition` / `ToolResponse` from
   `domain/models.py`. Not a `Protocol`. No import from `adapters/`.

**Test**

`tests/unit/test_payload_safety.py`:

- One blocked case per group, asserting the reason names that group:
  `{"command": "rm -rf /"}`, `{"cmd": "mv /data /data.bak"}`,
  `{"cmd": "echo x > /etc/hosts"}`, `{"cmd": "chmod -R 000 /work"}`,
  `{"cmd": "mkfs.ext4 /dev/sda"}`, `{"cmd": "dd of=/dev/sda"}`,
  `{"query": "DROP TABLE users"}`, `{"query": "TRUNCATE TABLE users"}`,
  `{"query": "'; DELETE FROM users--"}`, `{"cmd": "git push --force"}`,
  `{"cmd": "shutdown -h now"}`, `{"cmd": ":(){ :|:& };:"}`.
- Case-insensitivity: `drop table` and `DROP TABLE` both return a reason.
- Table invariants, one loop over `DESTRUCTIVE_CONSTRUCTS`:
  `assert pattern == pattern.lower()` and `assert not pattern.isalnum()` for every
  pattern of every construct.
- Harmless sinks stripped before matching: `{"cmd": "cat log 2> /dev/null"}` and
  `{"cmd": "cat log 2>/dev/null"}` return `None`, while
  `{"cmd": "echo x > /etc/hosts"}` is blocked.
- Allowed injection payloads return `None`: `' OR '1'='1`,
  `; SELECT sqlite_version()`, `$(id)`, `` `whoami` ``, `../../etc/passwd`,
  `UNION SELECT null, null`, `echo mcp-auditor-probe`.
- Writes allowed (the policy made executable): `{"repo_path": "/out/of/scope"}`
  (git_init shape), `{"files": ["."]}` (git_add shape),
  `{"path": "/tmp/x.txt", "content": "; echo marker"}` (write_file shape) all
  return `None`.
- Bare `>` is not a redirect: `{"query": "WHERE price > 5"}` and
  `{"body": "<script>alert(1)</script>"}` return `None`, while
  `{"cmd": "> /etc/hosts"}` is blocked.
- Accepted residuals, each named in the test name as known-permitted:
  `echo evil > notes.txt`, a bare `shutdown`, a bare `reboot`,
  `mv notes.txt /tmp/`, a value containing `/opt/halted` — all return `None`.
- `{"record_id": 1}` returns `None`; `{"record_id": "1; rm -rf /"}` is blocked.
- Recursive walk: `{"items": ["ok", "rm -rf /"]}` and
  `{"outer": {"inner": {"cmd": "rm -rf /"}}}` both blocked.
- Argument *name* containing the construct with benign values:
  `{"rm -rf /": "hello"}` returns `None`.
- `{}` returns `None`; `{"n": 1, "flag": True, "x": None}` returns `None`.

`tests/unit/test_audited_server.py`:

- `attempt` with a destructive payload returns a `BlockedPayload` whose `reason`
  names the construct, **and** `fake_client.calls == []`.
- `attempt` with a benign payload returns the client's `ToolResponse`, asserted
  on the content. Do **not** also assert on `fake_client.calls` here: the returned
  response already proves delegation, and asserting the recorded call would be a
  call-sequence assertion, which the testing standards forbid. The `calls` list
  exists for the one thing nothing else can observe, that a blocked payload
  produced *no* call.
- `list_tools` returns the client's tools.

**Verify**

```bash
uv run pytest tests/unit/test_payload_safety.py tests/unit/test_audited_server.py  # red first, then green
uv run pytest
uv run ruff check . && uv run ruff format .
uv run pyright
```

Expect: the two new files red before the production code exists, all green after,
zero pyright diagnostics, and the whole existing suite still green (the two model
fields are optional with defaults, so nothing else moves).

---

### Step 2: `AuditedServer` becomes the graph's only reach into the server

This step is one commit because the changes are inseparable: `build_graph`'s
signature change forces every composition site and both execution nodes at once,
and a half-migrated chain path would deadlock the subgraph.

**Files**

- `tests/unit/support/test_graph_given.py` (modify)
- `tests/unit/support/test_chain_nodes_given.py` (modify)
- `tests/unit/test_nodes.py` (modify)
- `tests/unit/test_chain_nodes.py` (modify)
- `tests/unit/test_graph.py` (modify)
- `src/mcp_auditor/graph/state.py` (modify)
- `src/mcp_auditor/graph/nodes.py` (modify)
- `src/mcp_auditor/graph/chain_nodes.py` (modify)
- `src/mcp_auditor/graph/builder.py` (modify)
- `src/mcp_auditor/cli.py`, `src/mcp_auditor/studio.py`, `evals/run_evals.py`,
  `evals/run_cve_benchmark.py` (one-line wraps)

**Do** (tests first)

1. Test support first:
   - `test_graph_given.py`: `a_graph` and `a_graph_with_checkpointer` wrap the fake
     client — `build_graph(fake_llm, AuditedServer(fake_mcp_client), ...)`. Add
     `a_fake_llm_for_destructive_and_safe_case()` returning a `TestCaseBatch` whose
     first payload has `arguments={"command": "rm -rf /"}` and second
     `arguments={"input": "malicious"}`, followed by **one** judgment (only the
     safe case is judged) and an `AttackContext()`.
   - `test_chain_nodes_given.py`: `a_chain_audit_state` adds
     `"blocked_step_reason": None` to the returned dict, with a
     `blocked_step_reason: str | None = None` parameter.
2. `tests/unit/test_nodes.py`, `tests/unit/test_chain_nodes.py`,
   `tests/unit/test_graph.py`: add the scenarios below; update existing
   constructions from `make_execute_tool(client)` / `make_discover_tools(client)` /
   `make_execute_step(client)` to pass `AuditedServer(client)`.
3. `src/mcp_auditor/graph/state.py`: `ChainAuditState` gains
   `blocked_step_reason: str | None`.
4. `src/mcp_auditor/graph/nodes.py`:
   - `make_discover_tools(server: AuditedServer, tools_filter=None)` calls
     `server.list_tools()`.
   - `make_execute_tool(server: AuditedServer)` — exactly the body in the plan:
     `outcome = await server.attempt(tool, case.payload)`, `isinstance` narrowing
     on `BlockedPayload`, blocked case goes to `judged_cases` via
     `case.model_copy(update={"blocked_reason": outcome.reason})` with
     `current_case` set to `None`, otherwise the existing error/response branch.
   - New `route_after_execute(state)` placed next to `route_test_cases`: returns
     `route_test_cases(state)` when `state["current_case"] is None`, else
     `"judge_response"`.
   - Drop the now-unused `MCPClientPort` import.
5. `src/mcp_auditor/graph/chain_nodes.py`:
   - `make_execute_step(server: AuditedServer)`: `outcome = await server.attempt(tool, payload)`,
     `if isinstance(outcome, BlockedPayload): return {"blocked_step_reason": outcome.reason}`
     before any `ChainStep` is built. A blocked step is never appended.
   - `make_judge_chain`: when `state["blocked_step_reason"]` is set, stamp it with
     `chain.model_copy(update={"blocked_reason": reason})` and clear
     `"blocked_step_reason": None` in the returned dict alongside the other
     per-chain resets. The judge prompt still receives only executed steps.
   - New sync node `abandon_chain(state)` right after `make_judge_chain`, exactly
     the body in the plan.
   - New `route_after_execute_step(state)` with the other routers, exactly the body
     in the plan.
   - `prepare_chain` adds `"blocked_step_reason": None` to its returned dict.
   - Drop the now-unused `MCPClientPort` import.
6. `src/mcp_auditor/graph/builder.py`:
   - `build_graph(llm, server: AuditedServer, ...)`, `build_dry_run_graph(llm, server: AuditedServer, ...)`,
     and both private subgraph builders take `AuditedServer`.
   - `_build_audit_tool_subgraph`: replace `builder.add_edge("execute_tool", "judge_response")`
     with
     ```python
     builder.add_conditional_edges(
         "execute_tool",
         route_after_execute,
         {"judge_response": "judge_response", "execute_tool": "execute_tool", END: END},
     )
     ```
   - `_build_chain_audit_subgraph`: register `abandon_chain`, replace
     `builder.add_edge("execute_step", "observe_step")` with
     `add_conditional_edges("execute_step", route_after_execute_step, {"observe_step": "observe_step", "judge_chain": "judge_chain", "abandon_chain": "abandon_chain"})`,
     and `add_conditional_edges("abandon_chain", route_after_judge)`.
   - Drop the `MCPClientPort` import.
7. Composition root, one line each: `cli.py` (the `build_graph` call site and
   `_run_dry_run`, whose `mcp_client: MCPClientPort` parameter becomes
   `server: AuditedServer` — wrap once at the `async with ... as mcp_client` block),
   `studio.py`, `evals/run_evals.py:216`, `evals/run_cve_benchmark.py:228`.
   **Leave `evals/cve_targets.py` on the raw `MCPClientPort`** — its calibration
   exploits are hand-written ground truth, not generated payloads.

   After this step, `grep -rn MCPClientPort src/mcp_auditor/graph/` must return
   nothing.

**Test**

`tests/unit/test_nodes.py`:

- A destructive payload produces a case in `judged_cases` carrying its
  `blocked_reason`, and `fake_client.calls == []`.
- That blocked case has `eval_result is None`, `response is None`, `error is None`,
  and the node returns `current_case: None`.
- A safe payload still populates `current_case.response` and leaves
  `blocked_reason` `None` (existing behavior, keep the existing tests green).
- `route_after_execute` returns `"judge_response"` when `current_case` is set;
  returns `"execute_tool"` when `current_case is None` and `pending_cases` is
  non-empty; returns `END` when `current_case is None` and no pending cases.

`tests/unit/test_chain_nodes.py`:

- First step blocked (state with empty `current_chain_steps`): running
  `execute_step` then `abandon_chain` yields a chain in `completed_chains` with
  `blocked_reason` set, `steps == []`, `eval_result is None`.
- Mid-chain step blocked: `execute_step` sets `blocked_step_reason` and does not
  append a step; `judge_chain` judges the executed prefix, the resulting chain
  carries `blocked_reason`, and the blocked payload is absent from `chain.steps`.
- `route_after_execute_step` returns `"observe_step"` / `"judge_chain"` /
  `"abandon_chain"` for the three state shapes.
- `blocked_step_reason` does not leak: `prepare_chain` on a state carrying a
  reason returns `blocked_step_reason: None`.

`tests/unit/test_graph.py`:

- End to end through the compiled graph with
  `a_fake_llm_for_destructive_and_safe_case()`: the single `ToolReport` has two
  cases, one with `blocked_reason` and `eval_result is None`, one judged, and the
  `FakeMCPClient` recorded exactly one call.

**Verify**

```bash
uv run pytest tests/unit/test_nodes.py tests/unit/test_chain_nodes.py tests/unit/test_graph.py
uv run pytest
uv run ruff check . && uv run ruff format .
uv run pyright
grep -rn MCPClientPort src/mcp_auditor/graph/   # must print nothing
```

Expect zero pyright diagnostics. If pyright reports
`Cannot access attribute "is_error" for class "BlockedPayload"`, the `isinstance`
narrowing is missing — that diagnostic is the design working, not a problem to
silence with a cast.

---

### Step 3: prompt constraint at the three generation sites, and the judge's echo-versus-execution line

**Files**

- `tests/unit/test_prompts.py` (modify)
- `tests/unit/test_chain_prompts.py` (modify)
- `src/mcp_auditor/graph/prompts.py` (modify)
- `src/mcp_auditor/graph/chain_prompts.py` (modify)
- `src/mcp_auditor/domain/category_guidance.py` (modify)

**Do** (tests first)

1. Add the assertions below to `tests/unit/test_prompts.py` and
   `tests/unit/test_chain_prompts.py`.
2. `graph/prompts.py`:
   - New module-level constant (single source of truth for all three sites), e.g.
     `NON_DESTRUCTIVE_CONSTRAINT`. Two halves, in this order:
     - **Prohibition**, co-extensive with `destructive_reason` and no wider: never
       destroy state and never affect host availability — no deleting or
       overwriting files, no `DROP` or `TRUNCATE`, no recursive permission change,
       no forced version-control write, no shutdown, no fork bomb.
     - **Preference**, explicitly phrased as a preference: when a benign reflected
       marker proves the same thing, prefer it — `echo mcp-auditor-probe`, `id`,
       `whoami`, read-only reads, `SELECT` / `UNION SELECT` rather than DDL or DML.
     - One clause of reason: a destructive payload proves nothing more than a
       benign marker and corrupts the rest of the audit.
     - Generic wording. No honeypot literal, no benchmark target name. No blanket
       prohibition on writing or mutating.
   - Rewrite the `injection` line of `build_attack_generation_prompt` (currently
     line 49) and interpolate the constant into the prompt.
   - `_format_cases_for_extraction`: `continue` on a case whose `blocked_reason`
     is set.
3. `graph/chain_prompts.py`: import the constant from `graph.prompts` (it already
   imports `build_context_section` and `format_tool_header` from there) and
   interpolate it into `build_chain_planning_prompt` (the `first_step` guidance)
   and `build_step_planning_prompt` (every subsequent step). Skip a blocked case
   in `_format_single_step_summary`.
4. `domain/category_guidance.py`: sharpen only the `INJECTION` entry's "What does
   NOT count" echo line so it distinguishes an echo *inside an error message* from
   output that evidences execution — a marker returned as command output, or a
   query result, is execution, not an echo. Leave the four other entries and the
   judge prompt's rules 1-3 untouched. **No prohibition goes in this module**: it
   feeds the judge only, and the judge generates nothing.

**Test**

`tests/unit/test_prompts.py`:

- `build_attack_generation_prompt(...)` contains `NON_DESTRUCTIVE_CONSTRAINT`.
- The constraint states the prohibition and names the benign markers.
- **Absence assertion**: the constraint contains no blanket prohibition on writing
  or mutating (assert the absence of a "do not write" / "do not modify" style rule
  — pick the literal phrasing chosen and assert it is not there, and assert the
  preference wording is present instead). This is the test that keeps
  `CVE-2025-68143` reachable, so name it accordingly.
- `build_context_extraction_prompt` omits a case whose `blocked_reason` is set:
  build a `ToolReport` with one normal case and one blocked case, assert the
  blocked case's description does not appear in the prompt.

`tests/unit/test_chain_prompts.py`:

- `build_chain_planning_prompt(...)` and `build_step_planning_prompt(...)` both
  contain `NON_DESTRUCTIVE_CONSTRAINT` — assert through the imported constant, not
  a copied literal, so the three sites cannot drift.
- `build_chain_planning_prompt` omits a blocked case from the single-step summary.

**Verify**

```bash
uv run pytest tests/unit/test_prompts.py tests/unit/test_chain_prompts.py
uv run pytest
uv run ruff check . && uv run ruff format .
uv run pyright
uv run python -m evals.run_judge_eval   # ~4s, needs an LLM key, F1 >= 0.90 gate
```

Note on the key: the default provider is `google` (`config.py`) and both eval
workflows pass `GOOGLE_API_KEY`, so that is the key this command needs unless
`MCP_AUDITOR_PROVIDER=anthropic` is set.

The judge eval is the check on the `CATEGORY_GUIDANCE` edit. If F1 drops below the
gate, the sharpened exclusion is the suspect.

**What to do when the gate fails**, since `run_judge_eval` raises `SystemExit(1)`
and blocks the step:

1. **Never lower `F1_THRESHOLD`.** The threshold is the contract; moving it to
   make a change fit is how a quality gate becomes decoration.
2. Read the failing fixtures in `evals/fixtures/judge_cases.json`. The sharpened
   line only touches `INJECTION`, so a failure outside that category points at
   something else and the edit is probably not the cause.
3. If an `INJECTION` fixture flipped, decide which of the two is wrong: the
   sharpened wording, or the fixture's `expected_verdict`. Re-litigating a
   fixture label is legitimate (`ADR 006` records how fixtures are sourced), but
   it is a **separate, argued decision**,
   not a way to make the number come back. If a label changes, say so in the
   commit and in `ADR 013`.
4. If neither is wrong, the edit is too aggressive: narrow it until the gate
   passes, rather than widening the exclusion to catch the fixture.

---

### Step 4: a block is visible — report, progress bar, live console

**Files**

- `tests/unit/support/test_rendering_given.py` (modify)
- `tests/unit/support/test_rendering_then.py` (modify)
- `tests/unit/test_rendering.py` (modify)
- `tests/unit/test_progress.py` (modify)
- `tests/unit/test_stream_handler.py` (new)
- `src/mcp_auditor/domain/rendering.py` (modify)
- `src/mcp_auditor/progress.py` (modify)
- `src/mcp_auditor/stream_handler.py` (modify)

**Do** (tests and fixtures first)

1. `test_rendering_given.py`: a builder for a blocked case (`TestCase` with
   `blocked_reason` set, no response, no error, no `eval_result`) and for a chain
   with `blocked_reason`. `test_rendering_then.py`: only add a helper if it
   actually abstracts something — a one-line `assert "BLOCKED" in markdown` stays
   inline in the test.
2. Add the scenarios below to `test_rendering.py`, `test_progress.py`, and the new
   `test_stream_handler.py`.
3. `domain/rendering.py`:
   - `_render_tool_section`: instead of skipping every case with
     `eval_result is None`, render a blocked case through a new
     `_render_blocked_section(case)` placed right below its caller:
     ```
     ### BLOCKED -- injection
     **Payload**: `{...}`
     **Reason**: destructive filesystem command: rm -rf
     ```
     A case with neither an `eval_result` nor a `blocked_reason` is still skipped.
   - `_render_chain_section`: render `chain.blocked_reason` when set.
   - `_render_summary_section`: keep `Test cases` as
     `len(tr.cases) + len(tr.chains)`; add a `**Blocked**: N` line when
     N > 0, where N counts **both** cases with a `blocked_reason` and chains with
     one.
4. `progress.py`: add `advance_blocked(reason: str)` to both `ToolProgress` and
   `CIProgress`. Do **not** widen `advance` to `EvalResult | None` — `_ResultTracker`
   records verdicts and a block is not a verdict.
   - `ToolProgress.advance_blocked` prints a one-line notice naming the reason
     through `self._progress.console` and advances the task when `_task_id` is set.
   - `CIProgress.advance_blocked` prints a plain line through `self._console`.
   - Extract the notice text into a small module-level formatter next to
     `format_failure_line` so both classes share it.
5. `stream_handler.py`: in `_on_tool_audit_event`, add an `execute_tool` branch.
   Read `state_update.get("judged_cases", [])`, and when the last case has a
   `blocked_reason` and a progress is active, call
   `self._active_progress.advance_blocked(reason)`. A normal `execute_tool` update
   carries `current_case`, not `judged_cases`, so it must change nothing.
   `console.py` needs no change.

**Test**

`tests/unit/test_rendering.py`:

- A report with a blocked case renders a `BLOCKED` heading, the payload, and the
  reason text.
- A chain with `blocked_reason` renders that reason.
- The summary shows a `Blocked` line with the right count when above zero
  (one blocked case + one blocked chain gives 2), and omits the line entirely when
  no case and no chain is blocked.

`tests/unit/test_progress.py` (writing through `given.a_display()` /
`given.a_ci_display()` from `tests/unit/support/test_console_given.py`):

- `ToolProgress.advance_blocked("destructive filesystem command: rm -rf")` writes
  a line containing the reason into the captured buffer, and the tool summary
  printed by `stop()` still reports all passed (a block is not a failure).
- `CIProgress.advance_blocked(...)` writes the reason in CI mode.

`tests/unit/test_stream_handler.py` (new file — `stream_handler.py` has no test
module today and `test_console_display.py` covers `console.py`, not the reporter):

- Feed the reporter a tool-audit-level `generate_test_cases` event
  (namespace tuple of length 1, e.g. `("audit_tool:1",)`) carrying two pending
  cases so a progress starts, then an `execute_tool` event carrying
  `{"judged_cases": [blocked_case]}`: the buffer contains the reason.
- A normal `execute_tool` event carrying `{"current_case": case, "pending_cases": []}`
  prints nothing and advances nothing.

**Verify**

```bash
uv run pytest tests/unit/test_rendering.py tests/unit/test_progress.py tests/unit/test_stream_handler.py
uv run pytest
uv run ruff check . && uv run ruff format .
uv run pyright
```

---

### Step 5: the decision record, the living docs, and the metric-neutrality proof

**Files**

- `tests/unit/test_readme_policy.py` (new)
- `tests/unit/test_eval_metrics.py` (modify)
- `docs/adr/013-non-destructive-payloads.md` (new)
- `README.md` (modify)
- `CLAUDE.md` (modify)
- `CHANGELOG.md` (modify)

**Do**

1. `docs/adr/013-non-destructive-payloads.md` — short ADR, same structure as the
   existing ones in `docs/adr/`. Cover every bullet listed under
   "`docs/adr/013-non-destructive-payloads.md` (new)" in this plan, in that order:
   context, decision, `AuditedServer` and the union return (with the
   no-shared-attribute-name invariant and the `Unknown tool` precedent), the
   deliberate raw port in `evals/cve_targets.py`, why no ground-truth cell
   requires a destructive payload,
   the scope of the policy (destruction and host availability, **not** writes, with
   the three reasons), prompt and guard deliberately co-extensive, the surviving
   read-only preference, the guard's honest limit, the bare-word bet recorded as a
   bet, why literal substring matching (with the rejected alternatives), the
   relation to `ADR 011`, and the alternatives considered including the precise
   decorator objection.
2. `README.md`:
   - `Scope and limitations`: new bullet with a bold lead-in, matching the style of
     the neighbouring bullets. **Both halves in the same bullet**: the promise (the
     auditor never aims to destroy; enumerated destructive constructs are refused
     before the payload leaves the auditor; a refused payload is reported as
     blocked, never sent, never judged) and the limit (it still calls the server's
     own tools with adversarial arguments, so **if a tool writes, auditing it
     writes**; it cannot observe side effects, see `ADR 011`; point it at a server
     whose state you can restore). Link `ADR 013`, reference `ADR 011`.
     Must not claim "read-only", "no side effects", "safe against production",
     "will not modify your server", or that the guard is a sandbox or a security
     boundary. Say "enumerated constructs", never a guaranteed property.
   - `audit_tool` subgraph diagram: `S2 --> S3` becomes conditional —
     `S2 -->|sent| S3[judge_response]` plus a blocked branch from `S2` back to
     `S2` (next case) and to `S4((end))`.
   - `chain_audit_tool` subgraph diagram: add `abandon_chain` and the branch out of
     `execute_step` (`E -->|sent| O`, `E -->|blocked, steps done| J`,
     `E -->|blocked, first step| A[abandon_chain]`, `A -->|more chains| C`,
     `A -->|done| X`).
3. `CLAUDE.md`: the two Coding/Testing standards lines invalidated by the
   `AuditedServer` signature change, per the section above.
4. `CHANGELOG.md`: entry under `[Unreleased]` / `### Changed` — the auditor now
   proves injection non-destructively and refuses to send a payload it judges
   destructive, reporting it as blocked. Reference `ADR 013`.
5. `tests/unit/test_readme_policy.py` (new): one test, reading `README.md` from the
   repo root. Locate the bullet containing the promise and assert that the **same**
   bullet also carries an `ADR 011` reference.

   Assert the `ADR 011` marker, **not** the sentence "if a tool writes, auditing it
   writes". Matching that literal clause would make the test brittle against any
   rewording while claiming to be scoped to an invariant, and a test that breaks on
   an innocuous edit without catching a real regression is the kind the standards
   say to delete rather than keep. The `ADR 011` reference is the load-bearing
   marker: it is what carries "the auditor cannot observe side effects", so its
   presence in the same bullet is the invariant worth pinning.
6. `tests/unit/test_eval_metrics.py` (+ `test_eval_metrics_given.py` if a blocked
   case builder is needed): the two scenarios below. No production change in
   `evals/` — `aggregate_verdicts`, `compute_distribution_coverage` and
   `evals/export.py` already guard on `eval_result is None`; these tests pin that
   the guarantee holds.

**Test**

- A report containing a blocked case yields the same recall, precision and
  consistency as the same report without it.
- Distribution coverage drops for a tool when the only case of a category is
  blocked (compared with the same report where that case was judged).
- `README.md`'s safety bullet keeps its promise and its limit adjacent.

**Verify**

```bash
uv run pytest tests/unit/test_readme_policy.py tests/unit/test_eval_metrics.py
uv run pytest
uv run ruff check . && uv run ruff format .
uv run pyright
```

Then the full verification sequence from the "Verification" section above, in that
order: `uv run python -m evals.run_judge_eval`, `uv run python -m evals.run_evals`,
then the Docker CVE benchmark. Read the `CVE-2025-53355` run by the verdicts on
`kubectl_generic` (critical `injection` FAIL, 3/3), **not** by the oracle status,
and run the `rm -rf` / `blocked_reason` grep only against a real
`mcp-auditor run -o <path>` report, never a `--dry-run` one.
