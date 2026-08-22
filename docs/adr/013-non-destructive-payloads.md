# ADR 013: Non-Destructive Attack Payloads

**Date:** 2026-08-22
**Status:** Accepted

## Context

The auditor writes its own attack payloads and sends them to a live server. A graded CVE benchmark run produced `rm -rf /` as one of the two injection attempts, landing in a different argument each run (`command`, then `name`, then `flags`). Nothing in the codebase stopped it from reaching the server.

Two harms, not one. The obvious one is damage to the audited server: the benchmark is only safe because its fixtures run under `docker run --rm`, and a user pointing the auditor at a real server with persistent state gets that payload executed for real. ADR 004 models the server as the subject under test, possibly flawed, with the attacker acting through the LLM client. The reverse duty, not being hostile *to* the server we were pointed at, had no counterpart anywhere in the code. The second harm is self-sabotage: a destructive payload that lands early in a run breaks the probes that follow it, so the auditor corrupts its own evidence.

## Decision

The auditor proves injection without destroying state, through two layers, because this is a safety property and a prompt is a probabilistic constraint. The measured failure mode, the same destructive command improvised into three different argument names, is precisely what an instruction alone does not reliably prevent.

1. A prompt constraint at the three generation sites (the single-step generator and the two chain planners).
2. A deterministic guard, `destructive_reason` in `domain/payload_safety.py`, a pure function over the generated argument values, enforced behind a single named door.

A blocked payload is reported as blocked, carrying its reason, never sent and never judged. It is not silently dropped (the budget would quietly shrink and distribution coverage would drift, so the metrics would lie about what was exercised) and not regenerated (that is a corrective generation loop, a different feature).

### `AuditedServer` and the union return

The guard lives in a domain service, `AuditedServer`, which becomes the only reach the graph has into the server under audit. After this change the hexagon interior holds no object able to call `call_tool`: obtaining one requires changing `build_graph`'s signature and every composition site, a deliberate reviewable edit rather than an omission. Calling `destructive_reason` from each execution node would have been complete today, since those are the only two call sites, but it would hold by convention, and a future execution path that forgets it (the `ExecutionObserver` seam ADR 011 reserves, a corrective regeneration loop) would send destructive payloads again in silence, with no type error and no failing test.

Its sending method returns a union, `ToolResponse | BlockedPayload`, and the invariant that makes this work is invisible in the code, so it is recorded here: **`BlockedPayload` shares no attribute name with `ToolResponse`**. No `content`, no `is_error`, no `error_type`. That non-overlap is what turns an unhandled refusal into a type error under strict `pyright` rather than a silent success, and what makes it structurally impossible for a refusal to be read as something the server said.

The precedent is not hypothetical. The `tool_name` bug made the auditor call a nonexistent tool, the server replied `Unknown tool: <category>`, the judge graded that auditor error as an `error_handling` finding, and the false conclusion then poisoned the cross-tool `AttackContext` feeding later generations. An auditor refusal wearing the shape of a server response is the same class of bug.

Honest limit: the type forces an author to acknowledge the variant, not to handle it well. Someone can narrow and discard it. Silence, not misuse, was the smell.

### The calibration path keeps the raw port, on purpose

`evals/cve_targets.py` still holds an `MCPClientPort` and calls it directly. Its exploits are hand-written ground truth, not generated payloads, so the guard has nothing to say about them. This is deliberate, not an inconsistency to fix: routing calibration through `AuditedServer` would block the exploits that prove each fixture is live and break the calibration gate.

The dry-run path keeps the wrapper for the opposite reason. `build_dry_run_graph` has no `execute_tool` node, so the guard is never consulted there and the wrap looks pointless. It is what keeps `AuditedServer` the only server-facing type the graph builders accept, so whoever later adds an execution node to that graph does not inherit a raw port.

### No ground-truth cell requires a destructive payload

The load-bearing claim, so it is stated rather than assumed. A destructive payload never carried detection value, and both cases are covered:

- If the injection is observable in the response, a benign reflected marker (`echo mcp-auditor-probe`, `id`, `whoami`, `SELECT` / `UNION SELECT`) proves it just as well. Destroying state adds nothing to the evidence.
- If it is observable only through a silent effect (an unechoed write, a spawned process, out-of-band exfiltration), the destructive payload did not reveal it either. A black-box auditor reads the response and nothing else.

Checked cell by cell against `evals/ground_truth.py`: all eleven `FAIL` cells are establishable non-destructively. `execute_query` returns `Executed: {query}` for any query, `project_manager` x `injection` is a path traversal in read mode, and `delete_record` x `input_validation` comes from a negative `record_id`, not from destroying anything. Note the wording: "requires", not "costs nothing". The guard drops a blocked case rather than substituting a benign one, so a cell can still be lost in a given run if the generator's only probe for it was destructive. That is a run-level risk, visible in the metrics.

### Scope: destruction and host availability, not writes

The policy covers destruction of state and host availability. It does **not** cover writes. `git_init`, `git_add`, `write_file` and any other mutating call go through. Three reasons, in decreasing order of force:

1. **Auditing a write tool requires writing.** Proving injection on `write_file`, `create_pod` or `execute_query` means calling the tool, and the call mutates because mutating is the tool's declared function. The honest consequence of a read-only policy is "the auditor does not test write tools for injection", which is not a property anyone wants.
2. **A read-only promise would be unverifiable by this tool's own admission.** ADR 011 records that the auditor cannot observe a call's side effects. A tool that has documented it cannot see writes cannot promise it causes none.
3. **It would move a benchmark denominator for a self-imposed rule.** `CVE-2025-68143` has the graded path `git_init(out-of-scope) -> git_add(.) -> git_diff_staged`, whose first two steps are writes. Under a read-only policy it would have to be reclassified out of scope for a rule we chose rather than a capability we lack.

### Prompt and guard, and the two ways they fail to line up

The prompt names every construct family `destructive_reason` blocks, and this is a decision, not a coincidence. The general rule this ADR contributes beyond the immediate fix is that **the prompt must never forbid more than the guard can enforce**. Past that line the guard stops being the deterministic backstop and the surplus prohibition becomes an unbacked promise. The correspondence is close, not exact, and both residues are named here rather than left to be discovered.

**The guard blocks a little more than the prompt forbids.** A non-recursive `chmod -r` (which removes read permission, while the pattern is aimed at `-R`), an `mv /`, a quoted `'drop table'` inside an otherwise legitimate `SELECT`. Cost: a generator that obeyed the prompt loses a case to a block, which shows up as one blocked payload in the eval report and, if the category had no other case, as lower distribution coverage. Tolerable, and visible where it happens.

**The prompt asks for slightly more restraint than the guard delivers.** It forbids deleting or overwriting a file as a *property*, and the guard enforces an enumerated list, so `echo evil > notes.txt` passes both the guard and the auditor's intent. This direction is the one the rule above forbids, and it is accepted for one reason: the surplus is guidance to our own generator, never a claim made to the user. The README states the enumerated-construct limit rather than the property.

Nothing pins either correspondence mechanically. A pattern added to the table without a matching line in the prompt widens the first residue in silence, and `tests/unit/test_prompts.py` only asserts hand-written substrings.

### The read-only preference survives, as a preference

The generator is still told to prefer a benign reflected marker when one proves the same thing. It is phrased as a preference, not a rule, because for a mutating tool there is no read-only way to probe it, and a rule the generator cannot satisfy is a rule it learns to ignore. It is generator guidance with no guarantee attached, never a claim made to the user.

### The guard's honest limit

It is an enumerated denylist aimed at our own generator's exuberance, not a security boundary and not bypass-resistant. It does not need to resist bypass: the generator is not trying to evade us. The list is enumerated, not complete, and what still passes is named here rather than left to be discovered: an obscure destructive binary, and a clobbering redirect to a relative path (`echo evil > notes.txt`). `CVE-2025-68144` is the documented case in this repo, where `git_diff --output=/path` silently overwrites a file and `--output=` is not in the table. Widening the list later is cheap and needs no new decision.

The two error directions are asymmetric: a false block costs recall and shows up in the evals, a false allow destroys a user's server. So the table is aggressive on unambiguous constructs and permissive on ambiguous ones, with the prompt carrying the rest.

### The bare-word bet, recorded as a bet

No pattern is a bare command word, so a bare `shutdown` or `reboot` in an argument value passes. The discrimination that would block it is unavailable: `command="shutdown"` and `service="shutdown"` are identical at the guard's signature, and only the argument *name* separates them. Names come from the server's own `inputSchema`, which ADR 004 declares hostile, and letting them decide what counts as dangerous would make a safety property depend on input the audited server controls. `tests/subtle_server.py` already ships a `get_service_status(service=...)` tool, so this is a live case, not a thought experiment.

The bet is that an LLM writes `shutdown -h now`, not a bare `shutdown`, and that the prompt covers the residual since it still forbids host shutdown. It is not measured. If it is wrong, the fix is one string in one tuple.

### Why literal substring matching

Most patterns carry an argument or a flag (`rm -rf`, `shutdown -`, `dd of=`, `chmod -r`), which delimits them on the right. Three do not: `init 0`, `init 6` and `kill -9 1` end on a bare digit, so `init 0` matched inside `git init 0auth`. One rule closes that: a pattern ending on a digit requires a non-alphanumeric character after it, or the end of the value. Patterns ending on a letter stay permissive, so `rm -rf` keeps matching `rm -rfv` and `chmod -r` keeps matching `chmod -Rf`.

**Nothing is required on the left, and that is the decision, not an omission.** `rm /` and `rm ~` carry no left delimiter either, so they fire inside `perform /admin` and `transform ~/data`. Requiring a boundary there was tried and reverted: an encoded separator is alphanumeric, so `%3Brm -rf /`, `..%2frm -rf /` and `telinit 0` all stopped matching. Percent-encoded separators are ordinary `injection` syntax, which is exactly what this generator is told to write. The asymmetry decides: a mid-word false block costs recall and shows up in the evals, a false allow destroys a user's server. The false blocks are accepted and named here.

Word boundaries in the regex sense would not have been enough anyway: `\bshutdown\b` still matches `service="shutdown"`. The rejections are recorded so nobody re-opens them:

- **A regex per construct.** The fork bomb pattern `:|:&` read as a regex matches every string and would block the whole suite, and a denylist that cannot be audited by eye defeats its own purpose.
- **`shlex` or shell-grammar parsing.** Payload values are routinely not valid shell (`' OR '1'='1` raises), so the fallback path *is* substring matching, and half the mandate is not shell at all.
- **An allowlist.** Wrong polarity: the benign side is the unbounded one.
- **A second LLM call.** A probabilistic backstop under a probabilistic constraint is not a backstop.
- **A per-category decision.** No category makes destruction legitimate.
- **The `destructiveHint` tool annotation.** It describes the tool, not our payload, and it is server-supplied.

The property that decides is that the adversary here is our own generator writing canonical forms, so bypass-resistance buys nothing.

## Relation to ADR 011

ADR 011 is load-bearing here, not merely referenced. The unobservability of side effects is both the reason this ADR cannot promise the absence of writes and the reason a destructive payload never carried detection value in the first place. This ADR adds no capability exclusion of its own: the residual silent-effect class stays exactly where ADR 011 put it, behind the deferred `ExecutionObserver` seam.

## Alternatives considered

### Prompt only, no guard

**Rejected.** A safety property must not depend on LLM compliance, and the failure mode was measured, not imagined: the model improvised the same destructive command into three different argument names across three runs.

### A decorator over `MCPClientPort`

**Rejected**, and the reason matters, because a reader who sees only "decorator rejected" will conclude the choke point was the problem and rebuild the wrong thing. The objection was never the choke point, it was `ToolResponse`'s shape. A decorator has to answer with `ToolResponse`, whose fields are `content` / `is_error` / `error_type`, so a refusal is indistinguishable from a server error, which is the `Unknown tool` false-positive class again. Widening the return type to a union removes that objection entirely, and that is exactly what `AuditedServer` does.

### Silently dropping a blocked case

**Rejected.** The budget would shrink and distribution coverage would drift, so the metrics would lie about what was actually exercised. One consequence of the chosen option is intended rather than tolerated: if the only `injection` case for a tool is blocked, that tool's distribution coverage drops, because the category was genuinely not exercised. Frequent blocks are a prompt-compliance signal we want to see rather than absorb.

### Read-only proof only, a `--read-only` flag, or a server-declared-scope boundary

All three **rejected** under "Scope" above. The flag's guarantee would be prompt-only, since the auditor cannot determine whether a given call writes, which is the probabilistic constraint this ADR exists to stop relying on, dressed as a setting. It would also fork the eval matrix and make the published CVE numbers describe a non-default mode. The declared-scope boundary is circular: the declared scope is the very property under test, and path traversal is the confirmation that the boundary does not hold, so using it as a guard would forbid the category's central probe.

## Consequences

- A blocked case appears in the report with its reason, and contributes nothing to recall, precision or consistency: we neither claim a detection nor a false positive for a payload we never sent. Distribution coverage does drop, on purpose.
- The graph builders take an `AuditedServer`, not an `MCPClientPort`. Adding a new execution path cannot bypass the guard by omission.
- No CVE benchmark target moves out of scope, and the auditor keeps calling mutating tools, which is how a write tool is audited at all.
- The README states the policy with its limit attached: enumerated constructs are refused, and auditing a write tool still writes.
