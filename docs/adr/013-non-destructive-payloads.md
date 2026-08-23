# ADR 013: Non-Destructive Attack Payloads

**Date:** 2026-08-22
**Status:** Accepted

## Context

The auditor writes its own attack payloads and sends them to a live server. Across three graded CVE benchmark runs against the kubernetes target, one of the two injection attempts in each run was `rm -rf /`, landing in a different argument every time. Nothing in the codebase stopped it from reaching the server. The benchmark absorbed it because its fixtures are disposable. A user pointing the auditor at a real server with persistent state gets the payload executed for real.

ADR 004 models the server as the subject under test, possibly flawed, with the attacker acting through the LLM client. The reverse duty, not being hostile to the server the auditor was pointed at, had no counterpart anywhere in the code.

## Decision

The auditor proves injection without issuing a payload whose purpose is to destroy state or take the host down. It does not become read-only (see "Scope" below). The policy holds through two layers, because this is a safety property and a prompt is a probabilistic constraint.

1. One prompt constraint, `NON_DESTRUCTIVE_CONSTRAINT`, shared by the three generation sites: the single-step generator and the two chain planners.
2. A deterministic guard, a pure function over the generated argument values, matched against an enumerated table of destructive constructs and enforced at a single choke point.

A blocked payload is reported as blocked, carrying its reason, never sent and never judged. Dropping it silently would shrink the budget and let distribution coverage drift, so the metrics would lie about what was exercised. Substituting a fresh payload would be a corrective generation loop, a different feature. The guarantee covers what the auditor writes. What the audited server does with it is another matter, so point the auditor at a server whose state you can restore.

### Scope: destruction and host availability, not writes

The policy covers destruction of state and host availability. It does **not** cover writes. Any mutating call goes through, unless its arguments carry one of the enumerated destructive constructs. Three reasons, in decreasing order of force:

1. **Auditing a write tool requires writing.** Proving injection on a tool that writes means calling it, and the call mutates because mutating is the tool's declared function. A read-only policy means the auditor does not test write tools for injection.
2. **A read-only promise would be unverifiable by this tool's own admission.** ADR 011 records that the auditor cannot observe a call's side effects. A tool that has documented that it cannot see writes cannot promise it causes none.
3. **It would move a benchmark denominator for a self-imposed rule.** The graded path of `CVE-2025-68143` opens on two writes, so a read-only policy would reclassify it out of scope over a rule this project set for itself.

The generator is still told to prefer a benign reflected marker when one proves the same thing. That is a preference, since a mutating tool has no read-only way to probe it and a rule the generator cannot satisfy is a rule it learns to ignore. It is guidance, never a claim made to the user.

### The guard sits behind one type, and a refusal is not a response

The guard lives in a domain service, `AuditedServer`, the graph's only access to the server under audit. No node holds an `MCPClientPort`, and obtaining one requires changing the graph builders' signature and every composition site. Calling the check from each execution node would cover both call sites today and would hold by convention, so a later execution path that forgot it would send destructive payloads again in silence.

Its sending method returns a union, `ToolResponse | BlockedPayload`, and the invariant that makes this work is invisible in the code, so it is recorded here: **`BlockedPayload` shares no attribute name with `ToolResponse`**. No `content`, no `is_error`, no `error_type`. That non-overlap turns an unhandled refusal into a type error under strict `pyright` instead of a silent success. The precedent is in this repo's own history: the `tool_name` bug made the auditor call a nonexistent tool, the judge graded that auditor error as an `error_handling` finding, and the false conclusion poisoned the cross-tool `AttackContext`. An auditor refusal that looks like a server response is the same class of bug. The type forces an author to acknowledge the variant, not to handle it well. What it closes is the silent path.

The calibration path keeps a raw `MCPClientPort`, because its exploits are hand-written ground truth and are what proves each fixture is live. Putting them under a table meant to grow would tie the calibration gate to any later widening of the list.

### What the policy costs, and where it stops

A destructive payload never carried detection value. An observable injection is proved as well by a benign reflected marker, and one observable only through a silent effect was not revealed by the destructive payload either, since a black-box auditor reads the response and nothing else. Checked cell by cell against the eval ground truth: all eleven planted flaws can be established without a payload the guard blocks. The three that look like counter-examples are not: `execute_query` echoes any query back, `project_manager` x injection is an unrestricted absolute-path read, and `delete_record` x input_validation comes from a negative record id. The guard drops a blocked case instead of substituting a benign one, so a cell is still losable in a given run.

The table is aimed at the commands the generator sometimes writes. It is not a security boundary and does not need to be, since the generator is not trying to evade it. What passes is named here rather than left to be discovered: an obscure destructive binary, a clobbering redirect to a relative path (`echo evil > notes.txt`), and any bare command word, since no pattern is one. `CVE-2025-68144` is the documented case in this repo, where `git_diff --output=/path` silently overwrites a file and `--output=` is not in the table. The bare word is a decision. Only the argument name separates `command="shutdown"` from `service="shutdown"`, and the name comes from the audited server's own declaration, so letting it decide what counts as dangerous would make a safety property depend on the subject under test. The collision is live: a `get_service_status(service=...)` tool already ships in the test fixtures.

The two error directions are asymmetric: a false block costs recall and shows up in the evals, while a false allow destroys a user's server. So matching is literal and nothing is required to the left of a pattern, which fires on some innocuous values. Those false blocks are accepted, because requiring a left boundary let `%3Brm -rf /` through. And the table bounds only what the auditor writes. The audited server's own code runs with the user's privileges, spawned as a subprocess by `StdioMCPClient.connect`, so execution isolation of the target is the durable control and this table is what stands until it ships.

## Alternatives considered

### Prompt only, no guard

**Rejected.** A safety property must not depend on LLM compliance. The behavior was observed and not imagined: under a prompt that said nothing about destruction, the model improvised the same destructive command into three different argument names across three runs. Whether a rewritten prompt alone would hold is the untested proposition a safety property must not rest on.

### A decorator over `MCPClientPort`

**Rejected.** A reader who sees only "decorator rejected" would rebuild the wrong thing. The objection was never the choke point: it was `ToolResponse`'s shape, since a decorator has to answer with `ToolResponse`, so a refusal is indistinguishable from a server error, which is the `tool_name` bug's class again. A union return removes that objection, and a second one it hides: a decorator still satisfying `MCPClientPort` leaves the graph builders accepting a raw client, so nothing forces every execution path through the guard.

### An allowlist, or a second LLM call

**Both rejected.** An allowlist has the wrong polarity, since the benign side is the unbounded one. A second LLM call is a probabilistic backstop under a probabilistic constraint.

### A `--read-only` flag, or a server-declared-scope boundary

**Both rejected** under "Scope" above. The flag's guarantee would be prompt-only, and it would fork the eval matrix so the published CVE numbers would describe a non-default mode. The declared-scope boundary is circular: the declared scope is the property under test, so using it as a guard would forbid the category's central probe.

## Consequences

- A blocked single-step case appears in the report with its reason and contributes nothing to recall, precision or consistency. Distribution coverage does drop, on purpose. Frequent blocks are worth reading, though a block means the table fired and not necessarily that the generator disregarded the prompt.
- A blocked chain step is not neutral in the same way. When a prefix already ran, the chain is judged on that prefix and carries a verdict into the aggregate, produced on a sequence the auditor itself cut short. Only a chain refused on its first step stays unjudged. The verdict is kept, since voiding it would discard evidence the prefix really produced.
- The graph builders take an `AuditedServer`. Adding a new execution path cannot bypass the guard by omission. The dry-run graph is wrapped too, although it has no execution node, so that a later one added there does not inherit a raw port.
- No CVE benchmark target moves out of scope, and the auditor keeps calling mutating tools, which is how a write tool is audited at all.
- The rule that governs later edits: nothing the prompt forbids may be published as a guarantee unless the table enforces it, which is why the README states the enumerated constructs and not the property. `NON_DESTRUCTIVE_CONSTRAINT` and `DESTRUCTIVE_CONSTRUCTS` are kept aligned by hand, and nothing pins the correspondence.
- The residual silent-effect class stays where ADR 011 put it, behind the deferred `ExecutionObserver` seam.
- The README states the policy with its limit attached: enumerated constructs are refused, and auditing a write tool still writes.
