# ADR 014: Proving What an Injection Reaches

**Date:** 2026-08-23
**Status:** Accepted
**Supersedes:** ADR 013 (the clause treating a read as one more reflected marker)

## Context

The auditor is black-box. It reads the protocol response and nothing else, which is the reason ADR 011 gives for leaving a silent side effect out of reach. Everything a finding can claim has to come back in that response.

Two kinds of evidence come back in that response, a reflected marker and a read. Both arrive as text and are easy to treat as one thing. A reflected marker, `echo mcp-auditor-probe` or `whoami`, shows the server ran what it was sent, and says nothing about what that run reaches. A read returns a value, and the value says whether reaching it matters.

ADR 013 established the non-destructive policy and, with it, a list of benign alternatives the generator can prefer. That list was written to give the generator something to do instead of destroying, and it does that job. It was not written as an evidence policy: it groups a read in among the reflected markers and names no target to read, so in practice every item on it proves a run. The auditor ends up reporting only that a run happened, and a reader cannot tell from the finding whether it reaches anything worth having.

## Decision

**The generator is instructed to prove what an injection reaches, and to quote what came back.** It is told to read something whose disclosure would matter and to put the returned value in evidence. A reflected marker stays in the list, below the read instruction, for the case where nothing worth reading is in reach, and it is named there as proof of a run rather than of impact.

**The list names classes, and pins each one with an example.** A class with no example is an instruction the generator cannot act on, and ADR 013 already records that a rule the generator cannot act on is a rule it learns to ignore. Without its class, an example reads as a closed list. The prompt line names a credential or configuration file, the process environment, and a path the tool's own arguments already reach.

**The examples come from the MCP threat landscape, not from this repo's fixtures, and they stay portable.** The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) ranks token and secret exposure first, and ADR 008 already maps injection to MCP-05, whose vulnerability checklist names reading environment variables through command substitution. A command that runs on one operating system only would narrow the audit to the hosts that run it.

**The examples do not reuse a fixture's own naming, and a test asserts it.** The test checks this constraint against the names this repo's fixtures plant under, so it catches a copied convention and not a new one. Naming from the fixtures would fit the product to the test set, and it is the kind of fit a reader can grep for, which is why the list keeps naming literals rather than falling back to categories.

## Alternatives considered

### Leaving the generator alone and teaching the judge to weigh impact

**Rejected.** The judge reads what came back and nothing else. If the generator never read anything, there is no impact in the response for a judge to weigh, however the rubric is written.

## Consequences

- A secret read to prove impact reaches the judge's prompt, the trace and the report, and on a real server those are live secrets. Nothing redacts them today. Execution isolation of the target bounds the exposure to a container's environment, and the residual question is redaction before a value reaches the judge.
- The bar for a finding is higher, which should raise precision and lower recall. Nothing in this repo measures that trade.
- None of what the prompt line names is in the guard's table of destructive constructs, so this widening costs nothing against ADR 013.
- The test catches a copied fixture name, not a copied technique. A change made to chase what the grader credits leaves no string behind, and nothing here catches that.
- The CVE benchmark's oracle credits only a target's planted sentinel. This decision does not change that, and a detection proved by a marker alone is still graded as missed.
