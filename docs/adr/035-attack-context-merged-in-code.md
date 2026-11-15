# ADR 035: The Attack Context Is Merged in Code and Bounded

**Date:** 2026-11-15
**Status:** Accepted
**Supersedes:** in ADR 009, the "Context merging" section and the consequence "Context is unbounded initially". The rest of ADR 009 stands.

## Context

After each tool, the context extraction call reads the tool's test cases and the attack context, and returns the attack context the next tools receive. ADR 009 had the model return the whole context each time, the existing content merged with the new, and set no bound on its size.

The answer to that call grows with the number of tools already audited. On 2026-11-15, the 21 extraction calls of one audit were sent again, in order, to claude-haiku-5-5 at medium reasoning: an answer used about 1,200 output tokens on the first tool and about 7,600 on the last, reasoning included. The auditor sets an output limit of 8,192 tokens on every provider but Google, and on some of them the limit counts the model's reasoning too. Past a number of tools that depends on the model and its reasoning level, the answer is cut at the limit and the auditor does not use a cut answer, so the call is a missed model call. The audit keeps the context it had, so the next tool has the same context to rewrite and its call is likely to be cut too.

The context also goes back into the prompts of every later tool: context extraction, test generation and chain planning. Merging in code would stop the cuts, but with no bound those prompts would keep growing with each tool.

## Decision

**The extraction call reports what the results of the current tool show, and a pure function in the domain merges that answer into the attack context.** The call still receives the attack context, and is asked to repeat in the same words an item it confirms, so that the merge recognises it. An item already in a list is not added again, and the comparison ignores case and whitespace.

**Each list holds a bounded number of items, each of a bounded length.** The prompt asks for one fact per item, in one short sentence. An item longer than the bound is dropped, since a cut item can state something false. When a list is full, the item whose last report is the oldest is evicted.

**The observations hold one note per tool.** A note is free text, so a long one is cut at a bounded length, and the oldest note is evicted when the observations are full.

**The database engine, the framework and the language take the value of the latest answer that gives one.** The extraction prompt shows the current values, so the model still judges whether a new value names a second backend or corrects an earlier misreading, as ADR 009 wanted.

**The bounds are set so that the merge drops nothing on a server of five to ten tools, the size ADR 009 calls typical.** Their values live with the merge function.

## Alternatives considered

**Raising the output limit, for every call or for the extraction call alone, or turning reasoning off for that call.** Each moves the threshold without stopping the growth, so a server with enough tools still reaches the new threshold.

**Bounds in the output schema.** Neither Anthropic nor OpenAI enforces them while the model writes: Anthropic's SDK moves them into the schema's description, and the OpenAI binding of this schema is not strict. An answer over a bound then fails validation and becomes the missed model call this decision removes.

**Asking the model to keep the rewrite short, or to compact it at intervals.** An instruction does not guarantee the size of the answer, and the model chooses what it drops at each call, where the merge applies one written rule.

## Consequences

- The size of the extraction answer, and of the context every later prompt receives, no longer depends on the number of tools.
- An item leaves the context only by eviction. On a server with many tools, a detail seen once on an early tool is gone by the later ones.
- The lists are merged without judgment. Two wordings of one fact take two places until the older one is evicted.
- The tool responses still enter the extraction prompt and the judge prompt in full: this decision bounds the attack context only.
