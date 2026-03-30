# ADR 010: Multi-Step Attack Chains

**Date:** 2026-03-30
**Status:** Proposed

## Context

The current audit graph generates all test cases for a tool in a single batch, executes them independently, and judges each response in isolation. Every test case is a single payload — one request, one response, one verdict. This is effective for straightforward vulnerabilities (missing input validation, SQL injection via a single crafted string, error messages that leak internals) but cannot express attacks that require multiple steps.

Real-world exploits often follow an observe-decide-act loop: call a tool to discover internal state, then use that state to craft a targeted payload, then escalate. The attacker adapts each step based on what the previous step revealed. Several CVEs against MCP reference servers (CVE-2025-53109 symlink traversal, CVE-2025-68144 argument injection via `git_diff`) require this kind of multi-step exploitation. A human pentester does this naturally. The current single-payload model cannot.

### Relationship to existing features

**Cross-tool learning (ADR 009)** extracts intelligence *between* tools — tool B's generator knows what tool A revealed. But within a single tool's audit, all test cases are pre-generated and independent. Multi-step chains operate *within* a tool's audit, where each step's payload depends on the previous step's response. The two features are complementary: cross-tool learning provides the initial context, chains provide the adaptive depth.

**The single-step audit is not replaced.** Single-step testing is the right model for the majority of test cases (input validation boundaries, error handling, resource abuse). Chains are a second pass that targets specifically the vulnerabilities that single-step cannot reach.

## Decision

Add multi-step attack chains as a **second phase within each tool's audit**, after single-step testing.

### Scope: intra-tool

Chains call the **same tool** multiple times with different arguments. Each step's arguments are informed by the previous step's response. Cross-tool chains (using tool A's response to craft a payload for tool B) are a natural extension but are not included in this decision — they require changes to how the main graph routes between tools and to how findings are attributed.

Intra-tool chains already cover the most valuable multi-step scenarios: probing then exploiting (e.g., listing entries to discover internal state, then using that state for traversal or injection).

### Triggering: second pass after single-step

Chains run after single-step testing for the current tool completes, not interleaved with it. This has three benefits:

1. **Chains exploit single-step results.** The single-step phase may reveal error messages, internal paths, or behavioral patterns. The chain planner uses these to craft smarter chain strategies.
2. **Clean architectural separation.** The single-step flow and the chain flow are separate subgraphs, each with its own state and prompts. No hybrid complexity.
3. **Independent evaluation.** Chain recall can be measured as a delta over single-step recall: "vulnerabilities found only via chains." This validates the feature's value with a concrete metric.

### Domain model: separate from TestCase

An attack chain is not a test case. A `TestCase` is a single request-response pair with a verdict. An attack chain is a *sequence* of observations leading to a conclusion — each step informs the next. Forcing them into the same model would obscure the chain structure in reports and complicate judging.

New domain types model chains independently. `ToolReport` is extended to carry both single-step cases and chains, with chains defaulting to empty when the feature is disabled. Renderers display chains as a separate section per tool, showing the full step sequence.

### Budget: dedicated, not shared

Chains have their own budget, independent of the single-step test budget:

- **Chain count**: max number of chains per tool (default: 2, CLI-controllable, 0 disables chains entirely)
- **Chain depth**: max steps per chain (default: 3)

**Cost per chain:** each step requires an LLM call to plan, an MCP call to execute, and an LLM call to observe. Plus one final LLM call to judge the chain. For default values (3 steps): up to 8 LLM calls + 3 MCP calls per chain. With 2 chains per tool, this adds at most 16 LLM calls — comparable to the single-step cost with budget 10 (1 generation + 10 judgments + 1 extraction = 12 calls).

The cost is explicitly opt-in. Disabling chains has zero overhead on the existing flow.

### Intermediate observation vs final judgment

Chain steps require two distinct types of LLM reasoning:

- **Observation** (after each step): "Did this response reveal something exploitable for a next step?" This is a routing decision — continue or stop — not a security verdict. It does not produce a PASS/FAIL.
- **Judgment** (after the chain ends): "Considering the entire sequence of interactions, was a vulnerability demonstrated?" This produces a standard verdict with category, severity, and justification referencing the full chain history.

This separation prevents intermediate steps from being reported as findings. A tool call that returns directory contents is not a vulnerability — but that same call followed by a traversal that succeeds *is*.

## Alternatives considered

### Chains in the batch generator

Instead of a separate chain phase, extend the generator to produce both single-step payloads and chain plans in one batch.

**Rejected** because it conflates two generation tasks with different structures and context requirements. The single-step generator produces N independent payloads. A chain planner produces a sequential strategy. Mixing them in one prompt increases complexity, makes distribution control harder (how many chains vs single-step?), and prevents chains from exploiting single-step results. Separate phases keep prompts focused and testable.

### Cross-tool chains from the start

Allow chains that span multiple tools (e.g., use tool A to discover state, then use tool B to exploit it).

**Rejected for now** because it requires fundamental changes to graph routing (the main graph currently processes one tool at a time) and to finding attribution (which tool "owns" a cross-tool finding?). Intra-tool chains deliver the majority of the value — the most common multi-step patterns (probe then exploit) typically involve the same tool called with different arguments. Cross-tool chains are a natural follow-up that builds on this foundation.

### Replace single-step with chains of length 1

Unify the model: every test is a chain, single-step is just a chain with one step.

**Rejected** because it changes the existing working flow without adding value. Single-step testing is battle-tested with established evals and known metrics. Forcing it through a chain abstraction adds overhead (chain planning for a single payload), changes the prompt structure, and risks regressing the eval metrics. The two models coexist cleanly — single-step for breadth, chains for depth.

### Merge observation and planning into one LLM call

Instead of separate "observe the response" and "plan the next step" calls, combine them into a single call that does both.

**Rejected for now.** Reduces LLM calls per step from 2 to 1, but at the cost of debuggability: with separate calls, traces make it clear *why* the agent chose a particular next step. Starting with separate calls and merging later once chain behavior is validated is lower-risk than optimizing prematurely.

### Chain planner without single-step context

Run chains independently of single-step results — the planner sees only the tool definition and attack context, not the single-step results.

**Rejected** because single-step results are valuable intelligence for chain planning. If single-step testing revealed that a tool returns "access denied" for absolute paths but succeeds for relative paths, the chain planner should know this. Sequencing chains after single-step is a small latency cost for significantly smarter chain plans.

## Consequences

- **Graph complexity increases.** The audit flow per tool goes from one subgraph to two. The chain subgraph has a recursive loop, more complex than the current linear execute-judge loop. Mitigated by the chain subgraph being self-contained — it does not modify the single-step flow.
- **Cost is opt-in and bounded.** Default settings add at most 16 LLM calls per tool. Disabling chains has zero overhead. Users control the trade-off explicitly.
- **New prompt types.** Three new prompts (chain planning, step observation, chain judgment) join the existing two (generation, single-step judgment). Each is a pure function, testable in isolation.
- **Reporting changes.** `ToolReport` gains chain findings. The chain format is richer than single-step (multiple request-response pairs per finding), requiring new rendering logic in all output formats.
- **Eval infrastructure expands.** A new honeypot with tools designed for multi-step exploitation, new ground truth entries distinguishing single-step-detectable from chain-only-detectable vulnerabilities, and a chain delta recall metric. Existing evals are unaffected.
- **Judge isolation eval expands (ADR 006).** The chain judge receives a full chain history, not a single request-response pair. The judge eval dataset needs chain-specific cases to validate that multi-step vulnerabilities are correctly distinguished from benign multi-step interactions.
- **`AuditReport.findings` includes chain findings.** The `findings` property still returns all FAIL verdicts — no change to its contract. Chain findings appear alongside single-step findings in exit codes and severity thresholds.
