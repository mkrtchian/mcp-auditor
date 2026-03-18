# ADR 005: LLM Model Selection

**Date:** 2026-03-18
**Status:** Accepted

## Context

`mcp-auditor` uses an LLM for two tasks: generating adversarial test cases (structured output) and judging tool responses (classification with justification). Both require reliable structured output (Pydantic schemas), security reasoning, and tool use capabilities.

The implementation hardcoded `claude-haiku-4-5-20251001` in `AnthropicLLM`. Before investing in multi-provider support, we needed a data-driven model selection that balances cost, quality, and integration maturity.

## Decision

Add a `GoogleLLM` adapter to support Gemini models alongside the existing `AnthropicLLM`. Adopt Gemini 3.1 Flash-Lite as the default model — empirical validation confirmed structured output works with our schemas (`TestCaseBatch`, `EvalResult`).

### Target configuration
- **Default model:** Gemini 3.1 Flash-Lite (`gemini-3.1-flash-lite-preview`, $0.25/$1.50) — GPQA 86.9%, 12x cheaper than Sonnet. Validated empirically: comparable quality to Haiku 4.5 with better structured output reliability.
- **Production upgrade path:** Gemini 3.1 Pro ($2/$12) — best benchmarks overall (GPQA 94.3%, MCP-Atlas 69.2%, TAU2 99.3%) at 1.5x cheaper than Sonnet. Not yet validated.

### Fallback
- **Production:** `claude-sonnet-4-6-latest` — proven tool use reliability (TAU2 92-98%) and integration maturity.
- **Development:** `claude-haiku-4-5-latest` — 3x cheaper, ~90% of Sonnet's reasoning quality on GPQA.

### Models eliminated
- **GPT-5-nano** — MMLU-Pro 78.0%, no tool use data. Cheapest option but unproven for structured security judgments.
- **Claude Haiku 3 / 3.5** — TAU-bench 22-51%, deprecated or stagnant.
- **Claude Opus 4.6** — 1.7x more expensive than Sonnet, worse on MCP-Atlas (60.3% vs 61.3%). Overkill for classification.
- **GPT-5.4** — comparable price to Sonnet but TAU2 Telecom at 64.3% vs 97.9%. Less reliable for agentic workflows.

## Models Evaluated

### Pricing

| Model                   | Input $/MTok | Output $/MTok | Cost vs Sonnet 4.6  |
|:------------------------|-------------:|--------------:|:--------------------|
| GPT-5-nano              |        $0.05 |         $0.40 | ~60x cheaper        |
| Gemini 3.1 Flash-Lite   |        $0.25 |         $1.50 | ~12x cheaper        |
| GPT-5-mini              |        $0.25 |         $2.00 | ~10x cheaper        |
| Claude Haiku 4.5        |        $1.00 |         $5.00 | 3x cheaper          |
| Gemini 3.1 Pro          |        $2.00 |        $12.00 | ~1.5x cheaper       |
| GPT-5.4                 |        $2.50 |        $15.00 | ~1x (comparable)    |
| **Claude Sonnet 4.6**   |    **$3.00** |    **$15.00** | **reference**       |
| Claude Opus 4.6         |        $5.00 |        $25.00 | 1.7x more           |

### Benchmark selection

`mcp-auditor` asks the LLM to do two things: generate adversarial payloads as structured JSON, and classify tool responses as PASS/FAIL with a justification. This is reasoning + structured tool use — not code generation. Benchmarks were selected accordingly:

- **GPQA Diamond** — graduate-level science questions requiring multi-step reasoning. Closest proxy for "can the model reason about whether a tool response leaks information or mishandles input validation."
- **MMLU-Pro** — broad knowledge and reasoning across domains, harder than MMLU. Measures general classification accuracy — relevant because the judge must understand what constitutes a vulnerability vs. normal behavior.
- **MCP-Atlas** — multi-step workflows using real MCP servers. Directly measures the model's ability to call tools via structured schemas, which is exactly what our `generate_structured` does.
- **TAU2 (Retail / Telecom)** — conversational agent reliability in constrained domains with policies to follow. Closest to our judge task: the model must apply rules (audit categories) to specific situations (tool responses) and produce consistent verdicts.

Coding benchmarks (SWE-bench, Terminal-Bench) were excluded — the LLM never writes code in this program.

### Reasoning & Tool Use

Models sorted by GPQA Diamond. Smaller models (nano, mini, Flash-Lite) are rarely evaluated on expensive agentic benchmarks — the absence of data is itself a risk signal.

| Model                   | GPQA Diamond | MMLU-Pro | MCP-Atlas | TAU2 Retail | TAU2 Telecom |
|:------------------------|-------------:|---------:|----------:|------------:|-------------:|
| Gemini 3.1 Pro          |        94.3% |    80.5% |     69.2% |       90.8% |        99.3% |
| GPT-5.4                 |        92.8% |    81.2% |     67.2% |           — |        64.3% |
| Gemini 3.1 Flash-Lite   |        86.9% |    83.0% |         — |           — |            — |
| GPT-5-mini              |        82.3% |    83.7% |         — |           — |        55.0% |
| **Claude Sonnet 4.6**   |    **74.1%** |**79.1%** | **61.3%** |   **91.7%** |    **97.9%** |
| Claude Haiku 4.5        |        73.0% |    80.0% |         — |       83.2% |        83.0% |
| GPT-5-nano              |        71.2% |    78.0% |         — |           — |            — |

## Integration Feasibility

### Anthropic (`langchain-anthropic`)
- **Status:** Production-ready. In use before this ADR.
- `with_structured_output(include_raw=True)` works reliably.
- `usage_metadata` on AIMessage provides accurate token counts.
- Async (`ainvoke`) works without issues.

### Google Gemini (`langchain-google-genai`)
- **Status:** Production-ready. Validated 2026-03-18.
- **Nested Pydantic schemas — resolved.** The risk from [langchain #24225](https://github.com/langchain-ai/langchain/issues/24225) did not materialize. `TestCaseBatch` (`cases: list[AuditPayload]`) parsed correctly across 9 generation calls (3 runs × 3 tools) with 0 failures. `EvalResult` with 3 `StrEnum` fields (`AuditCategory`, `EvalVerdict`, `Severity`) parsed correctly across 90 judgments with 0 failures.
- **Token usage — confirmed.** `usage_metadata` is populated on the raw AIMessage when using `with_structured_output(include_raw=True)`. No workaround needed.
- **Async regression (non-issue).** `ainvoke` is 3-4x slower in v4.2.0+ due to `google-genai >= 1.56` ([issue #1600](https://github.com/langchain-ai/langchain-google/issues/1600), open). **Workaround if needed: pin `langchain-google-genai>=4.1,<4.2`.**
- The adapter shares a `_BaseLLM` superclass with `AnthropicLLM` — no changes to domain or graph. Provider selection via `MCP_AUDITOR_PROVIDER` env var (default: `google`).

### OpenAI (`langchain-openai`)
- **Status:** Not evaluated in detail.
- GPT-5-nano and GPT-5-mini lack published tool use benchmarks, making them hard to assess for this use case.
- GPT-5.4 has weak TAU2 scores (64.3% Telecom) despite strong reasoning — suggests unreliable agentic behavior.

## Eval Results

Results from running the eval suite (`evals/run_evals.py`) against the honeypot. Config: 3 runs, budget 10 test cases per tool, 3 tools.

### Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) — 2026-03-18

2 of 3 runs completed (run 2 failed — unparseable structured output after 3 retries).

| Metric       | Result | Threshold | Status |
|:-------------|-------:|----------:|:-------|
| Recall       |   1.00 |      0.80 | PASS   |
| Precision    |   0.56 |      1.00 | FAIL   |
| Consistency  |   0.96 |      0.70 | PASS   |
| Distribution |   0.87 |      0.80 | PASS   |

Cost per run: ~34k input + ~12k output tokens → ~$0.09.

- Recall is perfect — all known vulnerabilities detected.
- Precision is the weak point — false positives on `list_items` (the sane tool), particularly `input_validation`.
- Structured output reliability issue: 1/3 runs failed because Haiku couldn't produce valid JSON for `TestCaseBatch`.

### Gemini 3.1 Flash-Lite (`gemini-3.1-flash-lite-preview`) — 2026-03-18

3 of 3 runs completed (no structured output failures).

| Metric       | Result | Threshold | Status |
|:-------------|-------:|----------:|:-------|
| Recall       |   0.93 |      0.80 | PASS   |
| Precision    |   0.61 |      1.00 | FAIL   |
| Consistency  |   0.88 |      0.70 | PASS   |
| Distribution |   0.82 |      0.80 | PASS   |

### Comparison: Flash-Lite vs Haiku 4.5

| Metric              | Haiku 4.5  | Flash-Lite  | Notes                              |
|:--------------------|-----------:|------------:|:-----------------------------------|
| Recall              |      1.00  |       0.93  | Slightly lower, both pass          |
| Precision           |      0.56  |       0.61  | Slightly better, both fail         |
| Consistency         |      0.96  |       0.88  | Lower, both pass                   |
| Distribution        |      0.87  |       0.82  | Lower, both pass                   |
| Runs completed      |       2/3  |        3/3  | Flash-Lite more reliable           |
| Structured failures |       1/3  |         0/3 | Haiku failed to produce valid JSON |
| Cost vs Sonnet      | 3x cheaper | 12x cheaper |                                    |

Precision is the weak point for both models — likely a prompt issue, not a model issue. Flash-Lite wins on reliability (0 parsing failures) and cost (~4x cheaper than Haiku).

## Consequences

- `GoogleLLM` adapter implemented, sharing a `_BaseLLM` superclass with `AnthropicLLM`. Dependency: `langchain-google-genai>=4.1` (tested with 4.1.3 and 4.2.1, no async regression observed).
- Empirical validation passed: nested schemas, `StrEnum` fields, and `usage_metadata` all work correctly with `langchain-google-genai` 4.1.x.
- Default switched to Gemini 3.1 Flash-Lite. `AnthropicLLM` kept as fallback via `MCP_AUDITOR_PROVIDER=anthropic`.
- Model choice is an architecture decision, not a runtime parameter — not exposed as a CLI option. A future configuration file will centralize this.

## Sources

### Benchmark data
- [Claude Sonnet 4.6 benchmarks & pricing](https://www.digitalapplied.com/blog/claude-sonnet-4-6-benchmarks-pricing-guide) — Sonnet/Opus 4.6 benchmark tables
- [Claude 3.5 Haiku vs Haiku 4.5](https://llm-stats.com/models/compare/claude-3-5-haiku-20241022-vs-claude-haiku-4-5-20251001) — TAU2, GPQA across Haiku generations
- [GPQA leaderboard](https://llm-stats.com/benchmarks/gpqa) — cross-provider GPQA Diamond scores
- [GPT-5.4 benchmarks](https://www.digitalapplied.com/blog/gpt-5-4-computer-use-tool-search-benchmarks-pricing) — MCP-Atlas, TAU2, Terminal-Bench
- [Gemini 3.1 Pro model card](https://deepmind.google/models/model-cards/gemini-3-1-pro/) — official benchmark table
- [Gemini 3.1 Flash-Lite model card](https://deepmind.google/models/model-cards/gemini-3-1-flash-lite/) — GPQA, BFCL v3, MMLU-Pro
- [GPT-5-nano benchmarks](https://rankedagi.com/models/gpt-5-nano) — GPQA Diamond

### Integration feasibility
- [langchain #24225 — structured output fails on nested schemas](https://github.com/langchain-ai/langchain/issues/24225) — closed NOT_PLANNED, `list[BaseModel]` pattern failed (pre-v4.x, may be resolved)
- [langchain-google issue #957 — usage_metadata not populated](https://github.com/langchain-ai/langchain-google/issues/957) — closed, workaround confirmed (`include_thoughts=True`)
- [langchain-google issue #1600 — async 3-4x regression in v4.2.0](https://github.com/langchain-ai/langchain-google/issues/1600) — open, workaround: pin v4.1.x
- [ChatGoogleGenerativeAI token usage docs](https://docs.langchain.com/oss/python/integrations/chat/google_generative_ai) — confirms `usage_metadata` works on standard calls
