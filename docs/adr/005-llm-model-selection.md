# ADR 005: LLM Model Selection

**Date:** 2026-03-17
**Status:** Draft

## Context

`mcp-auditor` uses an LLM for two tasks: generating adversarial test cases (structured output) and judging tool responses (classification with justification). Both require reliable structured output (Pydantic schemas), security reasoning, and tool use capabilities.

The current implementation hardcodes `claude-sonnet-4-6-latest` in `AnthropicLLM`. Before investing in multi-provider support, we need a data-driven model selection that balances cost, quality, and integration maturity.

## Decision

Add a `GoogleLLM` adapter to support Gemini models alongside the existing `AnthropicLLM`. If structured output works with our schemas (`TestCaseBatch`, `EvalResult`), adopt Gemini as the primary provider.

### Target configuration
- **Production model:** Gemini 3.1 Pro ($2/$12) — best benchmarks overall (GPQA 94.3%, MCP-Atlas 69.2%, TAU2 99.3%) at 1.5x cheaper than Sonnet.
- **Development model:** Gemini 3.1 Flash-Lite ($0.25/$1.50) — GPQA 86.9%, 12x cheaper than Sonnet.

### Fallback (current defaults, kept as-is)
- **Production:** `claude-sonnet-4-6-latest` — proven tool use reliability (TAU2 92-98%) and integration maturity.
- **Development:** `claude-haiku-4-5-latest` — 3x cheaper, ~90% of Sonnet's reasoning quality on GPQA.

### Models eliminated
- **GPT-5-nano** — MMLU-Pro 78.0%, no tool use data. Cheapest option but unproven for structured security judgments.
- **Claude Haiku 3 / 3.5** — TAU-bench 22-51%, deprecated or stagnant.
- **Claude Opus 4.6** — 1.7x more expensive than Sonnet, worse on MCP-Atlas (60.3% vs 61.3%). Overkill for classification.
- **GPT-5.4** — comparable price to Sonnet but TAU2 Telecom at 64.3% vs 97.9%. Less reliable for agentic workflows.

## Models Evaluated

### Pricing

| Model                   | Input $/MTok | Output $/MTok | Cost vs Sonnet 4.6 |
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
- **Status:** Production-ready. Currently in use.
- `with_structured_output(include_raw=True)` works reliably.
- `usage_metadata` on AIMessage provides accurate token counts.
- Async (`ainvoke`) works without issues.

### Google Gemini (`langchain-google-genai`)
- **Status:** Feasible with caveats — requires empirical validation.
- **Nested Pydantic schemas (main risk).** An older issue ([langchain #24225](https://github.com/langchain-ai/langchain/issues/24225), closed NOT_PLANNED) reported that `with_structured_output` fails on schemas containing `list[BaseModel]`. Our `TestCaseBatch` has exactly this pattern (`cases: list[AuditPayload]`), and `EvalResult` uses multiple `StrEnum` fields. The issue predates the v4.x rewrite, so it may be resolved — but this is unconfirmed and can only be validated empirically.
- **Token usage (low risk).** `usage_metadata` works on standard `invoke()` calls ([official docs](https://docs.langchain.com/oss/python/integrations/chat/google_generative_ai)). With `with_structured_output(include_raw=True)` in function calling mode, the raw AIMessage should expose the same metadata. Fallback: `include_thoughts=True` on the model constructor ([issue #957](https://github.com/langchain-ai/langchain-google/issues/957), closed, workaround confirmed).
- **Async regression (non-issue).** `ainvoke` is 3-4x slower in v4.2.0+ due to `google-genai >= 1.56` ([issue #1600](https://github.com/langchain-ai/langchain-google/issues/1600), open). **Workaround: pin `langchain-google-genai==4.1.x`.**
- The adapter change itself is minimal — a new `GoogleLLM` class implementing `LLMPort`, no changes to domain or graph.

### OpenAI (`langchain-openai`)
- **Status:** Not evaluated in detail.
- GPT-5-nano and GPT-5-mini lack published tool use benchmarks, making them hard to assess for this use case.
- GPT-5.4 has weak TAU2 scores (64.3% Telecom) despite strong reasoning — suggests unreliable agentic behavior.

## Consequences

- Build a `GoogleLLM` adapter implementing `LLMPort`, pinning `langchain-google-genai==4.1.x` to avoid the async regression.
- Validate empirically: (1) `TestCaseBatch` with nested `list[AuditPayload]` parses correctly, (2) `EvalResult` with `StrEnum` fields works, (3) `usage_metadata` is populated on the raw AIMessage.
- If validation passes, switch defaults to Gemini 3.1 Pro (prod) and Flash-Lite (dev). Keep `AnthropicLLM` as fallback.
- If nested schema support fails, stay on Anthropic and revisit when `langchain-google-genai` matures.
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
