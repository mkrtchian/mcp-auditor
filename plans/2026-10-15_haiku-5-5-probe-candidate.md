# Claude Haiku 5.5 as a probe candidate

## Context

The default model is `gpt-6-luna` at reasoning `none` (ADR 021). Claude Haiku 5.5 (`claude-haiku-5-5`, released 2026-10-07) is listed at the same prices as Luna: 0.10 dollars per million input tokens, 0.01 cached, 0.50 output, for prompts up to 100,000 tokens. Whether it can serve the auditor is an open question, and the reason is its safety classifiers: a declined request comes back as a normal response with `stop_reason: "refusal"` and a `stop_details.category`, the `cyber` category covers exploit development and, per Anthropic, penetration testing, and Haiku 5.5 has no server-side fallback. The attack generator writes payloads against a live server, so a refusal on it is a coverage gap (ADR 021), and a user who audits with their own key cannot lift it short of Anthropic's Cyber Verification Program.

This change makes Haiku 5.5 measurable by the model probe (`evals/run_probe`, `evals/probe_method.md`), nothing more. It changes no default: the default provider stays `openai` with Luna, and the `anthropic` provider's default model stays `claude-haiku-4-5-20251001` with no reasoning setting. A switch, if the probe and the evals support one, is a later ADR superseding ADR 021, with the reset of the three baselines it implies (ADR 020) and its effect on the holdout's cutoff split (ADR 028, Haiku 5.5's knowledge cutoff is June 2026). The evals that would feed that ADR run Haiku 5.5 through the same adapter before any switch, with `MCP_AUDITOR_PROVIDER=anthropic`, `MCP_AUDITOR_MODEL=claude-haiku-5-5` and `MCP_AUDITOR_REASONING` set explicitly: a model other than the provider's default gets no reasoning setting otherwise, and would run at the API default (adaptive thinking at `medium`).

The probe builds each candidate through the production adapter (`create_llm`, `create_judge_llm`), so measuring Haiku 5.5 as configured needs the `anthropic` provider to carry what Haiku 5.5 needs. Today `_make_anthropic_model` builds `ChatAnthropic(model=model, max_retries=3)` and nothing else, and `config.py` refuses any reasoning setting for `anthropic`. Four gaps, each a defect of the provider whatever the probe finds:

1. **No reasoning setting.** Haiku 5.5 thinks by default (adaptive thinking, effort `medium`). Its effort is set with `output_config.effort` (`low`, `medium`, `high`, `xhigh`, `max`), and thinking turns off with `thinking: {"type": "disabled"}`, accepted at `high` effort or below only.
2. **No request timeout and no output cap.** The other providers built on a timeout get 120 seconds and 8,192 output tokens (`_REQUEST_TIMEOUT_SECONDS`, `_MAX_OUTPUT_TOKENS`), the cap bounding a model that loops in a long-string payload. Haiku 5.5 counts thinking toward `max_tokens`.
3. **A cut answer is not detected.** `_was_truncated` reads `status == "incomplete"` or `finish_reason == "length"`. Anthropic reports a cut by `stop_reason: "max_tokens"`, which `langchain-anthropic` copies into `response_metadata`, so a JSON cut at the cap would be repaired and pass as valid.
4. **The refusal message drops the category.** `_anthropic_refusal` returns `"Anthropic stopped the answer: stop_reason refusal"`. The category (`cyber`, `bio`, `frontier_llm`, `reasoning_extraction`, `general_harms`, or `null`) is what tells a classifier decline on the attack generator apart from any other, in the audit report's coverage gap as in the probe's observations.

## Approach

### Structured output method stays `function_calling`

Anthropic's native structured output (`json_schema` in `langchain-anthropic`) requires `additionalProperties: false` on every object, which `AuditPayload.arguments` (an open `dict[str, Any]`) cannot meet, the same limit that keeps OpenAI off strict mode. The adapter keeps `method="function_calling"` for `anthropic`.

`langchain-anthropic` 1.7.5 decides whether to force the tool call from the `ChatAnthropic.thinking` field alone (`with_structured_output`, and `bind_tools` likewise), not from the effort nor from the model's default: with `thinking` unset it forces `tool_choice` to the schema's tool. The API rejects a forced tool use under manual extended thinking (`"enabled"`) only: on Haiku 5.5, adaptive thinking, the default-on mode included, accepts it and skips thinking, the response opening with the tool call (Anthropic's thinking docs, "Response prefill and forced tool use"). Haiku 5.5 has no profile in 1.7.5 (so the library does not add adaptive thinking on its own when an effort is set), and `claude-haiku-5-5` is not in `_supports_forced_tool_choice`'s exclusion list. A forced call would therefore run every effort level without thinking. Hence the explicit `thinking={"type": "adaptive"}` beside an effort, below, which makes `langchain-anthropic` drop the forced `tool_choice` so the model can think before calling the tool.

With `thinking` set to `adaptive`, `with_structured_output(method="function_calling", include_raw=True)` does not force the call, and it pipes the model into `_raise_if_no_tool_calls` *inside* the `raw` branch: a response without a tool call raises `OutputParserException` out of `ainvoke`, before the adapter sees the raw message. A classifier refusal (`stop_reason: "refusal"`, no tool call) and an answer cut at the cap during thinking would then surface as an `OutputParserException`, never as `ProviderRefusal` or a truncated attempt, and the probe would record an `ERROR` with zero usage instead of a refusal. So, for `anthropic`, `LLM._bind` does not call `with_structured_output`: it builds the same `include_raw` shape itself, `RunnableMap(raw=model.bind_tools([schema], tool_choice=<tool name>))` piped into a `PydanticToolsParser(first_tool_only=True)` (or `JsonOutputKeyToolsParser` for a dict schema) with a fallback to `parsed=None`. `bind_tools` drops the forced `tool_choice` itself when `thinking` is adaptive (with a warning), and keeps it otherwise, so Haiku 4.5 and `reasoning="none"` keep today's forced call. A response without the tool call then parses to `None`, which the adapter already retries and counts as a parse failure after three attempts, and the refusal and truncation checks read the raw message as for the other providers. The probe measures both settings, forced and not, which is one reason to run both.

The binding's tests build a real `ChatAnthropic` on an `httpx.MockTransport` (passed through its async HTTP client) that replays Anthropic API JSON: a tool-call answer, a refusal with `stop_details`, a `max_tokens` cut, a thinking-only answer. `FakeChatModel` only mimics `with_structured_output`, and teaching it the new binding would encode the very assumption about `langchain-anthropic` that was wrong here, leaving the coupling untested. A replayed transport is a fake at the HTTP boundary, deterministic and with no network, and it exercises the library's real parsing.

### Reasoning setting for `anthropic`

`_PROVIDERS["anthropic"].accepted_reasoning` becomes `("none", "low", "medium", "high", "xhigh", "max")`, the same vocabulary as `openai`. The default reasoning stays `None`, so the default model (Haiku 4.5) gets no setting, as today.

`_make_anthropic_model(model, reasoning)` maps the setting:

- `None`: neither `thinking` nor effort is sent (today's request, plus timeout and cap).
- `"none"`: `thinking={"type": "disabled"}`, no effort sent, so the API's default effort applies.
- `"low"` to `"max"`: `effort=<level>` (the `ChatAnthropic` field `reasoning_effort`, alias `effort`, written into `output_config.effort`) and `thinking={"type": "adaptive"}`, the model's default made explicit so that `langchain-anthropic` does not force the tool call (see above).

A level the model does not take (an effort on Haiku 4.5, `"none"` on a model that cannot disable thinking) is the API's or `langchain-anthropic`'s error at build or call time, as for the other providers.

### Timeout, cap, truncation

`ChatAnthropic` is built with `max_tokens=_MAX_OUTPUT_TOKENS` and the 120-second timeout (`default_request_timeout`, alias `timeout`), like OpenAI and Fireworks. 8,192 tokens leave room for adaptive thinking at `low` on a batch the reference writes in about 700. `_was_truncated` also reads `response_metadata.get("stop_reason") == "max_tokens"`.

The comment above `_MAX_OUTPUT_TOKENS` already says the cap counts reasoning on some providers, which now includes Anthropic. Do not restate it.

### Missing key

`_make_anthropic_model` raises `ValueError("ANTHROPIC_API_KEY is not set.")` when the variable is unset or empty, as `_make_openai_model` does, so the probe stops before any call when a candidate cannot be built (`_build_models` in `evals/run_probe.py`) and the CLI reports it like the other providers.

### Refusal category

`_anthropic_refusal` reads `response_metadata.get("stop_details")`. When it is a mapping with a string `category`, the message is `"Anthropic stopped the answer: stop_reason refusal, category <category>"`. Without it, the message stays as today. On the non-streaming path, `langchain-anthropic` 1.7.5's `_format_output` puts every field of the API message other than `content`, `role` and `type` into `llm_output`, which `langchain-core` merges into the message's `response_metadata` for a single generation: the same path `_anthropic_refusal` already relies on for `stop_reason`. `RefusalStopDetails` dumps to a mapping with a string `category`. Verified by reading the installed source; the refusal test confirms it.

### Probe candidates

Two candidates in `evals/probe_candidates.py`, after the existing ones:

```python
Candidate(
    name="claude-haiku-5-5 none",
    settings=Settings(provider="anthropic", model="claude-haiku-5-5", judge_model="", reasoning="none"),
    prices=Prices(input=0.10, cached_input=0.01, output=0.50),
    reasoning_expected=False,
),
Candidate(
    name="claude-haiku-5-5 low",
    settings=Settings(provider="anthropic", model="claude-haiku-5-5", judge_model="", reasoning="low"),
    prices=Prices(input=0.10, cached_input=0.01, output=0.50),
    reasoning_expected=True,
),
```

`reasoning_expected` is `False` for `none` (thinking disabled, so 0 thinking tokens over the corpus) and `True` for `low` (more than 0 over the corpus), the convention of the two Luna candidates. Anthropic's usage reports thinking tokens separately: `usage.output_tokens_details.thinking_tokens`, a part of `output_tokens` (thinking is billed as output), which `langchain-anthropic` 1.7.5 maps to `usage_metadata["output_token_details"]["reasoning"]`, the field `_to_provider_usage` already reads. So the probe's reasoning check can see whether thinking ran. Adaptive thinking at `low` may skip thinking on a simple call, which is why the check reads the whole corpus and not each call. If the implementer's smoke run shows Haiku 5.5 responses without `output_tokens_details`, `low` goes back to `None` before the full run, since a missing count would read as 0 and report a false defect. The difference between the two candidates also shows in their output tokens and latency.

The adapter does not set `cache_control`, so Anthropic caches nothing and the cached-input price never applies. Cache writes, which Anthropic bills above the input price, never occur either, so the probe's cost formula holds unchanged. Same list prices are not the same cost: Haiku 5.5's tokenizer counts the same text as about 30 % more tokens than Haiku 4.5, and the probe computes each call's cost from the provider's own token counts, so that difference shows in the cost ratio.

`PRICES_DATE` is one date for every candidate. It moves to 2026-10-15, once every listed price (reference, Luna, Gemini 3.5 Flash-Lite, Haiku 5.5) is checked against the provider's price page that day. A price that changed is updated in `probe_candidates.py` and in the table of `probe_method.md`.

### What the run asks, written before it

The run is exploratory: it says whether Haiku 5.5 is worth an ADR, it decides nothing on its own. Whether the model is kept is a judgment on everything the probe and the evals show, as in ADR 021, and is not specified in advance. What is fixed before the run is how its results are counted and read, so that the reading does not bend to the numbers.

**What counts as a refusal.** Every parse failure of a Haiku candidate, whatever its category, split by hand from the report's observations into two kinds: a classifier refusal (`ProviderRefusal`, its `error` holding `stop_reason refusal` and, when the API gives one, the category), and a response with no tool call and no message (`UnparseableOutput` with `error` empty, the way a model that declines in text ends on the unforced `low` path). The probe keeps no response text, so the second kind cannot be told apart from a malformed answer: it is read as a possible decline, and reported as such. The category serves the diagnosis only, it filters nothing: a refusal tagged `general_harms` or with no category leaves the same coverage gap as a `cyber` one. The probe's coverage gaps (a parsed batch missing a category) are a different defect, which the generator's completion covers, and are not counted as refusals.

**Read per role**, since a refusal does not cost the same at each step, split by each observation's `schema_name` (the probe's own `role` field only tells `main` from `judge`, and would lump the chain calls with generation): generation (the 55 `TestCaseBatch` calls, of which 47 on CVE tool definitions), chains (the 38 `AttackContext`, `AuditPayload`, `StepObservation` and `ChainPlanBatch` calls), judging (the 60 `Judgment` calls).

**The reference is zero.** The ADR 021 run (`evals/probe_runs/2026-09-25_adr-021.json`) recorded no provider refusal for Luna on this corpus: its only refusals by the probe's rule were batches missing `resource_abuse`. Luna's provider refusals (OpenAI's `invalid_prompt`) came later, a handful of times, on the chain planning step of eval runs. Haiku 5.5 has no fallback, so each refusal is a coverage gap the user cannot close.

**Indicative bars.** More than 2 refusals in one role (2 of 55 in generation, 2 of 38 in chains, 2 of 60 in judging) would point against pursuing Haiku 5.5, and so would refusals concentrated on one schema (both `ChainPlanBatch` calls, most `AuditPayload` calls). They are a reading aid, not a rule: the decision to write an ADR weighs them with the parse failures, cost, latency, and the refusals' categories and placement.

The refusals are counted by hand: the probe's statistics count refusals by its mechanical rule and do not split them by kind or category, and this run adds no statistic.

The run itself is not a step of this plan: it needs `GOOGLE_API_KEY`, `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` and is launched by hand once the change is committed. Its report stays under `output/`, and goes to `evals/probe_runs/` only with the ADR that uses it.

## Files to modify

- `src/mcp_auditor/config.py`: `accepted_reasoning` of `anthropic`.
- `src/mcp_auditor/adapters/llm.py`: `make_chat_model` passes `reasoning` to `_make_anthropic_model`, which maps it, sets timeout and cap, and checks the key. `_was_truncated` reads `stop_reason == "max_tokens"`. `LLM._bind` binds the schema as a tool for `anthropic` instead of `with_structured_output` (an `_STRUCTURED_OUTPUT` variant or flag naming it), by calling the new module below.
- `src/mcp_auditor/adapters/llm_tool_binding.py` (new): the tool binding of "Structured output method" (`bind_tools` with the forced `tool_choice`, the tools parser, the fallback to `parsed=None`, the `include_raw` shape), as one public function taking the chat model, the schema and whether it is passed as a dict. `llm.py` is at 287 lines and the binding with the Anthropic factory changes would take it past 300, so the binding lives beside it as `llm_refusals.py` does (CLAUDE.md: files rarely exceed 300 lines, functions rarely exceed 20).
- `src/mcp_auditor/adapters/llm_refusals.py`: `_anthropic_refusal` adds the category.
- `evals/probe_candidates.py`: two candidates, `PRICES_DATE`, any updated price.
- `evals/probe_method.md`: candidates named in the opening paragraph, price table and its date, the reasoning-check table (two rows, matching the candidates' `reasoning_expected`), the output-tokens sentence of the Cost section (Anthropic bills thinking as output tokens, counted inside `output_tokens`), the Anthropic refusal shape in the parse-failure item (`stop_reason: "refusal"` with its category), the keys of "Running it" (`ANTHROPIC_API_KEY` added), a data-retention item for the Anthropic API (its commercial terms on training and retention, checked on 2026-10-15, with the source URL), and Anthropic added to the once-after-the-first-run check of the computed cost against the billing console.
- `README.md`: the `MCP_AUDITOR_REASONING` row (`none`, `low`, `medium`, `high`, `xhigh` or `max` for `anthropic`, where `none` turns thinking off) and the provider paragraph (with `anthropic`, the 120-second timeout and the 8,192-token cap now apply as for `openai` and `fireworks`, if the paragraph states them for those; otherwise only the reasoning sentence changes).
- `CHANGELOG.md`, `[Unreleased]`: under Changed, `MCP_AUDITOR_REASONING` accepted with `anthropic`; the `anthropic` provider's timeout, output cap and detection of a cut answer; the refusal category in the coverage gap's provider message.
- `CLAUDE.md`: the `run_probe` command line names `ANTHROPIC_API_KEY` beside the two keys.
- `CONTRIBUTING.md`, "Model probe": the keys of every candidate (`GOOGLE_API_KEY`, `OPENAI_API_KEY`) gain `ANTHROPIC_API_KEY`.

## What stays unchanged

- Every default: provider `openai`, Luna at `none`, the `anthropic` default model and its absent reasoning.
- The structured output method of every provider, and every other provider's factory.
- The probe's corpus, refusal rule, statistics and report format. No corpus recapture.
- The baselines and the gated evals: they run on the default provider, which this change does not touch. No declared flip, no reset.
- `docs/adr/`, past plans.

## Edge cases

- `reasoning=""` with model `claude-haiku-5-5` named by `MCP_AUDITOR_MODEL`: `resolve_reasoning` returns `None`, nothing is sent, the API default (adaptive thinking at `medium`) applies. Unchanged rule, stated in the README already. `thinking` being unset, `langchain-anthropic` forces the tool call, which the API accepts on Haiku 5.5 by skipping thinking (the response opens with the tool call), so this path runs without thinking. The probe candidates always name a reasoning, so they never take this path.
- `reasoning="none"` with an effort-only model such as Opus 5.5: the API returns a 400 at call time (thinking cannot be disabled there; `langchain-anthropic` 1.7.5 checks this itself only for the Fable 5 models and Sonnet 5.5). Not intercepted.
- `stop_details` absent, `None`, or without a string `category`: the message stays without a category.
- A response cut at the cap with `stop_reason: "max_tokens"` and a partially parsed tool call: counted as a truncated attempt and retried, like the other providers.
- A refusal response also carries no tool call: the refusal is checked before parsing, as today, so it raises `ProviderRefusal` and never a parse retry. This holds on the thinking path only because the adapter binds the tool itself (see "Structured output method"): through `with_structured_output` it would raise `OutputParserException` first.
- A response cut during thinking, before any tool call (`stop_reason: "max_tokens"`, no tool use): a truncated attempt, retried, same reason.

## Test scenarios

Unit tests, in the existing files and style (`tests/unit/test_config.py`, `tests/unit/test_llm_adapter.py`, `tests/unit/test_llm_refusals.py`) except the binding tests, written first and seen red. The binding tests go to a new `tests/unit/test_llm_tool_binding.py`, mirroring the new module: `test_llm_adapter.py` is already at 335 lines (CLAUDE.md: files rarely exceed 300 lines). Their setup, the `ChatAnthropic` on an `httpx.MockTransport` and the replayed API JSON bodies, goes to `tests/unit/support/test_llm_tool_binding_given.py` (CLAUDE.md: Given/When/Then, setup extracted when it abstracts something), and a `then` module only if an assertion abstracts more than a one-liner.

- **Config.** `anthropic` with `reasoning="none"` and with `"low"` resolves to the value set. `anthropic` with `"minimal"` raises naming the accepted values. The default model still resolves no reasoning (`test_anthropic_resolves_no_reasoning_for_its_default_model` stays). `test_anthropic_with_any_reasoning_raises` is replaced by the rejection of `"minimal"`.
- **Factory.** The default `anthropic` settings build Haiku 4.5 with no effort and no `thinking`, with `max_tokens == 8192` and a 120-second timeout. `reasoning="none"` with `claude-haiku-5-5` builds `thinking == {"type": "disabled"}` and no effort. `reasoning="low"` builds effort `"low"` and `thinking == {"type": "adaptive"}`. A missing and an empty `ANTHROPIC_API_KEY` raise naming it. Assertions read the built model's public fields, as the existing factory tests do.
- **Truncation.** A response with `response_metadata={"stop_reason": "max_tokens"}` is retried, and on every attempt raises `UnparseableOutput` counting the truncated attempts, as the `finish_reason="length"` cases do.
- **Refusal.** A response with `stop_reason: "refusal"` and `stop_details: {"category": "cyber", ...}` raises `ProviderRefusal` whose message contains `category cyber`. Without `stop_details`, the message is the one of today (the existing `anthropic` parametrized case keeps passing).
- **Anthropic binding.** With adaptive thinking (tool call not forced): a response without a tool call is retried and ends in `UnparseableOutput`, a `stop_reason: "refusal"` response without a tool call raises `ProviderRefusal`, a `stop_reason: "max_tokens"` response without a tool call counts as a truncated attempt, and none raises `OutputParserException`. A response with the tool call parses to the schema. With thinking disabled (tool call forced, the `none` candidate), a refusal also raises `ProviderRefusal`. These tests run on a `ChatAnthropic` behind an `httpx.MockTransport` replaying API JSON (see "Structured output method").
- **Probe candidates.** No new test: the existing probe tests run over `CANDIDATES` where they read it. The implementer checks that `_build_models` builds the two new candidates when `ANTHROPIC_API_KEY` is set (one-off, not committed if it only restates the factory tests).

No integration test: none reaches an LLM.

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.run_probe --candidates "claude-haiku-5-5 none" "claude-haiku-5-5 low" --schema AttackContext
```

The last command, a subset run of 8 calls per candidate on the real API with `ANTHROPIC_API_KEY`, checks the wiring only (models build, a call returns, cost is non-zero), never the result. It is the implementer's smoke check, run once, and its output is not kept.

## Due diligence record

What the due-diligence pass concluded about each external fact this plan cites or defers, on 2026-10-15, read by the later fact-check passes. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `claude-haiku-5-5` is the Claude API model ID, released 2026-10-07, reliable knowledge cutoff June 2026 (verified against platform.claude.com/docs/en/models/haiku-5-5/overview)
- SETTLED: `Prices(input=0.10, cached_input=0.01, output=0.50)` for Haiku 5.5, for prompts up to 100,000 tokens; above it 0.50 / 0.05 / 2.50, 5-minute cache write 0.125 (verified against platform.claude.com/docs/en/about-claude/pricing)
- SETTLED: reference `Prices(input=0.25, cached_input=0.025, output=1.50)`, Luna `Prices(input=0.10, cached_input=0.01, output=0.50)`, Gemini 3.5 Flash-Lite `Prices(input=0.30, cached_input=0.03, output=2.50)` unchanged, so `PRICES_DATE = "2026-10-15"` with no price edit (verified against developers.openai.com/api/docs/pricing and ai.google.dev/gemini-api/docs/pricing)
- SETTLED: effort levels `low`, `medium`, `high`, `xhigh`, `max` on Haiku 5.5, default `medium`, sent as `output_config.effort` (verified against platform.claude.com/docs/en/build-with-claude/effort)
- SETTLED: `thinking={"type": "disabled"}` accepted on Haiku 5.5 at effort `high` or below, 400 at `xhigh` or `max`; thinking on by default and counted toward `max_tokens` (verified against the effort and thinking pages of platform.claude.com)
- SETTLED: forced `tool_choice` is accepted on Haiku 5.5 under adaptive thinking and skips thinking; rejected only under manual `"enabled"` thinking and on Opus 5.5, Sonnet 5.5, Fable 5.1, Mythos 5.1 (verified against platform.claude.com/docs/en/build-with-claude/thinking, corrected in this plan)
- SETTLED: `stop_reason: "refusal"` with `stop_details.category` in `cyber`, `bio`, `frontier_llm`, `reasoning_extraction`, `general_harms` or `null`; Haiku 5.5 has no server-side fallback (verified against platform.claude.com/docs/en/build-with-claude/refusals-and-fallback and the installed `anthropic` 1.11.0 `RefusalStopDetails`)
- SETTLED: Haiku 5.5's cyber safeguards "still block penetration testing" (verified against anthropic.com/claude-haiku-5-5)
- SETTLED: `stop_reason == "max_tokens"` is Anthropic's cut signal (verified against the installed `anthropic` 1.11.0 `StopReason`)
- SETTLED: `usage.output_tokens_details.thinking_tokens` reports thinking tokens, mapped by `langchain-anthropic` 1.7.5 to `output_token_details["reasoning"]` (verified against platform.claude.com/docs/en/build-with-claude/thinking-steering-and-cost and the installed `_create_usage_metadata`, corrected in this plan)
- SETTLED: `langchain-anthropic` 1.7.5 behavior: `reasoning_effort` alias `effort`, `default_request_timeout` alias `timeout`, `with_structured_output` routing to `_raise_if_no_tool_calls` when `thinking` is adaptive, `bind_tools` dropping a forced `tool_choice` under adaptive thinking, no Haiku 5.5 profile, `claude-haiku-5-5` absent from `_supports_forced_tool_choice`'s exclusions (verified against the installed package source, the version pinned in `uv.lock`)
- SETTLED: Anthropic API data handling: prompts and outputs not retained by default except for Covered Models (Fable and Mythos only, not Haiku 5.5), never used for training without express permission (verified against platform.claude.com/docs/en/manage-claude/api-and-data-retention)
- OPEN (unverified): `output_tokens_details` present in Haiku 5.5 responses specifically; the docs state it without naming models and `langchain-anthropic` notes older models omit it
- OPEN (unverified): no Anthropic cache write occurs without `cache_control`; not checked against an automatic-caching rule

## Implementation steps

Verification commands (from `CLAUDE.md`): short loop `uv run pytest tests/unit -n auto --maxprocesses 4`, `uv run pyright <changed files>` and `uv run ruff check .` while working. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .` and `uv run pyright` with no file argument, all green. Tests are written first and seen red before the production code.

### Step 1: Anthropic tool binding and cut-answer detection

- **Files**:
  - `tests/unit/support/test_llm_tool_binding_given.py` (new)
  - `tests/unit/test_llm_tool_binding.py` (new)
  - `tests/unit/test_llm_adapter.py` (truncation case)
  - `src/mcp_auditor/adapters/llm_tool_binding.py` (new)
  - `src/mcp_auditor/adapters/llm.py` (`_bind`, `_STRUCTURED_OUTPUT`, `_was_truncated`)
  - `CHANGELOG.md` (`[Unreleased]`, Changed: the `anthropic` provider detects an answer cut at the output cap)
- **Do**:
  1. `test_llm_tool_binding_given.py`: a builder for a real `ChatAnthropic(model="claude-haiku-5-5", api_key="dummy", thinking={"type": "adaptive"}, effort="low", max_retries=0)` whose async client sends every request to an `httpx.MockTransport` replaying one fixed Anthropic Messages API JSON body (status 200). `ChatAnthropic` 1.7.5 has no field taking an HTTP client: `_async_client` is a `cached_property` built from `_get_default_async_httpx_client` (which is cached, do not patch it), so seed the instance's cached value, e.g. `chat_model.__dict__["_async_client"] = anthropic.AsyncClient(api_key="dummy", http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))`, and confirm on the installed version that the request really goes through it. Body builders, each a complete API message (`id`, `type: "message"`, `role`, `model`, `content`, `stop_reason`, `stop_details` where relevant, `usage` with `input_tokens`/`output_tokens`): a `tool_use` block named after the schema with valid input (`stop_reason: "tool_use"`), a refusal (`stop_reason: "refusal"`, `stop_details: {"type": "refusal", "category": "cyber", ...}` matching `anthropic` 1.11.0 `RefusalStopDetails`, text content, no tool use), a cut during thinking (`stop_reason: "max_tokens"`, a `thinking` block only), a thinking-only answer ending normally (`stop_reason: "end_turn"`, no tool use). Plus a builder for `LLM(chat_model, <the anthropic StructuredOutput>, max_parse_attempts=3)`.
  2. `test_llm_tool_binding.py` (scenarios under **Test**), then `test_llm_adapter.py`: one truncation case with `response_metadata={"stop_reason": "max_tokens"}` alongside the `finish_reason="length"` ones (use the existing `truncated(...)` fake helper if it accepts arbitrary metadata keys, otherwise extend it in `tests/fakes/chat_model.py`). Do not grow the factory class here (step 2 touches it).
  3. `llm_tool_binding.py`: one public function, e.g. `bind_schema_as_tool(model: BaseChatModel, output_schema: type[BaseModel], schema_as_dict: bool) -> Runnable[str, object]`, returning the `include_raw` shape `{"raw": AIMessage, "parsed": ...}`: `RunnableMap(raw=model.bind_tools([schema], tool_choice=<tool name>))` then `RunnablePassthrough.assign(parsed=itemgetter("raw") | parser).with_fallbacks([RunnablePassthrough.assign(parsed=lambda _: None)], exception_key="parsing_error")`, with `PydanticToolsParser(tools=[output_schema], first_tool_only=True)` for a class and `JsonOutputKeyToolsParser(key_name=<tool name>, first_tool_only=True)` for a dict. Mirror `langchain-core`'s own `include_raw` composition in `with_structured_output` rather than inventing one. A response with no tool call must parse to `None`, never raise.
  4. `llm.py`: name the variant in `StructuredOutput` (e.g. a `Literal` method `"tool_binding"` or a boolean field), set it for `"anthropic"` only, and have `LLM._bind` call `bind_schema_as_tool` for it. The other providers keep `with_structured_output` unchanged. `_was_truncated` also returns true on `response_metadata.get("stop_reason") == "max_tokens"`. Keep `llm.py` under 300 lines.
  5. Confirm on the installed `langchain-anthropic` that `stop_details` reaches `response_metadata` on the non-streaming `ainvoke` path (the refusal test of step 2 depends on it). Record the finding for step 2 in the step's report, not in the repo.
- **Test** (`test_llm_tool_binding.py`, behavior through `LLM.generate_structured`, never `OutputParserException`):
  - A `tool_use` response returns the schema instance and the usage from the body.
  - A thinking-only `end_turn` response with no tool call is retried and ends in `UnparseableOutput` with `truncated_attempts == 0`.
  - A `stop_reason: "refusal"` response raises `ProviderRefusal` (message contains `stop_reason refusal`) on the first attempt.
  - A `stop_reason: "max_tokens"` thinking-only response ends in `UnparseableOutput` with `truncated_attempts == 3`.
  - On a `ChatAnthropic` built with `thinking={"type": "disabled"}` (forced tool call), a refusal response raises `ProviderRefusal`.
  - `test_llm_adapter.py`: a `stop_reason: "max_tokens"` response on every attempt raises `UnparseableOutput` counting the truncated attempts.
- **Verify**: the new tests red before the module exists, then green. Full closing checks green. `uv run pytest tests/unit/test_llm_adapter.py tests/unit/test_llm_refusals.py` unchanged otherwise.

### Step 2: Anthropic reasoning, timeout, cap, key and refusal category

- **Files**:
  - `tests/unit/test_config.py`
  - `tests/unit/test_llm_adapter.py` (factory class)
  - `tests/unit/test_llm_refusals.py`
  - `src/mcp_auditor/config.py`
  - `src/mcp_auditor/adapters/llm.py` (`make_chat_model`, `_make_anthropic_model`)
  - `src/mcp_auditor/adapters/llm_refusals.py` (`_anthropic_refusal`)
  - `README.md`, `CHANGELOG.md`
- **Do**:
  1. Tests first (scenarios under **Test**). In `test_config.py`, replace `test_anthropic_with_any_reasoning_raises` with the rejection of `"minimal"`, keep `test_anthropic_resolves_no_reasoning_for_its_default_model`. In `test_llm_adapter.py`, extend the factory class next to `test_anthropic_builds_the_named_model`, reading the built model's public fields (`model`, `thinking`, `effort`/`reasoning_effort`, `max_tokens`, `default_request_timeout`) with `getattr` as the existing tests do. `test_llm_adapter.py` is already past 300 lines: if the additions push it much further, move the factory class to its own file (e.g. `tests/unit/test_chat_model_factory.py`) in this step.
  2. `config.py`: `_PROVIDERS["anthropic"].accepted_reasoning = ("none", "low", "medium", "high", "xhigh", "max")`, default reasoning still `None`.
  3. `llm.py`: `make_chat_model` passes `reasoning` to `_make_anthropic_model(model, reasoning)`. It raises `ValueError("ANTHROPIC_API_KEY is not set.")` when the variable is unset or empty (as `_make_openai_model`), and builds `ChatAnthropic(model=..., max_retries=3, max_tokens=_MAX_OUTPUT_TOKENS, timeout=_REQUEST_TIMEOUT_SECONDS, ...)` with: `None`, neither `thinking` nor effort; `"none"`, `thinking={"type": "disabled"}` and no effort; any other level, `effort=<level>` and `thinking={"type": "adaptive"}`. Do not restate the cap comment. Keep the function under 20 lines and `llm.py` under 300.
  4. `llm_refusals.py`: `_anthropic_refusal` reads `response_metadata.get("stop_details")`; when it is a mapping with a string `category`, the message is `"Anthropic stopped the answer: stop_reason refusal, category <category>"`, otherwise unchanged.
  5. `README.md`: the `MCP_AUDITOR_REASONING` row gains the `anthropic` values (`none`, `low`, `medium`, `high`, `xhigh` or `max`, `none` turning thinking off); the provider paragraph names the 120-second timeout and 8,192-token cap for `anthropic` only if it states them for `openai` and `fireworks`. `CHANGELOG.md` `[Unreleased]`, Changed: `MCP_AUDITOR_REASONING` accepted with `anthropic`, the `anthropic` provider's timeout and output cap (merge with step 1's cut-answer line), the refusal category in the coverage gap's provider message.
- **Test**:
  - Config: `anthropic` with `reasoning="none"` and `"low"` resolves to that value. `"minimal"` raises naming the accepted values. Default model resolves `None`.
  - Factory: default `anthropic` settings build `claude-haiku-4-5-20251001` with no effort, `thinking` unset, `max_tokens == 8192`, timeout 120. `model="claude-haiku-5-5", reasoning="none"` builds `thinking == {"type": "disabled"}` and no effort. `reasoning="low"` builds effort `"low"` and `thinking == {"type": "adaptive"}`. Missing and empty `ANTHROPIC_API_KEY` each raise naming it.
  - Refusal: `stop_reason: "refusal"` with `stop_details: {"category": "cyber", ...}` raises `ProviderRefusal` whose message contains `category cyber`. `stop_details` absent, `None`, or with a non-string `category` keeps today's message (the existing parametrized `anthropic` case keeps passing).
- **Verify**: new tests red, then green. Full closing checks green. `test_starting_the_cli_loads_no_provider_sdk` still passes (the key check must not import `langchain_anthropic` at module level).

### Step 3: Haiku 5.5 probe candidates and probe docs

- **Files**:
  - `evals/probe_candidates.py`
  - `evals/probe_method.md`
  - `CLAUDE.md`, `CONTRIBUTING.md`
- **Do**:
  1. `probe_candidates.py`: append the two candidates exactly as in "Probe candidates" (`claude-haiku-5-5 none`, `reasoning_expected=False`; `claude-haiku-5-5 low`, `reasoning_expected=True`; `Prices(input=0.10, cached_input=0.01, output=0.50)`), and set `PRICES_DATE = "2026-10-15"` (the due diligence record found no other price changed; edit a price only if a fresh check says otherwise).
  2. `probe_method.md`: the candidates in the opening paragraph, the price table and its date, two rows in the reasoning-check table matching `reasoning_expected`, the Cost section's output-tokens sentence (Anthropic bills thinking as output, counted inside `output_tokens`), the Anthropic refusal shape in the parse-failure item (`stop_reason: "refusal"` with its category), `ANTHROPIC_API_KEY` in "Running it", and a data-retention item for the Anthropic API (not retained by default for Haiku 5.5, never used for training without express permission, checked 2026-10-15, source platform.claude.com/docs/en/manage-claude/api-and-data-retention), and Anthropic in the once-after-the-first-run check of the computed cost against the billing console.
  3. `CLAUDE.md`: the `uv run python -m evals.run_probe` line names `ANTHROPIC_API_KEY` beside the two keys. `CONTRIBUTING.md`, "Model probe": the keys gain `ANTHROPIC_API_KEY`.
  4. One-off checks, not committed: with `ANTHROPIC_API_KEY` set to a dummy, `_build_models` in `evals/run_probe.py` builds both new candidates. If a real key is available, run the smoke check `uv run python -m evals.run_probe --candidates "claude-haiku-5-5 none" "claude-haiku-5-5 low" --schema AttackContext` once (models build, a call returns, cost non-zero) and look whether the `low` responses carry `output_tokens_details`: if they do not, set `reasoning_expected=None` on `claude-haiku-5-5 low` (a missing count would read as 0 and report a false defect) and say so. Without a real key, report the smoke check as not run.
- **Test**: no new test. The existing probe tests (`tests/unit/test_probe*.py`, `tests/unit/test_run_probe.py`) run over `CANDIDATES` and must stay green.
- **Verify**: full closing checks green.
