# OpenRouter provider, with GLM 5.3 probe candidates

## Context

OpenRouter is an aggregator: one key, one OpenAI-compatible Chat Completions API (`https://openrouter.ai/api/v1`), and behind it hundreds of models, each open-weight one served by several inference hosts at different prices and quantizations. GLM 5.3 (`z-ai/glm-5.3`) alone has about forty endpoints, from the first-party Z.AI at 1.40 dollars per million input tokens and 4.40 output to third-party hosts several times cheaper on output. Billing goes to OpenRouter, which charges a platform fee on credit purchases (5.5 % pay-as-you-go).

For the auditor a host is not interchangeable, for two reasons:

1. **A host can filter on top of the model.** The attack generator writes offensive payloads against a live server, and a host-level classifier that blocks security content leaves a coverage gap the user cannot close. This is the one condition a host must meet. Research on 2026-10-15 (hosts' terms of service, OpenRouter's provider listing): OpenRouter moderates no open-weight request (`moderationRequired` is `false` for every GLM 5.3 host), and exposes no per-endpoint moderation flag. Z.AI documents a filter on input and output (error 1301, `finish_reason: "sensitive"`). Baidu is subject to Chinese content rules and likely filters. Novita reserves automated safety screening and bans "cyberweapons" in its terms, AkashML bans "generating ... security exploits", SiliconFlow reserves a right to vet content. For the others nothing is documented, which is not proof of absence, so the probe is the check.
2. **Quantization changes quality.** The same model is served in fp8 by some hosts and fp4 by others, and fp4 degrades long reasoning and exact schema compliance first, which is what the auditor needs.

So OpenRouter is usable only with the host pinned: without it OpenRouter picks a host per request, and two runs of one setting can land on different hosts, quantizations and filters. Data retention and training on prompts are, by contrast, a choice each user makes in their OpenRouter account settings (`data_collection`, zero data retention), and the auditor forces nothing there.

This change fixes the detection of a cut answer on the Chat Completions path the provider shares with `alibaba` (see "A cut answer on the parse path"), then adds an `openrouter` provider, a setting that pins its hosts, the recognition of a host-level block as a refusal, and two GLM 5.3 probe candidates on the two hosts that meet the conditions best: Sail Research (fp8, no documented filter, no exploit clause) and DeepInfra (fp4, no moderation clause, zero-retention contract). It changes no default: the default provider stays `openai` with Luna at `none` (ADR 021). A switch, if the probe and the evals support one, is a later ADR with the baseline resets it implies (ADR 020).

## Approach

### A cut answer on the parse path

With a `response_format` in the payload, `langchain-openai` 1.6.7 calls the `openai` SDK's `chat.completions.parse` (`_agenerate`), and the SDK raises before any message exists: `LengthFinishReasonError` on `finish_reason: "length"`, `ContentFilterFinishReasonError` on `finish_reason: "content_filter"` (`openai/lib/_parsing/_completions.py`, `parse_chat_completion`). `langchain-openai` re-raises both unchanged. So `_was_truncated` never sees a cut answer on this path, and the cut propagates as an exception: an `ERROR` in the probe, and a crashed step in an audit, since `graph/refusals.py` catches `ProviderRefusal` only. This is already the case for `alibaba` today, which `probe_method.md` wrongly lists among the providers whose cut answer counts as a parse failure. `openai` (Responses API), `fireworks` (`ChatFireworks`), `google` and `anthropic` do not take this path.

The fix, independent of OpenRouter and committed on its own: `LLM` treats an `openai.LengthFinishReasonError` raised by `ainvoke` as a truncated attempt, retried and counted in `UnparseableOutput.truncated_attempts` like the cuts `_was_truncated` reads. The attempt's usage comes from `error.completion.usage` (an `openai` `CompletionUsage`): `input_tokens = prompt_tokens`, `output_tokens = completion_tokens`, `cached_input_tokens = prompt_tokens_details.cached_tokens or 0`, `reasoning_tokens = completion_tokens_details.reasoning_tokens or 0`, the throttle count of the attempt added, all zero when `usage` is `None`. The cut is caught where `_invoke` already catches errors, and the loop of `generate_structured` stays the one place that counts attempts. `llm.py` is at 176 lines and gains about 20.

Where it lands (ADR 016): it changes the system under test for `alibaba` and `openrouter` only. The default provider (`openai`, Responses API) never raises `LengthFinishReasonError`, so no gated cell can move: no declared flip, no reset. The justification holds with no measurement: a cut answer is an output-cap event, retried for every other provider, and only the exception shape kept it from that rule.

### Provider

`openrouter` joins `_PROVIDERS` in `config.py`, built through `ChatOpenAI` pointed at OpenRouter's base URL with Chat Completions, as `alibaba` already is (`_make_alibaba_model`). Its structured output is `StructuredOutput(method="json_schema", schema_as_dict=True)`, for the reason the `alibaba` entry gives: `ChatOpenAI` makes a Pydantic class strict, and strict mode rejects the open `AuditPayload.arguments`.

Defaults: model `z-ai/glm-5.3`, reasoning `low`. GLM 5.3 cannot turn reasoning off (OpenRouter's model page: "Reasoning is always on and cannot be disabled", efforts `low`, `high`, `max`), and `low` is its cheapest setting. Accepted reasoning: OpenRouter's unified `reasoning.effort` vocabulary, `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max` (the seven values OpenRouter's reasoning-tokens doc lists). A level the routed model does not take is OpenRouter's or the host's error at call time, as for the other providers.

The reasoning setting is sent as `extra_body={"reasoning": {"effort": <level>}}`, OpenRouter's documented parameter, not as `ChatOpenAI`'s `reasoning_effort` field: OpenRouter's top-level `reasoning_effort` does not take `max`, which `reasoning.effort` does.

### Host pinning

A new `Settings` field, `openrouter_hosts: str = ""` (`MCP_AUDITOR_OPENROUTER_HOSTS`), a comma-separated list of OpenRouter provider slugs (`sail-research`, `deepinfra/fp4`), read by `Settings.resolve_openrouter_hosts() -> tuple[str, ...]` (split on commas, stripped, empty items dropped). The factory always sends OpenRouter's provider routing object:

- `require_parameters: true` always, so a host that ignores `response_format` or `reasoning` is never picked.
- With hosts set: `order: [<hosts>]` and `allow_fallbacks: false`, so only those hosts answer and a failure on them is returned as an error instead of silently falling back to another host.
- With hosts unset: OpenRouter's own routing (price-weighted load balancing). The README warns that a host may then filter, and recommends pinning.

The user's OpenRouter account privacy settings (denying data collection, requiring zero data retention) filter hosts before the order applies, so a pinned host that does not comply is excluded and, with no fallback, every call fails with a routing error. The README says so beside the hosts variable.

The setting is ignored by the other providers. Raising instead would make every probe candidate and every eval under another provider fail as soon as an operator has the variable set, since a `Settings` field left unnamed is read from the environment.

`make_chat_model` passes `settings.resolve_openrouter_hosts()` to `_make_openrouter_model(model, reasoning, hosts)`.

### Factory

```python
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def _make_openrouter_model(model: str, reasoning: str | None, hosts: tuple[str, ...]) -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is not set.")
    return ChatOpenAI(
        model=model,
        base_url=_OPENROUTER_BASE_URL,
        api_key=SecretStr(api_key),
        use_responses_api=False,
        extra_body=_openrouter_body(reasoning, hosts),
        max_retries=3,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        max_completion_tokens=_MAX_OUTPUT_TOKENS,
    )
```

`_openrouter_body(reasoning, hosts) -> dict[str, Any]` builds `{"provider": {...}}` plus `"reasoning": {"effort": reasoning}` when `reasoning` is not `None`. OpenRouter documents `max_completion_tokens` as sharing `max_tokens` semantics (its API parameters doc), so the cap stays on `max_completion_tokens`. The endpoints listing, though, names `max_tokens` among the supported parameters of the three pinned endpoints, not `max_completion_tokens`, and whether `require_parameters` normalizes the name before filtering is undocumented. If it does not, every call fails with OpenRouter's "no endpoints found that can handle the requested parameters" error: the smoke run checks it, and the fallback is to drop `max_completion_tokens=` and send `"max_tokens": _MAX_OUTPUT_TOKENS` in `extra_body`, with the factory test adjusted. The cap counts reasoning on GLM, and one GLM-5.3-Flash batch at `medium` used about 3,000 tokens (`probe_method.md`), so 8,192 leaves room at `low`.

Throttle counting and token usage need nothing: `ChatOpenAI` logs on `httpx2` as for `alibaba`, and `langchain-openai` maps `usage.completion_tokens_details.reasoning_tokens` and `prompt_tokens_details.cached_tokens`, which OpenRouter returns, into `usage_metadata`.

`chat_model_factory.py` is at 144 lines and gains about 30, under the 300-line bar.

### A host-level block is a refusal

OpenRouter's errors-and-debugging doc describes how a block surfaces. Two shapes reach the adapter, and each is a policy refusal, raised as `ProviderRefusal`, so it reaches the coverage gap and the probe's refusal count like any provider refusal. Both are recognized in `refusal_from_error`, which `_invoke` already calls on any exception, walking `__cause__`:

1. **HTTP 403** with `error.metadata.error_type` equal to `content_policy_violation` (a filter at the host) or `refusal` (a host that reports a model refusal as an error), the metadata carrying `provider_name`, `provider_code` (the host's own code, Z.AI's 1301 for instance) and `raw`. The `openai` SDK raises it as `openai.PermissionDeniedError` (verified: `.body` is the inner `error` object). `refusal_from_error` today only matches `openai.BadRequestError`. It gains a match on `openai.PermissionDeniedError` whose `body` is a mapping with `metadata.error_type` in `{"content_policy_violation", "refusal"}`, the only status the doc gives for these. The provider message is the body's `message`, followed by `(provider <provider_name>, code <provider_code>)` for whichever of the two is present. `_provider_message` widens from `openai.BadRequestError` to `openai.APIStatusError`.
2. **`finish_reason: "content_filter"`** on a 200, raised by the `openai` SDK as `openai.ContentFilterFinishReasonError` on the parse path (see "A cut answer on the parse path"), before any message reaches `response_metadata`. OpenRouter sets this finish both when a host filter stops the answer (it normalizes a native filter reason to `content_filter`) and beside `message.refusal` when the model itself declines. `refusal_from_error` matches the exception: the provider message is `completion.choices[0].message.refusal` when present (the model's own decline), `"finish_reason content_filter"` otherwise (a filter with no refusal text from the model). It applies to `alibaba` as well, the other provider on this path, where a filtered answer is a refusal too.

Not matched, by decision:

- **An error after headers were sent** (a `200 OK` whose body holds only an `error` object, no `choices`): the SDK's parse iterates `choices` and raises `TypeError`, which carries nothing to tell a block from any other failure. It propagates and counts as an error.
- **Z.AI's `native_finish_reason: "sensitive"`**: dropped by `langchain-openai`, and normalized by OpenRouter to `content_filter`, which shape 2 covers.
- **`finish_reason: "error"`** (a host failing mid-answer, partial content): neither a cut nor a refusal. The SDK does not raise on it, the partial JSON fails to parse, and the attempt is retried as a parse failure.

A refused call's tokens are not counted: `ProviderRefusal` from `refusal_from_error` carries the throttle count only, as for the existing OpenAI and Alibaba refusals, so the probe's cost of a refused call is undercounted. `probe_method.md` states it.

`llm_refusals.py` is at 108 lines and gains about 30.

### Probe candidates

Two candidates in `evals/probe_candidates.py`, after the existing ones:

```python
Candidate(
    name="glm-5.3 low sail-research",
    settings=Settings(
        provider="openrouter", model="z-ai/glm-5.3", judge_model="", reasoning="low",
        openrouter_hosts="sail-research",
    ),
    prices=Prices(input=0.15, cached_input=0.14, output=3.40),
    reasoning_expected=True,
),
Candidate(
    name="glm-5.3 low deepinfra-fp4",
    settings=Settings(
        provider="openrouter", model="z-ai/glm-5.3", judge_model="", reasoning="low",
        openrouter_hosts="deepinfra/fp4",
    ),
    prices=Prices(input=0.5625, cached_input=0.125, output=2.50),
    reasoning_expected=True,
),
```

`sail-research` covers its two GLM 5.3 endpoints (`sail-research/us`, `sail-research/fp8`), both fp8 at the same price. DeepInfra's endpoint carries `discount: 0.375` in OpenRouter's endpoint listing: the listed prices are read as net of it, since every other discounted GLM 5.3 endpoint's listed price divides back to Z.AI's 1.40 / 4.40 (no doc says so). The implementer checks the price billed for the smoke run on OpenRouter's activity page, and corrects `Prices` if it differs. The prices are OpenRouter's per-token list prices, without the 5.5 % fee on credits, so the report's cost for these two candidates is about 5 % below what they cost. `probe_method.md` says so beside the price table. No other candidate's price moves: `PRICES_DATE` stays 2026-10-15.

`reasoning_expected=True`: GLM 5.3 always reasons. If the implementer's smoke run shows responses without `completion_tokens_details.reasoning_tokens`, the two candidates go to `None` before the full run, since a missing count reads as 0 and would report a false defect.

`_candidate_entry` in `evals/run_probe.py` records `"openrouter_hosts"` beside the provider, so the report says which hosts were pinned (not which one answered: `langchain-openai` drops OpenRouter's `provider` field from the response): `list(settings.resolve_openrouter_hosts())` when the provider is `openrouter`, `[]` otherwise. The other candidates leave the field out of their `Settings`, so it is read from `MCP_AUDITOR_OPENROUTER_HOSTS` (the `probe_candidates.py` docstring), and an unconditional read would record an operator's hosts on Luna or Haiku, where they play no part.

### What the run asks, written before it

The run is exploratory: it says whether GLM 5.3 through OpenRouter is worth an ADR, and decides nothing on its own. What is fixed before it is how refusals are counted and read.

**Two kinds of refusal, split by hand from the observations' `error`:** a host-level block (the provider message carries `provider <name>` from shape 1, or reads `finish_reason content_filter` from shape 2), and a model refusal (`message.refusal`, or a response with no parsed output and no message, read as a possible decline as in the Haiku 5.5 plan). A single host-level block on a candidate excludes that host from any default: the condition is vital, and one occurrence shows the filter exists. Model refusals are read per role (generation, chains, judging, split by `schema_name`), with the indicative bar of the Haiku 5.5 run (more than 2 in one role, or concentrated on one schema, points against pursuing), weighed with parse failures, cost, latency and reasoning volume.

**fp8 against fp4.** The two candidates run the same model at the same setting, so the gap between them in parse failures and coverage gaps reads as the cost of fp4 on this corpus, at the probe's resolution.

The run itself is not a step of this plan: it needs `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and `OPENROUTER_API_KEY` and is launched by hand once the change is committed.

## Files to modify

- `src/mcp_auditor/config.py`: `openrouter_hosts` field, `resolve_openrouter_hosts`, the `openrouter` entry of `_PROVIDERS`, the provider name in `_provider_defaults`'s error message.
- `src/mcp_auditor/adapters/chat_model_factory.py`: the `openrouter` branch of `make_chat_model` (passing the hosts), `_make_openrouter_model`, `_openrouter_body`, the provider name in the unknown-provider message.
- `src/mcp_auditor/adapters/llm.py`: a `LengthFinishReasonError` is a truncated attempt with the usage of its completion ("A cut answer on the parse path"). `openrouter` in `_STRUCTURED_OUTPUT`, and the comment above it naming OpenRouter beside OpenAI and Alibaba.
- `src/mcp_auditor/adapters/llm_refusals.py`: the OpenRouter 403 match (shape 1), the `ContentFilterFinishReasonError` match (shape 2), the module comment naming them. `_provider_message` is typed on `openai.BadRequestError` today and widens to `openai.APIStatusError`.
- `src/mcp_auditor/adapters/throttling.py`: the module docstring lists the providers logging on `httpx2`, `openrouter` joins `openai`, `alibaba` and `anthropic`.
- `evals/probe_candidates.py`: two candidates.
- `evals/run_probe.py`: `openrouter_hosts` in `_candidate_entry`.
- `evals/probe_method.md`: the candidates in the opening paragraph if it names them, the price table (two rows, and the sentence on OpenRouter's fee), the Cost section's sentence on reasoning tokens (OpenRouter returns GLM's reasoning inside `completion_tokens`), the cut-answer sentence (step 1 makes it true for Alibaba, which it already names, and step 3 adds OpenRouter), the "Errors" bullet listing the providers with a 120-second timeout (OpenRouter added), the undercounted cost of a refused call, the once-after-the-first-run billing check (OpenRouter's activity page), the reasoning-check table (two rows, more than 0), the refusal shapes of a host-level block, a data-retention item for OpenRouter and the two hosts (their policies as OpenRouter lists them, and Sail Research's own terms reserving the right to store responses, with the source URLs and the check date), and `OPENROUTER_API_KEY` in "Running it".
- `README.md`: `openrouter` in the `MCP_AUDITOR_PROVIDER` row, `MCP_AUDITOR_REASONING` row (the OpenRouter vocabulary), new rows `MCP_AUDITOR_OPENROUTER_HOSTS` and `OPENROUTER_API_KEY`, the defaults paragraph (`z-ai/glm-5.3` at effort `low`, the hosts pinned by the new variable, unpinned routing may land on a host that filters security content or serves a lower quantization, and the account privacy settings can exclude a pinned host, which then fails every call), and the Safety paragraph (with `openrouter`, retention and training depend on the host and on the user's OpenRouter account settings).
- `CHANGELOG.md`, `[Unreleased]`: under Fixed (a new subsection), an `alibaba` answer cut at the output cap is retried as a truncated attempt instead of failing the step. Under Added, the `openrouter` provider and `MCP_AUDITOR_OPENROUTER_HOSTS`. Under Changed, a host-level block and a `content_filter` finish are reported as provider refusals.
- `CLAUDE.md`: the `run_probe` command line names `OPENROUTER_API_KEY` beside the three keys.
- `CONTRIBUTING.md`, "Model probe": `OPENROUTER_API_KEY` in the keys of every candidate. The evals paragraph listing the provider keys (`OPENAI_API_KEY` ... `DASHSCOPE_API_KEY`) gains `OPENROUTER_API_KEY`.
- `.env.example`: `openrouter` in the provider comment, its reasoning vocabulary (default `low` for the default model) in the reasoning comment, a commented `MCP_AUDITOR_OPENROUTER_HOSTS=sail-research` line, and `OPENROUTER_API_KEY` among the keys.

## What stays unchanged

- Every default: provider `openai`, Luna at `none`, every other provider's default model and reasoning.
- Every other provider's factory and structured output method.
- The eval conditions (`eval_session.py`, `judge_session.py`, `run_cve_benchmark.py`, `judge_gate.py`) record provider, model and reasoning, not the OpenRouter hosts. Running a gated eval under `openrouter` is out of scope: the ADR that would switch to it adds the hosts to the conditions, with the resets that implies. No baseline, fixture or scoring code changes, so no reset, no declared flip and no labeling log entry.
- The probe's corpus, refusal rule, statistics and report format apart from the new `openrouter_hosts` entry field. No corpus recapture.
- `docs/adr/`, past plans.

## Edge cases

- `MCP_AUDITOR_OPENROUTER_HOSTS` set under another provider: ignored, by the factory and by the probe report's `openrouter_hosts` entry.
- `MCP_AUDITOR_OPENROUTER_HOSTS=" sail-research , ,deepinfra/fp4"`: resolves to `("sail-research", "deepinfra/fp4")`.
- Hosts unset: the routing object holds `require_parameters` only, no `order`, no `allow_fallbacks`.
- A pinned host down or rate-limited: with `allow_fallbacks: false`, OpenRouter returns the error (a 429 counts as throttled and is retried by the client, a 5xx propagates as today).
- A model named by `MCP_AUDITOR_MODEL` under `openrouter` with `MCP_AUDITOR_REASONING` unset: no `reasoning` object is sent, the model's default applies, the existing rule.
- A 403 without `metadata.error_type` (OpenRouter Guardrails on the user's account, OpenRouter's own moderation, whose metadata is `reasons`, `flagged_input`, `provider_name`, `model_slug`): not a refusal, propagates unchanged. A 402 (credit exhausted) carries no `metadata` and is not a `PermissionDeniedError`: propagates.
- A `ContentFilterFinishReasonError` whose completion has no choice, or a choice without `refusal`: the message is `finish_reason content_filter`.
- A `LengthFinishReasonError` whose completion has no `usage`: a truncated attempt with zero tokens, the throttle count kept.
- A pinned host excluded by the account privacy settings: OpenRouter's routing error propagates, as any API error.
- `OPENROUTER_API_KEY` unset or empty: `ValueError` naming it at build time, so the probe stops before any call.

## Test scenarios

Unit tests, in the existing files and style, written first and seen red.

- **Config** (`tests/unit/test_config.py`): `test_unknown_provider_names_every_provider` gains `openrouter` in its loop. `openrouter` resolves `z-ai/glm-5.3` and `low`. `openrouter` with `reasoning="high"` resolves `high`, with an unknown level raises naming the accepted values. `resolve_openrouter_hosts` on `""`, on `"sail-research"`, and on the spaced list with an empty item.
- **Factory** (`tests/unit/test_chat_model_factory.py`): the default `openrouter` settings build `z-ai/glm-5.3` with OpenRouter's base URL, Chat Completions, `max_tokens == 8192`, `request_timeout == 120`, and `extra_body == {"provider": {"require_parameters": True}, "reasoning": {"effort": "low"}}`. With `openrouter_hosts="sail-research"`, the provider object adds `order == ["sail-research"]` and `allow_fallbacks is False`. A model override with no reasoning sends no `reasoning` key. A missing and an empty `OPENROUTER_API_KEY` raise naming it. Assertions read the built model's public fields, as the existing factory tests do.
- **Cut answer** (`tests/unit/test_llm_adapter.py`, `TestTruncatedOutput`): a scripted `openai.LengthFinishReasonError(completion=<ChatCompletion with usage>)` on every attempt raises `UnparseableOutput` with `truncated_attempts == 3` and the usage of the three completions summed. A cut followed by a valid response returns the output with both usages summed. A completion with `usage=None` counts the attempt with zero tokens. The exception is the SDK's real class, built on a real `ChatCompletion`, raised by `FakeChatModel` (which raises a scripted exception).
- **Refusals** (`tests/unit/test_llm_refusals.py`): an `openai.PermissionDeniedError` with body `{"message": ..., "metadata": {"error_type": "content_policy_violation", "provider_name": "Sail Research", "provider_code": "1301"}}` raises `ProviderRefusal` whose message names the provider and the code. The same with `error_type: "refusal"`. A 403 without `metadata` propagates unchanged. A scripted `openai.ContentFilterFinishReasonError` whose completion's message carries `refusal=<text>` raises `ProviderRefusal` without a retry, with the model's text as message. The same without `refusal` raises with `finish_reason content_filter`. The errors are built on an `httpx2.Response` as the existing OpenAI and Alibaba cases build theirs (`_bad_request`).
- **Probe**: no new test, the existing probe tests run over `CANDIDATES`. If a test pins `_candidate_entry`'s keys, it gains `openrouter_hosts`.

No integration test: none reaches an LLM.

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.run_probe --candidates "glm-5.3 low sail-research" "glm-5.3 low deepinfra-fp4" --schema AttackContext
```

The last command, a subset run of 8 calls per candidate on the real API with `OPENROUTER_API_KEY`, checks the wiring only, never the result: the models build, calls return (not OpenRouter's "no endpoints found" error, see "Factory"), and the observations in `output/probe_subset.jsonl` show non-zero reasoning tokens. The subset run prints defects only, so the host that answered and the billed price are read on OpenRouter's activity page. It is the implementer's smoke check, run once, and its output is not kept.

## Due diligence record

What the plan-diligence pass concluded about each external fact this plan cites or defers, as of 2026-10-15, for the implementation-phase fact check to read. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `https://openrouter.ai/api/v1` (verified against OpenRouter's quickstart)
- SETTLED: `extra_body={"reasoning": {"effort": ...}}`, efforts `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max` (verified against openrouter.ai/docs/use-cases/reasoning-tokens)
- SETTLED: `max_completion_tokens` honored with `max_tokens` semantics, reasoning counted in the cap (verified against openrouter.ai/docs/api-reference/parameters)
- SETTLED: `provider` object fields `order`, `allow_fallbacks` (default true), `require_parameters` (default false), and `order` with `allow_fallbacks: false` restricting to the listed hosts (verified against openrouter.ai/docs/features/provider-routing)
- SETTLED: `sail-research` and `deepinfra/fp4` are valid slugs, a base slug matches every variant and region endpoint of that host but not a priority-tier one (verified against the provider-routing doc and the z-ai/glm-5.3 endpoints listing, where `sail-research/us` and `sail-research/fp8` are non-tier)
- SETTLED: `z-ai/glm-5.3` exists, reasoning always on, efforts `low`, `high`, `max`, default `max` (verified against openrouter.ai/z-ai/glm-5.3/providers)
- SETTLED: Sail Research `Prices(input=0.15, cached_input=0.14, output=3.40)`, both endpoints fp8, both list `reasoning`, `response_format`, `structured_outputs` (verified against openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints)
- SETTLED: DeepInfra `deepinfra/fp4` listed at 0.5625 / 0.125 / 2.50 with `discount: 0.375`, fp4, lists `reasoning`, `response_format`, `structured_outputs` (verified against the same endpoints listing)
- OPEN (unverified): whether DeepInfra's listed 0.5625 / 2.50 is already net of the 0.375 discount, and how long the discount lasts. Every other discounted endpoint's listed price divides back to Z.AI's 1.40 / 4.40, which points to listed prices being net, but no doc says so
- SETTLED: Z.AI first-party at 1.40 / 4.40, about forty endpoints (43 listed) (verified against the endpoints listing)
- SETTLED: 403 with `error.metadata.error_type` `content_policy_violation` or `refusal`, `metadata.provider_name`, `provider_code`, `raw` (verified against openrouter.ai/docs/api/reference/errors-and-debugging)
- SETTLED: `finish_reason` normalized to `tool_calls`, `stop`, `length`, `content_filter`, `error`, raw value in `native_finish_reason` (verified against openrouter.ai/docs/api/reference/overview)
- SETTLED: a model's own refusal returns `message.refusal` with `finish_reason: "content_filter"` (verified against the errors doc)
- SETTLED: `usage.completion_tokens_details.reasoning_tokens` included in `completion_tokens`, `prompt_tokens_details.cached_tokens` present but optional (verified against the reasoning-tokens doc and the API overview)
- SETTLED: credit fee 5.5 % with a 0.80 dollar minimum by card, 5 % by crypto (verified against openrouter.ai/docs/faq)
- SETTLED: Z.AI error 1301, "potentially unsafe or sensitive content in input or generation" (verified against docs.z.ai/api-reference/api-code)
- OPEN (unverified): Z.AI's `finish_reason: "sensitive"`, not on the Z.AI error-code page
- OPEN (unverified): `moderationRequired` false for every GLM 5.3 host, the public endpoints listing carries no moderation field
- OPEN (unverified): the hosts' terms (Novita, AkashML, SiliconFlow, Baidu, Sail Research, DeepInfra zero retention), not re-fetched by this pass
- OPEN (deferred): the data-retention item of `probe_method.md`, with Sail Research's terms, the source URLs and the check date, gathered at implementation


## Implementation steps

Every step closes with the full check of `CLAUDE.md`: `uv run pytest -n auto` (all green), `uv run ruff check .` and `uv run ruff format --check .` (clean), `uv run pyright` with no file argument (0 errors). In the loop: `uv run pytest tests/unit -n auto --maxprocesses 4` and `uv run pyright <changed files>`.

### Step 1: a cut answer on the parse path is a truncated attempt

Committed on its own, before any OpenRouter work. Changes the system under test for `alibaba` only (no declared flip, no reset, see "A cut answer on the parse path").

- **Files**: `tests/unit/test_llm_adapter.py`, `src/mcp_auditor/adapters/llm.py`, `CHANGELOG.md`.
- **Do**:
  1. Tests first, in `TestTruncatedOutput` of `tests/unit/test_llm_adapter.py`. Build the SDK's real `openai.LengthFinishReasonError(completion=...)` on a real `openai.types.chat.ChatCompletion` (one choice, `finish_reason="length"`, a `CompletionUsage` with `prompt_tokens`, `completion_tokens`, `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens`), scripted into `FakeChatModel` as a raised exception (check `tests/fakes/chat_model.py` for how a scripted exception is given, as `Throttled` is). A small module-level builder `_cut_completion(usage: CompletionUsage | None)` is warranted, since three tests share it.
  2. In `llm.py`, catch `openai.LengthFinishReasonError` where `_invoke` already catches errors, and turn it into a truncated attempt (`parsed=None`, `truncated=True`, `refusal=None`) whose usage is read from `error.completion.usage`: `input_tokens = prompt_tokens`, `output_tokens = completion_tokens`, `cached_input_tokens = prompt_tokens_details.cached_tokens or 0`, `reasoning_tokens = completion_tokens_details.reasoning_tokens or 0` (each `details` object may be `None`), plus the attempt's throttle count, all tokens zero when `usage` is `None`. The loop of `generate_structured` stays the one place that counts attempts and truncations: the cleanest shape is for the per-attempt call to yield an `_Attempt` in both cases (normal response unpacked by `_unpack_raw_response`, cut built from the completion), so `generate_structured` stays unchanged in logic. The check of `refusal_from_error` stays before or beside it, unchanged. A helper `_completion_usage(usage: CompletionUsage | None, throttled_requests: int) -> ProviderUsage` beside `_to_provider_usage`. Keep functions under 20 lines, the file under 300 (about 196).
  3. `CHANGELOG.md`, `[Unreleased]`: a new `### Fixed` subsection (after `### Changed`, in the order the earlier releases use): an `alibaba` answer cut at the output cap is retried as a truncated attempt instead of failing the step.
  `evals/probe_method.md` needs no edit in this step: its cut-answer sentence already names Alibaba, and this step makes it true.
- **Test**:
  - A cut on every attempt (3 scripted errors, usages e.g. 100/50/20/10 each) raises `UnparseableOutput` with `truncated_attempts == 3` and `usage` the sum of the three (`input_tokens=300`, `output_tokens=150`, `cached_input_tokens=60`, `reasoning_tokens=30`).
  - A cut then a valid `raw_response(_DummyOutput(value="ok"), ...)` returns the output, usage the sum of both.
  - A cut whose completion has `usage=None`, on every attempt, raises `UnparseableOutput` with `truncated_attempts == 3` and zero tokens.
  - Each seen red before the change (today the error propagates).
- **Verify**: the full check above. Commit: `fix(llm): count a cut answer on the Chat Completions parse path as truncated`.

### Step 2: the openrouter provider and its host pinning

- **Files**: `tests/unit/test_config.py`, `tests/unit/test_chat_model_factory.py`, `src/mcp_auditor/config.py`, `src/mcp_auditor/adapters/chat_model_factory.py`, `src/mcp_auditor/adapters/llm.py`, `src/mcp_auditor/adapters/throttling.py`, `README.md`, `.env.example`, `CHANGELOG.md`.
- **Do**:
  1. Tests first (see "Test" below), in the existing files and style.
  2. `config.py`: `openrouter_hosts: str = ""` on `Settings` (read as `MCP_AUDITOR_OPENROUTER_HOSTS` through the existing prefix), `resolve_openrouter_hosts() -> tuple[str, ...]` (split on commas, strip, drop empty items), the `openrouter` entry of `_PROVIDERS` (default model `z-ai/glm-5.3`, default reasoning `low`, accepted `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`), `openrouter` in `_provider_defaults`'s error message (follow how the other entries are declared).
  3. `chat_model_factory.py`: the `openrouter` branch of `make_chat_model` passing `settings.resolve_openrouter_hosts()`, `_OPENROUTER_BASE_URL`, `_make_openrouter_model(model, reasoning, hosts)` as in "Factory", `_openrouter_body(reasoning, hosts) -> dict[str, Any]` returning `{"provider": {"require_parameters": True}}` plus `"order": list(hosts)` and `"allow_fallbacks": False` when hosts are set, plus `"reasoning": {"effort": reasoning}` when `reasoning` is not `None`. `openrouter` in the unknown-provider message. Newspaper order: the new private helpers right below `make_chat_model`'s other provider builders, in the order of the branch.
  4. `llm.py`: `"openrouter": StructuredOutput(method="json_schema", schema_as_dict=True)` in `_STRUCTURED_OUTPUT`, and the comment above it names OpenRouter beside OpenAI and Alibaba.
  5. `throttling.py`: the module docstring adds `openrouter` to the providers logging on `httpx2`.
  6. Living docs: `README.md` (`openrouter` in the `MCP_AUDITOR_PROVIDER` row, the OpenRouter vocabulary in the `MCP_AUDITOR_REASONING` row, new rows `MCP_AUDITOR_OPENROUTER_HOSTS` and `OPENROUTER_API_KEY`, the defaults paragraph and the Safety paragraph, as listed in "Files to modify"), `.env.example` (as listed), `CHANGELOG.md` `[Unreleased]` `### Added`: the `openrouter` provider and `MCP_AUDITOR_OPENROUTER_HOSTS`.
- **Test**:
  - Config (`test_config.py`): `test_unknown_provider_names_every_provider` gains `openrouter`. `Settings(provider="openrouter")` resolves `z-ai/glm-5.3` and `low`. `reasoning="high"` resolves `high`, an unknown level raises naming the accepted values. `resolve_openrouter_hosts` on `""` gives `()`, on `"sail-research"` gives `("sail-research",)`, on `" sail-research , ,deepinfra/fp4"` gives `("sail-research", "deepinfra/fp4")`. Pass `openrouter_hosts` explicitly so the operator's environment cannot leak in (follow how the file isolates other fields).
  - Factory (`test_chat_model_factory.py`): default `openrouter` settings build a `ChatOpenAI` with `model_name == "z-ai/glm-5.3"`, OpenRouter's base URL, `use_responses_api is False`, `max_tokens == 8192`, `request_timeout == 120`, `extra_body == {"provider": {"require_parameters": True}, "reasoning": {"effort": "low"}}`. With `openrouter_hosts="sail-research"`, `extra_body["provider"] == {"require_parameters": True, "order": ["sail-research"], "allow_fallbacks": False}`. A model override with reasoning unset sends no `reasoning` key. A missing and an empty `OPENROUTER_API_KEY` raise `ValueError` naming it. Public fields only, as the existing factory tests read them.
- **Verify**: the full check above. Commit: `feat(llm): add an openrouter provider with pinned hosts`.

### Step 3: host-level blocks as refusals, GLM 5.3 probe candidates, probe docs

- **Files**: `tests/unit/test_llm_refusals.py`, `src/mcp_auditor/adapters/llm_refusals.py`, `evals/probe_candidates.py`, `evals/run_probe.py`, `evals/probe_method.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md` (and `tests/unit/test_run_probe.py` only if a test pins `_candidate_entry`'s keys).
- **Do**:
  1. Tests first in `test_llm_refusals.py`, the errors built on an `httpx2.Response` as `_bad_request` does: a `_permission_denied(body)` builder for a 403 `openai.PermissionDeniedError`, and a builder for `openai.ContentFilterFinishReasonError(completion=<ChatCompletion>)` on a real `ChatCompletion` (one choice, `finish_reason="content_filter"`, `message.refusal` set or `None`), as `parse_chat_completion` raises it (`completion` is `ChatCompletion | None` on the SDK's class).
  2. `llm_refusals.py`, both recognized in `refusal_from_error` while walking `__cause__`:
     - Shape 1: `openai.PermissionDeniedError` whose `body` is a mapping with `metadata.error_type` in `{"content_policy_violation", "refusal"}`. Message: the body's `message`, followed by `(provider <provider_name>, code <provider_code>)` for whichever of the two is present. `_provider_message` widens to `openai.APIStatusError`.
     - Shape 2: `openai.ContentFilterFinishReasonError`. Message: the first choice's `message.refusal` when present, `"finish_reason content_filter"` otherwise (no completion, no choice, no refusal).
     - The module comment names the two shapes (OpenRouter's 403 metadata, the `content_filter` finish on the Chat Completions parse path, `alibaba` included). Functions under 20 lines, file about 140 lines.
  3. `evals/probe_candidates.py`: the two candidates of "Probe candidates", after the existing ones.
  4. `evals/run_probe.py`, `_candidate_entry`: `"openrouter_hosts": list(settings.resolve_openrouter_hosts()) if settings.provider == "openrouter" else []`, beside `provider`.
  5. `evals/probe_method.md`, every item listed under "Files to modify" (the cut-answer sentence now names OpenRouter, the 120-second timeout bullet, the price rows and the fee sentence, the reasoning-tokens sentence, the undercounted cost of a refused call, the billing check, the reasoning-check rows, the host-level block refusal shapes, the data-retention item for OpenRouter, Sail Research and DeepInfra with source URLs and the check date, gathered from the live pages at implementation, and `OPENROUTER_API_KEY` in "Running it").
  6. `CLAUDE.md`: the `run_probe` command line names `OPENROUTER_API_KEY` beside the three keys. `CONTRIBUTING.md`: as listed. `CHANGELOG.md` `[Unreleased]` `### Changed`: a host-level block and a `content_filter` finish are reported as provider refusals.
- **Test** (`test_llm_refusals.py`, through `LLM` with `FakeChatModel` as the file's other cases):
  - 403 with body `{"message": "blocked", "metadata": {"error_type": "content_policy_violation", "provider_name": "Sail Research", "provider_code": "1301"}}` raises `ProviderRefusal` whose message contains `blocked`, `Sail Research` and `1301`.
  - Same with `error_type: "refusal"` raises `ProviderRefusal`.
  - A 403 with no `metadata` propagates as `openai.PermissionDeniedError`.
  - A `ContentFilterFinishReasonError` with `refusal="I cannot help"` raises `ProviderRefusal` with that message, on the first attempt (the fake has one scripted response, no retry).
  - The same without `refusal` raises `ProviderRefusal` with `finish_reason content_filter`.
  - Probe: the existing tests over `CANDIDATES` run unchanged. If a test pins `_candidate_entry`'s keys, add `openrouter_hosts`.
- **Verify**: the full check above, then the smoke run with `OPENROUTER_API_KEY` only (a subset run needs only the named candidates' keys): `uv run python -m evals.run_probe --candidates "glm-5.3 low sail-research" "glm-5.3 low deepinfra-fp4" --schema AttackContext`. Expect calls to return (no "no endpoints found" error, else apply the `max_tokens` fallback of "Factory" and adjust the factory test), non-zero reasoning tokens in `output/probe_subset.jsonl` (else set `reasoning_expected=None` on both), and the billed price on OpenRouter's activity page matching `Prices` (else correct it). The smoke output is not kept. Commit: `feat(probe): add glm-5.3 through openrouter as probe candidates`.
