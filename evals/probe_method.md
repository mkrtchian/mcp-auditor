# Admission probe: method note

The probe (`uv run python -m evals.run_probe [--report PATH]`) replays a frozen corpus of prompts against the reference model and each challenger of ADR 019, and prints an admission verdict per challenger. This note defines what it measures and holds the bar values. The values were written down before the first probe run, and they are also the defaults of `Bars` in `evals/probe.py`. The candidates and their prices are in `evals/probe_candidates.py`.

## What the probe measures, and what it does not

It measures, per candidate, over the whole corpus: parse failures per schema, refusals, errors, the median latency per call in each role (generation calls and judge calls), the weighted corpus cost, and the reasoning tokens.

It does not measure detection quality. No verdict is compared with a label, and the corpus holds no label. Detection quality is measured afterwards by the judge isolation eval and the e2e evals, for an admitted challenger only (steps 2 and 3 of ADR 019).

## The corpus

`evals/fixtures/probe_corpus.json`, written by `uv run python -m evals.capture_probe_corpus` and committed. It holds prompts only: no response, no verdict, no justification.

- **Capture run.** One audit of each of the three honeypots at budget 10, on the reference settings (provider `google`, `gemini-3.1-flash-lite`, reasoning `minimal`, for both roles). The capture refuses any other setting. Every structured call the audit makes is recorded, a generator retry on an incomplete batch included, since it is a call the reference made.
- **Judge sample.** 60 judge calls drawn uniformly with a fixed seed from the judge calls of the capture run, kept in capture order, never selected by verdict. The seed and the number of judge calls captured are recorded in the corpus. Every non-judge call is kept.
- **CVE tool definitions.** One generation prompt (budget 10, all categories) per distinct tool listed by the CVE fixture servers, deduplicated on the whole tool definition. Reading a tool definition is not reading a trace (ADR 015). These calls widen the generator inputs beyond the honeypots.

## The refusal rule

A `TestCaseBatch` call is a refusal when its output does not parse within the adapter's attempts, when the batch holds fewer cases than the corpus budget, or when it covers fewer distinct categories than `min(budget, 5)`. The rule is mechanical and reads no payload. A watered-down payload that keeps its category is **not** detected.

## Bars written before measurement

A challenger is admitted when it clears every bar:

- **Parse failures** after the adapter's 3 attempts: 0, on each of the six schemas (`TestCaseBatch`, `Judgment`, `AttackContext`, `ChainPlanBatch`, `StepObservation`, `AuditPayload`).
- **Refusals**: 0.
- **Errors** (any exception other than a parse failure: API error, or an OpenAI or Fireworks call that exceeds its 120-second timeout on every retry): 0. A candidate that did not answer every call was not measured on the whole corpus. **On an error, rerun the probe** rather than read it as a verdict on the model.
- **Median latency per call, per role**: at most 3 times the reference's median measured in the same probe run. Equal to 3 times passes.
- **Weighted corpus cost**: at most the reference's (ratio 1.0). Equal passes.
- **Reasoning tokens consistent with the setting**: see below.
- **No training on API data** at the tier used. A documented fact per provider (below), not computed.

The reference is exempt from every bar (ADR 019). The bars it would fail are printed and written to the report as recorded only, and they trigger nothing.

The judge isolation F1 threshold (0.90) and the honeypot floors (0.50) are the existing ones, applied afterwards in steps 2 and 3 of ADR 019.

## Cost

Per call, with list prices in dollars per million tokens:

```
((input - cached_input) * input_price + cached_input * cached_input_price + output * output_price) / 1e6
```

Output tokens include reasoning tokens: `langchain-google-genai` adds `thoughts_token_count` into `output_tokens`, and OpenAI bills reasoning tokens as output tokens, counted inside `output_tokens`. Fireworks does not document it.

The weighted corpus cost sums that cost over a candidate's calls, each judge call multiplied by `judge_calls_captured / judge calls in the corpus`. The corpus holds every non-judge call of the capture run but only 60 of its judge calls, so the weight restores the share of judging in an audit. The CVE generation calls keep weight 1: the weighted cost approximates the capture run's audits plus those extra generator calls.

Prices are the list prices of 2026-09-24 (`PRICES_DATE`), per million tokens (input, cached input, output):

| Candidate | Input | Cached input | Output |
|---|---|---|---|
| Gemini 3.1 Flash-Lite | 0.25 | 0.025 | 1.50 |
| `gpt-6-luna` | 0.10 | 0.01 | 0.50 |
| GLM-5.3-Flash on Fireworks serverless | 0.15 | 0.03 | 0.50 |

A call that fails to parse raises without its token usage, so its cost counts as 0. It fails the parse bar anyway.

**Once, after the first run:** compare the cost the report computes for each provider with that provider's billing console over the run's time window. A gap means the token accounting or the prices are wrong, and the cost bar cannot be read until it is explained.

## Reasoning check per candidate

The check catches a setting that did not reach the API: the candidate would then not have been measured as configured.

| Candidate | Setting | Expected reasoning tokens |
|---|---|---|
| Gemini 3.1 Flash-Lite (reference) | thinking level `minimal` | not checked: `minimal` does not switch thinking fully off |
| `gpt-6-luna` | effort `none` | 0 |
| `gpt-6-luna` | effort `low` | more than 0 |
| GLM-5.3-Flash | schema enforced, no reasoning parameter | not checked |

GLM is not checked because `langchain-fireworks` does not report reasoning tokens (it never fills `output_token_details.reasoning`), and the enforced schema disables reasoning anyway.

## Data retention per provider

- **Gemini API, paid tier**: "Google doesn't use your prompts (...) or responses to improve our products". Source: Gemini API Additional Terms of Service, https://ai.google.dev/gemini-api/terms.
- **OpenAI API**: "data sent to the OpenAI API is not used to train or improve OpenAI models (unless you explicitly opt in to share data with us)". Abuse monitoring logs are retained up to 30 days by default. Source: https://developers.openai.com/api/docs/guides/your-data.
- **Fireworks serverless**: "Fireworks does not log or store prompt or generation data for any open models, without explicit user opt-in." Source: https://docs.fireworks.ai/guides/security_compliance/data_handling.

Checked on 2026-09-24.

## Order of calls

The calls run in corpus order, one at a time. On each call every candidate answers in turn, sequentially, and the first candidate rotates with the call index (`call_index % number of candidates`), so no candidate always runs first after a pause. Each call is timed with `time.perf_counter` around `generate_structured`, the production adapter built by `create_llm` (generation role) and `create_judge_llm` (judge role). Temperature is each provider's default, recorded as such in the report.

## Running it

Set the API key of every candidate before running: `GOOGLE_API_KEY`, `OPENAI_API_KEY` and `FIREWORKS_API_KEY`. A candidate whose models cannot be built stops the probe before any call. A key rejected only at the first call shows as an error on every call of that candidate.

The report goes to `output/probe_report.json` by default: the observations, the statistics, the admissions and the reference's failed bars. The command exits 0 whatever the verdict. Each observation is also appended to `output/probe_report.jsonl` as soon as it is measured, with one progress line per call on the console, so a run stopped by hand keeps what it measured. There is no resume: a stopped run is rerun from the start.

## Limits

- **Watered-down payloads** are not detected (see the refusal rule).
- **Retries on HTTP 429** happen inside the provider clients (`max_retries=3`) and count in the latency.
- **Same-session load** (network, provider load) affects all candidates alike only as far as the rotation spreads it.
- **Median, not p95.** A p95 over about 60 judge calls rests on its third-largest value, so the median is the statistic.
- **Parse failures carry no cost** (see Cost).
