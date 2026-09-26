# Model probe: method note

The probe (`uv run python -m evals.run_probe [--report PATH]`) replays a frozen corpus of prompts against the reference model and each candidate, and reports per model its statistics and its defects. They feed the written judgment an ADR takes when it chooses a model (ADR 021). The candidates, `gpt-6-luna` at `none` and at `low` and Gemini 3.5 Flash-Lite at `minimal`, and their prices are in `evals/probe_candidates.py`. The ADR 019 run is reported in ADR 019 and in `evals/probe_runs/2026-09-25_adr-019.json`. This note defines what the probe measures and what it reports.

## What the probe measures, and what it does not

It measures, per candidate, over the whole corpus: parse failures per schema, refusals, errors, the median latency per call in each role (generation calls and judge calls), the weighted corpus cost, and the reasoning tokens.

It does not measure detection quality. No verdict is compared with a label, and the corpus holds no label. Detection quality is measured by the judge isolation eval and the e2e evals, whose results also feed the judgment.

## The corpus

`evals/fixtures/probe_corpus.json`, written by `uv run python -m evals.capture_probe_corpus` and committed. It holds prompts only: no response, no verdict, no justification. It is recaptured when the generation prompt changes, and the committed corpus is the one the next probe run replays (ADR 021).

- **Capture run.** One audit of each of the three honeypots at budget 10, on the reference settings (provider `google`, `gemini-3.1-flash-lite`, reasoning `minimal`, for both roles). The capture refuses any other setting. Every structured call the audit makes is recorded, a generator retry on an incomplete batch included, since it is a call the reference made.
- **Judge sample.** 60 judge calls drawn uniformly with a fixed seed from the judge calls of the capture run, kept in capture order, never selected by verdict. The seed and the number of judge calls captured are recorded in the corpus. Every non-judge call is kept.
- **CVE tool definitions.** One generation prompt (budget 10, all categories) per distinct tool listed by the CVE fixture servers, deduplicated on the whole tool definition. Reading a tool definition is not reading a trace (ADR 015). These calls widen the generator inputs beyond the honeypots.

## The refusal rule

A `TestCaseBatch` call is a refusal when its output does not parse within the adapter's attempts, when the batch holds fewer cases than the corpus budget, or when it covers fewer distinct categories than `min(budget, 5)`. The rule is mechanical and reads no payload. A watered-down payload that keeps its category is **not** detected.

## What the probe reports

The defects, listed per model under the table and in the report, the reference's included:

- **Parse failures** after the adapter's 3 attempts, per schema (`TestCaseBatch`, `Judgment`, `AttackContext`, `ChainPlanBatch`, `StepObservation`, `AuditPayload`). A call the provider refuses on policy grounds is a parse failure too, with the provider's message in the observation's `error`, whether the refusal comes as the model's answer or as a 400 before the model (OpenAI's `invalid_prompt`, Alibaba's `DataInspectionFailed`). On a `TestCaseBatch` call it therefore counts as a refusal.
- **Refusals**, by the rule above.
- **Errors**: any exception other than a parse failure or a policy refusal, such as an API error, or an OpenAI, Fireworks or Alibaba call that exceeds its 120-second timeout on every retry. A model that did not answer every call was not measured on the whole corpus. **On an error, rerun the probe** rather than read it as a fact about the model.
- **Reasoning tokens at odds with the setting**: see below.

The numbers, per model: the weighted corpus cost and its ratio to the reference's, the median latency per call in each role, and the reasoning tokens. They are not judged against a threshold: each ADR that chooses a model states how it weighs them.

Training on API data at the tier used is a documented fact per provider (below), not computed.

## Cost

Per call, with list prices in dollars per million tokens:

```
((input - cached_input) * input_price + cached_input * cached_input_price + output * output_price) / 1e6
```

Output tokens include reasoning tokens: `langchain-google-genai` adds `thoughts_token_count` into `output_tokens`, and OpenAI bills reasoning tokens as output tokens, counted inside `output_tokens`.

The weighted corpus cost sums that cost over a candidate's calls, each judge call multiplied by `judge_calls_captured / judge calls in the corpus`. The corpus holds every non-judge call of the capture run but only 60 of its judge calls, so the weight restores the share of judging in an audit. The CVE generation calls keep weight 1: the weighted cost approximates the capture run's audits plus those extra generator calls.

Prices are the list prices of 2026-09-24 (`PRICES_DATE`), per million tokens (input, cached input, output):

| Candidate | Input | Cached input | Output |
|---|---|---|---|
| Gemini 3.1 Flash-Lite (reference) | 0.25 | 0.025 | 1.50 |
| `gpt-6-luna` | 0.10 | 0.01 | 0.50 |
| Gemini 3.5 Flash-Lite | 0.30 | 0.03 | 2.50 |

An OpenAI, Fireworks or Alibaba answer cut by the 8,192-token output cap counts as a parse failure, not as a parsed call: LangChain would otherwise repair the truncated JSON. A call that fails to parse costs the usage of all its attempts, truncated ones included, and counts as a parse failure anyway.

**Once, after the first run:** compare the cost the report computes for each provider with that provider's billing console over the run's time window. A gap means the token accounting or the prices are wrong, and the cost cannot be read until it is explained.

## Reasoning check per candidate

A reasoning-token count at odds with the setting is a defect: the setting did not reach the API, and the candidate was not measured as configured.

| Candidate | Setting | Expected reasoning tokens |
|---|---|---|
| Gemini 3.1 Flash-Lite (reference) | thinking level `minimal` | not checked: `minimal` does not switch thinking fully off |
| `gpt-6-luna none` | effort `none` | 0 |
| `gpt-6-luna low` | effort `low` | more than 0 |
| Gemini 3.5 Flash-Lite | thinking level `minimal` | not checked, as for the reference |

## Observations before the ADR 019 revision

Calls made on 2026-09-24 before ADR 019 revised its challenger list, kept here as the evidence its alternatives point to. They come from two probe runs stopped before the end and from informal calls on the corpus outside the probe.

- `gpt-6-luna` at `none` and `low`: when it writes a resource-abuse case whose argument is a long string, it repeats one character in that argument without stopping, over a million characters in 950 seconds on one call, with only its 128,000-token output limit to end it. It did not loop at `medium` on four calls of the same prompt.
- GLM-5.3-Flash is thinking-only: Fireworks refuses `reasoning_effort="none"`. With no effort set, it billed about ten thousand output tokens per batch, against about 700 for the reference, although Fireworks documents that an enforced schema "disables reasoning output". At `low`, it returned batches with a category or cases missing.
- DeepSeek V4 Flash and `gpt-5.4-nano` with reasoning off returned incomplete batches. So did `gpt-oss-120b` at `low`, its lowest setting, since it cannot turn its reasoning off.
- Each provider receives the output schema through its structured output mode. Fireworks enforces it during decoding. OpenAI receives it without strict mode, which refuses the open `arguments` object of a payload.
- The output cap the adapter sets on OpenAI and Fireworks calls counts reasoning tokens, so a challenger that reasons can be cut by it. The cap is set to bound a loop without cutting a batch at `medium`: 8,192 tokens, where one GLM batch at `medium` used about 3,000.

## Data retention per provider

- **Gemini API, paid tier**: "Google doesn't use your prompts (...) or responses to improve our products". Source: Gemini API Additional Terms of Service, https://ai.google.dev/gemini-api/terms.
- **OpenAI API**: "data sent to the OpenAI API is not used to train or improve OpenAI models (unless you explicitly opt in to share data with us)". Abuse monitoring logs are retained up to 30 days by default. Source: https://developers.openai.com/api/docs/guides/your-data.
- **Alibaba Cloud Model Studio**: "Alibaba Cloud strictly protects your data privacy and will never use your data for model training." No retention period is stated. Source: https://www.alibabacloud.com/help/en/model-studio/privacy-notice.
- **Fireworks serverless**: "Fireworks does not log or store prompt or generation data for any open models, without explicit user opt-in." Source: https://docs.fireworks.ai/guides/security_compliance/data_handling.

Checked on 2026-09-24, Alibaba on 2026-09-25.

## Order of calls

The calls run in corpus order, one at a time. On each call every candidate answers in turn, sequentially, and the first candidate rotates with the call index (`call_index % number of candidates`), so no candidate always runs first after a pause. Each call is timed with `time.perf_counter` around `generate_structured`, the production adapter built by `create_llm` (generation role) and `create_judge_llm` (judge role). Temperature is each provider's default, recorded as such in the report.

## Running it

Set the API key of every candidate before running: `GOOGLE_API_KEY` and `OPENAI_API_KEY`. A candidate whose models cannot be built stops the probe before any call. A key rejected only at the first call shows as an error on every call of that candidate.

The report goes to `output/probe_report.json` by default: the observations, the statistics and the defects of every measured model. The command exits 0 whatever it finds. Each observation is also appended to `output/probe_report.jsonl` as soon as it is measured, with one progress line per call on the console, so a run stopped by hand keeps what it measured. There is no resume: a stopped run is rerun from the start.

## Subset runs

`--candidates NAME [NAME ...]` and `--schema NAME` replay a slice of the corpus: the named candidates (every candidate of the full run when the flag is absent) on the calls of one schema, in corpus order (every call when the flag is absent). Either flag makes the run a subset run. It serves debugging only: it computes no statistics and writes no JSON report, and prints one row of defects per candidate. Its observations go to `output/probe_subset.jsonl` by default, so a debugging run never empties the full run's sink. Only the named candidates' models are built, so it needs their keys only.

A subset run names its candidates among the reference and the candidates.

A *parse failure with truncation* is a parse failure where at least one attempt was cut by the output cap.

## Limits

- **Watered-down payloads** are not detected (see the refusal rule).
- **Retries on HTTP 429** happen inside the provider clients (`max_retries=3`) and count in the latency.
- **Same-session load** (network, provider load) affects all candidates alike only as far as the rotation spreads it.
- **Median, not p95.** A p95 over about 60 judge calls rests on its third-largest value, so the median is the statistic.
- **A loop that a retry recovers from is not counted as a parse failure.** When an answer is cut at the output cap, the adapter retries it, and a retry that parses makes the call a parsed one, with `truncated_attempts` left at 0. The cut attempt shows only in the call's cost and latency.
- **Errors carry no cost.** An exception raised inside the provider client carries no token usage, so an error counts 0. A model answer holding an integer past the 4,300 digits Python converts is one: its tokens were billed but are not counted.
