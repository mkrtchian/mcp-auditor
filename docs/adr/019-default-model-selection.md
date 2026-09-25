# ADR 019: Default Model Selection

**Date:** 2026-09-24
**Status:** Accepted
**Supersedes:** ADR 005 (its default model, its fallbacks and its upgrade path)

## Context

The auditor calls one LLM in two roles: it generates the attack payloads, and it judges each response. Since ADR 005 chose Gemini 3.1 Flash-Lite in March 2026, cheaper models have appeared: OpenAI's `gpt-6-luna` lists at $0.10 per million input tokens and $0.50 per million output tokens, against $0.25 and $1.50 for Flash-Lite, and GLM-5.3-Flash (Fireworks) and Qwen3.8-Flash (Alibaba Cloud Model Studio) list at about $0.15 and $0.50 (list prices on 2026-09-24). Google has also scheduled the shutdown of Gemini 3.1 Flash-Lite for 2027-05-07, and names Gemini 3.5 Flash-Lite as its replacement (deprecations page, read on 2026-09-24).

Price is the reason to look again, and that reason holds with every eval number deleted.

## Decision

**One model serves both roles.** The public benchmarks read for this decision do not score payload writing and response classification separately, and this repository's own instruments cannot rank two working models on quality yet, let alone on each role apart.

**The OpenAI, Fireworks and Alibaba Cloud Model Studio providers join Google and Anthropic**, whatever the outcome, so a user can select them. Each new provider's default model is its challenger, at the setting measured below.

**The default model is Gemini 3.5 Flash-Lite at thinking level `minimal`.** None of the challengers cleared the admission bars set below, so the rule for that case applies and the default moves to the successor Google names.

## How the default is chosen

**The challengers are Qwen3.8-Flash with thinking off, GLM-5.3-Flash at reasoning effort `medium`, and `gpt-6-luna` at reasoning effort `medium`.** They are what remained after informal calls on the probe's corpus. On those calls, the lower settings of these models and other cheap models looped, returned incomplete batches or could not be set at all (see *Alternatives considered* and the observations in the probe's method note). Gemini 3.1 Flash-Lite at thinking level `minimal`, set explicitly, is the reference they are measured against, because it is the model the prompts were written for and the one an audit runs today. Gemini 3.5 Flash-Lite at `minimal` runs in the same session and is recorded, not admitted or refused. A bar it fails is recorded as a defect of the fallback and does not stop the move to it.

**A challenger is admitted if it clears bars written before the run that decides admission.** The cost of replaying the probe's corpus stays at or under the reference's, measured in the same session. The judge isolation eval keeps its F1 threshold of 0.90, and the honeypot suite keeps the floors of ADR 016. The definitions and the values live in the probe's method note, committed before that run. The reference is exempt: a bar it fails records a defect it already has, and does not trigger a switch.

**Latency is recorded against its bar, and it does not refuse a challenger on its own.** The bar is the one written before any measurement, a median per call and per role at most 3 times the reference's. Latency is the one property the auditor can reduce itself, by running independent calls in parallel, while parsing, refusals and cost belong to the model. A challenger that clears every other bar and fails only this one is decided case by case, in this ADR, with the reason written down. That verdict is exploratory under ADR 016, since the latencies of the candidates were known when this rule was written.

**If no challenger is admitted, the default moves to Gemini 3.5 Flash-Lite at thinking level `minimal`**, the successor Google names. That move is forced by the shutdown date, not chosen, so no bar applies to it. If one model is admitted, it becomes the default. When more than one is admitted, the choice is made on public benchmarks read again on the day of the choice, at the admitted setting when a benchmark reports it. The reason for the choice must hold with every probe and eval number deleted.

**What was known before the challengers and the latency rule were revised.** On 2026-09-24, two runs of the probe on the first challenger list (`gpt-6-luna` at `none` and `low`, GLM-5.3-Flash with no effort set) were stopped before the end, and the observations of the second were read. Informal calls on the probe's corpus followed, outside the probe. On generation calls, Qwen3.8-Flash and GLM-5.3-Flash at `medium` took about four times the reference's time, and `gpt-6-luna` at `medium` about seven times on four calls. The revision was written with that knowledge.

## Outcome

On 2026-09-25 the probe ran to the end on the committed corpus, with the three challengers, the reference and the fallback in the same session. None of the challengers was admitted. Each one failed at least one bar other than latency, so the case-by-case rule on latency was never reached.

- **Qwen3.8-Flash, thinking off.** Alibaba Cloud Model Studio rejected 12 calls before they reached the model, with `DataInspectionFailed: Input text data may contain inappropriate content`. All 12 came from the attack chains: 9 step payloads, a step observation, a chain plan and a chain verdict. The rejection comes from the provider's input moderation. All 12 were rejected again when the same calls were replayed after the run, the same day. Another 6 generated batches stopped at the 8,192-token output cap, while Qwen's complete batches used at most 2,779 tokens. The probe filed all 18 under its error bar, which allows none, because in `json_schema` mode the OpenAI SDK raises on a truncated answer before the adapter can count it as unparsed.
- **GLM-5.3-Flash at `medium`.** 9 generated batches missed cases or a category, which the probe counts as refusals. Replaying the corpus cost 1.10 times the reference, above the cost bar.
- **`gpt-6-luna` at `medium`.** 7 generated batches did not parse after the adapter's three attempts, which fails the parse bar. Reasoning tokens count against the output cap, but the probe does not record whether those attempts hit it. Two more calls failed because the model returned an integer of about 20,000 digits, over the limit Python sets on converting a string to an integer.

No bar applies to the fallback. It answered every call and returned no incomplete batch, but it would fail the cost bar at 1.65 times the reference. The cost ratios are not yet reconciled with the providers' billing consoles, a check the probe's method note calls for after the first run.

## Alternatives considered

**Rank the candidates on honeypot recall and precision.** Rejected. The suite only tells a collapsed model from a working one, and the prompts were tuned on the reference.

**A model per role.** Rejected. It squares the number of configurations to compare, and a pair could only be chosen on the honeypot scores.

**The cheapest admitted model wins, with no reading of the benchmarks.** Rejected. The rule would move the default toward the weakest model that clears the bars, and lose detection quality that no instrument in this repository measures.

**Keep Gemini 3.1 Flash-Lite when no challenger is admitted.** Rejected. Its shutdown on 2027-05-07 would force another ADR.

**Gemini 3.5 Flash-Lite as a challenger.** Rejected. It lists at $0.30 and $2.50, above the reference on every price, so it would fail the cost bar unless it used fewer tokens.

**The lower settings of the challengers.** Rejected on the calls made before the revision, whose observations are kept in the probe's method note. GLM-5.3-Flash is a thinking-only model, and Fireworks refuses to turn its reasoning off. At `low`, it returned batches with a category or cases missing.

**Other models.** Claude Haiku 4.5 lists at $1 and $5 per million tokens, about four and three times the reference. Mistral Small 4 scores below the challengers on public benchmarks. OpenRouter and Novita list Qwen3.8-Flash with Alibaba as their upstream, so another host would add a hop without serving another copy, and Fireworks does not offer it on its serverless tier.

## Consequences

- Alibaba Cloud Model Studio's input moderation rejects calls from the attack chains before they reach the model, so the rejection applies to any model the platform serves, not to Qwen3.8-Flash alone. Qwen3.8-Flash stays selectable through the `alibaba` provider despite that limit.
- Anthropic stays a supported provider, with Haiku 4.5 as its default model. Haiku is no longer a designated fallback.
- The judge eval runs once, so a challenger as good as the reference can be refused by one error on that draw. The judge prompt was tuned against its fixture on the reference, and this decision accepts that bias toward the reference.
- The public scores of Qwen3.8-Flash and GLM-5.3-Flash were measured with reasoning on. Neither is published at the setting run here, so a comparison that involves either of them rests on scores that do not match the setting.
- ADR 016's procedure for a model change applies. While Gemini 3.1 Flash-Lite is still served, the evals run on both models and the delta between them is recorded. No baseline exists for either model yet, so every eval figure for the new default stays exploratory until a second recording agrees with the first.
- The new default runs on prompts tuned on its predecessor.
