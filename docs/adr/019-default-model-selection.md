# ADR 019: Default Model Selection

**Date:** 2026-09-24
**Status:** Draft
**Supersedes:** ADR 005 (its default model, its fallbacks and its upgrade path)

## Context

The auditor calls one LLM in two roles: it generates the attack payloads, and it judges each response. ADR 005 chose Gemini 3.1 Flash-Lite in March 2026 on price, public benchmarks and a honeypot eval of three runs, where it parsed every call and Claude Haiku 4.5 lost one run to unparseable output. Since then, cheaper models have appeared: OpenAI's `gpt-6-luna` lists at $0.10 per million input tokens and $0.50 per million output tokens, against $0.25 and $1.50 for Flash-Lite, and GLM-5.3-Flash (Fireworks) and Qwen3.8-Flash (Alibaba Cloud Model Studio) list at about $0.15 and $0.50 (list prices on 2026-09-24). Google has also scheduled the shutdown of Gemini 3.1 Flash-Lite for 2027-05-07, and names Gemini 3.5 Flash-Lite as its replacement (deprecations page, read on 2026-09-24).

The last honeypot measurement was under the precision threshold when this was written, so the gate was red. Price is the reason to look again, and that reason holds with every eval number deleted.

## Decision

**One model serves both roles.** The public benchmarks read for this decision do not score payload writing and response classification separately, so only this repository's own instruments could be used to pick one model per role. If the adopted model later refuses to write the payloads the auditor needs, both roles move together to another model through a new ADR.

**The OpenAI, Fireworks and Alibaba Cloud Model Studio providers join Google and Anthropic**, whatever the outcome, so a user can select them. Each runs its default model at the setting its challenger is measured at below.

**The default model is the one the procedure below selects**, and it is named here, with its setting and the reason for the choice, before this ADR is accepted.

## How the default is chosen

**The challengers are Qwen3.8-Flash with thinking off, GLM-5.3-Flash at reasoning effort `medium`, and `gpt-6-luna` at reasoning effort `medium`.** Each runs with the schema enforced by the provider. Gemini 3.1 Flash-Lite at thinking level `minimal`, set explicitly, is the reference they are measured against. Gemini 3.5 Flash-Lite at `minimal` runs in the same session and is recorded, not admitted or refused: it is the fallback below.

**A challenger is admitted if it clears bars written before it runs.** Every structured call parses within the retries the adapter allows. The generator stays under a refusal ceiling. The time to replay the whole corpus and the cost of that replay stay within a set multiple of the reference's, with challenger and reference measured in the same session. The provider does not train on API data at the tier used. The judge isolation eval keeps its F1 threshold of 0.90, and the honeypot suite keeps the floors of ADR 016. The definitions and the values are committed with a probe that measures them, before its first run. The reference is exempt: a bar it fails records a defect it already has, and does not trigger a switch.

**The time bar is on the whole corpus, not on each call.** What a user waits for is an audit, and an audit makes one generation call per tool against about ten judgments. A median per call and per role would refuse a model whose slow generation costs the audit a few seconds while its judgments keep pace.

**Admission is per setting, and a model is admitted when one of its settings is.** If no challenger is admitted, the default moves to Gemini 3.5 Flash-Lite at thinking level `minimal`, the successor Google names. That move is forced by the shutdown date, not chosen, so it clears no bar. If one model is admitted, it becomes the default. When two are admitted, the choice is made on public benchmarks read again on the day of the choice, at the admitted setting when a benchmark reports it. The reason for the choice must hold with every probe and eval number deleted.

**What was known before the probe ran.** The challenger list and the time bar were revised after informal calls on the probe's corpus, outside the probe, on 2026-09-24. Those calls showed the latency of every candidate below, and the revision is written with that knowledge. The bars keep the multiple of 3 they had before those calls.

## Alternatives considered

**Rank the candidates on honeypot recall and precision.** Rejected. The suite only tells a collapsed model from a working one, and the prompts were tuned on the reference.

**A model per role.** Rejected. It squares the number of configurations to compare, and a pair could only be chosen on the honeypot scores.

**The cheapest admitted model wins, with no reading of the benchmarks.** Rejected. The rule would move the default toward the weakest model that clears the bars, and lose detection quality that no instrument in this repository measures.

**Keep the median latency per call and raise its multiple to 4 or 5.** Rejected. The latencies of the candidates were already known, so the multiple would have been chosen to admit them.

**Keep Gemini 3.1 Flash-Lite when no challenger is admitted.** Rejected. Its shutdown date would force another ADR within months.

**Gemini 3.5 Flash-Lite as a challenger.** Rejected. It lists at $0.30 and $2.50, above the reference, so it would fail the cost bar by construction. It is the fallback instead.

**The lower settings of the challengers.** Rejected on calls observed before the probe. `gpt-6-luna` at `none` and `low` loops on a payload that asks for a very long string, writing the same character until its 128,000-token output limit. GLM-5.3-Flash is a thinking-only model: Fireworks refuses to turn its reasoning off, it reasons for about ten thousand tokens per batch when no effort is set, and at `low` it returns batches with a category or cases missing. An enforced schema does not stop reasoning on Fireworks, despite its documentation.

**Other models.** DeepSeek V4 Flash, `gpt-5.4-nano` and `gpt-oss-120b` returned incomplete batches on the same calls, and `gpt-oss-120b` cannot turn its reasoning off. Claude Haiku 4.5 lists at $1 and $5 per million tokens. Mistral Small 4 scores below the challengers on public benchmarks. Qwen3.8-Flash on other hosts is relayed to Alibaba, and Fireworks does not serve it serverless.

## Consequences

- Anthropic stays a supported provider, with Haiku 4.5 as its default model. Haiku is no longer a designated fallback.
- The honeypot floors refuse only a collapsed model. The judge threshold is the one bar that can refuse a working model: with 8 FAIL cases among the 32, one misjudged case moves F1 by about 0.06, so the threshold admits one error and rejects two. The fixture was built from the reference's failures, and this decision accepts that bias toward the reference.
- The public scores of Qwen3.8-Flash and GLM-5.3-Flash were measured with their reasoning at its highest. Neither is published at the setting run here, so the comparison between two admitted models rests on scores that do not match the setting.
- The adapter's output cap counts reasoning tokens on some providers, so a challenger that reasons can be cut by it. The cap is set so that it bounds a loop without cutting a batch at `medium`.
- If the fallback applies, the default becomes a model that no instrument in this repository has measured, on prompts tuned for its predecessor. Its first honeypot run is exploratory, and the baseline follows ADR 016's procedure for a model change.
- If Gemini 3.1 Flash-Lite stops answering before the probe runs, the relative bars lose their reference, so the procedure is rewritten in this ADR before any challenger runs.
