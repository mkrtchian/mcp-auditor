# ADR 019: Default Model Selection

**Date:** 2026-09-24
**Status:** Draft
**Supersedes:** ADR 005 (its default model, its fallbacks and its upgrade path)

## Context

The auditor calls one LLM in two roles: it generates the attack payloads, and it judges each response. ADR 005 chose Gemini 3.1 Flash-Lite in March 2026 on price, public benchmarks and a honeypot eval of three runs, where it parsed every call and Claude Haiku 4.5 lost one run to unparseable output. Since then, OpenAI has released `gpt-6-luna` at $0.10 per million input tokens and $0.50 per million output tokens, against $0.25 and $1.50 for Flash-Lite (list prices on 2026-09-24). GLM-5.3-Flash, an open-weight model, scores highest among the low-cost models on public benchmarks, which measured it at its highest reasoning setting. Fireworks serves it at $0.15 and $0.50.

The last honeypot measurement was under the precision threshold when this was written, so the gate was red. Price is the reason to look again, and that reason holds with every eval number deleted.

## Decision

**One model serves both roles.** The public benchmarks read for this decision do not score payload writing and response classification separately, so only this repository's own instruments could be used to pick one model per role. If the adopted model later refuses to write the payloads the auditor needs, both roles move together to another model through a new ADR.

**The OpenAI and Fireworks providers join Google and Anthropic**, whatever the outcome, so a user can select them.

**The default model is the one the procedure below selects**, and it is named here, with its setting and the reason for the choice, before this ADR is accepted.

## How the default is chosen

**The challengers are `gpt-6-luna` and GLM-5.3-Flash**, in settings that keep a call short. Luna runs at reasoning effort `none` and at `low`. GLM runs on Fireworks, which enforces the schema during decoding and keeps no data by default. Fireworks documents that an enforced schema disables the model's reasoning, so GLM runs without it. Without an enforced schema, the output keys would have to be stated in the prompt, and stating them for one candidate would change the system under test for that candidate alone. Gemini 3.1 Flash-Lite at thinking level `minimal`, set explicitly, is the reference they are measured against.

**A challenger is admitted if it clears bars written before it runs.** Every structured call parses within the retries the adapter allows. The generator stays under a refusal ceiling. Latency per call and cost per audit stay within a set multiple of the reference's, with challenger and reference measured in the same session. The provider does not train on API data at the tier used. The judge isolation eval keeps its F1 threshold of 0.90, and the honeypot suite keeps the floors of ADR 016. The definitions and the values are committed with a probe that measures them, before its first run. The reference is exempt: a bar it fails records a defect it already has, and does not trigger a switch.

**Admission is per setting, and a model is admitted when one of its settings is.** If no challenger is admitted, Flash-Lite stays, at the same setting as in the reference run. If one model is admitted, it becomes the default. When two models or two settings of one model are admitted, the choice is made on public benchmarks read again on the day of the choice, at the admitted setting when a benchmark reports it. The reason for the choice must hold with every probe and eval number deleted.

## Alternatives considered

**Rank the candidates on honeypot recall and precision.** Rejected. The suite only tells a collapsed model from a working one, and the prompts were tuned on the reference.

**A model per role.** Rejected. It squares the number of configurations to compare (four challenger settings become sixteen pairs), and a pair could only be chosen on the honeypot scores.

**The cheapest admitted model wins, with no reading of the benchmarks.** Rejected. The rule would move the default toward the weakest model that clears the bars, and lose detection quality that no instrument in this repository measures.

**Other models.** Claude Haiku 4.5 lists at $1 and $5 per million tokens, ten times the price of Luna. DeepSeek's privacy policy lists user input among the data used to train its models. Gemini 3.5 Flash-Lite costs more than the model it would replace. Mistral Small 4 and `gpt-oss-120b` score below the challengers on public benchmarks. Z.ai serves GLM-5.3-Flash about four times slower than Fireworks, at the same price.

## Consequences

- Anthropic stays a supported provider, with Haiku 4.5 as its default model. Haiku is no longer a designated fallback.
- The honeypot floors refuse only a collapsed model. The judge threshold is the one bar that can refuse a working model: with 8 FAIL cases among the 32, one misjudged case moves F1 by about 0.06, so the threshold admits one error and rejects two. The fixture was built from the reference's failures, and this decision accepts that bias toward the reference.
- If Gemini 3.1 Flash-Lite stops answering before the probe runs, the relative bars lose their reference, so the procedure is rewritten in this ADR before any challenger runs.
