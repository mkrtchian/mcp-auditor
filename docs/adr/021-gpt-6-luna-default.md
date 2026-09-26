# ADR 021: gpt-6-luna at Reasoning Effort `none` as the Default Model

**Date:** 2026-09-25
**Status:** Accepted
**Supersedes:** in ADR 019, the default model, the default setting of the `openai` provider, the list of challengers, and its section *How the default is chosen*: the admission bars and the rule that admits a model on them.

## Context

The probe run reported in ADR 019 measured `gpt-6-luna` at reasoning effort `medium` only. At `none` and `low`, earlier calls, in two probe runs stopped partway and in informal calls outside the probe, looped: when writing a resource-abuse case, the model repeated one character in a string argument up to its 128,000-token output limit.

The loops came from the generation prompt, which asked for "extremely large" values and set no bound on the size of a literal. Two changes to it followed, each justified on product grounds, independently of any measurement. The first (`19e4349`) asks for integers of at most 10 digits and strings under 1,000 characters, since a 10-digit integer already exceeds any limit a tool plausibly sets. The second (`8fd8294`) asks that any string longer than a few dozen characters be composed of varied text, since a run of one repeated character tests nothing that varied text of the same length does not. Both were written while reading the output of `gpt-6-luna` on debugging runs of the generation calls. After the second change, `gpt-6-luna` at `none` and at `low` answered each of the 55 generation calls of the corpus recaptured after that change with a complete batch that parsed.

Price is the reason to look again. `gpt-6-luna` lists at $0.10 per million input tokens and $0.50 per million output tokens, against $0.30 and $2.50 for the current default, Gemini 3.5 Flash-Lite.

## Decision

**The default model is `gpt-6-luna` at reasoning effort `none`, for both roles.** The default provider moves from `google` to `openai`, and the default setting of the `openai` provider moves from `medium` to `none`.

**The generator completes the categories a batch misses.** When a generated batch still lacks a category after its retry, the auditor asks for the missing categories alone, instead of reporting the gap and auditing the tool without them. The need holds for any model: on 2026-09-25, Gemini 3.5 Flash-Lite left a batch of `list_items` without `error_handling` after the retry, and that audit ran without the category.

**A model is chosen on a written judgment, not on admission bars.** The probe keeps recording what a candidate does on the corpus: loops, answers that do not parse, errors, incomplete batches, cost and latency. Those facts and the evals feed the decision, and the ADR that takes it states the reasons for the choice, what weighs against it, and what would reverse it.

## Why `gpt-6-luna` at `none`

**The price.** Replaying the corpus cost 0.38 times the reference, Gemini 3.1 Flash-Lite, and about a quarter of Gemini 3.5 Flash-Lite, computed from list prices.

**The probe found no defect that stops an audit.** On 2026-09-25 it ran on the corpus captured at `8fd8294` (report in `evals/probe_runs/2026-09-25_adr-021.json`). At `none`, no answer failed to parse, no call raised an error, and every loop that reached the output cap was recovered by a retry. The one defect is 2 generated batches out of 55 that came back without the `resource_abuse` category, and the completion above covers that case.

**The evals do not show a weaker model.** The judge isolation eval gave an F1 of 0.93, where Gemini 3.5 Flash-Lite had 0.94. On the honeypot suite, 3 runs at budget 10 on the same commit, recall was 0.50 against 0.67 for Gemini 3.5 Flash-Lite, and precision 1.00 for both. Most of that gap is one cell, `execute_query` for `injection`, which Gemini reported in all 3 runs and `gpt-6-luna` in none. `gpt-6-luna` reads a tool built to run SQL as doing its job when it runs the injected query, and that reading can be defended for such a tool. On the same day, Gemini 3.5 Flash-Lite scored 0.83, 0.79 and 0.67 on the suite, across the two changes to the prompt.

**`none` rather than `low`.** Both settings behaved alike on the probe and the evals. `none` bills no reasoning tokens, and its median generation call took 4.9 seconds against 8.2 at `low`.

## What weighs against it

The injection payloads of `gpt-6-luna` return a marker, where those of Gemini read the database schema. Proving impact by reading is what ADR 014 asks for, and Gemini follows that preference more closely.

The instruments of this repository tell a working model from a collapsed one, but they cannot rank two working models (ADR 019). A lower detection rate for `gpt-6-luna` would go unseen.

## What would reverse it

- The billing consoles show a cost that is not clearly lower than Gemini 3.5 Flash-Lite.
- Audits keep reporting missing categories once the completion is built.
- The CVE benchmark, run with both models on the same targets, shows `gpt-6-luna` detecting fewer flaws.
- A later probe run shows loops or answers that do not parse again.

## Alternatives considered

**Qwen3.8-Flash or GLM-5.3-Flash as the default.** Rejected. Alibaba's input moderation blocked 12 calls to Qwen3.8-Flash from the attack chains, whose content an audit has to send whatever the wording of the generation prompt. GLM-5.3-Flash returned 9 generated batches with cases or a category missing in the probe of ADR 019.

**Keeping Gemini 3.5 Flash-Lite as the default and changing only the default setting of the `openai` provider.** Rejected. An audit runs on the default unless its user sets a provider, so the saving would reach only the users who do.

## Consequences

An audit run with no configuration needs `OPENAI_API_KEY` instead of `GOOGLE_API_KEY`. A configuration that names a Gemini model or the `minimal` setting without `MCP_AUDITOR_PROVIDER=google` then fails.

The probe's method note loses its admission verdict. Its bars become the list of defects the probe reports.

The knowledge cutoff of `gpt-6-luna`, 2026-05-18, falls after the advisories of the CVE benchmark, published between 2025-07-02 and 2025-12-17. The cutoff of Gemini 3.5 Flash-Lite, March 2026, also falls after them. With either default, a detection on that benchmark can come from what the model has read about the flaw.
