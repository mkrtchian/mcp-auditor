# ADR 021: gpt-6-luna at Reasoning Effort `none` as the Default Model

**Date:** 2026-09-25
**Status:** Proposed
**Supersedes:** in ADR 019, the default model, the default setting of the `openai` provider and the list of challengers.

## Context

The probe run reported in ADR 019 measured `gpt-6-luna` at reasoning effort `medium` only. At `none` and `low`, earlier calls, in two probe runs stopped partway and in informal calls outside the probe, looped: when writing a resource-abuse case, the model repeated one character in a string argument up to its 128,000-token output limit.

The loops came from the generation prompt, which asked for "extremely large" values and set no bound on the size of a literal. Two changes to it followed, each justified on product grounds, independently of any measurement. The first (`19e4349`) asks for integers of at most 10 digits and strings under 1,000 characters, since a 10-digit integer already exceeds any limit a tool plausibly sets. The second (`8fd8294`) asks that any string longer than a few dozen characters be composed of varied text, since a run of one repeated character tests nothing that varied text of the same length does not. Both were written while reading the output of `gpt-6-luna` on debugging runs of the generation calls. After the second change, `gpt-6-luna` at `none` and at `low` answered each of the 55 generation calls of the corpus recaptured after that change with a complete batch that parsed.

Price is the reason to look again. `gpt-6-luna` lists at $0.10 per million input tokens and $0.50 per million output tokens, against $0.30 and $2.50 for the current default, Gemini 3.5 Flash-Lite.

## Decision

**The default model is `gpt-6-luna` at reasoning effort `none`, for both roles.** The default provider moves from `google` to `openai`, and the default setting of the `openai` provider moves from `medium` to `none`.

## How the default is chosen

**The probe of ADR 019 is run again, with `gpt-6-luna` at `none` and at `low` as its challengers.** Its bars do not change, and neither does the rest of the admission procedure: a setting that clears the probe then goes through the judge isolation eval and its F1 threshold of 0.90, then the honeypot floors, and it is admitted when it clears all three. The probe replays the corpus recaptured after the second change, the one the debugging runs used, committed before the run.

**`none` is preferred when both settings are admitted.** ADR 019 chooses between admitted models on public benchmarks read at the admitted setting, but a benchmark that does not report both settings of one model cannot rank them. At the same per-token prices, `none` bills no reasoning tokens. Between two settings of one model, this is the rule ADR 019 rejected between models (the cheapest admitted one wins), and the risk it named is accepted here: `none` may detect less than `low`, and no instrument in this repository would show it.

**If only `low` is admitted, the Decision names `low` before this ADR is accepted. If neither is admitted, this ADR is not accepted.** Gemini 3.5 Flash-Lite at `minimal` then stays the default, the `openai` provider keeps `medium`, and the Outcome records the failure instead of a third change to the prompt.

### Outcome

Written after the admission run.

## Alternatives considered

**Qwen3.8-Flash or GLM-5.3-Flash as the default.** Rejected. Alibaba's input moderation blocked 12 calls to Qwen3.8-Flash from the attack chains, whose content an audit has to send whatever the wording of the generation prompt. GLM-5.3-Flash returned 9 generated batches with cases or a category missing in the probe of ADR 019.

**Keeping Gemini 3.5 Flash-Lite as the default and changing only the default setting of the `openai` provider.** Rejected. An audit runs on the default unless its user sets a provider, so the saving would reach only the users who do.

## Consequences

An audit run with no configuration needs `OPENAI_API_KEY` instead of `GOOGLE_API_KEY`. A configuration that names a Gemini model or the `minimal` setting without `MCP_AUDITOR_PROVIDER=google` then fails.

The knowledge cutoff of `gpt-6-luna`, 2026-05-18, falls after the advisories of the CVE benchmark, published between 2025-07-02 and 2025-12-17. The cutoff of Gemini 3.5 Flash-Lite, March 2026, also falls after them. With either default, a detection on that benchmark can come from what the model has read about the flaw.
