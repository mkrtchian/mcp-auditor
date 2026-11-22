# ADR 037: claude-haiku-5-5 at Reasoning `low` as the Default Model

**Date:** 2026-11-22
**Status:** Accepted
**Supersedes:** in ADR 021, the default provider and model and everything that justifies them. In ADR 019, the default model of the `anthropic` provider. The rest of ADR 021 stands, including the default model of the `openai` provider when a user selects it (`gpt-6-luna` at `none`).

## Context

The holdout detection rate and the holdout nuisance rate published on 2026-11-20 were measured with `claude-haiku-5-5` on the `anthropic` provider at reasoning `high`. A default audit runs `gpt-6-luna` at `none` on the `openai` provider, and so do the gates. The published rates therefore describe a model that neither a default audit nor a gate runs.

On the judge eval, over 3 runs of the 78 judge cases at commit `98c141b`, `gpt-6-luna` at `none` gave 5 wrong verdicts out of 234, and `claude-haiku-5-5` at `low` gave 4. The gap is below the resolution of the judge eval. On the honeypot suite, both models found 4 or 5 of the 8 planted flaws per run.

## Decision

**The default provider is `anthropic`, and its default model is `claude-haiku-5-5` at reasoning `low`, as generator and judge.**

**The holdout runs keep reasoning `high`.**

## Why

**The default runs the model the published rates were measured with.** Since the judge eval and the honeypot suite rank the two models level, the default follows the one that already has holdout rates. A default audit still differs from the holdout runs in its reasoning level and its chain settings, but no longer in its model.

**`low` for the default.** At `none`, `claude-haiku-5-5` judged FAIL in all 3 runs a case labeled PASS, in which a tool whose function is to execute SQL executes the query it is sent. At `low`, it judged that case PASS in all 3 runs. Above `low`, the judge eval and the honeypot suite show no gain, and each higher level costs more and takes longer for every audit.

**`high` for the holdout runs.** That these instruments show no gain above `low` does not mean there is none on real servers. A holdout run measures the auditor on real servers, so it runs at a higher reasoning level in case that gain exists. `xhigh` and `max` were left out because the detection holdout run and the nuisance holdout run already took more than 24 hours together at `high`.

## What weighs against it

A default audit costs more: in October 2026, `claude-haiku-5-5` at `low` cost 1.9 times as much as `gpt-6-luna` at `none` on the probe corpus.

The audit depends on Anthropic's safety classifier, which Anthropic can change. A refused call becomes a missed model call, which leaves the audit incomplete. So far the classifier has refused no call in the nuisance holdout run, and none in two runs of the detection acceptance layer.

## What would reverse it

- Anthropic's safety classifier starts refusing calls to `claude-haiku-5-5`.
- An open-weight model beats `claude-haiku-5-5` at `low` by more than the resolution of the judge eval or the honeypot suite, at a comparable cost.

## Alternatives considered

**Keeping `gpt-6-luna` at `none`.** A default audit and the gates would keep running a model the published rates do not describe.

**Repeating the holdout runs under `gpt-6-luna` at `none`.** The default would have its own holdout rates and stay cheaper per audit. But the judge eval and the honeypot suite rank the two models level, and the published rates already cover one of them.

**Sonnet 5.5 or Opus 5.5.** On 2026-10-17, Anthropic's safety classifier refused every model call they received on the honeypot suite, so neither produced a test case.

**A large open-weight model, postponed.** None of MiMo-V2.6-Pro, Kimi K3 and GLM 5.3 beat `claude-haiku-5-5` at `low` by more than the resolution of the judge eval or the honeypot suite. Kimi K3, which gave the fewest wrong verdicts of the three, cost about 11 times as much as `claude-haiku-5-5` at `low` per honeypot run.

## Consequences

- A default audit needs `ANTHROPIC_API_KEY` instead of `OPENAI_API_KEY`. A configuration that sets the model to `gpt-6-luna` without `MCP_AUDITOR_PROVIDER=openai` now fails, since the name goes to the `anthropic` provider.
- The default model of the `anthropic` provider changes from `claude-haiku-4-5-20251001`, which ran with no reasoning level set, to `claude-haiku-5-5` at `low`.
- The knowledge cutoff of the default model moves from 2026-05-18 to June 2026, the month Anthropic gives for `claude-haiku-5-5`.
- The honeypot and judge baselines are reset under `claude-haiku-5-5` at `low`.
