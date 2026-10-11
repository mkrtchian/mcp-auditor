# ADR 030: A CVE Credit Is Checked by a Replay on the Patched Version

**Date:** 2026-10-11
**Status:** Accepted
**Supersedes:** nothing.

## Context

Calibration ties a proof to the flaw on one path only, the exploit's. The exploit surfaces the proof on the vulnerable version but not on the first patched version, and a benign call surfaces none (`docs/holdout-rule.md`, *Eligibility*). A holdout run does not restrict the auditor to the vulnerable tool ([ADR 015](015-eval-instruments-and-claims.md)), and even a run restricted to that tool can reach a nonce ([ADR 029](029-nonce-only-proof.md)) through another flaw of the same pinned version. So the auditor can surface a nonce on paths the exploit never took: another flaw, or a tool whose declared function reaches a place of a nonce. The calibration card states that only the flaw reaches the nonces, and nothing tests that claim beyond the exploit's path.

## Decision

**Every run of the CVE benchmark that detects a target is replayed on the patched version**, on the acceptance layer and on the holdout alike. The replay tests the path each credit was earned on, where calibration tests only the path of the exploit.

A step without an LLM sends the calls the run made to that target, in their order, to a fresh container of the patched version with fresh nonces. If a unit (the case or chain the grammar grades as one) carried a nonce in the run and also surfaces the fresh nonce of the same place on the replay, the grammar strikes that proof from the unit and grades the run again on what remains.

A target whose patched version fails the calibration check that precedes the run is treated like a target whose vulnerable version fails: on the holdout it is not run and is not counted in the number of targets N, and on the acceptance layer the run is not comparable to the baseline.

A replay that fails to launch is retried as an audit is. A credit still not replayed is kept and reported as unchecked, beside the credits the replay refused. A conclusion that changes when unchecked credits count as misses is inconclusive.

The calls and the patched responses are kept in memory and never written, so the replay leaves no trace that could spend a target.

The grammar fingerprint covers the rule that strikes a proof, while the replay itself runs in the benchmark outside the grammar, so a change to the replay code does not change the fingerprint.

## Alternatives considered

**A set of credited tools per target, written at calibration.** Rejected. It depends on the calibration agent listing every tool that shares the vulnerable code, and the advisory does not give that list: the fixture of an acceptance target already exploits a tool its advisory does not name.

**Crediting only a unit aimed at the target's mechanism.** Rejected. The oracle's aim predicates, which say whether a unit is aimed at the target's mechanism, are loose diagnostics. Gating credit on them would count a detection as missed whenever a predicate wrongly reads its unit as not aimed.

**Replaying the holdout only.** Rejected. The 2 layers share one oracle (ADR 015), so a credit has to mean the same on both. On the acceptance layer the refusals of the replay can also be read to check the replay, since the targets of that layer are spent.

## Consequences

In the baseline reset of [ADR 029](029-nonce-only-proof.md), the 6 acceptance targets gain a patched version, calibrated like a holdout candidate's. In the acceptance gate, a refused credit counts as not detected.

The replay must be in place before the first holdout run. No acceptance baseline holds a detection yet, so no real credit can test the replay. A permanent test runs it on a fixture written for that purpose, a server whose declared tool reaches a nonce, with a patched twin, and checks that it refuses that credit and keeps one earned through the flaw.

The replay can only refuse a credit, but it errs in both directions. A credit earned on a sibling flaw fixed in the same release as the target is not refused. Neither is a credit earned on another path whose calls depended on a response of the vulnerable version, since they may fail on the patched version. A credit earned on the target's mechanism is refused when the payload gets past an incomplete patch.

The replay runs the auditor's calls without the auditor, so it does not measure whether the auditor still reports a fixed flaw.
