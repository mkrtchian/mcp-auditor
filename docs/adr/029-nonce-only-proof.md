# ADR 029: The Nonce Is the Only Proof, in Places Chosen per Target

**Date:** 2026-10-11
**Status:** Accepted
**Supersedes:** in [ADR 028](028-cve-holdout-selection.md), membership in a class of the frozen grammar as an eligibility criterion of the holdout, and the grammar trigger that lets a missing class enter the grammar. The grammar fingerprint, which ADR 028 counts among the run conditions, stays there. In [ADR 024](024-cve-acceptance-gate.md), the command-output rung and the report of a move between detection rungs: the ladder keeps one detection rung, the planted sentinel, called the nonce here.

## Context

The CVE oracle grades each audit by frozen rules, its grammar. Each target is filed in 1 of its 3 effect classes (`read_outside_scope`, `command_execution`, `internal_fetch`), and the class sets which proofs the target admits. The nonce is a random value placed where only the flaw reaches it: the auditor cannot write it, so a response that surfaces it ties the detection to the flaw. It is drawn once per benchmark process. The other proof, `computed_output`, is the output of `id` or the root line of `/etc/passwd`, graded on a lower detection rung than the nonce ([ADR 024](024-cve-acceptance-gate.md)). Its form is fixed, so a payload can write it without the flaw, and the check that discards a proof copied from the auditor's own arguments catches only a literal copy.

`read_outside_scope` and `internal_fetch` admit the same proof, the nonce, so the 3 classes differ only in whether they admit `computed_output`. The holdout's eligibility criterion that a flaw falls in one of these classes also depends on the name the classifiers of the holdout census give the effect: 2 names for one effect can decide eligibility differently.

This decision comes after the census of version 3 of the rule was read, including the flaws the class criterion keeps out and the proof that could show each of them. It opens version 4 of the selection rule before any draw, and that version applies its criteria to the same draw order. No one involved computed that order, so the decision could not be aimed at the flaws a draw would reach. The decision does not rest on that reading: it would stand even if none of those flaws could be proven, since calibration would then give them up.

## Decision

**The nonce is the only proof.** Each place of a target holds its own nonce, drawn for each launch of the target, where one nonce is drawn today for each benchmark process. The report can then tell which place each detection came from.

**The places of the nonce come from a list written from MITRE ATT&CK, a published catalogue of attacker techniques**, and the auditor's prompts are not used to write it. The list overlaps the places the auditor's prompt names, since both follow what attackers commonly probe, and the catalogue covers places the prompt does not name. The list belongs to the selection rule, so a change to it opens a new version of the rule. Calibration chooses, for each target, every listed place that only its flaw reaches, and each launch plants a fresh nonce in each of them. To earn a detection, the auditor therefore has to look where an attacker would look, not in a place specific to the fixture.

**On a target whose flaw runs code the caller chooses, the account of the process is one of these places.** The process runs under an account named after the nonce of that place, so `id`, `whoami` and the passwd file print it. `computed_output` and its rung are removed: the output of `id` now carries a nonce, and the passwd root line, which any read of the file prints, attributes nothing.

**The effect class is no longer an eligibility criterion.** It stays a label of the target, and that label still sets which judge categories count in the `fail_without_proof` diagnostic, a unit judged FAIL in such a category without a proof. Calibration already tests whether a flaw can be proven: the exploits written at calibration have to surface the nonce of each kept place in a tool response, and a candidate is excluded when 2 calibrations give up on it.

**The grammar trigger is removed.** Any value of a tool response that the fixture controls can now hold a nonce. A new proof kind would therefore be read outside the tool response, which the trigger's own condition, an effect proven in a tool response, ruled out: the trigger could no longer fire.

## Alternatives considered

**Reshaping the classes**, by merging read and fetch or by adding one class per effect found in the census. Rejected. The new classes would all admit the nonce, so they would differ in name only.

**Keeping `computed_output` on the targets whose server cannot print the nonce otherwise.** Rejected. With an account named after a nonce, the same probe, `id`, prints a value the auditor cannot write.

**A user id drawn for each launch**, matched in the output of `id`. Rejected. A drawn id has no account, so `whoami` fails and some servers do not start.

**One place per target.** Rejected. An attacker who reaches a flaw looks in several places, and the catalogue lists several. With one place, a detection would depend on which of them the fixture picked.

## Consequences

The grammar fingerprint changes, so the acceptance baseline is reset as ADR 024 requires. The acceptance fixtures hold nonces in the listed places only, as the holdout's targets will. A place added to the list after this decision changes the fixtures where calibration chooses it and resets their baselines.

The holdout number covers the flaws whose calibration passes. A give-up is the calibration agent's conclusion that the calibration cannot pass, and that conclusion can come from the limits of its attempts, not only from a flaw that cannot be proven.

Some flaws stay out of the holdout as a known gap, reported with its share of the census: those whose effect shows in a tool response only as an acknowledgement (a success message, for instance) and that reach no place able to hold a nonce: writes with content the caller supplied, mutations under a read-only mode, blind network probes. Their proof would be read outside the tool response, by an oracle that observes the container, and only a new ADR can add that oracle. On a flaw that does reach a place for a nonce, an auditor that proves it only through a value the runtime computes, such as the version a database reports, is graded as a miss.
