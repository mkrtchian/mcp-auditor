# ADR 022: The Recall Floor of the Honeypot Gate Detects Only Collapse

**Date:** 2026-09-27
**Status:** Accepted
**Supersedes:** nothing. This is the ADR that ADR 016 requires for lowering a floor.

## Context

On 2026-09-23, before any baseline was recorded, the plan for the paired gate (`plans/2026-09-23_paired-eval-gate.md`) set the floors at 0.50 for recall, precision and distribution coverage. Their written purpose is to detect collapse: "a judge that passes everything scores recall 0". ADR 016 states the rule: "A floor is a collapse detector and not a quality bar, and lowering one takes a new ADR."

A recall floor of 0.50 requires the auditor to find half of the planted flaws, whichever model runs. The collapse it was written for scores 0, so a floor of 0.50 is a quality bar.

Twice, a bar written in advance blocked `gpt-6-luna`. The proposed ADR 021 (`e4d2165`) was not to be accepted unless one of the two reasoning settings of `gpt-6-luna` cleared its admission bars. The probe admitted neither (`5335ad0`), and the accepted ADR 021 (`2cd755f`) replaced the admission bars with a written judgment, at a honeypot recall of 0.50, exactly the floor. On 2026-09-27, the recall floor refused a baseline recording on `gpt-6-luna` at `none`, at a mean recall of 0.46. The floor's firing exposed it as a quality bar. The decision below does not rest on that firing: its criterion is the purpose written on 2026-09-23.

## Decision

**The recall floor is set at one planted flaw found per run, on average over the runs.** Its value is computed from the ground truth, as 1 divided by the number of FAIL cells (1/8 today), so that a revision of the labels moves it too.

**The precision and distribution coverage floors stay at 0.50.** Each is breached by the collapse it was written for: a judge that fails everything scores a precision of about 8/36, the share of FAIL cells, and a generator that stops covering categories drops coverage towards 0.

**A baseline recording is refused when no planted FAIL cell, or no PASS cell, comes out stable and correct.** Without a stable FAIL cell, the gate catches a lost detection only when recall falls below its floor, and without a stable PASS cell, it catches a new false positive only when precision falls below its floor. The condition also holds when a label revision re-scores a baseline (ADR 020): a baseline left with no stable and correct cell on one side is not comparable until it is recorded again.

## Alternatives considered

**Remove the recall floor.** Rejected. An exploratory baseline and `--ungated` are guarded by the floors alone, and a judge that passes everything scores a precision of 1.00, so both would stay green.

**Keep 0.50 and record again.** Rejected. A floor inside a model's run-to-run spread turns CI red with no regression behind it.

## Consequences

No floor guards detection quality. The paired comparison catches a regression on the cells a baseline records as stable and correct, and the CVE benchmark measures detection without a gate.

This is an instrument change. It changes no recorded observation and no metric, and requires no baseline reset. Its entry is in `docs/labeling-log.md`.
