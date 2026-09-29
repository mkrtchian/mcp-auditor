# Judge isolation fixture: method note

The judge isolation eval (`uv run python -m evals.run_judge_eval`) judges each case of `evals/fixtures/judge_cases.json` several times and gates case by case against `evals/baselines/judge_isolation.json` ([ADR 025](../docs/adr/025-judge-eval-drawn-fixture.md)). This note defines how the cases are drawn, what the fixture holds, how a redraw and a relabel change the gate, and the procedure that produces a drawn and labeled fixture. The rule below is fixed before any draw. Changing it after a draw is a new rule, and the draw it produces is a redraw.

## The draw rule

**Sources.** Fresh runs at one commit that contains the draw code, at the default conditions, on a clean tree: two `run_evals --ungated` invocations and one `run_cve_benchmark --ungated`, each with its own `--report` path. The draw reads the judged cases each run exports (`judged_cases.jsonl`, `cve_judged_cases.jsonl`) and the report beside the export (`eval_report.json`, `cve_report.json`). It refuses a source whose report says `dirty`, and sources at different commits. Exports written before the rule existed are not used. A CVE replay is not exported, since it runs only for a gated target that missed and would add cases chosen by their outcome.

**Candidates.** A candidate is a single-step judged case. Attack chains are left out, another prompt judges them. A honeypot case counts only when its cell is in the ground truth of `evals/ground_truth.py`. A case is identified by its content (below), so the same judge inputs in two runs or two exports are one candidate.

**Strata and quotas.**

| Stratum | Strata | Quota | Cases |
|---|---|---|---|
| Honeypot cell the ground truth labels FAIL | 8 | 4 | 32 |
| Honeypot cell the ground truth labels PASS | 28 | 1 | 28 |
| CVE target | 6 | 3 | 18 |

About 78 cases. A stratum with fewer candidates than its quota gives all of them, and the draw records a shortfall line for it. A CVE target with no judged case is a stratum with a shortfall, not a missing stratum.

**Why 4 cases per FAIL cell.** Under the any-fail rule of `evals/metrics.py`, one failing case fails a cell, so a case drawn from a FAIL cell is often a legitimate PASS. With `p` the share of failing cases in such a cell and `s` the chance that a failing case comes out stable and correct in the baseline, 4 cases give the cell at least one protected FAIL case with probability `1 - (1 - p·s)^4`: about 0.87 at `p = 0.5` and 0.79 at `p = 0.4`, with `s = 0.8`. The honeypot gate already protects the same planted flaws end to end, so the judge gate aims lower than 0.9. One case per PASS cell covers every PASS cell. The labeling effort, about two hours with an assistant, bounds the total.

**Seed and order.** `DRAW_SEED = 20260928` (`evals/draw_judge_cases.py`), one `random.Random` for the whole draw. FAIL cells, then PASS cells, then CVE targets, each in sorted key order, each stratum sorted by case id before `rng.sample`. The draw is a function of the seed and the source files.

**Complement rule.** If, once labeled, the cases labeled FAIL are 40 % or more of the cases labeled PASS or FAIL, one more case is drawn in every PASS cell with `DRAW_SEED + 1`, among the candidates not drawn yet, and labeled the same way. The precision floor catches a judge that fails everything only while the FAIL cases are under half ([ADR 025](../docs/adr/025-judge-eval-drawn-fixture.md)). `--complement` refuses an unlabeled case, a rule that does not fire, a second complement, and exports that differ from the sources the draw recorded.

**What is stripped.** A drawn case carries its id, its source, its origin (`cell <tool>/<category>` or `cve <CVE id>`) and its judge inputs, nothing else. The judge's verdict and justification, `correct`, `expected_verdict` and the run index never reach the drawn file. The draw also refuses to write when a case's inputs hold the invoking user's home path, user name or an API key pattern, since the file is committed with raw server responses. A refused draw is not patched by hand: the source runs are inspected and rerun.

## The fixture format

`JudgeFixture` (`evals/judge_fixture.py`) holds `draw`, the `DrawRecord` (seed, quotas, each source with its path, sha256, commit and scalar conditions, the shortfalls, the complement seed), `null` for the legacy fixture, and `cases`. Each case holds:

- `id`: the first 16 hex characters of the sha256 of the canonical JSON of its inputs (`sort_keys`, no whitespace).
- `source`: `honeypot`, `cve`, or `legacy` for the 32 hand-written cases the drawn fixture replaces.
- `origin`: the stratum it was drawn from.
- `inputs`: exactly what `build_judge_prompt` reads: `tool_name`, `tool_description`, `category`, `description`, `arguments`, `response`, `error`.
- `label`: `pass`, `fail` or `unspecified`. `null` only in the drawn file before labeling.
- `clause`: the rubric clause of `docs/labeling-log.md` that decided the label.

Loading refuses a case whose id does not match its inputs and a duplicate id. The eval refuses an unlabeled case. An `unspecified` case is judged and observed in every run, and stays out of the ground truth, so out of the metrics, the floors, the protected counts and the comparison.

The inputs fingerprint is the sha256 of the sorted case ids. It covers the cases, not the labels, and not the judge prompt nor `category_guidance`, which are the system under test.

## How a relabel and a redraw change the gate

**A relabel** changes labels only, by a rubric clause applied to every case it covers. The fingerprint does not move, and the stored observations of the baseline are re-scored under the current labels ([ADR 020](../docs/adr/020-honeypot-baseline-changes.md)). A case moved out of `unspecified` already has observations. A relabel that leaves no stable and correct case on the FAIL side or the PASS side is refused before any judge call: the baseline is deleted in a commit of its own and recorded twice at that commit ([ADR 022](../docs/adr/022-honeypot-recall-floor.md)).

**A redraw** changes the cases, so the fingerprint, and a run against the old baseline is not comparable. The baseline file is deleted in the redraw commit and recorded again twice at that commit. A redraw replaces the cases a red gate names, so it is made only from a green gate ([ADR 025](../docs/adr/025-judge-eval-drawn-fixture.md)).

## Operating procedure

Human work, in this order, once the code is in.

1. **Rubric and brief.** The maintainer writes the rubric entry (clauses J0, J1, ...) in `docs/labeling-log.md` and reviews [`judge_labeling_brief.md`](judge_labeling_brief.md). The rubric answers whether the response or error shows a failure, planted or not, in the category tested, without reference to the judge prompt or `category_guidance`. A pilot on legacy cases, stripped of their labels, tests the rubric before it is frozen. The maintainer has seen those labels, and the log entry says so. Commit.
2. **Source runs**, clean tree, default conditions, at that commit:
   ```bash
   uv run python -m evals.run_evals --ungated --report output/judge_source/honeypot_1/eval_report.json
   uv run python -m evals.run_evals --ungated --report output/judge_source/honeypot_2/eval_report.json
   uv run python -m evals.run_cve_benchmark --ungated --report output/judge_source/cve/cve_report.json
   ```
3. **Draw**, then commit the unlabeled `evals/fixtures/judge_cases_drawn.json`, so git shows the draw preceded the labels:
   ```bash
   uv run python -m evals.draw_judge_cases \
     --honeypot-export output/judge_source/honeypot_1/judged_cases.jsonl \
     --honeypot-export output/judge_source/honeypot_2/judged_cases.jsonl \
     --cve-export output/judge_source/cve/cve_judged_cases.jsonl
   ```
4. **Labeling**, in the drawn file, with the assistant under the brief. If the complement rule fires, run the draw again with the same exports and `--complement`, commit, and label the new cases. Once every case is labeled, two agents on different models label every case independently, and the maintainer examines again every case where one of them disagrees ([`judge_labeling_brief.md`](judge_labeling_brief.md), section "Independent labelers"). A clause revised during labeling is applied again to every case already labeled.
5. **Swap**, in one commit: the labeled draw replaces `evals/fixtures/judge_cases.json`, the drawn file is deleted, and the labeling log records the instrument change, answering the four questions of [ADR 016](../docs/adr/016-eval-gate-governance.md).
6. **Recordings**: `uv run python -m evals.run_judge_eval --record-baseline` twice at that commit, then commit `evals/baselines/judge_isolation.json`.
