# Fault injection on the honeypot gate: method note

The harness (`evals/fault_harness.py`) checks that the honeypot gate catches a collapse of the system it gates, the proof ADR 016 names. It audits the three honeypots with one fault planted in the production models, `DEFAULT_RUNS` runs at `DEFAULT_BUDGET`, and hands the runs to the production gate (`judge_runs`), once in the `paired` mode and once in the `floors_only` mode, against the committed fixture `evals/fixtures/fault_injection_baseline.json`. It then decides a first recording of the faulted runs, with no baseline before it, on the `floors_only` result. Per fault it prints the expected result next to the observed one and writes `output/fault_injection_report.json`.

It needs `OPENAI_API_KEY` and runs at the default conditions. It is run by hand after a change to the gate's logic, never in CI. The unit tests in `tests/unit/test_eval_fault_injection.py` feed the same gate faulted observations built from the fixture, with no model and no server: they pin what the gate does, and this harness checks the faults reach it through a real audit.

## The fixture

The runs of the recording refused on 2026-09-27 at `519168f`, 3 runs on `gpt-6-luna` at `none`, budget 10, stored as observations only (no payload, response or judgment). Recall 0.46, precision 1.00. Of the 8 planted FAIL cells, 3 are stable and correct (`get_user × error_handling`, `execute_query × info_leakage`, `delete_record × input_validation`), 3 are never detected (`get_user × info_leakage`, `search_users × info_leakage`, `user_directory × info_leakage`) and 2 are unstable (`execute_query × injection` and `project_manager × info_leakage`, each detected in 1 run of 3). The 28 PASS cells are all stable and correct. So 31 cells are gated in the paired mode.

The harness refuses to start, before any model is built, when `condition_refusals` or `baseline_integrity` complains about the fixture: a fixture made stale by a honeypot, label or model change is rebuilt, never compared against in silence.

## The faults

Each wraps the production model on the role it targets (`evals/fault_injection.py`, the table in `evals/fault_catalog.py`).

- **`judge_passes_everything`**: the judge answers PASS to every case without calling the model.
- **`judge_fails_everything`**: the judge answers FAIL to every case.
- **`judge_fails_at_random`**: the judge draws FAIL with probability 0.5 per case, seeded. A cell fails when any of its cases fails (`aggregate_verdicts`), so a cell of k cases reads FAIL with probability 1 - 0.5^k. The unit test draws per cell instead, at 0.5, which is why its recall sits lower than the harness's is expected to.
- **`no_verdict`**: the judge refuses every case (`ProviderRefusal`), so no case is judged, which is how a missing verdict reaches the report.
- **`half_the_detections_lost`**: the real judge runs, then each FAIL cell of the run's verdict map turns PASS with probability 0.5 (`lose_detections`), the draw keyed on the cell, the seed and the audit index. A draw per case would lose a cell of k FAIL cases only with probability 0.5^k. The index counts every audit, replays included, so each replay draws afresh.
- **`generator_drops_error_handling`**: the generator's `error_handling` cases are removed from every test case batch, the completions included, and its chain goals from every chain plan. Four categories of five are left per tool, so distribution coverage reads 0.80.
- **`provider_refuses_chain_steps`**: the provider refuses every chain planning, step observation and next step call. The single-step cases still cover every cell. The cells whose planted flaw only a multi-step chain reaches are `project_manager × info_leakage` and `user_directory × info_leakage`.

## Why the fault stays active in the replays

A replay asks whether a flip is a property of the candidate or a draw. The candidate is the faulted system: replaying it without the fault would ask the healthy system, clear every flip, and prove only that the healthy system is healthy. So the replays use the same faulted models, and the half-loss draw goes on in them.

Under the replay rule, 4 reproductions out of at most 5 replays with early stopping, a flip that reproduces with probability 0.5 per replay is confirmed with probability 6/32, about 0.19 (4 or 5 successes out of 5 draws). The gate is therefore expected to miss most losses of the half-loss fault: each lost detection of a stable and correct FAIL cell settles `flip_not_reproduced` with probability about 0.81. That is the gate's documented blind spot, not a harness failure.

## Expected results, floors at 0.50

Written before any run. The fixture's own recall, 0.46, is under the recall floor, so every fault that does not raise recall is red on recall in both modes, whatever else the gate sees, and its recording is refused on recall. The unit tests pin the same verdicts on faulted observations.

| Fault | `paired` | `floors_only` | Recording |
|---|---|---|---|
| `judge_passes_everything` | red: recall 0.00, regressions on the 3 stable and correct FAIL cells | red: recall | refused: recall |
| `judge_fails_everything` | red: precision 0.22, regressions on the 28 PASS cells | red: precision | refused: precision |
| `judge_fails_at_random` | red: precision, PASS cells flipped (wrong verdict), recall likely over 0.50 with the per-case draw | red: precision | refused: precision |
| `no_verdict` | red: recall 0.00, distribution coverage 0.00, regressions (uncovered) on the 31 stable and correct cells | red: recall, distribution coverage | refused: recall, distribution coverage |
| `half_the_detections_lost` | red: recall, the lost detections settling `flip_not_reproduced` about 0.81 each | red: recall | refused: recall |
| `generator_drops_error_handling` | red: recall, regressions (uncovered) on the 8 stable and correct `error_handling` cells, `get_user × error_handling` among them | red: recall alone, coverage 0.80 clears its floor | refused: recall |
| `provider_refuses_chain_steps` | red: recall, no gated cell moves: `project_manager × info_leakage` (unstable in the fixture) reads inconclusive, `user_directory × info_leakage` (never detected) unchanged | red: recall | refused: recall |

On these floors the recall floor fires on every fault but the two judges that fail cases, and on the fixture itself: it tells none of these collapses from the healthy system.

## Expected results, floors of ADR 022

Written before any run. The recall floor becomes one detection per run on average (at least 3 detections over 3 runs), and a recording is refused when no planted FAIL cell or no PASS cell comes out stable and correct. The fixture holds 11 detections over its 3 runs.

| Fault | `paired` | `floors_only` | Recording |
|---|---|---|---|
| `judge_passes_everything` | red: recall (0 detections), regressions on the 3 stable and correct FAIL cells | red: recall | refused: recall, no stable and correct FAIL cell |
| `judge_fails_everything` | red: precision, regressions on the 28 PASS cells | red: precision | refused: precision, no stable and correct PASS cell |
| `judge_fails_at_random` | red: precision, PASS cells flipped | red: precision | refused: precision, and likely no stable and correct PASS cell (a PASS cell of 2 cases stays PASS over 3 runs with probability 1/64) |
| `no_verdict` | red: recall, distribution coverage, regressions (uncovered) on the 31 stable and correct cells | red: recall, distribution coverage | refused: recall, distribution coverage, no stable and correct cell on either side |
| `half_the_detections_lost` | green unless a lost detection reproduces (about 0.19 each) or the detections fall under 3 | green unless the detections fall under 3 | accepted when one of the 3 stable FAIL cells survives the 3 runs (about 1 - (7/8)^3, 0.33, on the fixture's rates), refused otherwise for no stable and correct FAIL cell |
| `generator_drops_error_handling` | red: regressions (uncovered) on the 8 stable and correct `error_handling` cells | green: the miss, no floor sees a dropped category | accepted |
| `provider_refuses_chain_steps` | green: no chain-only flaw is stable and correct in the fixture, so the gate cannot see its loss | green | accepted |

The misses expected on these floors: the half-loss fault in both modes (the replay blind spot), the dropped category in `floors_only` (caught only by the paired comparison), and the refused chain steps in both modes (no chain-only flaw is gated).

## Recorded runs

Filled by hand after each run: the date, the commit, the floors in force, the observed results per fault, and where they differ from the expected ones.
