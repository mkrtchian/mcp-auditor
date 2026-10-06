# Fault injection on the honeypot gate: method note

The integration test `tests/integration/test_gate_fault_injection.py` checks that the honeypot gate catches a collapse of the system it gates, the proof ADR 016 names. For each scenario it audits the three real honeypot servers `DEFAULT_RUNS` times through the production graph, with one fault planted in the models, and hands the runs to the production gate (`judge_runs`), once in the `paired` mode and once in the `floors_only` mode, against the committed fixture `evals/fixtures/fault_injection_baseline.json`. It then decides a first recording of the faulted runs, with no baseline before it, on the `floors_only` result. The harness is `evals/fault_harness.py`, the faults and their expectations `evals/fault_catalog.py`.

It needs no API key and runs in CI with the other integration tests. ADR 003 defines the integration level as real MCP servers and no LLM. This test is the first at that level to exercise the eval gate rather than an adapter.

## What it proves, and what it does not

It proves wiring: a fault planted in the models reaches the gate through a real audit (the graph, the aggregation of verdicts, `judge_runs`, the replays with the fault still active, the recording decision) and produces the gate's response on the floors of ADR 022. The unit tests in `tests/unit/test_eval_fault_injection.py` feed the same gate faulted observations built from the fixture: they pin what the gate does with a fault, and this test checks what an audit makes of it.

It does not prove what a real model detects: the honeypot evals and the CVE benchmark measure that. Nor does it prove the gate's response at another operating point than the fixture's, recorded on 2026-09-27. When a first confirmed baseline exists, the fixture can move to it. Nor does it exercise the audit of a freshly started server: each scenario audits servers already started, one per honeypot shared by its runs and replays, while the other integration tests and the evals start their own, and the reuse changes no verdict because the verdicts come from the fixture through the fake judge, not from the servers' responses.

## The fixture

The runs of the recording refused on 2026-09-27 at `519168f`, 3 runs on `gpt-6-luna` at `none`, budget 10, stored as observations only (no payload, response or judgment). Recall 0.46, precision 1.00. Of the 8 planted FAIL cells, 3 are stable and correct (`get_user × error_handling`, `execute_query × info_leakage`, `delete_record × input_validation`), 3 are never detected (`get_user × info_leakage`, `search_users × info_leakage`, `user_directory × info_leakage`) and 2 are unstable (`execute_query × injection` and `project_manager × info_leakage`, each detected in 1 run of 3). The 28 PASS cells are all stable and correct. So 31 cells are gated in the paired mode, and the fixture holds 11 detections over its 3 runs.

On 2026-10-06 the five cells of `execute_query` were renamed with the tool to `search_products` (`docs/labeling-log.md`, entry of that date). The figures above describe the recording of 2026-09-27 under the old name, and its observations did not move. The fixture's ground truth fingerprint follows the renamed keys, so that the check below still sees a missing cell, and its source fingerprints stay those of the recording.

The test fails before any audit when `baseline_integrity` complains about the fixture: a fixture made stale by a honeypot or label change is rebuilt, never compared against in silence. The fixture's model and budget play no role, the test runs fakes at budget 5.

## The two fakes

The healthy system is made of two fakes in `tests/fakes/`, keyed on what they are asked rather than on the order of the calls, which each fault changes (retries, completions, chain steps, replays).

- **`ScriptedAuditModel`**, the generator: one case per category the attack prompt asks for, arguments `{}` (the server answers with an error, still a response to judge), one `info_leakage` chain per tool that stops after its first step. At budget 5 a full batch holds the budget, so no retry happens in the healthy state.
- **`FixtureJudge`**, the judge: it reads the tool and the category from the judge prompt and answers the fixture's observation of that cell, the n-th judgment of a cell reading the n-th run. An uncovered observation is a refusal, a cell outside the ground truth is PASS. The two chain-only cells (`project_manager × info_leakage`, `user_directory × info_leakage`) are PASS on single-step prompts and the fixture's observation on chain prompts, so that refusing the chains removes exactly those verdicts, as in a real audit.

The judge reproduces the fixture rather than the ground truth so that the test keeps the fixture's shape and exercises the gate's real weaknesses. A perfect judge would hide them: it would make the two chain-only flaws stable and correct, turning the documented miss of the refused chain steps into a catch, and it would never exercise an unstable cell. The first test, the healthy audit, shows the fakes stand for the fixture: the observations of each run equal the fixture's and the paired gate is green with every gated cell unchanged. Every fault test rests on it.

## The faults

Each wraps the healthy model on the role it targets (`evals/fault_injection.py`, the table in `evals/fault_catalog.py`).

- **`judge_passes_everything`**: the judge answers PASS to every case without calling the model.
- **`judge_fails_everything`**: the judge answers FAIL to every case.
- **`judge_fails_at_random`**: the judge draws FAIL with probability 0.5 per case, seeded. A cell fails when any of its cases fails (`aggregate_verdicts`), so a cell of k cases reads FAIL with probability 1 - 0.5^k. With one case per category, most cells hold one case per run.
- **`no_verdict`**: the judge refuses every case (`ProviderRefusal`), so no case is judged, which is how a missing verdict reaches the report.
- **`half_the_detections_lost`**: the healthy judge runs, then each FAIL cell of the run's verdict map turns PASS with probability 0.5 (`lose_detections`), the draw keyed on the cell, the seed and the audit index. A draw per case would lose a cell of k FAIL cases only with probability 0.5^k. The index counts every audit, replays included, so each replay draws afresh.
- **`generator_drops_error_handling`**: the generator's `error_handling` cases are removed from every test case batch, the completions included, and its chain goals from every chain plan. Four categories of five are left per tool, so distribution coverage reads 0.80.
- **`generator_drops_error_handling_declared`**: the same fault as `generator_drops_error_handling`, run with every `error_handling` cell declared (`Fault.declares`), as the commit that makes such a change would declare them in `evals/declared_flips.json`. The harness hands the declarations to the session directly, with no file and no git read. It pins that the flips the undeclared fault turns red on are exactly the ones a declaration clears: the stable and correct `error_handling` cells read `declared`, no cell reads `flip`, `regression` or `flip_not_reproduced`, and a recording of the runs is accepted.
- **`provider_refuses_chain_steps`**: the provider refuses every chain planning, step observation and next step call. The single-step cases still cover every cell, and the chain-only cells keep their single-step verdicts.

## Why the fault stays active in the replays

A replay asks whether a flip is a property of the candidate or a draw. The candidate is the faulted system: replaying it without the fault would ask the healthy system, clear every flip, and prove only that the healthy system is healthy. So the replays use the same faulted models, and the half-loss draw goes on in them.

Under the replay rule, 4 reproductions out of at most 5 replays with early stopping, a flip that reproduces with probability 0.5 per replay is confirmed with probability 6/32, about 0.19 (4 or 5 successes out of 5 draws). The gate is therefore expected to miss most losses of the half-loss fault: each lost detection of a stable and correct FAIL cell settles `flip_not_reproduced` with probability about 0.81. That is the gate's documented blind spot, not a test failure.

## Expected results, floors of ADR 022

The recall floor is one detection per run on average (at least 3 detections over 3 runs), and a recording is refused when no planted FAIL cell or no PASS cell comes out stable and correct. The test asserts both verdicts, whether the recording is refused, and the reasons the `Expectation` of each fault names.

| Fault | `paired` | `floors_only` | Recording |
|---|---|---|---|
| `judge_passes_everything` | red: recall (0 detections), regressions on the 3 stable and correct FAIL cells | red: recall | refused: recall, no stable and correct FAIL cell |
| `judge_fails_everything` | red: precision, regressions on the 28 PASS cells | red: precision | refused: precision, no stable and correct PASS cell |
| `judge_fails_at_random` | red: precision, PASS cells flipped | red: precision | refused: precision |
| `no_verdict` | red: recall, distribution coverage, regressions (uncovered) on the 31 stable and correct cells | red: recall, distribution coverage | refused: recall, distribution coverage, no stable and correct cell on either side |
| `half_the_detections_lost` | green unless a lost detection reproduces (about 0.19 each) or the detections fall under 3 | green unless the detections fall under 3 | accepted when one of the 3 stable FAIL cells survives the 3 runs, refused otherwise for no stable and correct FAIL cell |
| `generator_drops_error_handling` | red: regressions (uncovered) on the 8 stable and correct `error_handling` cells | green: the miss, no floor sees a dropped category | accepted |
| `generator_drops_error_handling_declared` | green: the 8 stable and correct `error_handling` cells read `declared`, no other cell flips | green | accepted |
| `provider_refuses_chain_steps` | green: no chain-only flaw is stable and correct in the fixture, so the gate cannot see its loss | green | accepted |

The misses the test pins: the half-loss fault in both modes (the replay blind spot), the dropped category in `floors_only` (caught only by the paired comparison), and the refused chain steps in both modes (no chain-only flaw is gated).

Two rows are asserted by rule rather than pinned. The random judge's exact flipped cells depend on the graph's call order and would break on every refactoring, so the test asserts precision red in both modes and some PASS cells flipped. A PASS cell of one case stays PASS over 3 runs with probability 1/8, so whether the recording is also refused for no stable and correct PASS cell is left open. The half-loss fault's draws depend on the audit index, which the runs and the replays share, so a legitimate change to the number or order of replays would move them with no regression behind it. Its test asserts what follows from the gate's rules whatever the draws: `floors_only` is red exactly when the detections left fall under the number of runs, every stable and correct FAIL cell a run lost settles `regression` or `flip_not_reproduced`, and the recording is refused for no stable and correct FAIL cell exactly when none of those cells survived every run.

The expectations for the former floors at 0.50 are pinned in history at `35aeaec`.

## Cost

Each of the nine scenarios (the healthy one and the eight faults) is its own test, with its own fakes. It starts one server per honeypot and reuses it for its runs and its replays, and pytest-xdist runs the scenarios in parallel under `-n auto`. On 2026-09-27, when there were eight, on a 16-core machine, each scenario took about 3 to 4 seconds and the eight about 9 seconds under `-n auto`, about 17 seconds one after the other, and the whole integration suite took about 13 seconds under `-n auto`.
