# Test review: fix the tests added since the new-tests review

## Context

The review of `plans/2026-11-05_new-tests-review.md` ended at commit 39fc0ff. Since then about 370 test files gained five lines or more (161 new files, about 12,700 lines in them, and about 7,600 lines added to existing files, counted with rename detection across the directory move of 60f6a35). This time the growth is not only in the eval harness: the product gained the relaunch of a stopped server (ADR 036), the bounded attack context (ADR 035), bounded tool responses, the endless-device guard and the removal of a named declared container, and the instruments gained the realism repairs (real backends, keyed stand-in routes), the vet's second pass, the run status lines and the exits table.

The tests were reviewed against the testing standards of `CLAUDE.md` with the method of the two previous reviews: five reviewers by area (auditor, cve, nuisance, detection, the rest with integration), then two verifiers who checked each finding against the code at d7dc9ef, with mutation probes where the ruling hinged on one. 105 test findings: 89 hold, 15 hold in part (the fix below is the amended one), 1 does not. Verification found five more issues, included below. Every finding recommended for application is in this plan, and the rest is listed under "Out of scope" with the reason.

The findings fall into the same kinds as before: tests that cannot fail, names that promise more than the test checks, coupling to data or wiring that changes for good reasons, tests of the library or of a constant, Given/When/Then structure, and duplication. Three traits set this batch apart:

1. **The product has a coverage hole.** Deleting the reset of a tool's timeout count in `ServerWatch._answered` leaves every test green, while ADR 036 stops a tool after timeouts "in a row". The fix is one new test, and it comes first in its area.
2. **The retired-word scan costs more than it catches in two places.** It takes about 14 s of a 32 s short loop, mostly reading five Android Dockerfiles that embed 423 KB device captures (and those captures forced three allowlist entries), and its `\b`-anchored patterns never see a retired word inside a snake_case test name, so about thirty test names kept the old vocabulary. The scan is narrowed to living text and widened to test names, after the renames.
3. **Monkeypatch substitutions are left for a follow-up plan.** About thirty test files replace a production dependency with `monkeypatch.setattr` because production has no injection point (the CLI `main` functions, the fix-check, vet, run and gate commands, the Doris clock, the subprocess runner of the backends). The standards ask for injected dependencies, but each seam is a production signature change, several in fingerprinted modules, and the patches that remain all hit the consumer's own binding, so a rename fails loudly. They go to a separate plan, with the per-launch responder concept the previous plan deferred. This plan only keeps its test-side cleanups compatible with those seams.

Every change keeps or strengthens what the suite guards. Where a test is deleted, the behavior it named is covered elsewhere (named in the item) or was never observable through it.

## Approach

Seven areas. Area 0 lands first: shared test support, the cross-area deletions that must go with their allowlist entries, and the renames. Area A holds the small production edits, each its own commit with the test edits its new name or signature forces. Areas B to F are test-only. The retired-word scan change (Area 0, item 0.7) lands last of all, once every rename is in, so the widened scan arrives green.

Production edits go test-first like any change: the test written against the new public name or signature, seen red (an import error is the expected red for a new name), then production. A refactoring that keeps behavior is checked by the existing tests staying green on top.

Registry-wide parametrized tests that replace copied tests are green on arrival, since they characterize code that already works. Each is shown red on one hand-broken case before its copies are deleted (a backend container with its memory bound removed, a builder missing from the table, a fix-check launch granted a capability), then reverted. The commit message records the mutation tried.

Shared decisions across areas (the previous plan's, still in force):

- Fakes of production collaborators live in `tests/fakes/` (exported from `tests/fakes/__init__.py`). Test vocabulary used by one test file lives in its own `support/*_given.py`. Vocabulary shared by several test files lives in a named non-given module (like `tests/unit/support/docker_argv.py`): in the area's `support/` when one area uses it, in `tests/unit/support/` when several areas do. A test file never imports another test file's given.
- When a test file splits, a given function that both halves need moves to a named non-given module in the same `support/` (or `tests/unit/support/` across areas), never imported by one half from the other half's given (`CLAUDE.md`: one given/then pair per test file).
- A message is specified once, at the module that owns it. Callers assert the effect, or compare against the owner's function or table, never the wording again.
- An attempt budget, a timeout, a bound, a count of registry members: tests read the constant or derive the value, never restate the literal.
- A launch's container name is asserted with `isinstance(declared_container_name(args), str)` (from `mcp_auditor.domain.container_name`), never by argv position and never with `is not None`, which also accepts `Undecidable.NAME`.

### Governance

No change touches a module hashed by a fingerprint or a golden master's output: `GRAMMAR_PATHS` and `ENVIRONMENT_PATHS` of `evals/cve/detection/baseline.py`, the targets' `backend_sources`, `CONFINEMENT_SOURCE` and `_PUBLIC_NAME_SOURCES` of `evals/cve/nuisance/fingerprint.py`, the `served` modules of `evals/cve/nuisance/backend_registry.py`, `_COUNTER_PATHS` of `evals/cve/nuisance/counter.py`, the grammar golden (`tests/unit/cve/support/test_cve_grammar_golden_given.py`) and the golden of what reaches a model or an agent (`tests/unit/auditor/support/test_model_inputs_golden_given.py`). No baseline reset, no labeling log entry, no declared flip. Each production commit message states this.

The production modules this plan edits are `src/mcp_auditor/adapters/chat_model_factory.py`, `src/mcp_auditor/graph/chain_prompts.py`, `evals/cve/census/census.py`, `evals/run_census.py`, `evals/run_detection_holdout.py`, `evals/cve/nuisance/commands.py` and `evals/run_nuisance.py`. None is in a tuple above at d7dc9ef (checked by the verifiers). The implementer reruns that check before the first production commit, since a tuple may have grown.

`graph/chain_prompts.py` builds a prompt: item A2 names a literal there without changing any output, which the model-inputs golden proves by staying green without regeneration. Item 0.3 moves one import line of the grammar golden's given (`cve_grammar_golden_corpus` changes directory): the given's output, the committed golden, does not change, and the golden test stays green without regeneration.

Several places stay untouched because they are hashed, listed under "Out of scope": the per-launch backend container code copied across `gitlab.py`, `kubernetes.py` and `node_sandbox_engine.py`, the six copies of the fixture authority path in production, the Doris cluster's missing hardening, and `n8n_instance.py`'s removal without `-v`.

## Area 0: shared test support, cross-area deletions, renames

### 0.1 Acceptance targets by flaw ID

"A real acceptance target by flaw ID" is looked up in seven places, and six files import the holdout run given for it (four only for it: `test_detection_calibration_check_exit.py`, `support/test_detection_holdout_pre_run_check_given.py`, `test_run_detection_holdout.py`, `tests/unit/cve/test_cve_run_images.py`; `tests/unit/cve/test_cve_closed_network_refusal.py` and `support/test_run_detection_holdout_run_given.py` also use its `deps_auditing`, `run` and `scripted`, so they keep the import): `support/test_detection_holdout_run_given.py:43` (`a_target`), `support/test_detection_audit_given.py:29`, `support/test_detection_baseline_given.py:32,35`, `support/test_detection_session_given.py` (`KUBERNETES`, `SYMLINK`), `support/test_detection_targets_given.py:13`, `support/test_detection_replay_given.py:115`, `test_detection_targets.py:34,130,236`, `test_run_detection.py:209` (all under `tests/unit/detection/`), and the importers `test_detection_calibration_check_exit.py:5`, `support/test_detection_holdout_pre_run_check_given.py:7`, `support/test_run_detection_holdout_run_given.py:9`, `test_run_detection_holdout.py:6`, `tests/unit/cve/test_cve_closed_network_refusal.py:11`, `tests/unit/cve/test_cve_run_images.py:9`.

Create `tests/unit/support/acceptance_targets.py` (cross-area: the cve area imports it) with the `FILESYSTEM`, `KUBERNETES` and `GIT` flaw IDs and `an_acceptance_target(flaw_id: str, **changes: object) -> Target` (`dataclasses.replace` over the `ACCEPTANCE_TARGETS` member). Every copy above uses it. The holdout run given keeps its `tools_filter=None` default on top. `support/test_detection_replay_given.py::_a_target_serving_its_nonce` replaces both `builder` and `kept_places`, so it takes any acceptance target through the helper rather than CVE-2025-53109 by name.

The holdout run vocabulary that other test files borrow from `support/test_detection_holdout_run_given.py` (`deps_auditing`, `run`, `scripted`, read by `tests/unit/cve/test_cve_closed_network_refusal.py`, `support/test_run_detection_holdout_run_given.py` and `test_detection_holdout_run_interrupted.py`) moves in the same commit to a non-given `tests/unit/support/holdout_runs.py` (cross-area: the cve file reads it), imported by the holdout run given and the three borrowers. The move keeps the functions' bodies.

### 0.2 One sound layout

`LayoutCheck(...)` literals are rebuilt in five places: `support/test_detection_session_given.py` (`SOUND_LAYOUT`, `BROKEN_LAYOUT`), `support/test_detection_holdout_pre_run_check_given.py:16-18` (`SOUND`, `BROKEN`, `LEAKING`), `test_detection_layout_check.py` (`_SOUND`), `support/test_detection_holdout_run_given.py` (default of `deps_auditing`), and three inline literals in `test_detection_holdout_run.py`. Adding `leaking` forced an edit at each. Create `tests/unit/detection/support/layouts.py` (a non-given module, absent at d7dc9ef) holding `SOUND_LAYOUT`, and build the variants from it with `dataclasses.replace(SOUND_LAYOUT, breaks=True)` and similar. No production defaults are added to `LayoutCheck` for the tests' sake.

### 0.3 Repository root, and the golden corpus's directory

Three test copies of the repository root are computed from file depth, against the previous plan's decision that they import `evals.honeypots.REPO_ROOT`: `tests/unit/support/retired_word_scan.py:19` (`parents[3]`), `tests/unit/evals/support/test_fixture_contamination_given.py:11` (`_TESTS_DIR`), `tests/unit/support/cve_grammar_golden_corpus.py:15` (`JUDGE_FIXTURE_PATH`). Each imports `REPO_ROOT`, with `REPO_ROOT / "tests"` for the tests directory.

`tests/unit/support/cve_grammar_golden_corpus.py` has one user, `tests/unit/cve/support/test_cve_grammar_golden_given.py:23`: move it to `tests/unit/cve/support/` and rewrite that import line. The golden output does not change (Governance).

### 0.4 Argparse refusal tests and their allowlist entries

These tests check that argparse rejects an undeclared flag or subcommand (exit 2), which it does for any name the parser does not declare, and the retired-word scan already keeps the old names out of the code: `tests/unit/detection/test_run_detection.py::test_an_old_flag_is_refused_by_the_parser`, `tests/unit/detection/test_run_detection_holdout.py::test_an_old_command_or_flag_is_refused_by_the_parser` and `::test_draw_order_is_no_longer_a_command_of_the_holdout_run`, `tests/unit/evals/test_run_honeypot_suite.py:88` and `tests/unit/evals/test_run_judge_eval.py:68` (`test_the_old_ungated_flag_is_refused`), `tests/unit/evals/test_draw_judge_cases.py:270` (`test_the_old_cve_export_flag_is_refused`), and the old command and flag parser test of `tests/unit/nuisance/test_run_nuisance.py:257-270`. Delete them in one commit, with the allowlist entries of `tests/unit/support/retired_word_exemptions.py` that exist only for them (the `ungated`, `cve-flag`, `calibrate-cmd` and `readmission` entries scoped to `tests/unit/*/test_run_*.py` and `tests/unit/evals/test_draw_judge_cases.py`): a stale entry turns `test_every_allowlist_entry_matches_a_line` red, so entries and tests go together. The implementer lists the entries by running the scan after deleting the tests.

In the same commit, the two `no_baseline` tests (`test_run_honeypot_suite.py:82`, `test_run_judge_eval.py:62`) are renamed `test_the_no_baseline_flag_is_read`: they check only that the flag parses, and the floors-only behavior is covered by `test_eval_session.py::test_a_no_baseline_run_gates_on_floors_only_even_with_a_confirmed_baseline` and `test_judge_session.py::test_no_flip_is_retested_in_a_no_baseline_run`. `test_draw_judge_cases.py::test_the_detection_export_is_read_from_its_flag` stays.

### 0.5 Retired keys absent from a `model_dump`

A model dumps only the fields it declares, so an assertion that a retired key is absent from its dump cannot fail: `tests/unit/auditor/test_rendering.py:410-411` (`{"target", "missed_steps"}` and `relayed_variables` absent from `render_json`), and in `tests/unit/detection/test_run_detection_holdout_run.py::test_the_result_and_the_report_carry_the_glossary_keys` the `RETIRED_KEYS` constant and its disjointness assertion (with `result_keys` and `_keys` of `support/test_run_detection_holdout_run_given.py` kept only if the positive half still uses them). `RETIRED_KEYS` is defined in `support/test_run_detection_holdout_run_given.py:16`, where its four allowlist entries are scoped. Delete these assertions with their allowlist entries (`missed-steps` and `relayed-variables` scoped to `test_rendering.py`, since line 410 is the only line of that file carrying `"missed_steps"`, and the four `RETIRED_KEYS` entries) in one commit. The `eval-result` entry of `test_rendering.py` stays with the assertion at line 422, which this item does not touch. The positive half of the holdout key test stays: it pins the published holdout result and report format.

### 0.6 Renames to the current vocabulary

Test names and test vocabulary that kept a retired word or a moved meaning, grouped here so the scan change of 0.7 lands on a clean tree. Each rename keeps the test's body. The checkpointing tests' "refused steps"/"missed steps" are old channel names, a compatibility spec, and stay.

- "missed step", "refused step", "throttled step" (now missed model call, refusal): `tests/unit/auditor/test_missed_model_calls.py:15,34,54,75`, `tests/unit/auditor/test_models.py:167`, `tests/unit/auditor/test_console_display.py:181,195,206,229`, `tests/unit/auditor/support/test_console_given.py:170`, `tests/unit/auditor/test_graph.py:291,327`, `tests/unit/auditor/test_chain_nodes.py:305`, `tests/unit/cve/test_cve_failure_text.py:45`, `tests/unit/detection/test_detection_audit.py:162,170,179,353`, `tests/unit/nuisance/test_nuisance_audit_once.py:117`, `tests/unit/nuisance/test_nuisance_retry_policy.py:154`, `tests/unit/evals/test_eval_metrics.py:322,330,409`, `tests/unit/evals/test_run_honeypot_suite.py:13,23,31`, `tests/unit/evals/support/test_honeypot_fault_harness_given.py:175` (`_a_refused_step` becomes `_a_refused_judgment`), and the "throttled step" names the scan does not see (no retired-word pattern covers it): `tests/unit/auditor/test_cli.py:105`, `tests/unit/detection/test_detection_audit.py:300`, `tests/unit/nuisance/test_nuisance_assembly.py:113`.
- "acceptance server" unqualified (now nuisance acceptance server, pattern `bare-acceptance-server`, which the widened scan of 0.7 sees in these test names): `tests/unit/nuisance/admission/test_nuisance_admission_walk.py:24`, `tests/unit/nuisance/test_nuisance_holdout_servers.py:55,64`, `tests/unit/nuisance/test_nuisance_vet.py:176`.
- "target" for the audited server: `tests/unit/auditor/test_console_display.py:15` (`test_header_contains_the_server_command`).
- "CVE" alone for a flaw ID or a target result: `support/test_detection_gate_given.py:7` (`CVE_ID` to `FLAW_ID`), `support/test_run_detection_given.py:23,25` (`BILLED_FLAW`, `RECORDED_FLAW`), `support/test_detection_console_given.py` (`NOT_RUN_FLAW`, `DETECTED_FLAW`), `support/test_detection_oracle_given.py` (`a_target_result`, `a_detection_report`), `tests/integration/support/test_detection_calibration_check_given.py:25` (`GIT_FLAW_ID`), `tests/unit/evals/support/test_fixture_contamination_given.py:56,61,82` (`detection_cases`, `servers_by_flaw`, `a_detection_case`; `CaseSource.CVE` is production and stays).
- "admitted" for a layout place with a route: `tests/unit/detection/test_detection_layout_check.py` (`..._only_the_layout_place_without_a_route`, `..._when_every_kept_place_has_a_route`).
- `acceptance_gate` and `target_dead`: `tests/unit/detection/test_detection_audit.py:342`, `tests/unit/detection/test_detection_holdout_run.py:163` (now "out of calibration").
- "settle" (now apply retests): `tests/unit/evals/test_eval_gate.py:213,223` (`test_applying_retests_turns_*`).
- "benchmark target" (now acceptance target): `tests/unit/census/test_census_grouping.py:63,75`.
- "figure" (retired): `tests/unit/nuisance/test_nuisance_holdout_servers.py:14,44,64,74` (`..._among_the_exits`), `tests/unit/nuisance/test_nuisance_statistic.py:30` (`test_the_holdout_nuisance_rate_is_the_mean_flagged_share`).
- "replay" in the sense of retest: `tests/unit/nuisance/test_nuisance_solo.py:1,67`, `support/test_nuisance_solo_given.py:84`, `support/test_nuisance_solo_then.py:12`, `gate/test_nuisance_gate_session.py:297`, `gate/test_nuisance_gate.py:97,105,114`, `gate/test_nuisance_gate_console.py:31` (under `tests/unit/nuisance/`).
- "replay a capture" (now serve a capture): `tests/unit/nuisance/test_nuisance_backend_registry.py:116`, `tests/integration/test_cve_planting_stand_ins.py:80`.
- "verdicts" for real-software records: `tests/unit/nuisance/admission/support/test_nuisance_admission_records_given.py:62-83,217` (`with_a_tool_given_two_real_software_records`).
- `the_committed_census()` returning `WalkInputs`: `tests/unit/support/test_nuisance_committed_admission_given.py:13` (`the_committed_walk_inputs()`).
- "exploratory baseline" (the glossary reserves "exploratory" for a number, a baseline is unconfirmed): `an_exploratory_baseline` and the test names that use it in `tests/unit/nuisance/gate/` (five files) become `an_unconfirmed_baseline`.

### 0.7 The retired-word scan: living text only, test names seen, scaffolding gone

After 0.6, in `tests/unit/support/retired_word_scan.py`, `tests/unit/support/retired_words.py`, `tests/unit/support/retired_word_exemptions.py` and `tests/unit/project/test_glossary.py`:

- **Embedded captures are records.** `living_texts` skips the files that embed a device capture: a size bound (files above 100 KB), applied only inside its walk over `src/`, `evals/` and `tests/`, never to the Markdown it reads in part (`CHANGELOG.md` and the three suite and labeling logs are over 100 KB, and the scan reads their `[Unreleased]` section and preambles). It leaves out exactly the five Android Dockerfiles at HEAD (`Dockerfile.android`, `Dockerfile.holdout-2026-19978-android` and `-patched`, `Dockerfile.holdout-2026-81562-claude-in-mobile` and `-patched`), and a test in `test_glossary.py` pins the skipped set to those five, so a future large file in those directories fails that test instead of leaving the scan unseen. Every other Dockerfile stays scanned, since their comments are living text. The three `$Stub` allowlist entries go. The commit message records the fixture's setup time before and after (13.8 s at HEAD with `--durations`).
- **Test names are read with `_` as a space.** The scan also reads every `def test_\w+` name with `_` replaced by a space, so a retired word inside a snake_case test name is found. Only test function names: a second read of every text the same way yields about 130 false positives on `sentinel-value` alone. The symbol patterns stay: they are the only guard on comments and docstrings that name an old symbol, which pyright never reads. A new test in `test_glossary.py` shows a fixture tree whose test name carries a retired word is reported.
A dry run of the test-name reading at d7dc9ef (every pattern applied to `def test_\w+` with `_` as a space, minus the hits the raw name already gives) finds 42 names: all are renamed in 0.6, deleted in 0.4, or are F1's `..._keyed_replay_rule_...` tests, which the `replay-retest` entry for `replay_rule` keeps allowed.
- **Dead migration scaffolding goes.** `RetiredWord.step`, `Exemptions.not_yet_renamed` and `Exemptions.not_yet_migrated` (both tuples empty) and every `step` value in `retired_words.py`, with `test_a_word_not_yet_renamed_is_skipped` and `test_a_file_not_yet_migrated_is_skipped`. `test_an_unknown_pattern_id_in_the_exemptions_is_refused` is rewritten with an `AllowedLine` naming `no-such-word`.

The scan must come out green with no new allowlist entry beyond the ones 0.6 makes unnecessary. A hit that is a legitimate compatibility name (the checkpointing channels) gets an allowlist entry with that reason.

## Area A: small production edits

Each is its own commit, test-first, with the test edits the new name or signature forces.

### A1. One census path

`CENSUS_PATH = REPO_ROOT / "evals" / "census.json"` is defined three times (`evals/run_census.py:51`, `evals/run_detection_holdout.py:59`, `evals/cve/nuisance/commands.py:16`) and pinned equal by `tests/unit/census/test_census.py:25` (`test_every_command_reads_the_committed_census_by_default`), which loads the committed census three times. Define `CENSUS_PATH` once in `evals/cve/census/census.py` from its own `__file__` (`Path(__file__).parents[2] / "census.json"`, so the census module does not import the auditor through `evals.honeypots`), import it in the three commands and in `tests/unit/support/test_nuisance_committed_admission_given.py`. The test becomes `test_the_committed_census_loads`, over the one constant.

### A2. Named bounds read by the tests

- `_ANTHROPIC_MAX_OUTPUT_TOKENS` in `src/mcp_auditor/adapters/chat_model_factory.py` becomes public `ANTHROPIC_MAX_OUTPUT_TOKENS`, read by `tests/unit/auditor/test_chat_model_factory.py:56` instead of `16384` (the literal that had to follow the bound when it moved from 8192).
- The bare `200` of the response snippet at `src/mcp_auditor/graph/chain_prompts.py:180` becomes `RESPONSE_SNIPPET_LENGTH`, read by `tests/unit/auditor/test_chain_prompts.py::test_bounds_each_error_and_keeps_the_response_snippet` instead of `response[:200]`. The model-inputs golden stays green without regeneration.

### A3. The current fingerprint of each holdout calibration copy

`tests/unit/support/test_nuisance_committed_admission_given.py:22` (`current_copy_fingerprints`) is a line-for-line copy of `evals/run_nuisance.py:289-294` in `_refuse_stale_holdout_calibration_copies`, so a change to how the run resolves copies would leave the test checking the old rule. Extract `current_copy_fingerprints(draw: DrawRecord | None) -> dict[str, str]` as a public function of `evals/run_nuisance.py`, called by `_refuse_stale_holdout_calibration_copies` and by `tests/unit/nuisance/admission/test_nuisance_admission_loads.py:31`, and delete the given's copy. It stays out of `evals/cve/nuisance/admission/holdout_calibration_copies.py`, which imports neither `HOLDOUT_TARGETS` nor the fingerprint code and stays pure.

## Area B: the auditor (product) tests

All paths under `tests/unit/auditor/` unless absolute.

### B1. A real response resets the timeout count (coverage hole)

Add `test_a_real_response_resets_the_timeout_count` to `test_server_watch.py`: `TIMEOUTS_IN_A_ROW - 1` timeouts on a tool, a real answer, `TIMEOUTS_IN_A_ROW - 1` timeouts again, then the tool has no unsent cause. Shown red by deleting `self._timeouts[tool_name] = 0` in `ServerWatch._answered`, then restored. The existing `test_a_real_response_resets_the_counts_and_forgets_the_tool_stopped_before` checks only the relaunch count and the stopped-last memory: rename it `..._resets_the_relaunch_count_and_forgets_the_tool_stopped_before`.

### B2. The watch's counts through their constants

`TIMEOUTS_IN_A_ROW` (3) and `RELAUNCHES_IN_A_ROW` (2) are restated as literals in `test_server_watch.py:50,52,56,59,67,69,78,79,82,90,95,103,106-107,125,129`, `test_audited_server.py:127-139`, `test_graph.py:341-345` (`test_a_tool_timing_out_three_times_...`, `num_cases=3`, `test_budget=3`), `support/test_chain_nodes_given.py:117` (docstring) and the counts of `test_relaunch_rendering.py:65-66,89`. Use `given.timeouts_on(watch, tool, TIMEOUTS_IN_A_ROW)` and `TIMEOUTS_IN_A_ROW - 1`, add `given.relaunches_in_a_row(watch, tool)` to `support/test_server_watch_given.py`, take the graph budget and the audited server loop count from the constant, and rename the tests to say "in a row" instead of the number. `test_relaunch_rendering.py` owns the labels, so it keeps their wording spelled out and only its counts go through the constants.

### B3. Callers compare against the label owners

Rewording a label today turns red its owner's test plus three files that only print it. Assert `f"run_command: {describe_relaunch(lost)}"` in `test_stream_handler.py::test_each_relaunch_is_reported_once_...`, `UNSENT_CAUSE_LABELS[cause]` in `test_stream_handler.py::test_cases_not_sent_advance_the_progress_bar_to_its_end` and in `test_progress.py` (`test_tool_progress_reaches_its_end_on_cases_not_sent_...`, `test_ci_progress_names_the_cause_...`), `describe_coverage_gap(gap)` in `test_console_display.py::test_summary_warns_about_the_calls_not_sent_to_a_tool_as_a_coverage_gap`, and `str(PromptTooLong(usage))` in `test_missed_model_calls.py:75`. `PROMPT_TOO_LONG_MESSAGE` of `support/test_rendering_given.py` becomes a neutral detail string, since any string serves there.

### B4. The bounded context keeps the most recent items

`test_attack_context.py:175` (`test_a_carried_context_over_every_bound_comes_back_within_them`) checks upper bounds only, so a merge that empties an over-long carried list passes. In `support/test_attack_context_given.py:13-20` (`a_context_over_every_bound`), derive the over-bound sizes from the constants (`MAX_LIST_ITEMS + 10` instead of 40 and 45), and assert that the last `MAX_LIST_ITEMS` items are the ones kept (of the items within `MAX_ITEM_LENGTH`: `_merge_list` drops an over-long item before it keeps the last `MAX_LIST_ITEMS`, and `exposed_internals` ends with one) and that the over-long `db_engine` is dropped. Notes are left out: `test_the_oldest_notes_are_evicted_past_the_bound` already covers their eviction.

### B5. Audited server: outcome over the timeout ping count

The control ping counts (one per session, none for a blocked payload, one after a relaunch) are what the server receives and stay as a protocol spec. Only `pings == 4` with its comment in `test_audited_server.py:139` counts a mechanism: rewrite that test on its outcome (the tool is stopped after `TIMEOUTS_IN_A_ROW` calls, with B2's constant) and drop the ping count.

### B6. Audited server vocabulary shared by three test files

"A server taken as down" and "a stopped tool" are set up in `support/test_nodes_given.py:130-137` (`a_server_taken_as_down`), `support/test_chain_nodes_given.py:98-122` (the same body plus `a_server_that_stopped`, `a_server_losing_its_connection`) and inline in `test_audited_server.py:172-187`. Move the three builders to a non-given module `support/audited_servers.py`, used by the three. `support/test_server_watch_given.py:4-8` (`TIMEOUT`, `LOST_CONNECTION`) uses the fake's builders, and `tests/fakes/mcp_client.py::a_lost_connection_response` is built from `LOST_CONNECTION_RESPONSES[0]` instead of restating `("McpError", "Connection closed")`.

### B7. Chain node tests assert one node at a time

`test_chain_nodes.py:186-234` (`test_a_step_not_sent_after_steps_were_made_judges_them`, `test_a_first_step_not_sent_records_no_chain_and_counts_it`, `test_a_step_followed_by_a_relaunch_ends_the_chain_unobserved`) and the `route_after_execute` assertions of `test_nodes.py`'s `test_a_case_not_sent_is_counted_apart_and_not_judged` and `test_a_case_followed_by_a_relaunch_is_judged_and_the_relaunch_kept` rebuild a graph path by merging `{**state, **result}` by hand, standing in for the reducers. Trim each to single-node assertions: what execute returns, what the router returns for a given state, what the judge records from a state holding the executed steps. The one path not covered end to end, "the server goes down mid-chain and the executed prefix is judged", moves to `test_graph.py`.

### B8. `graph/unsent_calls.py` gets its own test file, and the oversized files split

- `TestReportToolsLeft` (from `test_nodes.py`) and `TestCountChainsNotPlanned` (from `test_chain_nodes.py`) move to a new `test_unsent_calls.py` with its own given, holding what the moved tests set up (their tools, tool report and chain audit state), the servers coming from B6's `support/audited_servers.py`. The three `build_tool_report` gap tests stay in `test_nodes.py`, since they test through the node, and `a_tool_state_with_calls_not_sent` stays in `support/test_nodes_given.py`: only those tests use it, and the new file does not import another test file's given.
- `test_rendering.py` (664 lines): the execution record tests (`test_markdown_shows_a_confined_execution_...` through `test_json_execution_is_null_...`) move to `test_execution_rendering.py`, the missed model call and completeness tests to `test_missed_model_call_rendering.py`, each with its slice of `support/test_rendering_given.py` (465 lines).
- `test_graph.py` (402): the four ADR 036 tests and their givens (`a_server_timing_out_on`, `a_server_dying_on*`, the three relaunch `a_fake_llm_for_*`) move to `test_graph_relaunch.py` with its own given, which also relieves `support/test_graph_given.py` (394).
- `test_prompts.py` (328): the context extraction prompt tests move to `test_context_extraction_prompt.py`.
- `test_server_execution.py` (376): the `decide_launch` tests move to `test_launch_decision.py`.
- `test_llm_adapter.py` (302) stays.

### B9. Names, givens and tables

- `test_nodes.py::test_a_tool_stopped_at_its_last_call_with_no_chain_budget_has_no_gap` builds a cause with no call withheld and no chain budget key: rename it `test_a_cause_with_no_call_withheld_leaves_no_gap`, rename the given `a_tool_state_with_calls_not_sent` to `a_tool_state` (it is called with none), and build the expected gap of `test_merges_a_short_generation_...` as `given.a_coverage_gap().model_copy(update=...)` instead of restating 5, 3 and `RESOURCE_ABUSE`.
- `test_container_name.py:6-28` (`test_declared_container_name`, 16 rows): give every row a `pytest.param(..., id=...)` naming its rule (a name after the image belongs to the server, `-e` swallows a following `--name`, an unknown option makes the name undecidable, `container run` is not read, `--name=` clears the name, and so on).
- `support/test_cli_given.py:7-38` (`a_report` with five flag arguments, where `calls_not_sent` silently overrides `coverage_gap`): replace with named givens `a_report_with_a_finding(severity)`, `a_report_with_calls_not_sent()`, `a_relaunched_report()`. The gap of calls not sent, built four times (`_a_gap`, `support/test_console_given.py::a_report_with_calls_not_sent_on_get_user`, `support/test_relaunch_rendering_given.py::a_gap_with_calls_not_sent`, inline at `test_relaunch_rendering.py:79,94`), becomes one `a_gap_with_calls_not_sent(cause)` in a non-given module `support/coverage_gaps.py` used by the four.
- `test_shown_response.py`: `10_000` at lines 23-26 becomes `MAX_SHOWN_LENGTH // 2`, and line 35 (`[30000 ...]`, already asserted by `then.shows_cut`) goes. `test_rendering.py::test_markdown_tool_section_counts_its_responses_shown_cut` uses `f"{MAX_SHOWN_LENGTH:,}"`.

### B10. Deletions and the misplaced export test

- `test_prompts.py::TestContextExtractionPrompt::test_no_longer_asks_to_preserve_previous_findings` (asserts the word "findings" is absent, named after a past prompt): delete. Covered by `test_asks_to_repeat_a_confirmed_item_in_the_same_words` and the `extraction/*` keys of the model-inputs golden.
- `test_export.py` with `support/test_export_given.py` and `support/test_export_then.py` test only `evals/` code: move them unchanged to `tests/unit/evals/` and its `support/`.

## Area C: detection tests

All paths under `tests/unit/detection/` unless absolute.

### C1. Builder-keyed backend sources

The five per-target "fingerprints its backend module" tests of `test_detection_holdout_targets.py:134-172` (doris, n8n, kubectl, mcp_ssh, searxng) look up drawn flaw IDs with `next()`, and the ckan target is not covered. Replace them with one parametrized test over the builder-keyed table of D7 (`tests/unit/support/audited_launch_builders.py`), whose backend-sources column holds `{doris_db_env: {doris}, ssrf_redirect_env: {n8n_instance}, kubernetes_injection_env: {kubernetes, kubernetes_detection, backend_beside_launch}, mcp_ssh_injection_env: {mcp_ssh_holdout, backend_beside_launch}, searxng_env: {searxng}, ckan_ssrf_env: {ckan_holdout, ckan, doris}}`: for every acceptance and holdout target whose builder is in the column, the entry is a subset of `backend_sources`. The `CONTROL_PLANE_SERVICE` and `SEARXNG_SERVICE` image assertions become an image column of the same table. D7's guard (every builder a target uses is in the table) keeps the table from going vacuous. Lands after D7.

### C2. Duplicates and tests that cannot fail

- `test_detection_holdout_targets.py:89` (`test_every_target_declaring_stand_ins_lists_the_stand_in_image`) repeats `test_detection_baseline.py:94`: delete the new one and its comment.
- `test_detection_layout_check.py::test_an_unrouted_unkept_layout_place_adds_no_admission_failure` cannot see an unkept place (`layout_check` only receives kept records) and its other halves repeat two existing tests: delete. In `test_layout_check_reports_a_nonce_of_the_vulnerable_planted_arm_in_its_ordinary_surface`, drop the second assertion, which passes because `patched.nonces == {}`.
- `test_detection_holdout_card_readiness.py::test_a_check_without_a_rule_version_does_not_load` tests a required pydantic field: delete.
- `test_detection_gate.py::test_the_gate_outcome_is_the_shared_gate_outcome` repeats `test_green`: delete. `test_a_gated_miss_waits_for_its_retests` (asserts the JSON string `"pending_retest"`) folds into `test_a_gated_target` as the case `([MISSED] * 3, TargetOutcome.PENDING_RETEST)`.
- The stale sentence around `test_detection_holdout_targets.py:222` ("trivially satisfied while the tuple is empty") goes.

### C3. Layout failure wording through its owner

`layout_failure` owns the layout failure texts and `test_detection_layout_check.py` specifies each. `test_detection_holdout_pre_run_check.py:65` compares against `layout_failure(target, given.LEAKING)` instead of the spelled reason. In `test_detection_session.py`, `test_a_target_the_layout_breaks_under_the_normal_launch_is_not_run` compares against `layout_failure(...)`, and `test_a_layout_failure_refuses_a_recording_before_any_audit` asserts the flaw ID is in the reason instead of `"layout breaks"`.

### C4. CLI tests observe what their names promise

- `test_run_detection.py::test_the_calibration_check_runs_on_every_target_or_on_the_flaws_named` asserts only exit 0, since `deps_with()` ignores the targets: give it a `deps_with` that records the targets it receives, and assert every acceptance ID with no flag and only `RECORDED_FLAW` with `--flaw`.
- `test_run_detection.py::test_a_no_baseline_run_compares_nothing_and_exits_0` checks "compares nothing" inside its own fake. Nothing else checks that `main` passes `--no-baseline` into `DetectionOptions.no_baseline`: rewrite it to record the options the fake `run_gated` receives and assert `no_baseline is True` and exit 0, renamed `test_the_no_baseline_flag_reaches_the_session`.
- `test_run_detection_holdout.py::test_the_calibration_check_takes_one_flaw` passes only an unknown flaw: draw two targets, install a calibration check that keeps the targets it checks, pass `--flaw <first>`, assert only the first was checked. The unknown-flaw case is renamed `..._on_a_flaw_not_drawn_...`.
- `test_detection_audit.py::test_a_server_taken_as_down_on_a_holdout_run_is_a_launch_failure_retried` stays green with a single attempt (retries are covered in `test_detection_holdout_audit.py`): rename it `..._drops_the_run_as_a_launch_failure`.

### C5. Replay givens and thens

- `support/test_detection_replay_then.py:11`: every caller passes `REPLAY_ATTEMPTS` as `attempts`, so the then reads the constant and drops the parameter.
- `support/test_detection_replay_given.py:66` (`a_response`) copies `tests/unit/cve/support/test_cve_server_health_given.py::a_response`, and `calls()` builds `a_response(None, "ok")`, the given's own `OK`: `calls()` uses `OK` and `a_response` goes.
- `test_detection_replay.py:60` (`..._unchecked_without_launching`) observes "without launching" only through the Docker tripwire and builds its run inline from `ACCEPTANCE_TARGETS[0]`: build it as `dataclasses.replace(given.a_detecting_run(), recorded_calls=given.calls("/outside/wrong"))` with `patched = given.APatchedVersion([])` passed in, and assert `patched.launches == []`.
- `test_detection_replay.py:90` (`test_the_patched_launch_carries_a_container_name`) asserts `launch.args[:2] == ["run", "--name"]`: assert `isinstance(declared_container_name(launch.args), str)`.

### C6. Coupling to argv order and to committed data

- `test_detection_targets.py:283-287` reads the second `--network` by chained `args.index`: use `CONTROL_PLANE_NETWORK in values_after(args, "--network")` and `value_after(args, "-w") == PROJECT`; `:267` uses `evals.cve.layout.PROJECT` instead of `"/srv/app"`.
- `test_detection_preflight.py::test_expected_services_carry_the_stand_in_only_while_a_target_declares_one` assumes the fetch target is the only one with a stand-in: filter on `t.planting_host.public_names.stand_ins` instead of `FETCH_ID`.
- `test_detection_calibration_check_exit.py:8-9` builds a real target and loads the committed places at import time, both ignored by `deps_with`: pass `[]` and `{}`.
- `test_detection_holdout_run.py:107` builds `ServerHealth(0, 0, 1, 4, 2)` positionally: use keywords.

### C7. Holdout report test and oversized files

- `test_detection_holdout_report.py:199-252` (`test_a_target_line_keeps_its_disclosure_date_and_the_facts_of_each_run`) spells every `TargetRunLine` field, so each new health field rewrote three literal blocks: compare only the per-run facts the name promises. The cutoff tests (lines 391-457) move to `test_detection_holdout_report_cutoff.py`. They use `_target` and `_run_result` too, so those two go to a named non-given `support/holdout_report_runs.py` read by both files, while `_with_incidents` and `_run_with_incidents` move to a new `support/test_detection_holdout_report_given.py`, where the "Incomplete runs" heading is stated once.
- Files over 300 lines that grew again split along the seams they have: `test_detection_holdout_run.py` (459: pre-run check and second pass to `test_detection_holdout_run_pre_run.py`, container hygiene to `test_detection_holdout_run_containers.py`), `test_detection_audit.py` (452: the holdout and taken-as-down tests to `test_detection_audit_holdout.py`), `test_run_detection.py` (343: the recording and confirming-command tests to `test_run_detection_recording.py`), `test_detection_session.py` (386: the recording tests to `test_detection_session_recording.py`). Each split takes its slice of the given. `test_detection_oracle.py` (392), `test_detection_targets.py` (342) and `support/test_detection_baseline_given.py` (318) grew by ten lines or less and stay.

## Area D: CVE benchmark tests

All paths under `tests/unit/cve/` unless absolute. Order inside the area: D1 first (its support modules serve D2, D3 and D7), then the rest.

### D1. Shared launch and Docker vocabulary

- The generic planting specs "with a holder", "without a holder" and "with no network" live in `backends/support/test_kubernetes_backend_given.py` and are borrowed by `backends/test_mcp_ssh_holdout_builder.py:6`: move them to a non-given module `backends/support/backend_launch_specs.py`.
- The doris launch fakes (`doris_helpers_faked`, `a_minimal_doris_spec`), used by three files through `backends/support/test_doris_serialization_given.py`, move to a non-given `backends/support/doris_launch.py`, and `backends/test_doris_backend.py:10`'s private `_strip_pair` moves with them.
- `backends/support/test_audited_launch_names_given.py:8-13` stops importing five other givens: it builds its launches from these modules and from D7's registry.
- `tests/fakes/scripted_docker.py::ScriptedDocker(answers: Mapping[tuple[str, ...], str])` records commands and inputs, answers by command prefix, exposes `started()`, `created_networks()`, `removed()` and `installed(monkeypatch)`, with a `CLOSED_NETWORK_INSPECT` answer, exported from `tests/fakes/__init__.py`. Its `run(args, *, input=None)` takes the shape the follow-up plan's Docker command port will have, so that plan swaps the patch for an injection without rewriting the fake. It replaces `FakeGitLabDocker` (`backends/support/test_gitlab_backend_given.py:18-91`) and `FakeControlPlaneDocker` (`backends/support/test_kubernetes_backend_given.py:26-84`) and the three `_a_closed_network` copies. `FakeDorisDocker` (`backends/support/test_doris_seed_given.py:26-77`) is stateful and keeps its own class, taking only `CLOSED_NETWORK_INSPECT`. `RecordedDocker` (`backends/support/test_ckan_holdout_builder_given.py:63-77`) and `FakeDocker` (`backends/support/test_mcp_ssh_holdout_builder_given.py:55-69`) are replaced by `tests/unit/support/recorded_subprocess.recorded_commands(monkeypatch)`.

### D2. `launch_beside_backend` tested once

`evals/cve/backends/backend_beside_launch.py::launch_beside_backend` is tested only through its two wrappers, twice, with two fakes that are one class (`FakeControlPlane` and `FakeSshd`). Add `backends/test_backend_beside_launch.py` with its given, driving `launch_beside_backend` with one `FakeBackendStand` whose `stand` yields an object exposing `network` and `mount_args()` (`StoodSshd` has that shape): the holder joins the backend network, the backend network is the second network when there is no holder, the holder is removed before the backend, and the layout is mounted read-only (`:ro`, which the mcp_ssh test checked only for presence). Then delete the four copied tests in `backends/test_kubernetes_backend.py:71,82,99,111` and in `backends/test_mcp_ssh_holdout_builder.py:73,96,115,127`, with `FakeControlPlane.planting` and `FakeSshd.planting`. Each wrapper file keeps what its wrapper adds: kubernetes the `has_network` refusal and the fix-check launch, mcp_ssh the refusal, the root owner and the known_hosts mount.

### D3. Per-launch backends in the registry tests

`backends/test_backend_lifecycle.py:117,133` run over `given.shared_keys()` only, so gitlab, kubernetes and node_sandbox_engine rewrite the server checks file by file. Run both tests over `sorted(BACKENDS)` through `given.through_the_kit(given.a_lifecycle_without_side_effects(key))` (the quiet kit launch of each per-launch backend already carries the memory bound, the resolver option, the confinement, the unprivileged user, the working directory, `--rm` and the `[image, *server_launch]` tail), asserting the network and the name with `startswith(BACKENDS[key].network)` (a per-launch network is `<prefix>-quiet`, the engine's is `none`). Then delete `backends/support/test_gitlab_backend_then.py:31-36` (`the_server_is_confined_as_the_hosts_user`), `backends/support/test_node_sandbox_engine_then.py:23-27` (`the_server_runs_its_image_as_the_hosts_user`) and `backends/support/test_httpbin_backend_then.py:24-28` (`runs_its_image_as_the_hosts_user`, httpbin being a shared backend already covered), and the tests using them. Per backend, only what its module does on its own stays: gitlab's token and failed reconfigure, the engine's socket and socket directory, kubernetes' kubeconfig. The "two launches stand two backends" and "removed when the body raises" tests stay per backend (their fakes differ).

### D4. Every backend container in one hardening test

The test named for "every built backend container" (`backends/test_backend_lifecycle.py:216-246`) keeps a hand list that leaves out the httpbin parts, n8n, the gitlab container, the control plane and the engine, which get partial copies elsewhere. Add `every_backend_container_argv()` to `backends/support/test_backend_lifecycle_given.py`, built from the existing run-args functions (`doris_cluster_run_args()`, `part.run_args()` for the ckan, gravitino and httpbin parts, `singleton_run_args()`, `gitlab_run_args(name, network)`, `control_plane_run_args(name, network)`, `engine_run_args(name, directory)`, n8n's `n8n.singleton_run_args()`, the jenkins controller's, and `searxng_args(name, ["--network", "container:<holder>"])`, the holder join production passes it, since the searxng target declares a stand-in and so always plants a holder), keyed by a readable id. One parametrized test asserts on each: `carries(args, memory_bound_args())`, the resolver option or the `none` network, `carries(args, confinement_args())`, and no `--cap-add`. Explicit expected exceptions, each with its reason in the test data: the Doris all-in-one cluster carries the memory bound and resolver only (no hardened options were measured for it, see Out of scope), GitLab CE carries its own hardening and the capabilities its start needs (its then keeps those checks, minus the memory line), searxng carries its own hardening (`--cap-drop ALL`, `no-new-privileges`, its own pids limit) instead of `confinement_args()`, and no resolver option, since it joins the holder's network namespace and reads the holder's `resolv.conf` (the resolver Landmine of `CLAUDE.md`). Then delete the sshd hardening test of `backends/test_backend_hostnames.py:110`, `test_the_jenkins_controller_drops_every_capability_and_bounds_its_processes`, both `carries_the_hardening_with_no_capability` thens (`backends/support/test_httpbin_backend_then.py:41-47`, `backends/support/test_node_sandbox_engine_then.py:39-44`), the memory lines of `backends/support/test_kubernetes_backend_then.py:17-31`, `backends/support/test_gitlab_backend_then.py:19-27` and `backends/test_searxng_backend.py:23`, the loop of `backends/test_httpbin_backend.py:23`, and `test_no_ckan_backend_container_is_granted_a_capability` (from the nuisance registry file, see E6). Shown red by removing the memory bound from one container's run args.

### D5. The memory bound through its constant

`"4g"` is restated at `test_cve_planting.py:378,391,392`, `test_cve_planting_stand_ins.py:69`, `test_cve_launches.py:102`, `backends/test_backend_hostnames.py:117` and `backends/support/test_httpbin_backend_then.py:46`. One test, `test_the_confinement_bounds_memory_with_no_swap`, pins the value as `(MEMORY_BOUND, MEMORY_BOUND)` and keeps one literal `"4g"` check, since `CLAUDE.md` documents that value. Everywhere else assert `carries(args, memory_bound_args())`. `support/test_cve_planting_then.py`'s `memory_bound_in` goes, and `resolver_options_in` becomes `docker_argv.count(argv, resolver_args())`. The integration counterpart is F5.

### D6. Constants equal to their own literal

Delete the equality lines that hold by construction, keeping the ties between two files: `backends/test_httpbin_backend.py:29` (`HTTPBIN_FRONT_IP`) goes and `backends/support/test_httpbin_backend_then.py:20` reads `HTTPBIN_FRONT_IP`; `backends/test_backend_hostnames.py:44` becomes "the `--gravitino-uri` host is the alias of a `GRAVITINO_PARTS` member"; `backends/test_facebook_ads_backend.py:32` (`FACEBOOK_ADS_CA_BUNDLE`) and `backends/test_mcp_ssh_holdout_builder.py:93` (`KNOWN_HOSTS`) go; `backends/test_apify_backend.py:27` (`test_the_token_is_the_readme_placeholder`) goes, the kind of env-literal test the previous plan deleted; `backends/support/test_gitlab_backend_then.py:23,26,59` reads `GITLAB_PIDS_LIMIT` and `GITLAB_SHM_SIZE` and the token-length line goes; `backends/test_searxng_backend.py:32` goes. The mcp-ssh constants (`SSH_CONFIG_HOST`, `SSHD_ALIAS`, `SSHD_PORT`, `backends/test_backend_hostnames.py:82,85-86`) are handled in D8.

### D7. One registry of audited launch builders

"Every builder" is split over two hand lists (`test_cve_launches.py:57-73` `_LAYOUT_BUILDERS`, `backends/support/test_audited_launch_names_given.py:102-113` `unnamed_launch_builders`), the backed builders get only the name test, and each backed builder's file restates part of the launch checks (`backends/test_doris_backend.py:16-25`, `backends/test_ckan_holdout_builder.py:24-30`, `backends/test_searxng_backend.py:57`, `backends/test_mcp_ssh_holdout_builder.py:106-112`). Create `tests/unit/support/audited_launch_builders.py` (cross-area: C1's detection test reads it, so it sits in `tests/unit/support/` per `CLAUDE.md`), a table keyed by builder function (`Target.builder`), each entry a context manager that yields the launch argv on fakes (the ten layout builders, `ssrf_redirect_env` among them, and the five backed ones reusing the fakes of `unnamed_launch_builders` and D1's modules), with C1's backend-sources and image columns. Parametrize over it the memory bound, the readable container name and the layout mounted `:ro`, plus the user and working directory where the spec sets them: the readable-name test in `backends/test_audited_launch_names.py` and the others in `test_cve_launches.py`, the two files the `CLAUDE.md` Landmine names as reading every builder's argv, so that Landmine stays true. Add the guard `{t.builder for t in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)} <= set(table)`, shown red by removing one builder from the table. Two hand lists also cover builders no target names, and their rows move to the module beside the table rather than going: the five kit builders of `_LAYOUT_BUILDERS` (`kit_launch.filesystem_env`, `git_init_traversal_env`, `command_injection_env`, `ssrf_env`, `arcadedb_env`, the launches a calibration kit runs, kept under the `:ro` layout check), and the nuisance `single_container_run_args` and `single_container_launch_args` of `unnamed_launch_builders` (kept under the readable-name check). The guard reads only the target builders, so these rows stay listed by hand. Then delete the doris and ckan confinement tests, `test_the_holdout_launch_mounts_the_layout`, searxng's `WORKSPACE` line, and `_LAYOUT_BUILDERS` and `unnamed_launch_builders`.

### D8. mcp-ssh backend facts in their own file

`backends/test_backend_hostnames.py:71-117` and `backends/support/test_backend_hostnames_given.py:65-125` grew the mcp-ssh key pairing, the sshd account, the config entry and a 60-line OpenSSH wire parser, beyond the file's subject (no value reaching an admitted server names the audit). Move them to `backends/test_mcp_ssh_sshd_backend.py` with its given. There, `SSH_CONFIG_HOST == "production"` and `SSHD_ALIAS == "prod.example.com"` give way to the ties `carries(singleton_run_args(), ["--network-alias", SSHD_ALIAS])` and `test_the_mcp_ssh_config_is_the_readme_production_entry` (`Hostname == SSHD_ALIAS`), and `test_the_mcp_ssh_benign_calls_name_the_config_host`'s `len(aliases) == 6` becomes `aliases and set(aliases) == {SSH_CONFIG_HOST}`. Lands before D2 and E3.

### D9. The trust of the fixture authority checked once

The same three-step check (an environment variable names `/etc/ssl/extra-ca.pem`, the authority of the host's stand-in files is mounted there read-only, no skip-verify variable) is written in `backends/support/test_httpbin_backend_then.py:31-33`, `backends/support/test_ckan_holdout_builder_then.py:15-19`, `backends/test_searxng_backend.py:38`, `backends/test_facebook_ads_backend.py:28` and `backends/test_apify_backend.py:20` (which only checked that the variable is set). One `trusts_the_fixture_authority(args, variable, host)` in a non-given `backends/support/fixture_authority.py`, used by the five and by the ckan trust test moved from the nuisance registry file (E6).

### D10. Small fixes

- `backends/test_kubernetes_backend.py:14` and `backends/test_mcp_ssh_holdout_builder.py:30` cannot fail on their assertions (`import_closure` raises first on an `mcp_auditor` module): replace both with one test parametrized over `sorted(BACKENDS)` that calls `import_closure([f"evals.cve.backends.{key}"])`, the raise being the check, in `test_cve_dossier_closure.py`. It does not depend on which backends the committed admission uses.
- `test_committed_stand_ins.py:30` asserts over an empty set (no committed host is an IP literal) and is implied by the test at line 20: delete. The test at line 47 skips with "no committed stand-in host is an IP literal" while none exists. The `if not authority.exists()` branch of `support/test_committed_stand_ins_given.py:47-49` goes, so a missing authority fails loudly.
- `test_cve_server_health.py:16` (`test_no_incidents_counts_nothing`): delete, `test_healths_add_up_count_by_count` fixes every field at 0.
- `test_cve_launch_audit.py:22-31` drops its `server_command` line (the second test owns that spec) and asserts `test_budget == given.BUDGET`, exposed by `support/test_cve_launch_audit_given.py`.
- `backends/support/test_ckan_holdout_builder_given.py:16-18` and `backends/support/test_searxng_backend_given.py:12-14` call `TARGET.planting_spec(kept_records(TARGET.kept_places, load_places(DETECTION_PLACES)))` instead of re-implementing `kept_records`.
- `backends/test_ckan_holdout_builder.py:38-39` derives the expected events and sentinel hosts from `given.the_targets_spec()` instead of copying the target's kept places.
- `test_cve_keyed_stand_in_routes.py:77-78,90` drops its `beside_a_form_field` case (the validator never reads the identifier; `test_cve_public_stand_ins.py:150` owns it).
- `test_cve_public_stand_ins.py:42` (`test_a_route_keyed_by_the_old_target_is_refused_naming_it`, a migration check of a landed rename): delete. The `source` Literal test at `:134` stays, it pins the documented contract.
- `test_cve_launches.py::test_the_houtini_fixture_puts_its_two_environment_variables_before_the_image` stays green with an `-e` removed: assert `environment(launch.args[:image])` holds both pairs.
- `backends/support/test_ckan_holdout_builder_given.py:53` (`a_ckan_docker`) and `backends/support/test_searxng_backend_given.py:45` (`a_searxng`) wrap a constructor: inline them.

### D11. Oversized files

`test_cve_planting.py` (530 lines) splits by subject: the confinement, resolver and memory tests to `test_cve_planting_confinement.py`, the host files and cleanup tests to `test_cve_planting_host_files.py`, the holder and sentinels staying. `test_cve_public_stand_ins.py` (314) moves its keyed and form-field load tests to `test_cve_keyed_stand_in_routes.py`.

## Area E: nuisance tests

All paths under `tests/unit/nuisance/` unless absolute.

### E1. One scripted benign-call fake

The second pass brought the same scripted fake into `support/test_nuisance_run_given.py:163-182` (`deps_auditing`), `support/test_nuisance_vet_given.py:23-56` (`deps_on`), `gate/support/test_nuisance_gate_session_given.py:61-82` (`a_harness`) and `support/test_nuisance_vetting_given.py:31-60` (`ScriptedVet`). Add `tests/fakes/benign_call.py::ScriptedBenignCall(reasons: Mapping[str, str | Sequence[str | None] | None])`, recording `calls` per package, exported from `tests/fakes/__init__.py`. The three givens use it, `ScriptedVet` wraps it for its event list.

### E2. Exit reason texts through `EXIT_REASON_TEXTS`

`evals/cve/nuisance/exits.py::EXIT_REASON_TEXTS` owns the texts, restated in `admission/test_nuisance_admission_walk.py:89,106,120-126,140-147`, `test_nuisance_report.py:77-86,96-104`, `gate/test_nuisance_gate_console.py:64`, `gate/test_nuisance_gate_report.py:27` and `gate/test_run_nuisance_gate.py:65`. Use `EXIT_REASON_TEXTS[reason]` everywhere: the walk parametrization collapses to `reason`, the report's order test builds its rows from `ExitReason` in order, the pending test reads the last reason instead of naming "spent by a reading".

### E3. mcp-ssh fix-check tests

After D8 and D2. Delete the copies in `fix_checks/test_mcp_ssh_fix_check_builder.py:9-53` and `fix_checks/support/test_mcp_ssh_fix_check_builder_given.py:13-21`: `the_cve_2025_9654_fixture()` rebuilding `FIXTURES[0]` with its six literals, the two sshd tests (covered by D8's file), the witness-mount presence test (covered by `backends/test_mcp_ssh_holdout_builder.py`'s `mount_of` test), "five exploits and three benign calls" (the registry tests derive the counts), and `SSHD_ALIAS == "prod.example.com"`. Move the two fix-check tests of `tests/unit/cve/backends/test_mcp_ssh_holdout_builder.py:149-170` into `fix_checks/test_mcp_ssh_fix_check_builder.py`, built on `FIXTURES[0].planting_spec()`. Keep the network test (with `value_after`) and the injection-shape test.

### E4. Hand-built fix-check launches in one table

The jenkins and gravitino confinement checks (`fix_checks/test_jenkins_fix_check_builder.py:16-22`, `fix_checks/test_gravitino_fix_check_builder.py:16-31`, `fix_checks/test_mcp_ssh_fix_check_builder.py:17-24`) test token membership, so `--cap-drop NET_RAW ... ALL` passes, and the resolver table `_BUILDERS` of `fix_checks/test_fix_check_resolver.py:15-46` misses gravitino's `server_args`/`part_args` and `mcp_ssh_fix_check.server_args`. Rename the test file `fix_checks/test_fix_check_launches.py` with its given `fix_checks/support/test_fix_check_launches_given.py` holding `HAND_BUILT_LAUNCHES` (the old `_BUILDERS` plus the three missing builders, without the dead `_NO_PLANTING` and its `PlantedArgs` import). Parametrize over it twice: the resolver test, and `test_every_hand_built_fix_check_container_carries_the_confinement`, asserting `carries(args, confinement_args())` for every entry except `neo4j-database` (the exception the previous plan decided) and `set(values_after(args, "--cap-add")) <= {"NET_BIND_SERVICE"}`, empty for the `*-server` and `*-part` entries (every responder and sentinel binds a low port). Shown red by granting one server entry a capability. Then delete the three per-module confinement tests, and in the gravitino file `test_one_exploit_and_one_benign_call_per_counted_tool` (the literal 27), using `value_after` for its remaining argv reads.

### E5. Copies and committed-data couplings

- `test_nuisance_confinement.py:136-149` (`test_a_trust_setting_points_its_variable_at_the_mounted_fixture_authority`) checks only that the variable is set: rename it `test_a_trust_setting_carries_its_variable`, since `tests/unit/cve/test_cve_planting_stand_ins.py::test_a_trust_setting_mounts_the_authority...` covers the mount content. In the same file, `_holds` becomes `docker_argv.carries`, `args[args.index("--network")+1]` becomes `value_after`, and the four `single_container_launch_args` tests take their shared setup from `a_launch_serving(tmp_path, names, working_directory)` in a new `support/test_nuisance_confinement_given.py`.
- `admission/support/test_nuisance_re_admission_dossier_given.py:20-21,46-49`: `A_DRAWN_TARGET = "CVE-2026-85787"` and `ITS_SIBLING = "CVE-2026-87911"` are derived from the copy resolution, `next((sibling, drawn) for sibling, drawn in resolution.items() if sibling != drawn)`, in a given `a_drawn_target_and_its_sibling()` read by `a_server_copying_a_drawn_target_and_its_sibling` and `test_a_copy_on_a_drawn_target_and_its_sibling_resolve_to_one_target`. `the_copy_resolution` stays: it returns the copy-to-drawn-target map (`copy_targets` over the committed draw) that six call sites of `test_nuisance_re_admission_dossier.py` and its given pass to `holdout_target_references` and `re_admission_dockerfiles`, while A3's function returns fingerprints, not that map.
- `admission/test_nuisance_re_admission_dossier.py` (the n8n shared-helper test, about line 160) pins two module paths of one server: rewrite as a property over the committed admission, deriving the package's helpers as the modules of `evals.cve.nuisance.fix_checks` without `FIXTURES` (`pkgutil.iter_modules` over the package path) and asserting none appears in any committed server's `fix_check_modules`.
- `admission/test_nuisance_holdout_calibration_copies.py:15-19` (`test_each_drawn_id_points_at_itself`) and `test_nuisance_counting.py:48-54,166-171` (two effect-is-function tests) duplicate named sibling tests: delete.
- `test_nuisance_run.py:91-120` spells every status line `run_status.run_status_line` owns: build the expected lines with `run_status_line(...)`. `test_nuisance_run_status.py:24-25` reads `DROPPED_RUN_REASONS` instead of spelling the reason.
- `test_nuisance_vetting.py:39-46` asserts `connected.args[:2] == ["run", "--name"]`: assert `isinstance(declared_container_name(connected.args), str)`.
- `support/test_nuisance_solo_given.py:17-21` and `test_nuisance_solo.py:31-40`, `test_nuisance_run.py:21,97`: `MAGENTO2` reads `solo.SOLO_SERVERS`, and `calls=4` and `calls=6` are derived from the given's scripts. `test_vet_plays_a_heavy_backend_server_beside_the_others` stays as deliberate friction on the 16 November 2026 log decision, with a one-line comment saying so.

### E6. Backend tests out of the nuisance registry file

`test_nuisance_backend_registry.py:66-161,182-195` holds eleven ckan and n8n backend tests, a gitlab test (line 66) and a run test; the registry tests at lines 166 and 170 stay. The ckan capability test goes into D4's registry and the ckan trust test into D9's shared check. The other ckan tests move to a new `tests/unit/cve/backends/test_ckan_backend.py`, the n8n tests to `tests/unit/cve/backends/test_n8n_backend.py`, the gitlab test into `tests/unit/cve/backends/test_gitlab_backend.py` (its last line, `GITLAB_RESPONDER_ALIAS == GITLAB_HOST`, goes), and the two-image run test into `test_nuisance_run.py`. `test_the_n8n_registry_entry_builds_the_instance_and_serves_its_dockerfile` (restates a registry tuple) and `test_the_doris_cluster_is_reset_by_its_container_name` (a constant against what builds it) are deleted. Lands after D4 and D9.

### E7. Registry copies and constant tests

- `fix_checks/test_geekgod_fs_fix_check_builder.py:11-56`: `TOOLS` and `test_each_of_the_ten_tools_has_an_exploit_and_a_benign_call` repeat two registry tests, delete them. The scope tests and the modifying-exploit test with `MODIFYING_TOOLS` stay. `recorded` leaves `support/test_nuisance_fix_checks_given.py` for a named non-given `fix_checks/support/recorded_exchanges.py`, read by that given and by a new `fix_checks/support/test_geekgod_fs_fix_check_builder_given.py`, where `_record` (built on `recorded`) and `_path_values` move: a test file does not import another test file's given.
- `test_nuisance_run_containers.py:50-77`: the gravitino tag test restates what `test_a_backend_built_locally_names_the_compose_service_of_its_image` and `test_the_built_backend_tags_are_the_image_tags_of_their_services` cover, delete.
- `test_run_nuisance_run.py:154-159` uses `f"default {NUISANCE_RUNS}"`. `gate/test_nuisance_gate_baseline.py::test_the_baselines_live_under_evals_baselines_nuisance` (a constant against a path): delete. `test_nuisance_compose.py:38-48` derives the services the detection targets build as `{image for t in targets for image in t.images} & BUILT_SERVICES` instead of a hand list. `admission/support/test_nuisance_dossier_then.py:12-17` iterates `FlawClass` instead of listing class tokens, and drops the assertion that a removed phrase is absent.
- `test_run_nuisance.py:289,304`: the absent-admission and empty-admission tests become one parametrized test, as `fix_checks/test_nuisance_fix_check_command.py` already does. No production helper: the three commands' branches differ.

### E8. Structure

- `fix_checks/test_nuisance_fix_check_command.py:96-206` repeats a four-line setup eight times with private `_checking_with` and `_leftovers` in the test file: one `given.a_fix_check_ready(monkeypatch, fixture, result, networks)` absorbing both helpers, shaped so the follow-up plan can swap its patches for an injected deps object, and the Docker requirement text read from `evals.cve.run_images.DOCKER_REQUIREMENT`.
- `test_nuisance_holdout_servers.py:112-133`: `_listing`, `_walked`, `_admitted` and `_admitting` move to a new `support/test_nuisance_holdout_servers_given.py`. `admitting(*servers)`, for the three `an_admission().model_copy(update={"servers": ...})` sites, goes to the non-given `tests/unit/support/admission_mutations.py` of the next bullet, since several test files use it.
- Files past 300 lines: the `with_*` mutators of `admission/support/test_nuisance_admission_given.py` (397) move to a named non-given `tests/unit/support/admission_mutations.py`, beside `admitting` (vocabulary shared by several test files leaves the given, and `with_a_backend` and `with_host` are read by both the nuisance and the cve areas, so the module sits in `tests/unit/support/` per `CLAUDE.md`), the Exits and Not run tests of `test_nuisance_report.py` (381) to `test_nuisance_report_sections.py`, the benign-call and second-pass tests of `gate/test_nuisance_gate_session.py` (355) to `gate/test_nuisance_gate_benign_calls.py`, the dossier subcommand tests of `test_run_nuisance.py` (344) to `test_run_nuisance_dossier.py`. `test_nuisance_fingerprint.py` (305) stays.

## Area F: evals, census and integration tests

### F1. The committed honeypot and judge baselines

`tests/unit/evals/test_eval_baseline.py:202` and `tests/unit/evals/test_judge_baseline.py:115` (`test_the_committed_baseline_still_keyed_replay_rule_loads_and_gates`) first assert that the committed file still carries `replay_rule`, while both writers now write `retest_rule`: the next legitimate re-recording turns them red. Rewrite each on a temporary file: a given `a_baseline_file_keyed_replay_rule(tmp_path)` dumps `given.a_baseline()` with the key renamed, and the test asserts `load_baseline(path).retest_rule == RetestRule()` (same for the judge). The written-key tests at `test_eval_baseline.py:212` and `test_judge_baseline.py:126` assert `written["retest_rule"] == RetestRule().model_dump()` instead of restating the defaults. The `replay_rule` allowlist entries stay while the alias does. The entry scoped to `tests/unit/evals/test_*baseline*.py` does not match the new givens in `tests/unit/evals/support/` (`test_eval_baseline_given.py`, `test_judge_baseline_given.py`), which write `replay_rule`: widen its glob to `tests/unit/evals/*test_*baseline*.py` in the same commit, a scope change of an existing entry, not a new one.

### F2. Census and declared flips

- `tests/unit/evals/test_declared_flips.py:27` (`test_an_entry_names_its_instrument`, pydantic's enum parsing): delete, covered by `test_a_valid_file_round_trips`.
- `tests/unit/census/test_census_work.py:12` asserts the values its given wrote: rewrite as "a census whose drawn flaw's only calibrator record carries a fallback model loads", without the read-back. `:37` (`test_two_records_of_one_role_and_scope_with_no_fallback_read_as_two_agents`, `read_jsonl` and a default): delete. The remaining tests check `draw_record._agent_problems`, so the file and its given move to `tests/unit/detection/` (`test_detection_census_work.py`), which also ends the census given's import of a detection given.

### F3. Integration support shared once

- Three givens build the same unconfined `Audit` (`tests/integration/support/test_audit_server_failures_given.py:42` and `test_mcp_client_transport_given.py:169` `an_audit_of`, `test_resume_earlier_checkpoint_given.py:41` `an_audit_resuming`), and the support servers are launched from four places. Add the non-given modules `tests/integration/support/support_servers.py` (`a_read_server`, `a_stalling_server`, `A_COMMAND_NOT_FOUND`) and `tests/integration/support/unconfined_audit.py`, used by the three givens and `test_confined_launch.py:22`. What the three builders vary (model, output path, resume, tools filter) is one concept, the variant of the audit under test: the module defines a frozen dataclass `AuditVariant(llm, output, resume, tools)` with the defaults of the commonest caller, and `an_unconfined_audit(launch, variant=AuditVariant())` builds the fixed rest (`AuditRunOptions(budget=1, chains=0, ...)`, `ReportPaths()`, `CIOptions()`, `LaunchOptions(unconfined=True, ...)`, `ServerExecution(launch, FakeContainerRuntime(untouchable=True))`, the display). Each given passes `dataclasses.replace`d variants for what differs.
- The "skip, or fail under `CVE_PLANTING_REQUIRED=1`" branch is copied in nine files (`test_cve_planting_stand_ins.py:22`, `test_cve_keyed_stand_in_routes.py:21`, `test_nuisance_public_names.py:28`, `test_cve_planting.py:33`, `test_cve_layout_mount.py:24`, `test_cve_closed_networks.py`, `test_detection_calibration_check.py:282`, `test_kit.py:42`, `test_nuisance_doris_backend.py:49`). Add `skip_or_require(missing: str)` to a non-given `tests/integration/support/docker_prerequisites.py`, with `stand_in_prerequisites()` for the three identical stand-in fixtures, and use them in the nine.
- `tests/integration/support/test_mcp_client_transport_given.py:64` (`a_docker_on_the_host`) duplicates the `docker_on_the_host` fixture of `tests/integration/conftest.py:12`: the fixture returns the shim directory, the five transport tests use it, the given goes.

### F4. Integration names and size

- `tests/integration/test_nuisance_public_names.py:61` says the launch joins the holder but asserts only that the network is not `none`: assert `value_after(args, "--network").startswith("container:")`.
- `tests/integration/test_mcp_client_transport.py` (313 lines, three subjects): the ping, relaunch and declared-container removal tests move to `test_mcp_client_relaunch.py`, the four cancelled-caller tests to `test_mcp_client_cancellation.py`, each with its slice of the given.

### F5. The memory bound in bytes

`tests/integration/test_cve_planting.py:54` asserts `"4294967296 4294967296"`: derive the byte count from `MEMORY_BOUND` (a parse of its `g` suffix in the test's given) and assert that `MemorySwap` equals `Memory`. The test stays at integration level, the only one that reads a real container's `memory.max`, and keeps guarding the `--memory-swap` Landmine.

## What stays unchanged

- Every honeypot server, fixture, label, ground truth, baseline, golden master output and declared flip.
- Every module of the fingerprint tuples listed under Governance.
- The production behavior of every command, report and exit code. A2 and A3 change names and structure only.
- The integration test levels: no Docker test becomes a unit test or the reverse.
- `CLAUDE.md`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`: no command, flag, prerequisite or user-facing behavior changes.
- The tests kept on purpose: `test_detection_holdout_targets.py::test_only_the_desktop_commander_and_frogman_targets_settle_a_leak_at_calibration` (intended friction: a settled leak hides a nonce, the same reasoning as the read-write layout pin kept by the previous plan), the positive key half of the holdout result test, the control ping counts of `test_audited_server.py`, the `source` Literal test of the stand-ins, the per-command exit-0 tests of the nuisance commands, the unit `remove_backend_containers` tests.

## Out of scope

- **A follow-up plan: injection points instead of monkeypatch.** The `main(argv, deps)` seams of `run_detection`, `run_detection_holdout`, the honeypot suite, the judge eval and `draw_judge_cases`; the fix-check, vet, benign-call, run and gate command deps of the nuisance suite; the calibration check's `connect`; the console of `eval_display` and the auditor; the client's ping and teardown timeouts; the checkpoint path in `AuditConfig`; the benign probe's deps; `lifecycle_of`'s loader; the re-admission dossier's closure roots; the nuisance fixture fingerprint's inputs; and the LLM retry path's sleeper (`tests/unit/auditor/test_throttling.py` patches `asyncio.sleep`, a clock the standards ask to inject). Several of these, and the Docker command port that would replace the process-wide `subprocess.run` patches of the backends, the Doris clock, the holdout Doris launch's deps and `DockerPlanting`'s probe budgets and temp directory, touch fingerprinted modules (`gitlab.py`, `kubernetes.py`, `node_sandbox_engine.py`, `doris.py`, `mcp_ssh_sshd.py`, `closed_network.py`, `holdout_environments.py`, `planting_docker.py`), so that plan weighs each fingerprint move. The per-launch responder concept the previous plan deferred goes there too. This plan's `ScriptedDocker` and `a_fix_check_ready` are shaped so that plan replaces their patches without rewriting them.
- **Does not hold:** keying `InterruptedLLM`'s interruption on the schema instead of a call index (`tests/unit/auditor/support/test_checkpointing_given.py`): `FakeLLM` raises `TypeError` when a scripted answer does not match the asked schema, so a new model call kind turns those tests red loudly.
- **Fingerprinted, left alone:** a shared per-launch container helper for `gitlab.py`, `kubernetes.py` and `node_sandbox_engine.py` (all in `served`; D3 removes the test copies instead); one `authority_trust_args` for the six copies of the fixture authority path (`planting_stand_ins.py` and five backend modules, hashed; D9 removes the test copies); aligning `n8n_instance.py`'s removal to `docker rm -f -v` (a `backend_sources` member, and harmless today: the container runs with `--rm` and its image declares no volume).
- **A maintainer question, not a test fix:** the Doris all-in-one cluster runs without `--cap-drop ALL` and `no-new-privileges`, while the realism repairs of 13 November hardened every other backend from its measured start. D4 records it as an explicit exception. Hardening it means measuring its start under those options and moves the fixture fingerprints of the Doris targets and servers, which is a fixture repair of its own.
- **Not worth it now:** a production `admitted_or_say_none` helper for the three nuisance commands (their branches differ: the fix check also needs fixtures and sits outside the `with`, run and vet keep the walk inputs); merging the two equal `DROPPED_RUN_REASONS` tables of `evals/cve/nuisance/results.py` and `evals/cve/detection/holdout_results.py` (they key two distinct enums); trimming the nuisance run-level backend removal tests.
- **The moved-path patterns of the retired-word scan stay hand-kept.** Replacing `moved-module`, `moved-module-other`, `moved-test` and `_OLD_TEST_STEMS` by a check that every path or module a living text names resolves to a tracked file was weighed and left out: a dry run at d7dc9ef flags about 40 names that are not this repository's moved modules (dotted names ending in an attribute, a logger name, CHANGELOG's `(was ...)` rename entries, paths inside the audited servers' own repositories, the fake paths of two tests, `CLAUDE.md`'s illustrative `test_audit.py`), so the check would need either an exemption list of its own or a narrowing that leaves out much of what the patterns read today. A list of old names that grows by one line per rename costs less.
- **Grew by ten lines or less past 300, left as they are:** `test_llm_adapter.py`, `test_detection_oracle.py`, `test_detection_targets.py`, `support/test_detection_baseline_given.py`, `test_nuisance_fingerprint.py`.

## Verification

Each commit closes with the full check of `CLAUDE.md`:

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

Per area, beyond that:

- Area 0: the retired-word scan is green after 0.4, 0.5 and 0.6 with no new allowlist entry, and after 0.7 too. The fixture's setup time is measured before and after 0.7 (`uv run pytest tests/unit/project/test_glossary.py -n 0 --durations=3`). The test-name reading is shown red on a fixture tree whose test name carries a retired word, then reverted.
- Area A: `uv run pytest tests/unit/auditor/test_model_inputs_golden.py tests/unit/cve/test_cve_grammar_golden.py -n 0` green with no regeneration after A2 and 0.3. The fingerprint tuples are re-read before the first production commit (Governance).
- Area B: B1 is shown red with the timeout reset deleted in `ServerWatch._answered`, then restored. B4 is shown red with a merge that empties an over-long carried list.
- Areas C and D: each registry test (C1, D3, D4, D7, D10's closure test) is shown red on one hand-broken case before its copies go, and the commit message records the mutation.
- Area E: E4 is shown red by granting a `*-server` entry a capability.
- Area F: the integration files changed run with Docker (`uv run pytest tests/integration/test_cve_planting.py tests/integration/test_cve_planting_stand_ins.py tests/integration/test_cve_keyed_stand_in_routes.py tests/integration/test_nuisance_public_names.py tests/integration/test_cve_layout_mount.py tests/integration/test_cve_closed_networks.py tests/integration/test_detection_calibration_check.py tests/integration/test_kit.py tests/integration/test_mcp_client_relaunch.py tests/integration/test_mcp_client_cancellation.py tests/integration/test_mcp_client_transport.py tests/integration/test_audit_server_failures.py tests/integration/test_resume_earlier_checkpoint.py tests/integration/test_confined_launch.py -n auto`), with `CVE_PLANTING_REQUIRED=1` so a skip fails. The Doris backend test stays behind `NUISANCE_DORIS=1` and is run by hand only if its prerequisite branch changed shape.
- At the end: every new or split test file is under about 300 lines, `grep -rn "monkeypatch.setattr" tests` lists no new site (this plan adds no patch beyond `ScriptedDocker.installed` and `a_fix_check_ready`, which replace existing ones), and the unit suite's test count drops while its wall time drops by the scan's saving.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, one line each, read by later passes (the implementation-phase fact check among them). No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes its line here rather than updating it, so this section never asserts something nobody checked.

- SETTLED: argparse exits with code 2 on a flag or subcommand the parser does not declare (0.4) (verified on the project's Python 3.13.16, stdlib `argparse`)
- SETTLED: a pydantic model's `model_dump` carries only its declared fields, so a retired key cannot appear in `render_json` or the holdout result while no model declares it (0.5) (verified against `render_json` = `report.model_dump(mode="json")`, no `extra="allow"` in the dumped models, pydantic 2.14.1 locally)
- SETTLED: `MEMORY_BOUND = "4g"` is `4294967296` bytes, Docker's `g` suffix being 1024³ (F5) (verified against docker/go-units `RAMInBytes`, binary map `'g': GiB`; Docker's resource-constraints page names the suffixes without their base)
- SETTLED: `--memory-swap` equal to `--memory` gives the container no swap, so `MemorySwap == Memory` is the assertion F5 keeps (verified against docs.docker.com, engine/containers/resource_constraints)

## Implementation steps

### Conventions for every step

- **Order.** Steps follow dependencies, not the area letters: Area D comes before Area C because C1 reads D7's registry, and the retired-word scan change (0.7) is the last step. Each step reads the plan item(s) it names for the full detail. The step adds what the item leaves to the implementer.
- **One commit per step.** The commit message never names this plan's item numbers or areas. A production commit (Steps 6 to 8) states that no fingerprinted module, golden output, baseline, label or declared flip moves (Governance). A step that shows a registry test red on a hand-broken case records the mutation tried in its commit message, and reverts the mutation before committing.
- **Moves and splits.** A test file that moves or splits takes its slice of its given and then. A given function two halves both need goes to a named non-given module in the same `support/` (or `tests/unit/support/` across areas), never imported by one half from the other's given. When a moved line is covered by a path-scoped `AllowedLine` of `tests/unit/support/retired_word_exemptions.py`, the entry's path follows the line in the same commit (a scope change, not a new entry), or `test_every_allowlist_entry_matches_a_line` turns red. Every new or split file stays under about 300 lines.
- **Docker disk.** Do not grow Docker disk use: build no image the tests do not already build, and leave pruning existing images to the maintainer.
- **Short loop** (`CLAUDE.md` Workflow): while a test is red, `uv run pytest <test files> -n 0`. Once green, `uv run pytest tests/unit -n auto --maxprocesses 6` (with `--lf` on failure until green, then the full short loop again), and `uv run pyright <changed files>`.
- **Closing check** (every step, no file argument): `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green.

### Step 1: Acceptance targets by flaw ID, and the shared holdout run vocabulary

- **Files**: create `tests/unit/support/acceptance_targets.py` and `tests/unit/support/holdout_runs.py`. Modify, under `tests/unit/detection/`: `support/test_detection_holdout_run_given.py`, `support/test_detection_audit_given.py`, `support/test_detection_baseline_given.py`, `support/test_detection_session_given.py`, `support/test_detection_targets_given.py`, `support/test_detection_replay_given.py`, `support/test_detection_holdout_pre_run_check_given.py`, `support/test_run_detection_holdout_run_given.py`, `test_detection_targets.py`, `test_run_detection.py`, `test_detection_calibration_check_exit.py`, `test_run_detection_holdout.py`, `test_detection_holdout_run_interrupted.py`. Modify `tests/unit/cve/test_cve_closed_network_refusal.py` and `tests/unit/cve/test_cve_run_images.py`.
- **Do** (item 0.1):
  - `acceptance_targets.py`: `FILESYSTEM`, `KUBERNETES`, `GIT` flaw ID constants, and `an_acceptance_target(flaw_id: str, **changes: object) -> Target` returning `dataclasses.replace` of the `ACCEPTANCE_TARGETS` member with that flaw ID.
  - `holdout_runs.py`: move `deps_auditing`, `run` and `scripted` out of `support/test_detection_holdout_run_given.py` with their bodies unchanged. The holdout run given re-exports nothing: it and the three borrowers (`test_cve_closed_network_refusal.py`, `support/test_run_detection_holdout_run_given.py`, `test_detection_holdout_run_interrupted.py`) import `holdout_runs` directly.
  - Replace every "acceptance target by flaw ID" lookup listed in 0.1 with `an_acceptance_target`. The holdout run given's `a_target` keeps its `tools_filter=None` default on top of it. `_a_target_serving_its_nonce` in the replay given takes any acceptance target through the helper instead of CVE-2025-53109 by name.
  - The four files that imported the holdout run given only for its target (`test_detection_calibration_check_exit.py`, `support/test_detection_holdout_pre_run_check_given.py`, `test_run_detection_holdout.py`, `tests/unit/cve/test_cve_run_images.py`) drop that import.
- **Test**: no new test. A refactoring: every existing test stays green. `grep -rn "test_detection_holdout_run_given" tests` lists only the holdout run test file itself.
- **Verify**: short loop on `tests/unit/detection tests/unit/cve`, then the closing check.

### Step 2: One sound layout, one repository root, the golden corpus beside its user

- **Files**: create `tests/unit/detection/support/layouts.py`. Modify `tests/unit/detection/support/test_detection_session_given.py`, `support/test_detection_holdout_pre_run_check_given.py`, `test_detection_layout_check.py`, `test_detection_holdout_run.py` (all under `tests/unit/detection/`), `tests/unit/support/holdout_runs.py` (the `deps_auditing` default, moved there by Step 1), `tests/unit/support/retired_word_scan.py`, `tests/unit/evals/support/test_fixture_contamination_given.py`. Move `tests/unit/support/cve_grammar_golden_corpus.py` to `tests/unit/cve/support/cve_grammar_golden_corpus.py` and rewrite the import line of `tests/unit/cve/support/test_cve_grammar_golden_given.py`.
- **Do** (items 0.2, 0.3): `layouts.py` holds `SOUND_LAYOUT`. Every other `LayoutCheck(...)` literal listed in 0.2 (`BROKEN_LAYOUT`, `BROKEN`, `LEAKING`, `_SOUND`, the `deps_auditing` default and the three inline literals) becomes `dataclasses.replace(SOUND_LAYOUT, ...)`. No production default on `LayoutCheck`. The three repository-root copies import `evals.honeypots.REPO_ROOT` (`REPO_ROOT / "tests"` for the tests directory). The moved corpus computes `JUDGE_FIXTURE_PATH` from `REPO_ROOT`.
- **Test**: no new test. The grammar golden test stays green with no regeneration.
- **Verify**: `uv run pytest tests/unit/cve/test_cve_grammar_golden.py -n 0` green without regenerating, `git status` shows no change to the committed golden, then the closing check.

### Step 3: Delete the argparse refusal tests and the retired dump-key assertions, with their allowlist entries

- **Files**: `tests/unit/detection/test_run_detection.py`, `tests/unit/detection/test_run_detection_holdout.py`, `tests/unit/evals/test_run_honeypot_suite.py`, `tests/unit/evals/test_run_judge_eval.py`, `tests/unit/evals/test_draw_judge_cases.py`, `tests/unit/nuisance/test_run_nuisance.py`, `tests/unit/auditor/test_rendering.py`, `tests/unit/detection/test_run_detection_holdout_run.py`, `tests/unit/detection/support/test_run_detection_holdout_run_given.py`, `tests/unit/support/retired_word_exemptions.py`.
- **Do** (items 0.4, 0.5):
  - Delete the argparse refusal tests 0.4 lists. Rename the two `no_baseline` tests `test_the_no_baseline_flag_is_read`. Keep `test_the_detection_export_is_read_from_its_flag`.
  - Delete the two assertions at lines 410-411 of `test_rendering.py` (the `{"target", "missed_steps"}` and `relayed_variables` absences) and, in `test_the_result_and_the_report_carry_the_glossary_keys`, `RETIRED_KEYS` and its disjointness assertion. Keep `result_keys` and `_keys` only if the positive half still reads them.
  - Then run `uv run pytest tests/unit/project/test_glossary.py -n 0`: the stale entries it reports are the ones to delete (the `ungated`, `cve-flag`, `calibrate-cmd`, `readmission` entries of 0.4, the `missed-steps` and `relayed-variables` entries of `test_rendering.py`, the four `RETIRED_KEYS` entries). The `eval-result` entry of `test_rendering.py` stays. Add no entry.
- **Test**: deletions only. The glossary tests come out green with fewer entries.
- **Verify**: the closing check.

### Step 4: Renames, part 1: the missed model call vocabulary in test names

- **Files** (renames only, bodies kept): `tests/unit/auditor/test_missed_model_calls.py`, `test_models.py`, `test_console_display.py`, `support/test_console_given.py`, `test_graph.py`, `test_chain_nodes.py`, `test_cli.py` (under `tests/unit/auditor/`), `tests/unit/cve/test_cve_failure_text.py`, `tests/unit/detection/test_detection_audit.py`, `tests/unit/nuisance/test_nuisance_audit_once.py`, `test_nuisance_retry_policy.py`, `test_nuisance_assembly.py` (under `tests/unit/nuisance/`), `tests/unit/evals/test_eval_metrics.py`, `test_run_honeypot_suite.py`, `support/test_honeypot_fault_harness_given.py` (under `tests/unit/evals/`).
- **Do** (item 0.6, first bullet): rename every "missed step", "refused step" and "throttled step" test name or given at the lines listed to the current terms (missed model call, refusal, judgment): `_a_refused_step` becomes `_a_refused_judgment`. The checkpointing tests' channel names stay.
- **Test**: renames only, every test green and collected under its new name (`uv run pytest --collect-only -q <files>` shows no old name).
- **Verify**: `grep -rnE "def test_\w*(missed|refused|throttled)_step" tests` empty except the checkpointing compatibility tests, then the closing check.

### Step 5: Renames, part 2: the remaining vocabulary

- **Files** (renames only, bodies kept): the files of item 0.6's other bullets: `tests/unit/nuisance/admission/test_nuisance_admission_walk.py`, `test_nuisance_holdout_servers.py`, `test_nuisance_vet.py`, `test_nuisance_statistic.py`, `test_nuisance_solo.py` with `support/test_nuisance_solo_given.py` and `support/test_nuisance_solo_then.py`, `gate/test_nuisance_gate_session.py`, `gate/test_nuisance_gate.py`, `gate/test_nuisance_gate_console.py`, the five `gate/` files using `an_exploratory_baseline` (with `gate/support/test_nuisance_gate_given.py` and the baseline and recording givens), `test_nuisance_backend_registry.py`, `admission/support/test_nuisance_admission_records_given.py` (under `tests/unit/nuisance/`), `tests/unit/auditor/test_console_display.py`, the detection givens `support/test_detection_gate_given.py`, `support/test_run_detection_given.py`, `support/test_detection_console_given.py`, `support/test_detection_oracle_given.py` with their callers, `tests/unit/detection/test_detection_layout_check.py`, `test_detection_audit.py`, `test_detection_holdout_run.py`, `tests/unit/evals/test_eval_gate.py`, `tests/unit/evals/support/test_fixture_contamination_given.py` with its test, `tests/unit/census/test_census_grouping.py`, `tests/unit/support/test_nuisance_committed_admission_given.py` with its callers, `tests/integration/support/test_detection_calibration_check_given.py` with its test, `tests/integration/test_cve_planting_stand_ins.py`.
- **Do** (item 0.6, bullets two to the end): apply each rename as listed. `CaseSource.CVE` is production and stays. `the_committed_census()` becomes `the_committed_walk_inputs()`. `an_exploratory_baseline` becomes `an_unconfirmed_baseline`, with the test names that carry it.
- **Test**: renames only, every test green under its new name.
- **Verify**: `grep -rn "an_exploratory_baseline\|the_committed_census\b\|def test_\w*benchmark_target\|def test_\w*figure" tests` empty, then the closing check (the integration renames run in the full `uv run pytest -n auto`).

### Step 6: One census path

- **Files**: `evals/cve/census/census.py`, `evals/run_census.py`, `evals/run_detection_holdout.py`, `evals/cve/nuisance/commands.py`, `tests/unit/support/test_nuisance_committed_admission_given.py`, `tests/unit/census/test_census.py`.
- **Do** (item A1):
  - Governance first: re-read `GRAMMAR_PATHS` and `ENVIRONMENT_PATHS` (`evals/cve/detection/baseline.py`), `CONFINEMENT_SOURCE`, `_PUBLIC_NAME_SOURCES` and every target's `backend_sources` (`evals/cve/nuisance/fingerprint.py`), the `served` modules (`evals/cve/nuisance/backend_registry.py`), `_COUNTER_PATHS` (`evals/cve/nuisance/counter.py`), and confirm none names a production module of Steps 6 to 8 (`chat_model_factory.py`, `chain_prompts.py`, `census.py`, `run_census.py`, `run_detection_holdout.py`, `commands.py`, `run_nuisance.py`). Stop and report if one does.
  - Test first: rewrite `test_every_command_reads_the_committed_census_by_default` as `test_the_committed_census_loads`, importing `CENSUS_PATH` from `evals.cve.census.census` (red on the import).
  - Then define `CENSUS_PATH = Path(__file__).parents[2] / "census.json"` in `census.py` (no import of `evals.honeypots`), import it in the three commands and in the committed admission given, deleting the three definitions.
- **Test**: `test_the_committed_census_loads`: loading `CENSUS_PATH` gives a census (one load, not three).
- **Verify**: the new test red then green, then the closing check.

### Step 7: Named bounds read by the tests

- **Files**: `src/mcp_auditor/adapters/chat_model_factory.py`, `src/mcp_auditor/graph/chain_prompts.py`, `tests/unit/auditor/test_chat_model_factory.py`, `tests/unit/auditor/test_chain_prompts.py`.
- **Do** (item A2): test first, both tests read the new public names (`ANTHROPIC_MAX_OUTPUT_TOKENS` instead of `16384`, `RESPONSE_SNIPPET_LENGTH` instead of `response[:200]` in `test_bounds_each_error_and_keeps_the_response_snippet`), red on import. Then rename `_ANTHROPIC_MAX_OUTPUT_TOKENS` to `ANTHROPIC_MAX_OUTPUT_TOKENS` and name the bare `200` at `chain_prompts.py:180` `RESPONSE_SNIPPET_LENGTH`.
- **Test**: the two tests above, green on the named constants.
- **Verify**: `uv run pytest tests/unit/auditor/test_model_inputs_golden.py -n 0` green with no regeneration, then the closing check.

### Step 8: The current fingerprint of each holdout calibration copy, owned by the run

- **Files**: `evals/run_nuisance.py`, `tests/unit/support/test_nuisance_committed_admission_given.py`, `tests/unit/nuisance/admission/test_nuisance_admission_loads.py`.
- **Do** (item A3): test first, `test_nuisance_admission_loads.py:31` imports `current_copy_fingerprints` from `evals.run_nuisance` (red on import). Then extract `current_copy_fingerprints(draw: DrawRecord | None) -> dict[str, str]` from `_refuse_stale_holdout_calibration_copies` (lines 289-294), called by it, and delete the given's copy. Nothing moves into `holdout_calibration_copies.py`.
- **Test**: the admission-loads test passes on the production function. The run's stale-copy refusal tests stay green.
- **Verify**: the closing check.

### Step 9: Server watch: the timeout reset covered, the counts through their constants

- **Files**: `tests/unit/auditor/test_server_watch.py`, `support/test_server_watch_given.py`, `test_audited_server.py`, `test_graph.py`, `support/test_chain_nodes_given.py`, `test_relaunch_rendering.py` (under `tests/unit/auditor/`).
- **Do** (items B1, B2, B5):
  - B1 first: add `test_a_real_response_resets_the_timeout_count` (`TIMEOUTS_IN_A_ROW - 1` timeouts, a real answer, `TIMEOUTS_IN_A_ROW - 1` timeouts again, the tool has no unsent cause). Show it red by deleting `self._timeouts[tool_name] = 0` in `ServerWatch._answered`, then restore. Rename `test_a_real_response_resets_the_counts_and_forgets_the_tool_stopped_before` to `..._resets_the_relaunch_count_and_forgets_the_tool_stopped_before`.
  - B2: add `relaunches_in_a_row(watch, tool)` to the server watch given. Replace the literal 3 and 2 at the lines listed with `TIMEOUTS_IN_A_ROW` and `RELAUNCHES_IN_A_ROW` (or `- 1`). Rename tests naming the number to say "in a row". The graph test takes `num_cases` and `test_budget` from the constant. `test_relaunch_rendering.py` keeps its label wording, only its counts change.
  - B5: rewrite the `pings == 4` test of `test_audited_server.py:139` on its outcome (the tool is stopped after `TIMEOUTS_IN_A_ROW` calls) and drop the ping count and its comment. The other control ping counts stay.
- **Test**: the new reset test (red with the mutation, green restored), and every renamed test green.
- **Verify**: the mutation red then reverted (`git diff src` empty), then the closing check.

### Step 10: Label callers compare against their owners, the bounded context keeps the latest items

- **Files**: `tests/unit/auditor/test_stream_handler.py`, `test_progress.py`, `test_console_display.py`, `test_missed_model_calls.py`, `support/test_rendering_given.py`, `support/test_attack_context_given.py`, `test_attack_context.py` (under `tests/unit/auditor/`).
- **Do** (items B3, B4): B3's four replacements (`describe_relaunch`, `UNSENT_CAUSE_LABELS[cause]`, `describe_coverage_gap(gap)`, `str(PromptTooLong(usage))`), and `PROMPT_TOO_LONG_MESSAGE` becomes a neutral detail string. B4: `a_context_over_every_bound` derives its sizes from `MAX_LIST_ITEMS` (`MAX_LIST_ITEMS + 10`), and `test_a_carried_context_over_every_bound_comes_back_within_them` also asserts that the kept items are the last `MAX_LIST_ITEMS` of those within `MAX_ITEM_LENGTH` and that the over-long `db_engine` is dropped. Notes left out.
- **Test**: the strengthened bound test, shown red by a temporary `_merge_list` that empties an over-long carried list, then reverted.
- **Verify**: the mutation red then reverted, then the closing check.

### Step 11: Audited server builders shared by three test files

- **Files**: create `tests/unit/auditor/support/audited_servers.py`. Modify `support/test_nodes_given.py`, `support/test_chain_nodes_given.py`, `test_audited_server.py`, `support/test_server_watch_given.py` (under `tests/unit/auditor/`), `tests/fakes/mcp_client.py`.
- **Do** (item B6): move `a_server_taken_as_down`, `a_server_that_stopped` and `a_server_losing_its_connection` into `audited_servers.py`, used by the two givens' callers and by `test_audited_server.py` in place of its inline setup (lines 172-187). `TIMEOUT` and `LOST_CONNECTION` of the server watch given use the fake's builders. `a_lost_connection_response` is built from `LOST_CONNECTION_RESPONSES[0]`.
- **Test**: no new test, every existing test green.
- **Verify**: the closing check.

### Step 12: Chain and node tests assert one node at a time

- **Files**: `tests/unit/auditor/test_chain_nodes.py`, `test_nodes.py`, `test_graph.py`, and their givens as needed (`support/test_chain_nodes_given.py`, `support/test_nodes_given.py`, `support/test_graph_given.py`).
- **Do** (item B7): trim the three chain node tests (lines 186-234) and the `route_after_execute` parts of the two node tests to single-node assertions: what execute returns, what the router returns for a given state, what the judge records from a state holding the executed steps. No hand merge of `{**state, **result}` remains. Add to `test_graph.py` the end-to-end path "the server goes down mid-chain and the executed prefix is judged" (green on arrival, since it characterizes working code: show it red by making the judge skip a chain with a step not sent, then revert).
- **Test**: the trimmed node tests, and the new graph test.
- **Verify**: `grep -n "\*\*state, \*\*result" tests/unit/auditor` empty, then the closing check.

### Step 13: `graph/unsent_calls.py` gets its own tests, the export tests move to evals, a stale prompt test goes

- **Files**: create `tests/unit/auditor/test_unsent_calls.py` and `support/test_unsent_calls_given.py`. Modify `test_nodes.py`, `test_chain_nodes.py` and their givens, `test_prompts.py`. Move `tests/unit/auditor/test_export.py`, `support/test_export_given.py`, `support/test_export_then.py` to `tests/unit/evals/` and `tests/unit/evals/support/` (import lines updated).
- **Do** (items B8 first bullet, B10): move `TestReportToolsLeft` and `TestCountChainsNotPlanned` into `test_unsent_calls.py`, its given holding the tools, tool report and chain audit state they set up, the servers from `support/audited_servers.py`. The three `build_tool_report` gap tests and `a_tool_state_with_calls_not_sent` stay in `test_nodes.py` and its given. Delete `TestContextExtractionPrompt::test_no_longer_asks_to_preserve_previous_findings`.
- **Test**: the moved tests green in their new homes, the collected count lower by one only.
- **Verify**: the closing check.

### Step 14: Split `test_rendering.py`

- **Files**: create `tests/unit/auditor/test_execution_rendering.py`, `support/test_execution_rendering_given.py`, `test_missed_model_call_rendering.py`, `support/test_missed_model_call_rendering_given.py`. Modify `test_rendering.py`, `support/test_rendering_given.py`, `tests/unit/support/retired_word_exemptions.py`.
- **Do** (item B8 second bullet): the execution record tests (`test_markdown_shows_a_confined_execution_...` through `test_json_execution_is_null_...`) to `test_execution_rendering.py`, the missed model call and completeness tests to `test_missed_model_call_rendering.py`, each with its slice of the rendering given (a given function shared by two of the three goes to a non-given `support/report_builders.py` or similar). The `eval-result` allowlist entry follows the `"eval_result"` line to its new file.
- **Test**: moves only, the same tests green.
- **Verify**: `wc -l` of the three test files and their givens under about 300, then the closing check.

### Step 15: Split `test_graph.py`, `test_prompts.py` and `test_server_execution.py`

- **Files**: create `tests/unit/auditor/test_graph_relaunch.py` with `support/test_graph_relaunch_given.py`, `test_context_extraction_prompt.py` (and a given if its tests use one), `test_launch_decision.py` (and a given if needed). Modify `test_graph.py`, `support/test_graph_given.py`, `test_prompts.py`, `test_server_execution.py` and its given.
- **Do** (item B8 third to fifth bullets): the four ADR 036 tests and their givens (`a_server_timing_out_on`, `a_server_dying_on*`, the three relaunch `a_fake_llm_for_*`) to `test_graph_relaunch.py`, the context extraction prompt tests to `test_context_extraction_prompt.py`, the `decide_launch` tests to `test_launch_decision.py`. `test_llm_adapter.py` stays.
- **Test**: moves only.
- **Verify**: every file touched under about 300 lines, then the closing check.

### Step 16: Names, givens and tables of the auditor tests

- **Files**: create `tests/unit/auditor/support/coverage_gaps.py`. Modify `test_nodes.py`, `support/test_nodes_given.py`, `test_container_name.py`, `support/test_cli_given.py`, `test_cli.py`, `support/test_console_given.py`, `support/test_relaunch_rendering_given.py`, `test_relaunch_rendering.py`, `test_shown_response.py`, and the file now holding `test_markdown_tool_section_counts_its_responses_shown_cut` (under `tests/unit/auditor/`).
- **Do** (item B9): the `test_nodes.py` rename and given rename (`a_tool_state_with_calls_not_sent` to `a_tool_state`), the expected gap built from `given.a_coverage_gap().model_copy(update=...)`. `pytest.param(..., id=...)` naming each rule of the 16 container name rows. `a_report` of the CLI given replaced by `a_report_with_a_finding(severity)`, `a_report_with_calls_not_sent()`, `a_relaunched_report()`. One `a_gap_with_calls_not_sent(cause)` in `coverage_gaps.py` replaces the four copies. `MAX_SHOWN_LENGTH // 2` and `f"{MAX_SHOWN_LENGTH:,}"` in place of the literals, line 35 of `test_shown_response.py` goes.
- **Test**: renames and rewired givens, every test green, the container name rows collected under readable ids.
- **Verify**: the closing check.

### Step 17: Shared backend launch specs, Doris launch fakes, recorded commands

- **Files**: create `tests/unit/cve/backends/support/backend_launch_specs.py` and `backends/support/doris_launch.py`. Modify `backends/support/test_kubernetes_backend_given.py`, `backends/test_mcp_ssh_holdout_builder.py`, `backends/support/test_doris_serialization_given.py`, `backends/test_doris_backend.py` and the other two users of the Doris launch fakes, `backends/support/test_ckan_holdout_builder_given.py`, `backends/support/test_mcp_ssh_holdout_builder_given.py` (under `tests/unit/cve/`).
- **Do** (item D1, first two bullets and the last sentence of the fourth): the "with a holder", "without a holder" and "with no network" specs into `backend_launch_specs.py`. `doris_helpers_faked`, `a_minimal_doris_spec` and `_strip_pair` into `doris_launch.py`. `RecordedDocker` and the mcp-ssh `FakeDocker` give way to `tests/unit/support/recorded_subprocess.recorded_commands(monkeypatch)`.
- **Test**: no new test, the same tests green.
- **Verify**: `grep -rn "class RecordedDocker\|class FakeDocker" tests/unit/cve` empty, then the closing check.

### Step 18: One scripted Docker fake

- **Files**: create `tests/fakes/scripted_docker.py`, export from `tests/fakes/__init__.py`. Modify `backends/support/test_gitlab_backend_given.py`, `backends/support/test_kubernetes_backend_given.py`, `backends/support/test_doris_seed_given.py`, the three files holding an `_a_closed_network` copy, and the tests reading the replaced fakes (under `tests/unit/cve/`).
- **Do** (item D1, fourth bullet): `ScriptedDocker(answers: Mapping[tuple[str, ...], str])` records commands and inputs, answers by command prefix, exposes `started()`, `created_networks()`, `removed()`, `installed(monkeypatch)`, and `run(args, *, input=None)`. A module constant `CLOSED_NETWORK_INSPECT` answers the closed-network inspect. It replaces `FakeGitLabDocker`, `FakeControlPlaneDocker` and the three `_a_closed_network`. `FakeDorisDocker` stays its own class and takes `CLOSED_NETWORK_INSPECT`.
- **Test**: no new test, the gitlab, kubernetes and Doris seed tests green on the new fake.
- **Verify**: `grep -rn "FakeGitLabDocker\|FakeControlPlaneDocker\|_a_closed_network" tests` empty, then the closing check.

### Step 19: mcp-ssh sshd facts in their own file, `launch_beside_backend` tested once

- **Files**: create `tests/unit/cve/backends/test_mcp_ssh_sshd_backend.py` with `support/test_mcp_ssh_sshd_backend_given.py`, and `test_backend_beside_launch.py` with `support/test_backend_beside_launch_given.py`. Modify `test_backend_hostnames.py` and its given, `test_kubernetes_backend.py` and its given, `test_mcp_ssh_holdout_builder.py` and its given (under `tests/unit/cve/backends/`).
- **Do** (items D8 then D2):
  - D8: move lines 71-117 of `test_backend_hostnames.py` and 65-125 of its given to the sshd file. Replace the two constant equalities with `carries(singleton_run_args(), ["--network-alias", SSHD_ALIAS])` and `test_the_mcp_ssh_config_is_the_readme_production_entry` (`Hostname == SSHD_ALIAS`). `len(aliases) == 6` becomes `aliases and set(aliases) == {SSH_CONFIG_HOST}`.
  - D2, tests first: `test_backend_beside_launch.py` drives `launch_beside_backend` with one `FakeBackendStand` (its `stand` yields an object with `network` and `mount_args()`), four tests: the holder joins the backend network, the backend network is the second network with no holder, the holder is removed before the backend, the layout is mounted `:ro`. Then delete the four copies in each wrapper file with `FakeControlPlane.planting` and `FakeSshd.planting`. Each wrapper keeps what it adds: kubernetes the `has_network` refusal and the fix-check launch, mcp_ssh the refusal, the root owner and the known_hosts mount.
- **Test**: four `launch_beside_backend` tests, the moved sshd tests.
- **Verify**: the closing check.

### Step 20: Per-launch backends in the registry tests

- **Files**: `tests/unit/cve/backends/test_backend_lifecycle.py`, `support/test_backend_lifecycle_given.py`, `support/test_gitlab_backend_then.py`, `support/test_node_sandbox_engine_then.py`, `support/test_httpbin_backend_then.py`, `test_gitlab_backend.py`, `test_node_sandbox_engine.py`, `test_httpbin_backend.py`.
- **Do** (item D3): the two server-check tests at lines 117 and 133 run over `sorted(BACKENDS)` through `given.through_the_kit(given.a_lifecycle_without_side_effects(key))`, the network and name asserted with `startswith(BACKENDS[key].network)`. Show red by dropping `--user` from one per-launch backend's quiet kit launch, then revert. Then delete the three "as the host's user" thens and the tests using them. Per backend, keep only what its module does on its own, and the "two launches" and "removed when the body raises" tests.
- **Test**: the two registry tests, now over every backend.
- **Verify**: the mutation red then reverted, then the closing check.

### Step 21: Every backend container in one hardening test

- **Files**: `tests/unit/cve/backends/support/test_backend_lifecycle_given.py`, `test_backend_lifecycle.py`, `test_backend_hostnames.py` (or the sshd file of Step 19 if the sshd hardening test moved there), `support/test_httpbin_backend_then.py`, `support/test_node_sandbox_engine_then.py`, `support/test_kubernetes_backend_then.py`, `support/test_gitlab_backend_then.py`, `test_searxng_backend.py`, `test_httpbin_backend.py`, `tests/unit/nuisance/test_nuisance_backend_registry.py`.
- **Do** (item D4): `every_backend_container_argv()` in the lifecycle given, keyed by a readable id, built from the production run-args functions D4 lists (searxng with `["--network", "container:<holder>"]`). One parametrized test: memory bound, resolver option or `none` network, `confinement_args()`, no `--cap-add`, with the three explicit exceptions (Doris with the memory bound and resolver only, GitLab with its own hardening and the capabilities its start needs, searxng with its own hardening and no resolver), each with its reason in the test data. Show red by removing the memory bound from one container's run args, then revert. Then delete the tests and lines D4 lists, `test_no_ckan_backend_container_is_granted_a_capability` included.
- **Test**: one parametrized hardening test over every backend container.
- **Verify**: the mutation red then reverted, then the closing check.

### Step 22: The memory bound through its constant

- **Files**: `tests/unit/cve/test_cve_planting.py`, `support/test_cve_planting_then.py`, `test_cve_planting_stand_ins.py`, `test_cve_launches.py`, `backends/test_backend_hostnames.py`, `backends/support/test_httpbin_backend_then.py` (if line 46 survived Step 21).
- **Do** (item D5): `test_the_confinement_bounds_memory_with_no_swap` pins `(MEMORY_BOUND, MEMORY_BOUND)` and keeps one literal `"4g"`. Elsewhere `carries(args, memory_bound_args())`. `memory_bound_in` goes, `resolver_options_in` becomes `docker_argv.count(argv, resolver_args())`.
- **Test**: rewired assertions, no new test.
- **Verify**: `grep -rn '"4g"' tests/unit` shows only the pin, then the closing check.

### Step 23: Constants equal to their literal go, the fixture authority trust checked once

- **Files**: create `tests/unit/cve/backends/support/fixture_authority.py`. Modify `test_httpbin_backend.py`, `support/test_httpbin_backend_then.py`, `test_backend_hostnames.py`, `test_facebook_ads_backend.py`, `test_mcp_ssh_holdout_builder.py`, `test_apify_backend.py`, `support/test_gitlab_backend_then.py`, `test_searxng_backend.py`, `support/test_ckan_holdout_builder_then.py` (under `tests/unit/cve/backends/`).
- **Do** (items D6, D9): delete or rewire each equality D6 lists (the `--gravitino-uri` host becomes "the alias of a `GRAVITINO_PARTS` member", gitlab reads `GITLAB_PIDS_LIMIT` and `GITLAB_SHM_SIZE`). `trusts_the_fixture_authority(args, variable, host)` (variable names `/etc/ssl/extra-ca.pem`, the host's authority mounted there read-only, no skip-verify variable) replaces the five copies, apify gaining the full check.
- **Test**: the shared trust check on five backends (apify's now checks the mount too).
- **Verify**: the closing check.

### Step 24: One registry of audited launch builders

- **Files**: create `tests/unit/support/audited_launch_builders.py`. Modify `tests/unit/cve/test_cve_launches.py`, `backends/test_audited_launch_names.py`, `backends/support/test_audited_launch_names_given.py`, `backends/test_doris_backend.py`, `backends/test_ckan_holdout_builder.py`, `backends/test_searxng_backend.py`, `backends/test_mcp_ssh_holdout_builder.py`.
- **Do** (item D7, and D1's third bullet): the table keyed by builder function, each entry a context manager yielding the launch argv on fakes (ten layout builders, five backed ones on the fakes of `unnamed_launch_builders` and Step 17's modules), with C1's backend-sources and image columns (filled as C1 lists). Beside it, the hand-listed rows no target names (the five kit builders under the `:ro` check, the two nuisance single-container builders under the readable-name check). Parametrize: the readable name in `test_audited_launch_names.py` (with `isinstance(declared_container_name(args), str)`), the memory bound, the `:ro` layout, the user and working directory where the spec sets them in `test_cve_launches.py`. Add the guard `{t.builder for t in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)} <= set(table)`, shown red by removing one builder from the table, then restored. The audited launch names given imports no other given. Then delete the doris and ckan confinement tests, `test_the_holdout_launch_mounts_the_layout`, searxng's `WORKSPACE` line, `_LAYOUT_BUILDERS` and `unnamed_launch_builders`.
- **Test**: the parametrized launch checks and the guard.
- **Verify**: the guard red then restored, `grep -rn "_LAYOUT_BUILDERS\|unnamed_launch_builders" tests` empty, then the closing check.

### Step 25: Detection: builder-keyed backend sources, duplicates, layout wording through its owner

- **Files**: `tests/unit/detection/test_detection_holdout_targets.py`, `test_detection_layout_check.py`, `test_detection_holdout_card_readiness.py`, `test_detection_gate.py`, `test_detection_holdout_pre_run_check.py` with `support/test_detection_holdout_pre_run_check_given.py`, `test_detection_session.py`.
- **Do** (items C1, C2, C3): the five "fingerprints its backend module" tests become one test over Step 24's table (for every acceptance and holdout target whose builder has a backend-sources entry, the entry is a subset of its `backend_sources`, ckan now covered), and the `CONTROL_PLANE_SERVICE` and `SEARXNG_SERVICE` assertions read its image column. Show red by removing one module from a target's production `backend_sources` in a scratch edit, then revert. C2's deletions and the gate fold. C3's comparisons against `layout_failure(...)` and the flaw ID in the refusal reason.
- **Test**: one parametrized backend-sources test, the gate table gains its `PENDING_RETEST` case.
- **Verify**: the mutation red then reverted, then the closing check.

### Step 26: Detection CLI tests observe what their names promise

- **Files**: `tests/unit/detection/test_run_detection.py`, `support/test_run_detection_given.py`, `test_run_detection_holdout.py` and its given, `test_detection_audit.py`.
- **Do** (item C4): a `deps_with` recording the targets it receives (every acceptance ID with no flag, only `RECORDED_FLAW` with `--flaw`). `test_the_no_baseline_flag_reaches_the_session` records the options the fake `run_gated` receives (`no_baseline is True`, exit 0). The holdout calibration check test draws two targets and checks only the first with `--flaw`, the unknown-flaw case renamed `..._on_a_flaw_not_drawn_...`. The taken-as-down test renamed `..._drops_the_run_as_a_launch_failure`.
- **Test**: three strengthened tests, one rename.
- **Verify**: each strengthened test shown red by a scratch break of what it now observes (the `--flaw` filter ignored, `no_baseline` not passed), then reverted, then the closing check.

### Step 27: Detection replay givens and argv/data couplings

- **Files**: `tests/unit/detection/support/test_detection_replay_then.py`, `support/test_detection_replay_given.py`, `test_detection_replay.py`, `test_detection_targets.py`, `test_detection_preflight.py`, `test_detection_calibration_check_exit.py`, `test_detection_holdout_run.py`.
- **Do** (items C5, C6): the replay then reads `REPLAY_ATTEMPTS`, `a_response` goes (`calls()` uses `OK`), the unchecked replay built from `given.a_detecting_run()` with `patched.launches == []`, the container name through `declared_container_name`. `values_after`/`value_after` and `layout.PROJECT` in `test_detection_targets.py`, the preflight test filters on `public_names.stand_ins`, `[]` and `{}` in the calibration check exit test, `ServerHealth` by keywords.
- **Test**: rewired, no new test.
- **Verify**: the closing check.

### Step 28: Split the holdout report and holdout run tests

- **Files**: create `tests/unit/detection/test_detection_holdout_report_cutoff.py`, `support/holdout_report_runs.py`, `support/test_detection_holdout_report_given.py`, `test_detection_holdout_run_pre_run.py`, `test_detection_holdout_run_containers.py` (with given slices). Modify `test_detection_holdout_report.py`, `test_detection_holdout_run.py`, `support/test_detection_holdout_run_given.py`.
- **Do** (item C7, first bullet and the holdout run split): the target line test compares only the per-run facts its name promises. The cutoff tests move, `_target` and `_run_result` to `holdout_report_runs.py`, `_with_incidents` and `_run_with_incidents` to the new report given with the "Incomplete runs" heading stated once. The pre-run check and second pass tests and the container hygiene tests leave `test_detection_holdout_run.py`.
- **Test**: moves and one narrowed test.
- **Verify**: every touched file under about 300 lines, then the closing check.

### Step 29: Split the detection audit, run and session tests

- **Files**: create `tests/unit/detection/test_detection_audit_holdout.py`, `test_run_detection_recording.py`, `test_detection_session_recording.py`, with given slices. Modify `test_detection_audit.py`, `test_run_detection.py`, `test_detection_session.py` and their givens.
- **Do** (item C7, second bullet): the holdout and taken-as-down tests, the recording and confirming-command tests, and the session recording tests move to their new files. `test_detection_oracle.py`, `test_detection_targets.py` and the baseline given stay.
- **Test**: moves only.
- **Verify**: every touched file under about 300 lines, then the closing check.

### Step 30: CVE small fixes and the backend import-closure test

- **Files**: `tests/unit/cve/test_cve_dossier_closure.py`, `backends/test_kubernetes_backend.py`, `backends/test_mcp_ssh_holdout_builder.py`, `test_committed_stand_ins.py` and its given, `test_cve_server_health.py`, `test_cve_launch_audit.py` and its given, `backends/support/test_ckan_holdout_builder_given.py`, `backends/support/test_searxng_backend_given.py`, `backends/test_ckan_holdout_builder.py`, `test_cve_keyed_stand_in_routes.py`, `test_cve_public_stand_ins.py`, `test_cve_launches.py`.
- **Do** (item D10): one closure test over `sorted(BACKENDS)` calling `import_closure([f"evals.cve.backends.{key}"])`, shown red by a scratch `import mcp_auditor` in one backend module, then reverted, and the two vacuous tests go. Each other bullet as listed: deletions, the `test_budget == given.BUDGET`, `kept_records` through `TARGET.planting_spec`, expected events derived from `the_targets_spec()`, the `beside_a_form_field` case gone, the houtini test asserting `environment(launch.args[:image])` holds both pairs, the two constructor wrappers inlined, the missing-authority branch removed.
- **Test**: the closure test, the strengthened houtini test.
- **Verify**: the mutation red then reverted, then the closing check.

### Step 31: Split `test_cve_planting.py` and `test_cve_public_stand_ins.py`

- **Files**: create `tests/unit/cve/test_cve_planting_confinement.py`, `test_cve_planting_host_files.py` (with given slices). Modify `test_cve_planting.py`, `support/test_cve_planting_given.py`, `support/test_cve_planting_then.py`, `test_cve_public_stand_ins.py`, `test_cve_keyed_stand_in_routes.py`.
- **Do** (item D11): confinement, resolver and memory tests, then host files and cleanup tests, leave `test_cve_planting.py`. The keyed and form-field load tests move to `test_cve_keyed_stand_in_routes.py`.
- **Test**: moves only.
- **Verify**: every touched file under about 300 lines, then the closing check.

### Step 32: One scripted benign-call fake, exit texts through their table

- **Files**: create `tests/fakes/benign_call.py`, export from `tests/fakes/__init__.py`. Modify `tests/unit/nuisance/support/test_nuisance_run_given.py`, `support/test_nuisance_vet_given.py`, `gate/support/test_nuisance_gate_session_given.py`, `support/test_nuisance_vetting_given.py`, `admission/test_nuisance_admission_walk.py`, `test_nuisance_report.py`, `gate/test_nuisance_gate_console.py`, `gate/test_nuisance_gate_report.py`, `gate/test_run_nuisance_gate.py`.
- **Do** (items E1, E2): `ScriptedBenignCall(reasons: Mapping[str, str | Sequence[str | None] | None])` recording `calls` per package, used by the three givens, `ScriptedVet` wrapping it for its events. `EXIT_REASON_TEXTS[reason]` everywhere E2 lists, the walk parametrization collapsing to `reason`, the report order test building rows from `ExitReason` in order, the pending test reading the last reason.
- **Test**: no new test.
- **Verify**: the closing check.

### Step 33: mcp-ssh fix-check tests, hand-built fix-check launches in one table

- **Files**: `tests/unit/nuisance/fix_checks/test_mcp_ssh_fix_check_builder.py`, `support/test_mcp_ssh_fix_check_builder_given.py`, `tests/unit/cve/backends/test_mcp_ssh_holdout_builder.py`, rename `test_fix_check_resolver.py` to `test_fix_check_launches.py` with a new `support/test_fix_check_launches_given.py`, `test_jenkins_fix_check_builder.py`, `test_gravitino_fix_check_builder.py` (under `tests/unit/nuisance/fix_checks/` unless absolute).
- **Do** (items E3, E4): E3's deletions and the two fix-check tests moved from the cve file, built on `FIXTURES[0].planting_spec()`, the network test with `value_after`. `HAND_BUILT_LAUNCHES` (old `_BUILDERS` plus gravitino's `server_args`/`part_args` and `mcp_ssh_fix_check.server_args`, without `_NO_PLANTING`) drives the resolver test and `test_every_hand_built_fix_check_container_carries_the_confinement` (`neo4j-database` excepted, `--cap-add` values within `{"NET_BIND_SERVICE"}`, none for `*-server` and `*-part`). Show red by granting a `*-server` entry a capability, then revert. Then delete the three per-module confinement tests and the gravitino count test.
- **Test**: two parametrized tests over the launch table.
- **Verify**: the mutation red then reverted, then the closing check.

### Step 34: Nuisance copies and committed-data couplings

- **Files**: `tests/unit/nuisance/test_nuisance_confinement.py` with a new `support/test_nuisance_confinement_given.py`, `admission/support/test_nuisance_re_admission_dossier_given.py`, `admission/test_nuisance_re_admission_dossier.py`, `admission/test_nuisance_holdout_calibration_copies.py`, `test_nuisance_counting.py`, `test_nuisance_run.py`, `test_nuisance_run_status.py`, `test_nuisance_vetting.py`, `support/test_nuisance_solo_given.py`, `test_nuisance_solo.py`.
- **Do** (item E5): each bullet as listed. The n8n shared-helper test becomes a property over the committed admission (`pkgutil.iter_modules` over `evals.cve.nuisance.fix_checks`, modules without `FIXTURES` absent from every `fix_check_modules`). `a_drawn_target_and_its_sibling()` derives the pair from the copy resolution. Status lines built with `run_status_line(...)`. The heavy-backend vet test keeps a one-line comment on why it stays.
- **Test**: the property test, rewired assertions.
- **Verify**: the closing check.

### Step 35: Backend tests out of the nuisance registry file

- **Files**: create `tests/unit/cve/backends/test_ckan_backend.py`, `test_n8n_backend.py` (with givens if needed). Modify `tests/unit/nuisance/test_nuisance_backend_registry.py`, `tests/unit/cve/backends/test_gitlab_backend.py`, `tests/unit/nuisance/test_nuisance_run.py`.
- **Do** (item E6): the ckan tests to the new ckan file (its trust test on Step 23's `trusts_the_fixture_authority`), the n8n tests to the n8n file, the gitlab test to the gitlab file without its last line, the two-image run test to `test_nuisance_run.py`. Delete the n8n registry tuple test and the Doris container-name test. The registry tests at lines 166 and 170 stay.
- **Test**: moves only.
- **Verify**: the closing check.

### Step 36: Nuisance registry copies and constant tests

- **Files**: create `tests/unit/nuisance/fix_checks/support/recorded_exchanges.py`, `fix_checks/support/test_geekgod_fs_fix_check_builder_given.py`. Modify `fix_checks/test_geekgod_fs_fix_check_builder.py`, `support/test_nuisance_fix_checks_given.py`, `test_nuisance_run_containers.py`, `test_run_nuisance_run.py`, `gate/test_nuisance_gate_baseline.py`, `test_nuisance_compose.py`, `admission/support/test_nuisance_dossier_then.py`, `test_run_nuisance.py`.
- **Do** (item E7): each bullet as listed (`recorded` to the non-given module, `_record` and `_path_values` to the geekgod given, the services derived from `t.images & BUILT_SERVICES`, `FlawClass` iterated, the two admission tests parametrized).
- **Test**: one parametrized admission test, deletions.
- **Verify**: the closing check.

### Step 37: Fix-check command given, holdout servers given, admission mutations

- **Files**: create `tests/unit/support/admission_mutations.py`, `tests/unit/nuisance/support/test_nuisance_holdout_servers_given.py`. Modify `fix_checks/test_nuisance_fix_check_command.py`, `fix_checks/support/test_nuisance_fix_check_command_given.py`, `test_nuisance_holdout_servers.py`, `admission/support/test_nuisance_admission_given.py`, and the import lines of every test file reading a `with_*` mutator or `admitting` (under `tests/unit/nuisance/` and `tests/unit/cve/`).
- **Do** (item E8, first three bullets' non-split parts): `given.a_fix_check_ready(monkeypatch, fixture, result, networks)` absorbing `_checking_with` and `_leftovers`, the Docker requirement read from `DOCKER_REQUIREMENT`. The holdout servers helpers to their new given. Every `with_*` mutator of the admission given and `admitting(*servers)` (replacing the three `model_copy(update={"servers": ...})` sites) to `admission_mutations.py`.
- **Test**: no new test.
- **Verify**: `grep -rn "^def with_" tests/unit/nuisance/admission/support/test_nuisance_admission_given.py` empty, the given under about 300 lines, then the closing check.

### Step 38: Split the nuisance report, gate session and run tests

- **Files**: create `tests/unit/nuisance/test_nuisance_report_sections.py`, `gate/test_nuisance_gate_benign_calls.py`, `test_run_nuisance_dossier.py`, with given slices. Modify `test_nuisance_report.py`, `gate/test_nuisance_gate_session.py`, `test_run_nuisance.py` and their givens.
- **Do** (item E8, last bullet): the Exits and Not run tests, the benign-call and second-pass tests, the dossier subcommand tests move. `test_nuisance_fingerprint.py` stays.
- **Test**: moves only.
- **Verify**: every touched file under about 300 lines, then the closing check.

### Step 39: Committed baselines on temporary files, census and declared-flips cleanups

- **Files**: `tests/unit/evals/test_eval_baseline.py`, `support/test_eval_baseline_given.py`, `test_judge_baseline.py`, `support/test_judge_baseline_given.py`, `test_declared_flips.py` (under `tests/unit/evals/`), `tests/unit/support/retired_word_exemptions.py`, move `tests/unit/census/test_census_work.py` and its given to `tests/unit/detection/test_detection_census_work.py` and `tests/unit/detection/support/test_detection_census_work_given.py`.
- **Do** (items F1, F2): `a_baseline_file_keyed_replay_rule(tmp_path)` in each given, the tests asserting `load_baseline(path).retest_rule == RetestRule()` (and the judge's), the written-key tests against `RetestRule().model_dump()`. Widen the `replay_rule` entry's glob to `tests/unit/evals/*test_*baseline*.py`. F2's deletion, rewrite and move (the census given stops importing a detection given).
- **Test**: two rewritten load tests on temporary files.
- **Verify**: the closing check.

### Step 40: Integration support: support servers, one unconfined audit, the Docker shim fixture

- **Files**: create `tests/integration/support/support_servers.py`, `tests/integration/support/unconfined_audit.py`. Modify `tests/integration/support/test_audit_server_failures_given.py`, `test_mcp_client_transport_given.py`, `test_resume_earlier_checkpoint_given.py`, `tests/integration/test_confined_launch.py`, `tests/integration/conftest.py`, `tests/integration/test_mcp_client_transport.py`.
- **Do** (item F3, first and third bullets): `a_read_server`, `a_stalling_server`, `A_COMMAND_NOT_FOUND` in `support_servers.py`. `AuditVariant(llm, output, resume, tools)` (frozen, defaults of the commonest caller) and `an_unconfined_audit(launch, variant=AuditVariant())` in `unconfined_audit.py`, the three givens passing `dataclasses.replace`d variants. The `docker_on_the_host` fixture returns the shim directory, the five transport tests use it, `a_docker_on_the_host` goes.
- **Test**: no new test.
- **Verify**: `uv run pytest tests/integration/test_audit_server_failures.py tests/integration/test_mcp_client_transport.py tests/integration/test_resume_earlier_checkpoint.py tests/integration/test_confined_launch.py -n auto` green, then the closing check.

### Step 41: One prerequisite check for the Docker integration tests

- **Files**: create `tests/integration/support/docker_prerequisites.py`. Modify `tests/integration/test_cve_planting_stand_ins.py`, `test_cve_keyed_stand_in_routes.py`, `test_nuisance_public_names.py`, `test_cve_planting.py`, `test_cve_layout_mount.py`, `test_cve_closed_networks.py`, `test_detection_calibration_check.py`, `test_kit.py`, `test_nuisance_doris_backend.py`.
- **Do** (item F3, second bullet): `skip_or_require(missing: str)` and `stand_in_prerequisites()`, used in the nine files.
- **Test**: no new test. A run with `CVE_PLANTING_REQUIRED=1` and Docker unavailable (for instance `DOCKER_HOST=unix:///nonexistent`) fails instead of skipping, then the normal run passes.
- **Verify**: `CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration/test_cve_planting.py tests/integration/test_cve_planting_stand_ins.py tests/integration/test_cve_keyed_stand_in_routes.py tests/integration/test_nuisance_public_names.py tests/integration/test_cve_layout_mount.py tests/integration/test_cve_closed_networks.py tests/integration/test_detection_calibration_check.py tests/integration/test_kit.py -n auto` green with no skip. The Doris backend test runs by hand with `NUISANCE_DORIS=1` only if its prerequisite branch changed shape. Then the closing check.

### Step 42: Integration names, the transport split, the memory bound in bytes

- **Files**: `tests/integration/test_nuisance_public_names.py`, `tests/integration/test_mcp_client_transport.py` and its given, create `tests/integration/test_mcp_client_relaunch.py` and `test_mcp_client_cancellation.py` (with given slices), `tests/integration/test_cve_planting.py` and its given.
- **Do** (items F4, F5): `value_after(args, "--network").startswith("container:")`. The ping, relaunch and declared-container removal tests, and the four cancelled-caller tests, leave the transport file. The byte count derived from `MEMORY_BOUND` in the planting given, and `MemorySwap == Memory` asserted.
- **Test**: one strengthened assertion, moves, one derived value.
- **Verify**: `CVE_PLANTING_REQUIRED=1 uv run pytest` over the integration file list of the plan's Verification section (Area F) `-n auto`, green with no skip, then the closing check.

### Step 43: The retired-word scan reads living text only and sees test names

- **Files**: `tests/unit/support/retired_word_scan.py`, `tests/unit/support/retired_words.py`, `tests/unit/support/retired_word_exemptions.py`, `tests/unit/project/test_glossary.py`.
- **Do** (item 0.7):
  - Before any edit, measure the fixture's setup time: `uv run pytest tests/unit/project/test_glossary.py -n 0 --durations=3`.
  - Tests first in `test_glossary.py`: the skipped set of the size bound is exactly the five Android Dockerfiles 0.7 names, and a fixture tree whose test name carries a retired word in snake_case is reported. Both red before the scan change.
  - `living_texts` skips files above 100 KB inside its walk over `src/`, `evals/` and `tests/` only (never the Markdown it reads in part). The three `$Stub` allowlist entries go.
  - The scan also reads every `def test_\w+` name with `_` as a space. Symbol patterns stay.
  - Remove `RetiredWord.step`, every `step` value, `Exemptions.not_yet_renamed`, `Exemptions.not_yet_migrated` (and `NOT_YET_RENAMED`, `NOT_YET_MIGRATED`), with `test_a_word_not_yet_renamed_is_skipped` and `test_a_file_not_yet_migrated_is_skipped`. `test_an_unknown_pattern_id_in_the_exemptions_is_refused` uses an `AllowedLine` naming `no-such-word`.
  - Add the old stems of the test files this plan renamed (`test_fix_check_resolver`, `test_census_work`, `test_census_work_given`) to `_OLD_TEST_STEMS`, per the one-line-per-rename convention under Out of scope.
  - The scan comes out green with no new allowlist entry. A hit on a legitimate compatibility name (the checkpointing channels) gets an entry with that reason. Any other hit is a rename Step 4 or 5 missed, renamed here.
- **Test**: the pinned skipped set, the test-name reading (shown red on the fixture tree before the scan change), the rewritten unknown-pattern test.
- **Verify**: the setup time measured again (both times in the commit message). Final checks of the plan: every new or split test file is under about 300 lines. `git grep -n "monkeypatch.setattr" -- tests` lists no site absent at d7dc9ef beyond `ScriptedDocker.installed` and `a_fix_check_ready` (compare with `git grep -n "monkeypatch.setattr" d7dc9ef -- tests`). The unit test count (`uv run pytest tests/unit --collect-only -q | tail -1`) is lower than at d7dc9ef (collect it there in a temporary `git worktree` under the scratchpad, then remove the worktree). Then the closing check.
