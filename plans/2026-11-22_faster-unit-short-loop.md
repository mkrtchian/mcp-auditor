# A faster unit short loop

## Context

The short loop, `uv run pytest tests/unit -n auto --maxprocesses 6`, takes about 30 s on the maintainer's laptop (i7-11800H, 8 cores / 16 threads): 5410 tests, about 90 s of CPU in total, plus about 5 s of collection per worker and about 2 s of worker shutdown. Measured on 2026-11-21:

- `tests/unit/nuisance/test_run_nuisance_run.py` costs 10.2 s. `evals/run_nuisance.py:_refuse_stale_holdout_calibration_copies` calls `current_copy_fingerprints`, which recomputes `fixture_fingerprint` for 259 targets on every call: 3515 `ast.parse` of the same few dozen sources per test, through `evals/baseline.py:fingerprint_source`. With a cache on `fingerprint_source` the file takes about 1 s.
- `evals/cve/holdout_hierarchical.py:_difference_mass` runs about 13 million pure-Python iterations per contrast (320 theta points squared, times 128 concentration points). `check_conclusion` makes four contrasts. The statistic and report tests (`tests/unit/cve/test_cve_holdout_statistic.py`, `tests/unit/nuisance/test_nuisance_statistic.py`, `tests/unit/detection/test_detection_holdout_report.py`, `tests/unit/nuisance/test_nuisance_report.py`) take 37 s run serially. With a 40 × 16 grid they take 4 s and all pass. Skipping the terms below 1e-18 of their maximum and updating the mass by list slices makes one contrast about 2.2 times faster, with identical intervals on random inputs.
- About 1800 unit tests check the committed content of the repository (records, fixtures, compose services, Dockerfiles, docs, workflows) rather than the behavior of code. They cost about 25 s of CPU, among them the retired-word scan of `tests/unit/project/test_glossary.py` (12 s, alone at the tail of the run, +7 s of wall time).

Removing the content tests alone brings the loop to 19 s. Together with the fingerprint cache and the faster contrast it comes to about 16 s. The rest is collection (about 4 s per worker, mostly the provider SDKs that `mcp_auditor/adapters/__init__.py` loads through `llm.py`) and worker shutdown, out of scope here.

## Decisions

- The retired-word scan is neither split nor prefiltered: it moves with the content tests (Part D), where it runs on one worker beside the Docker tests and does not set the wall time.
- The contrast gets both speedups: an exact-in-practice pruning in production code (Part B) and a grid the statistic and report tests can pass (Part C).
- A content test moves when it goes red on a change of committed content, not on a change of code. Tests that sweep a committed registry but check code stay in `tests/unit`: the launch-builder sweeps (`test_cve_launches.py`, `test_audited_launch_names.py`, `test_backend_lifecycle.py`) and the import-boundary scans (no kit, dossier, fix-check or grammar module imports `mcp_auditor`, no instrument imports the holdout target module, the clean closure of every admitted server). Several of them are the guards the CLAUDE.md Landmines name, and a broken builder or import must still show in the short loop.
- The moved tests go to `tests/integration/committed/`, keeping the area layout of `tests/unit/` (`project/`, `census/`, `evals/`, `cve/`, `cve/backends/`, `detection/`, `nuisance/`, `nuisance/admission/`, `nuisance/fix_checks/`), each with its `support/`. The full check (`uv run pytest -n auto`) and the CI integration step run them with no change to the CI.

## Part A: cache `fingerprint_source`

`evals/baseline.py`: decorate `fingerprint_source(source: str) -> str` with `functools.cache`. The function is pure on its argument, and the sources it sees are bounded by the files of the repository. No other change: `fingerprint_sources` and every caller stay as they are. The callers that read files (`fixture_fingerprint`, `counter_fingerprint`, the nuisance fingerprints) still read them on every call, so an edited file is fingerprinted anew.

No new test: the existing ones in `tests/unit/evals/test_eval_baseline.py` pin what the function returns, and the cache changes only its speed. The step's evidence is the timing of `tests/unit/nuisance/test_run_nuisance_run.py` before and after (10.2 s to about 1 s).

## Part B: a faster `_difference_mass`

`evals/cve/holdout_hierarchical.py`, `_difference_mass` only. Two changes:

1. Skip the negligible terms. A module constant `_NEGLIGIBLE = 1e-18`. A concentration point `j` whose `weight` (already `exp(log_evidence[j] - ceiling)`, so at most 1) is below `_NEGLIGIBLE` is skipped. For the others, the loops run only over the support of `cond_a[j]` and of `cond_b[j]`: the index range from the first to the last value above `_NEGLIGIBLE` times that row's maximum. A short comment states why this is safe: every dropped product is below 1e-18 of the largest one, far under what the 95 % quantiles can see.
2. Update the mass by slices. For a fixed `j` and `ia`, the indices `ia - ib + offset` over the support of `b` are one contiguous range in reverse order. Reverse the support of `cond_b[j]` once per `j` and update `mass[start:start + width]` with a list comprehension over `zip`. Each mass cell still receives its additions in the same order.

Keep the function under 20 lines: move the support computation into a small helper below it (`_support(row: list[float]) -> tuple[int, int]`). Keep the "Pure, `math` only" docstring true.

Test first, a characterization test in `tests/unit/cve/test_cve_holdout_hierarchical.py`: before touching the code, compute `contrast_hierarchical` on two or three fixed inputs (a lopsided pair, a balanced pair, sides of different sizes, both priors used by the statistic: `GammaPrior(1.0, 1.0)` and `GammaPrior(2.0, 2.0)`) on the current code, and pin `low` and `high` to within 1e-9. Compute them on the file's existing `COARSE` grid (`Grid(theta_points=120, d_points=48)`), not the default one: both changes are independent of the grid size, and one default-grid contrast costs about 1 s of CPU today (`test_contrast_all_extreme_matches_the_offline_untruncated_value`), so six of them would add seconds to the loop this plan shortens. The existing default-grid tests of the file keep covering the production grid. The test is green before the change and must stay green after. The existing tolerance tests of that file must stay green too.

## Part C: a grid the statistic and report tests can pass

Thread a keyword parameter `grid: Grid = DEFAULT_GRID` (`Grid` and `DEFAULT_GRID` from `evals/cve/holdout_hierarchical.py`) from the report builders down to the two hierarchical functions. The default is the production grid, so no run, report or stored result changes.

- `evals/cve/holdout_statistic.py`: `read_contrast(reading_a, reading_b, runs, suffix="", *, grid=DEFAULT_GRID)` passes it to both `contrast_hierarchical` calls. `check_conclusion(side_a, side_b, runs, *, grid=DEFAULT_GRID)` passes it to both `read_contrast` calls. `detection_rate_controls(results, runs, *, grid=DEFAULT_GRID)` passes it through `_hierarchical` to `hierarchical_interval`.
- `evals/cve/nuisance/statistic.py`: same for its `check_conclusion` and `nuisance_rate_controls`.
- `evals/cve/detection/holdout_report.py` and `evals/cve/nuisance/report.py`: `build_report(run, *, grid=DEFAULT_GRID)` passes it to the controls and to `_conclusion_line(pair, runs, grid)`.

The commands (`evals/run_detection_holdout.py`, `evals/run_nuisance.py`) keep calling `build_report(run)`: production never passes a grid.

Tests: a shared constant `COARSE_GRID = Grid(theta_points=40, d_points=16)` in a new `tests/unit/support/coarse_grid.py`, with a one-line comment saying it is for tests whose assertions do not depend on the precision of the hierarchical intervals. The test files `test_cve_holdout_statistic.py`, `test_nuisance_statistic.py`, `test_detection_holdout_report.py`, `test_detection_holdout_report_cutoff.py`, `test_nuisance_report.py` and `test_nuisance_report_sections.py` pass `grid=COARSE_GRID` at each of their calls of `check_conclusion`, `read_contrast`, the rate controls or `build_report`. These calls sit in the test files themselves, not in their given modules (`build_report(run)` is called inline some 60 times, and `test_cve_holdout_statistic.py` has no given module). A test whose assertion reads a hierarchical bound to a precision the coarse grid does not keep (a pinned number, a placement that changes with the grid) keeps the default grid. A test that compares the rate controls to an expected `hierarchical_interval(...)` (`test_nuisance_statistic.py`, `test_cve_holdout_statistic.py`) either keeps the default grid or passes `COARSE_GRID` to both sides. `test_cve_holdout_hierarchical.py` keeps its grids as they are (the default, `FINER`, and its own `COARSE` for two contrast tests). Add one test per statistic module showing the grid reaches the computation: the same sides read with `COARSE_GRID` and with the default grid give different hierarchical intervals (so a dropped parameter would show). The `test_run_*` tests go through the commands and keep the default.

## Part D: content tests move to `tests/integration/committed/`

### What moves

A content test is one that goes red on a change of committed content, not on a change of code. The list below applies that rule. The implementer moves exactly these, and stops to report a test whose move would break a STAY test of the same file rather than deciding otherwise.

Whole files (with the given and then modules only they use):

- `tests/unit/project/test_readme_policy.py`
- `tests/unit/project/test_workflow_path_filters.py` (its given runs `git ls-files`)
- `tests/unit/cve/test_committed_stand_ins.py`
- `tests/unit/cve/test_cve_compose_labels.py`
- `tests/unit/cve/backends/test_backend_hostnames.py`
- `tests/unit/nuisance/admission/test_nuisance_admission_loads.py`
- `tests/unit/nuisance/admission/test_nuisance_walk_record_loads.py`
- `tests/unit/nuisance/test_nuisance_compose.py`
- `tests/unit/nuisance/test_nuisance_fixture_sources.py`
- `tests/unit/detection/test_detection_holdout_fixture_sources.py`

Some functions of a file (the rest of the file stays in `tests/unit`):

- `project/test_glossary.py`: `test_living_files_use_no_retired_word`, `test_every_allowlist_entry_matches_a_line` (with the module fixture `repository_scan`), `test_the_size_bound_skips_only_the_files_embedding_an_android_capture` (with `THE_ANDROID_DOCKERFILES`), `test_claude_md_imports_the_glossary`. `tests/unit/support/retired_words.py` and `tests/unit/support/retired_word_exemptions.py`, used only by these tests, move to `tests/integration/committed/project/support/`. `tests/unit/support/retired_word_scan.py` stays, since the scanner's behavior tests use it.
- `project/test_pypi_readme.py`: `test_every_link_of_the_real_readme_is_absolute_on_pypi`.
- `census/test_census.py`: `test_the_committed_census_loads`.
- `census/test_census_grouping.py`: `test_every_current_and_dropped_acceptance_target_is_an_acceptance_target_flaw`.
- `evals/test_eval_baseline.py`: `test_no_honeypot_passes_instructions_to_its_server`, `test_no_tool_name_appears_in_two_honeypots`.
- `evals/test_judge_fixture.py`: `test_the_committed_fixture_is_a_labeled_draw`.
- `evals/test_honeypot_fault_harness.py`: `test_the_harness_accepts_the_fixture`.
- `cve/test_cve_holdout_conditions.py`: `test_the_committed_file_is_ready_for_the_logged_models`.
- `cve/test_cve_places.py`: `test_the_imported_places_file_matches_the_recorded_hash`, `test_every_target_reaches_only_the_closed_vocabulary`, `test_every_kept_place_is_offered_by_the_file_within_its_target_reach`, `test_no_target_keeps_an_unplaceable_place`, `test_every_target_kept_list_plants_together`.
- `cve/backends/test_mcp_ssh_sshd_backend.py`: `test_the_mcp_ssh_config_is_the_readme_production_entry`, `test_the_sshd_serves_the_account_the_mcp_ssh_config_names`, `test_the_mcp_ssh_benign_calls_name_the_config_host`, `test_the_mcp_ssh_key_halves_are_one_pair_with_the_readme_comment`.
- `detection/test_detection_targets.py`: `test_every_exploit_reads_as_aimed_and_the_benign_call_does_not`, `test_four_targets_remain_and_the_prefix_collision_merged_into_the_symlink_target`, `test_the_repository_bypass_cve_is_out_of_scope_with_a_reason`, `test_the_tools_filter_names_exactly_the_tools_its_exploits_call`, `test_every_server_and_patched_image_of_a_target_is_a_compose_service`, `test_every_surviving_target_carries_a_fallback_scope_and_the_normal_launch_mode`, `test_only_the_git_target_declares_a_read_write_layout`, `test_every_acceptance_target_runs_from_the_checkout`. The module helper `_a_fictional_places` is shared with STAY tests: move it into a support module both sides import.
- `detection/test_detection_holdout_targets.py`: every test except the import scan and its two sanity checks (`test_every_instrument_the_scan_reads_exists`, `test_the_module_the_scan_looks_for_exists`, `test_no_instrument_imports_the_holdout_target_module`), which stay.
- `detection/test_detection_draw_record.py`: `test_the_committed_census_draw_validates_clean`.
- `detection/test_detection_baseline.py`: `test_a_target_declaring_a_stand_in_builds_the_stand_in_image`.
- `detection/test_detection_preflight.py`: `test_the_printed_services_are_compose_services_and_no_holdout_one`.
- `nuisance/admission/test_nuisance_re_admission_dossier.py`: `test_no_committed_server_carries_a_shared_helper_of_the_fix_check_package`, `test_every_copied_flaw_resolves_to_one_target_and_one_fixture`. `test_every_admitted_server_has_a_clean_closure` stays (import boundary).
- `nuisance/fix_checks/test_nuisance_fix_checks.py`: every test except the four import scans (`test_the_scans_read_the_fix_check_modules`, `test_the_environments_scan_names_an_importable_module`, `test_no_fix_check_module_imports_mcp_auditor`, `test_no_fix_check_module_imports_cve_environments`), which stay.
- `nuisance/test_nuisance_backend_registry.py`: `test_the_run_image_bakes_the_address_its_backend_stands_at`, `test_the_jenkins_run_image_bakes_the_api_token_the_controller_image_seeds`, `test_a_built_backend_resets_no_container_by_name`.
- `nuisance/test_nuisance_backend_registry_built.py`: `test_a_backend_built_locally_names_the_compose_service_of_its_image`, `test_every_run_responder_image_is_rebuilt_with_its_backend`, `test_every_fix_check_responder_image_is_rebuilt_by_a_fix_check_naming_it`.
- `nuisance/test_nuisance_fingerprint.py`: `test_every_served_path_of_a_registered_backend_exists`.

Stay in `tests/unit`, explicitly: `test_fixture_contamination.py` (its scans read `src/`), `test_cve_dossier_closure.py`, `test_cve_grammar_boundary.py`, `test_kit_isolation.py`, `test_cve_launches.py`, `test_audited_launch_names.py`, `test_backend_lifecycle.py`, the golden masters, and the single-record pins (the git_init staged set, the Doris launch difference, the unconfined thread-id hash, the Anthropic wire-model parity).

### How a file moves

- A moved test keeps its name. A file moved whole keeps its name under the matching area of `tests/integration/committed/`. The moved functions of a split file go to a file of the same name there, so `git log --follow` and a reader find them.
- Given and then: a module used only by moved tests moves with them to the new area's `support/`. A module used by both sides stays in `tests/unit/.../support/` and the moved tests import it from there (`tests/integration` already imports from `tests.unit` in four places). A constant or helper used only by moved tests moves into the new given; one used by both sides goes to a support module both import. A moved given that holds only one-line wrappers after the split is inlined, per the testing standards.
- Every new directory gets an `__init__.py`, as the test tree does today.
- Paths computed from the test file's depth. Three module-level constants find the repository through `Path(__file__).resolve().parents[3]`, one level short under `tests/integration/committed/<area>/`: `README` in `test_readme_policy.py`, `COMPOSE_PATH` in `test_detection_targets.py` (used only by a moved test) and `_EVALS` in `test_detection_holdout_targets.py` (used by the moved `test_the_a11y_images_bake_the_committed_fixture_authority` and by the import scan that stays). In the moved code, build them from `evals.honeypots.REPO_ROOT`, as `test_glossary.py` already does. The STAY copies may keep theirs. (`_FIX_CHECK_DIR` in `test_nuisance_fix_checks.py` is used only by the import scans that stay.)
- The Docker shim. `tests/unit/conftest.py` installs an autouse `docker` shim that exits 99, a safety net for tests that build launches. Move its body into a helper `install_docker_shim(monkeypatch, tmp_path_factory)` in `tests/unit/support/docker_shim.py`. `tests/unit/conftest.py` keeps its autouse fixture, now a call to the helper, and a new `tests/integration/committed/conftest.py` gets an autouse fixture that makes the same call. The rest of `tests/integration` keeps real Docker. The shim's message becomes neutral, "a test reached docker", since it now also guards tests outside `tests/unit`.
- The retired-word scan names paths. In `tests/unit/support/retired_word_scan.py`, `_SKIPPED` lists the moved glossary test file, its given if it has one, and the moved `retired_words.py` and `retired_word_exemptions.py` at their new paths, beside the unit glossary test and its given, which stay. In the moved `retired_word_exemptions.py`, an allowlist entry whose `path_glob` names a moved file is updated to the new path, else it goes stale and `test_every_allowlist_entry_matches_a_line` fails.

### Living text that names a moved path

- `CLAUDE.md`, Landmines: the CVE-2026-5323 entry names `tests/unit/detection/test_detection_holdout_targets.py` as the test that catches a stale authority copy. It now names `tests/integration/committed/detection/test_detection_holdout_targets.py`. The Workflow paragraph on the README names `tests/unit/project/test_readme_policy.py`, which moves too. The entries citing `test_cve_launches.py` and `test_audited_launch_names.py` stay as they are.
- `CLAUDE.md`, Commands: the `tests/integration` line also says it runs the tests of the committed content under `tests/integration/committed/` (no Docker, no network beyond `git ls-files`), and a new line gives `uv run pytest tests/integration/committed -n auto`, "the tests of the committed content alone".
- `CLAUDE.md`, Testing standards, the "Three test levels" bullet: the integration level reads "integration (real MCP server or Docker, no LLM, and the tests of the committed content)", so the bullet no longer says that every integration test runs a server. No new ADR: ADR 003 already gave way to the gate fault injection and the Docker tests at this level without one, and the levels' purpose (code in the short loop, the rest in the full check) is unchanged.
- `CLAUDE.md`, Testing standards: after the sentence on where a unit test lives, one sentence: a test that goes red on a change of committed content (a record, a fixture, compose.yml, a Dockerfile, a doc or a workflow) rather than of code lives under `tests/integration/committed/`, in the directory of its area, its given and then in that directory's `support/`. A test that sweeps a registry to check code stays a unit test.
- `CLAUDE.md`, Workflow: after the sentence on which integration files to run in the loop, one sentence: a change to committed content also runs `uv run pytest tests/integration/committed -n auto`.
- `CONTRIBUTING.md`: the sentence naming `tests/unit/cve/test_cve_compose_labels.py` (the fingerprint label to paste) names the new path. The command block gets the line for the committed-content tests.
- `evals/docker/compose.yml`, the header comment: the new path of `test_cve_compose_labels.py`.
- `CHANGELOG.md`, the `[Unreleased]` entry on the digest-pinned base images names `tests/unit/cve/test_cve_compose_labels.py`: it names the new path. The released sections are not touched.
- Grep the repository's living text (code, comments, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `docs/usage.md`, `docs/evals.md`, `evals/*.md`, the workflows) for every moved file's old path and update each. `plans/`, `docs/adr/` and the dated entries of the logs are historical and are not touched.

## What stays unchanged

- Every production result: the default grid, the reports, the stored run results, the fingerprints and their values.
- The test count of the full check (`uv run pytest -n auto`): only the location changes. The unit and integration counts move by the same number.
- The CI workflows. `tests/integration/committed/` is under the integration step's path.
- The retired-word scanner, its words and its exemptions (except the path globs of moved files).
- `plans/`, `docs/adr/`, the historical logs.

## Edge cases

- A file is edited in a long-lived process after its fingerprint was cached: the callers read the file again and pass the new text, which misses the cache. Nothing caches the read.
- A row of `cond_a[j]` or `cond_b[j]` whose values are all equal: its support is the whole row.
- A weight exactly at `_NEGLIGIBLE`: kept (the test is strictly below).
- A moved test that needs a STAY helper defined in a test module (not a support module): the helper moves to a support module first, in the same step.
- A moved file whose name collides with a STAY file of the same area: both are fine under distinct packages. The split keeps the name on both sides on purpose.

## Verification

Before any change, record the baseline: `uv run pytest tests/unit -n auto --maxprocesses 6` wall time (three runs, median), the unit count, the integration count, and the full check's count.

After each part, the short loop and `uv run pyright` on the changed files. After Part D, also:

- `uv run pytest tests/integration/committed -n auto`, green.
- The counts: unit count + integration count after = before, and the full check's count unchanged.
- `git grep -n` for each moved file's old path returns only historical text.
- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green.
- The short loop's wall time, three runs, median, reported against the baseline (target: about 16 s at 6 workers).

## Due diligence record

This section records what the due-diligence pass concluded about the external facts this plan cites or defers, for the passes that run after it, the implementation-phase fact check included. It says what was concluded once, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- SETTLED: `functools.cache` (standard library since Python 3.9, the project requires `>=3.13`, verified against the project's own interpreter with `uv run python`). The plan cites no other third-party API, library, action or version, and defers none.

## Implementation steps

Common to every step:

- Since this plan was written, the holdout run renaming landed (`4e7cfed`): the file the plan calls `tests/unit/nuisance/test_run_nuisance_run.py` is now `tests/unit/nuisance/test_run_nuisance_holdout_run.py`, and its given is `tests/unit/nuisance/support/test_nuisance_holdout_run_given.py`. Use the current names.
- Docker disk: no step builds or pulls an image. The full check (`uv run pytest -n auto`) contains the Docker image tests, which build a missing image on first run. Before running it, check with `docker images` that the images those tests use are present. If one is missing, run the full check with `--deselect` on the tests that would build it, and say so in the step report. Cleanup of existing images is left to the maintainer.
- The short loop and the per-file pyright run follow the Workflow of `CLAUDE.md`. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .` and `uv run pyright`, all green.
- Every Part D step (Steps 4 to 9) also runs, before and after its moves, `uv run pytest --collect-only -q | tail -1` (no Docker runs at collection): the total is unchanged, and `uv run pytest tests/unit --collect-only -q | tail -1` drops by exactly the number of tests the step moved. It also runs `uv run pytest tests/integration/committed -n auto` green, which holds the retired-word scan from Step 4 on.
- Part D rules apply to every move step, as the plan's "How a file moves" states them: a moved test keeps its name, a split file keeps its name on both sides, a support module used only by moved tests moves to the new area's `support/`, one used by both sides stays in `tests/unit` and the moved tests import it from there, a helper defined in a test module and shared by both sides goes to a support module first, every new directory gets an `__init__.py`, a `Path(__file__).resolve().parents[3]` in moved code becomes `evals.honeypots.REPO_ROOT`. Use `git mv` for a file moved whole. A test whose move would break a STAY test of the same file is not moved: stop and report it.
- After each move step, `git grep -n` for the old path of every file the step moved returns only `plans/`, `docs/adr/` and dated log entries.

### Step 1: baseline, cache `fingerprint_source`, faster `_difference_mass`

- **Files**: `tests/unit/cve/test_cve_holdout_hierarchical.py`, `evals/baseline.py`, `evals/cve/holdout_hierarchical.py`.
- **Do**:
  1. Record the baseline before any change: `uv run pytest tests/unit -n auto --maxprocesses 6` wall time (three runs, median), the unit count, `uv run pytest tests/integration --collect-only -q | tail -1`, and `uv run pytest --collect-only -q | tail -1`. Also time `uv run pytest tests/unit/nuisance/test_run_nuisance_holdout_run.py -n 0` (plan: about 10.2 s). Write these numbers into the commit message body of this step, so Steps 4 to 9 can compare against them (`git log`).
  2. Characterization test first (Part B): in `tests/unit/cve/test_cve_holdout_hierarchical.py`, add tests computing `contrast_hierarchical` on the file's existing `COARSE` grid (`Grid(theta_points=120, d_points=48)`) for three fixed inputs: a lopsided pair, a balanced pair, sides of different sizes, each under `GammaPrior(1.0, 1.0)` and `GammaPrior(2.0, 2.0)` (a parametrized test is fine). Compute `low` and `high` on the current code and pin them with `pytest.approx(..., abs=1e-9)`. Run them green before touching the code. The default-grid tests of the file stay as they are.
  3. Part A: decorate `fingerprint_source(source: str) -> str` in `evals/baseline.py` with `functools.cache`. Nothing else changes.
  4. Part B: in `evals/cve/holdout_hierarchical.py`, rewrite `_difference_mass` as the plan's Part B describes: a module constant `_NEGLIGIBLE = 1e-18`, skip a `j` whose `weight` is strictly below it, loop only over the support of `cond_a[j]` and `cond_b[j]` (first to last index whose value exceeds `_NEGLIGIBLE` times the row's maximum, a row of equal values keeping its whole range) through a helper `_support(row: list[float]) -> tuple[int, int]` below the function, reverse the support of `cond_b[j]` once per `j`, and update `mass[start:start + width]` with a list comprehension over `zip`, each mass cell still receiving its additions in the same order. A short comment states why the pruning is safe (every dropped product is below 1e-18 of the largest one). `_difference_mass` stays under 20 lines, and the module docstring's "Pure, `math` only" stays true.
- **Test**: the new characterization tests, green before and after the rewrite. The existing tests of `test_cve_holdout_hierarchical.py` and `tests/unit/evals/test_eval_baseline.py`, green.
- **Verify**: `uv run pytest tests/unit/cve/test_cve_holdout_hierarchical.py -n 0` green; the timing of `tests/unit/nuisance/test_run_nuisance_holdout_run.py` down to about 1 s; the short loop green; `uv run pyright` on the three files; then the step's closing checks.

### Step 2: a grid parameter through the statistic modules

- **Files**: `tests/unit/support/coarse_grid.py` (new), `tests/unit/cve/test_cve_holdout_statistic.py`, `tests/unit/nuisance/test_nuisance_statistic.py`, `evals/cve/holdout_statistic.py`, `evals/cve/nuisance/statistic.py`.
- **Do**:
  1. Tests first. Create `tests/unit/support/coarse_grid.py` with `COARSE_GRID = Grid(theta_points=40, d_points=16)` and a one-line comment saying it is for tests whose assertions do not depend on the precision of the hierarchical intervals. In each of the two test files, add one test showing the grid reaches the computation: the same sides read (the rate controls, or `check_conclusion`) with `grid=COARSE_GRID` and with the default grid give different hierarchical intervals. Run it red (the keyword does not exist yet).
  2. `evals/cve/holdout_statistic.py`: `read_contrast(reading_a, reading_b, runs, suffix="", *, grid: Grid = DEFAULT_GRID)` passes `grid` to both `contrast_hierarchical` calls; `check_conclusion(side_a, side_b, runs, *, grid=DEFAULT_GRID)` passes it to both `read_contrast` calls; `detection_rate_controls(results, runs, *, grid=DEFAULT_GRID)` passes it through `_hierarchical` to `hierarchical_interval`.
  3. `evals/cve/nuisance/statistic.py`: same for its `check_conclusion` (through the imported `read_contrast`) and `nuisance_rate_controls` (both `hierarchical_interval` calls).
  4. In both test files, pass `grid=COARSE_GRID` at each call of `check_conclusion`, `read_contrast` or the rate controls, except a test whose assertion reads a hierarchical bound to a precision the coarse grid does not keep (it keeps the default grid). A test comparing the rate controls to an expected `hierarchical_interval(...)` either keeps the default grid or passes `COARSE_GRID` to both sides. Confirm each changed test still asserts what it asserted, by running it on both grids while deciding.
- **Test**: the two new grid-reaches-the-computation tests; every existing test of both files green.
- **Verify**: `uv run pytest tests/unit/cve/test_cve_holdout_statistic.py tests/unit/nuisance/test_nuisance_statistic.py -n 0 --durations=5`, green and markedly faster than before; the short loop; `uv run pyright` on the five files; then the step's closing checks.

### Step 3: a grid parameter through the report builders

- **Files**: `evals/cve/detection/holdout_report.py`, `evals/cve/nuisance/report.py`, `tests/unit/detection/test_detection_holdout_report.py`, `tests/unit/detection/test_detection_holdout_report_cutoff.py`, `tests/unit/nuisance/test_nuisance_report.py`, `tests/unit/nuisance/test_nuisance_report_sections.py`.
- **Do**:
  1. In both report modules: `build_report(run, *, grid: Grid = DEFAULT_GRID)` passes `grid` to the rate controls (`detection_rate_controls` / `nuisance_rate_controls`) and to `_conclusion_line(pair, runs, grid)`, which passes it to `check_conclusion`. The commands (`evals/run_detection_holdout.py`, `evals/run_nuisance.py`) keep calling `build_report(run)`.
  2. In the four test files, pass `grid=COARSE_GRID` (from `tests/unit/support/coarse_grid.py`) at each inline `build_report(run)` call (53 calls), except a test whose assertion depends on the precision of a hierarchical bound (a pinned number, a placement that changes with the grid), which keeps the default. The `test_run_*` tests go through the commands and keep the default: do not touch them.
- **Test**: every existing test of the four files green. No new test: Step 2 already shows the grid reaches the computation, and the report builders only pass it on (a dropped pass-through makes the files slow, not wrong, which the timing below shows).
- **Verify**: `uv run pytest` on the four test files with `-n 0 --durations=10`, green, none of them in the seconds the plan's Context reports; the short loop; `uv run pyright` on the six files; then the step's closing checks.

### Step 4: the committed-content directory, the shared Docker shim and the project area

- **Files**: `tests/unit/support/docker_shim.py` (new), `tests/unit/conftest.py`, `tests/integration/committed/__init__.py`, `tests/integration/committed/conftest.py`, `tests/integration/committed/project/` (`__init__.py`, `support/__init__.py`, the moved files below), `tests/unit/project/test_glossary.py`, `tests/unit/project/test_pypi_readme.py`, `tests/unit/support/retired_word_scan.py`, `CLAUDE.md`, `CONTRIBUTING.md`.
- **Do**:
  1. Docker shim: move the body of `tests/unit/conftest.py`'s autouse fixture into `install_docker_shim(monkeypatch, tmp_path_factory) -> None` in `tests/unit/support/docker_shim.py`, its message now "a test reached docker: $PYTEST_CURRENT_TEST". `tests/unit/conftest.py` keeps its autouse fixture, now one call to the helper. `tests/integration/committed/conftest.py` gets an autouse fixture making the same call.
  2. Whole files, `git mv` to `tests/integration/committed/project/`: `test_readme_policy.py` (its `README` constant rebuilt from `REPO_ROOT`), `test_workflow_path_filters.py` with `support/test_workflow_path_filters_given.py`.
  3. Splits: `test_glossary.py` moves `test_living_files_use_no_retired_word`, `test_every_allowlist_entry_matches_a_line` (with the module fixture `repository_scan` and its comment), `test_the_size_bound_skips_only_the_files_embedding_an_android_capture` (with `THE_ANDROID_DOCKERFILES`, which moves out of the unit given if nothing else there uses it) and `test_claude_md_imports_the_glossary` to `tests/integration/committed/project/test_glossary.py`. `git mv` `tests/unit/support/retired_words.py` and `tests/unit/support/retired_word_exemptions.py` to `tests/integration/committed/project/support/`. `tests/unit/support/retired_word_scan.py` stays. `test_pypi_readme.py` moves `test_every_link_of_the_real_readme_is_absolute_on_pypi`.
  4. `retired_word_scan.py`: `_SKIPPED` lists the unit glossary test and its given (which stay), the moved glossary test file (and a moved given if one was created), and `retired_words.py` and `retired_word_exemptions.py` at their new paths. In the moved `retired_word_exemptions.py`, update any `path_glob` that names a file moved by this step.
  5. `CLAUDE.md`: the Commands block, the Testing standards and the Workflow lines of the plan's "Living text that names a moved path" (bullets 2, 3, 4 and 5: the `tests/integration` line mentions `tests/integration/committed/`, a new line `uv run pytest tests/integration/committed -n auto` "the tests of the committed content alone", the "Three test levels" wording, the sentence on where a content test lives, the Workflow sentence on running the committed-content tests after a change to committed content), and the Workflow paragraph's path of `test_readme_policy.py`. `CONTRIBUTING.md`: the command block gets the line for the committed-content tests.
- **Test**: no new test. The moved tests pass from their new place; the glossary scan stays green, its allowlist with no stale entry; a test that reaches `docker` under `tests/integration/committed/` still hits the shim (check by hand once, then drop the probe).
- **Verify**: the collection counts of the common section (4 + 1 + 3 + 2 = 10 tests leave `tests/unit`, if no STAY conflict was found); `uv run pytest tests/integration/committed -n auto` green; the grep for the old paths; the short loop; `uv run pyright` on the changed files; then the step's closing checks.

### Step 5: census, evals and cve/backends areas

- **Files**: under `tests/integration/committed/`, the `census/`, `evals/`, `cve/` and `cve/backends/` packages (with `__init__.py` and `support/__init__.py`) and the moved files; `tests/unit/census/test_census.py`, `tests/unit/census/test_census_grouping.py`, `tests/unit/evals/test_eval_baseline.py`, `tests/unit/evals/test_judge_fixture.py`, `tests/unit/evals/test_honeypot_fault_harness.py`, `tests/unit/cve/backends/test_mcp_ssh_sshd_backend.py`, their given/then modules as the rules require.
- **Do**: move, under the common rules:
  - `census/test_census.py`: `test_the_committed_census_loads`. `census/test_census_grouping.py`: `test_every_current_and_dropped_acceptance_target_is_an_acceptance_target_flaw`.
  - `evals/test_eval_baseline.py`: `test_no_honeypot_passes_instructions_to_its_server`, `test_no_tool_name_appears_in_two_honeypots`. `evals/test_judge_fixture.py`: `test_the_committed_fixture_is_a_labeled_draw`. `evals/test_honeypot_fault_harness.py`: `test_the_harness_accepts_the_fixture`. The allowlist entry `tests/unit/evals/*test_*baseline*.py` of `retired_word_exemptions.py` keeps matching the STAY file; add a glob for the moved one only if the moved functions carry the allowlisted text.
  - `cve/backends/test_backend_hostnames.py` whole (with its given). `cve/backends/test_mcp_ssh_sshd_backend.py`: `test_the_mcp_ssh_config_is_the_readme_production_entry`, `test_the_sshd_serves_the_account_the_mcp_ssh_config_names`, `test_the_mcp_ssh_benign_calls_name_the_config_host`, `test_the_mcp_ssh_key_halves_are_one_pair_with_the_readme_comment`.
- **Test**: the moved tests pass from their new place, the STAY tests of every split file still pass.
- **Verify**: the collection counts (2 + 4 + 6 + 4 = 16 tests leave `tests/unit`, the whole file counted at its current count); `uv run pytest tests/integration/committed -n auto`; the grep for `tests/unit/cve/backends/test_backend_hostnames`; the short loop; `uv run pyright` on the changed files; then the step's closing checks.

### Step 6: cve area

- **Files**: under `tests/integration/committed/cve/` (package from Step 5), the moved files; `tests/unit/cve/test_cve_holdout_conditions.py`, `tests/unit/cve/test_cve_places.py`, their given/then as the rules require; `CONTRIBUTING.md`, `evals/docker/compose.yml` (header comment), `CHANGELOG.md` (`[Unreleased]` only).
- **Do**:
  - Whole files: `cve/test_committed_stand_ins.py` (with its given and then), `cve/test_cve_compose_labels.py`.
  - `cve/test_cve_holdout_conditions.py`: `test_the_committed_file_is_ready_for_the_logged_models`. `cve/test_cve_places.py`: `test_the_imported_places_file_matches_the_recorded_hash`, `test_every_target_reaches_only_the_closed_vocabulary`, `test_every_kept_place_is_offered_by_the_file_within_its_target_reach`, `test_no_target_keeps_an_unplaceable_place`, `test_every_target_kept_list_plants_together`.
  - Living text: `CONTRIBUTING.md` (the fingerprint-label sentence), the header comment of `evals/docker/compose.yml`, and the `[Unreleased]` entry of `CHANGELOG.md` on digest-pinned base images name `tests/integration/committed/cve/test_cve_compose_labels.py`. Released sections untouched.
- **Test**: the moved tests pass from their new place; `test_cve_compose_labels.py` still prints the label value on a mismatch.
- **Verify**: the collection counts (5 + 4 + 1 + 5 = 15 tests leave `tests/unit`); `uv run pytest tests/integration/committed -n auto`; the grep for both whole files' old paths; the short loop; `uv run pyright` on the changed files; then the step's closing checks.

### Step 7: detection area

- **Files**: `tests/integration/committed/detection/` (package, `support/`) and the moved files; `tests/unit/detection/test_detection_targets.py`, `test_detection_holdout_targets.py`, `test_detection_draw_record.py`, `test_detection_baseline.py`, `test_detection_preflight.py`, their given/then as the rules require; a new support module for `_a_fictional_places`; `CLAUDE.md` (Landmines).
- **Do**:
  - Whole file: `detection/test_detection_holdout_fixture_sources.py` (with its then).
  - `test_detection_targets.py`: the eight tests the plan lists. `_a_fictional_places` is shared with STAY tests: move it first into a support module both sides import (for example `tests/unit/detection/support/fictional_places.py`). `COMPOSE_PATH` goes with the moved test, rebuilt from `REPO_ROOT`.
  - `test_detection_holdout_targets.py`: every test except `test_every_instrument_the_scan_reads_exists`, `test_the_module_the_scan_looks_for_exists`, `test_no_instrument_imports_the_holdout_target_module`. `_EVALS` is used on both sides: the moved file builds its own from `REPO_ROOT`, the STAY file keeps its `parents[3]`.
  - `test_detection_draw_record.py`: `test_the_committed_census_draw_validates_clean`. `test_detection_baseline.py`: `test_a_target_declaring_a_stand_in_builds_the_stand_in_image`. `test_detection_preflight.py`: `test_the_printed_services_are_compose_services_and_no_holdout_one`.
  - `CLAUDE.md`, Landmines: the CVE-2026-5323 entry names `tests/integration/committed/detection/test_detection_holdout_targets.py`.
- **Test**: the moved tests pass from their new place, the STAY tests (the import scan above all) still pass.
- **Verify**: the collection counts (1 + 8 + 16 + 1 + 1 + 1 = 28 tests leave `tests/unit`, counting the holdout targets file at its current 19 minus the 3 that stay, adjust to the parametrized ids collected); `uv run pytest tests/integration/committed -n auto`; the grep for `tests/unit/detection/test_detection_holdout_fixture_sources` and for the Landmines path; the short loop; `uv run pyright` on the changed files; then the step's closing checks.

### Step 8: nuisance area, admission and the whole files

- **Files**: `tests/integration/committed/nuisance/` and `nuisance/admission/` (packages, `support/`) and the moved files; `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` and its given/then as the rules require.
- **Do**:
  - Whole files: `nuisance/admission/test_nuisance_admission_loads.py`, `nuisance/admission/test_nuisance_walk_record_loads.py`, `nuisance/test_nuisance_compose.py`, `nuisance/test_nuisance_fixture_sources.py` (with `support/test_nuisance_fixture_sources_then.py`). `tests/unit/support/test_nuisance_committed_admission_given.py` is used by STAY modules too: it stays, the moved tests import it from there.
  - `nuisance/admission/test_nuisance_re_admission_dossier.py`: `test_no_committed_server_carries_a_shared_helper_of_the_fix_check_package`, `test_every_copied_flaw_resolves_to_one_target_and_one_fixture`. `test_every_admitted_server_has_a_clean_closure` stays.
- **Test**: the moved tests pass from their new place, the STAY tests of the split file still pass.
- **Verify**: the collection counts (6 + 4 + 2 + 3 + 2 = 17 tests leave `tests/unit`, adjusted to the parametrized ids collected); `uv run pytest tests/integration/committed -n auto`; the grep for the four whole files' old paths; the short loop; `uv run pyright` on the changed files; then the step's closing checks.

### Step 9: nuisance area, fix checks and backend registry, and the final measurements

- **Files**: `tests/integration/committed/nuisance/fix_checks/` (package, `support/`) and the moved files; `tests/unit/nuisance/fix_checks/test_nuisance_fix_checks.py`, `tests/unit/nuisance/test_nuisance_backend_registry.py`, `tests/unit/nuisance/test_nuisance_backend_registry_built.py`, `tests/unit/nuisance/test_nuisance_fingerprint.py`, their given/then as the rules require.
- **Do**:
  - `nuisance/fix_checks/test_nuisance_fix_checks.py`: every test except the four import scans (`test_the_scans_read_the_fix_check_modules`, `test_the_environments_scan_names_an_importable_module`, `test_no_fix_check_module_imports_mcp_auditor`, `test_no_fix_check_module_imports_cve_environments`). `_FIX_CHECK_DIR` stays with the scans. `support/recorded_exchanges.py` and `support/test_nuisance_fix_checks_given.py` move only if no STAY test uses them.
  - `nuisance/test_nuisance_backend_registry.py`: `test_the_run_image_bakes_the_address_its_backend_stands_at`, `test_the_jenkins_run_image_bakes_the_api_token_the_controller_image_seeds`, `test_a_built_backend_resets_no_container_by_name`.
  - `nuisance/test_nuisance_backend_registry_built.py`: `test_a_backend_built_locally_names_the_compose_service_of_its_image`, `test_every_run_responder_image_is_rebuilt_with_its_backend`, `test_every_fix_check_responder_image_is_rebuilt_by_a_fix_check_naming_it`.
  - `nuisance/test_nuisance_fingerprint.py`: `test_every_served_path_of_a_registered_backend_exists`.
  - Final sweep: `git grep -n` for the old path of every file moved whole in Steps 4 to 9 and of `retired_words.py` and `retired_word_exemptions.py`, over code, comments, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `docs/usage.md`, `docs/evals.md`, `evals/*.md` and the workflows; fix any living hit.
- **Test**: the moved tests pass from their new place, the STAY import scans still pass.
- **Verify**: the collection counts for this step; then the plan's final verification: `uv run pytest tests/integration/committed -n auto` green; the unit count plus the integration count equal Step 1's (from its commit message), and `uv run pytest --collect-only -q` gives Step 1's total; the final grep returns only historical text; the step's closing checks; the short loop's wall time, three runs, median, reported against Step 1's baseline (target: about 16 s at 6 workers).
