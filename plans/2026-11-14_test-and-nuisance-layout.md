# Unit test and nuisance package layout

## Context

Three directories have grown flat past the point where they are easy to navigate: `tests/unit` (228 files), `tests/unit/support` (198 files) and `evals/cve/nuisance` (44 files). The file name prefixes already form clear groups (`test_nuisance_*`, `test_detection_*`, `test_cve_*`, `gate_*`, `admission*`), so the groups exist and only the directories are missing.

This change is a pure move: no behavior changes, no test changes beyond import paths and `Path(__file__)` depth, and no fingerprint moves.

A third candidate, `evals/docker` (239 Dockerfiles), stays flat, for three reasons found while scoping:

- 58 committed record fields cite a Dockerfile by its flat path (`"file": "evals/docker/Dockerfile.<service>"`, 26 in `evals/census.json` written by the calibration agents, 32 in `evals/nuisance_admission.json`), and `evals/cve/fixture_sources.py` reads them (`unheld_requests`, `unserved_captures`, `unfingerprinted_stand_in_files`, through `test_detection_holdout_fixture_sources` and `test_nuisance_fixture_sources`). Moving the files means rewriting records the agents and the admission wrote, or adding a path shim.
- The calibration and admission kits use the flat convention `docker/Dockerfile.<service>` (`evals/cve/kit/launch.py`, the dossier instructions in `evals/cve/detection/calibration_dossier.py` and `evals/cve/nuisance/dossier.py`), and so does `image_dockerfile` in `evals/cve/docker_paths.py`.
- The `Dockerfile.holdout-*` prefix already sorts the 75 holdout Dockerfiles together, so the gain is smaller than the file count suggests.

## The constraint every move respects: no fingerprint moves

The fixture, grammar and counter fingerprints hash the AST of some modules, import statements included (`evals/baseline.py`, `fingerprint_source`). A module that moves changes the import lines of every module that imports it, so a fingerprinted module that imports a moved module would move a fingerprint, which resets the detection gate's baseline and makes the 17 recorded `holdout_fingerprint` stale. The fingerprinted modules are:

- `ENVIRONMENT_PATHS` and `GRAMMAR_PATHS` in `evals/cve/detection/baseline.py`, the `backend_sources` of the targets (modules of `evals/cve/backends/`), `CONFINEMENT_SOURCE` and `_PUBLIC_NAME_SOURCES` in `evals/cve/nuisance/fingerprint.py`, the `served` modules of `evals/cve/nuisance/backend_registry.py` (modules of `evals/cve/backends/` plus `closed_network.py`), and `_COUNTER_PATHS` in `evals/cve/nuisance/counter.py`.
- Inside `evals/cve/nuisance`, three of them are imported by fingerprinted modules or are fingerprinted themselves: `confinement.py` (imported by twelve backend modules and hashed by the nuisance fixture fingerprint), `counter.py` and `counting.py` (the counter fingerprint, `counter.py` imports `counting`). These three stay where they are.
- At module level, no fingerprinted module imports any other module of `evals/cve/nuisance` or anything under `tests/` (`grep -nE "^(from|import) evals\.cve\.(nuisance|detection)"` on every fingerprinted module: only `evals.cve.nuisance.confinement` appears). That anchored grep misses indented imports, and `fingerprint_source` hashes them too (the whole AST, `if TYPE_CHECKING:` blocks included): `counting.py` line 29 holds `from evals.cve.nuisance.admission import AdmittedServer, FlawRecord, ToolRecord` under `if TYPE_CHECKING:`. Moving `admission.py` to `admission/admission.py` rewrites that line and moves the counter fingerprint, which CONTRIBUTING.md (nuisance gate paragraph) and the glossary (**counter**) make a whole reset of the nuisance gate and a break in the comparability of holdout nuisance rates. No nuisance gate baseline exists (`evals/baselines/nuisance/` is absent) and no committed record carries a counter fingerprint, so the practical cost today is nil, but the plan's invariant does not hold as written. The unanchored grep (`grep -nE "^\s*(from|import) evals\.cve\.nuisance\."`) over the fingerprinted modules finds no other case.

**Decision: the counter fingerprint is allowed to move, and only it.** The import line in `counting.py` is rewritten like every other, and Part 1's commit adds an entry to `docs/labeling-log.md` (every instrument change has one, CLAUDE.md), following the shape of the existing entries that record a fingerprint moved by a module path (the grammar fingerprint entry around line 833, the counter fingerprint entry around line 869): **State** (no nuisance baseline under `evals/baselines/`, no nuisance run or gate run, the honeypot ground truth unchanged), **What changes** (the `TYPE_CHECKING` import of `counting.py` follows `admission.py` into `evals/cve/nuisance/admission/`, nothing the counter reads or counts changes), **Fingerprint** (the counter fingerprint moves from its value before Part 1 to its value after, both copied from the verification script's output, and the grammar, detection fixture and nuisance fixture fingerprints do not move), and the four questions of ADR 016 (an instrument change by module path, raised by the repository layout and by no measured value, reading no measured value, applying to every server alike). Nothing is reset, since nothing is recorded. Rejected: re-exporting the three names from `admission/__init__.py` (a compatibility shim, and an import of the whole package on first touch), and keeping `admission.py` at the root under a differently named subpackage (a package and a module of one name cannot coexist, and the layout would lose its point).


The verification section adds a before/after comparison of every fingerprint, as the vocabulary alignment did for `8132997`.

## Part 1: `evals/cve/nuisance` gets two subpackages

Module file names are kept as they are (`gate/gate_session.py`, not `gate/session.py`): every base name stays unique in the repository, so a search or an editor's file finder still lands on one file, and the change stays a move with no rename.

### `evals/cve/nuisance/gate/` (9 modules)

`gate.py`, `gate_baseline.py`, `gate_command.py`, `gate_console.py`, `gate_recording.py`, `gate_report.py`, `gate_session.py`, `gate_session_model.py`, `gate_session_recording.py`, plus an empty `__init__.py`.

### `evals/cve/nuisance/admission/` (11 modules)

`admission.py`, `admission_records.py`, `admission_walk.py`, `walk.py`, `walk_record.py`, `dossier.py`, `re_admission_dossier.py`, `re_admission_docs.py`, `holdout_target_reference.py`, `holdout_calibration_copies.py`, `unrecorded.py`, plus an empty `__init__.py`.

### What stays at `evals/cve/nuisance/` (23 modules and `fix_checks/`)

`__init__.py`, `assembly.py`, `audit.py`, `backend_registry.py`, `benign_call.py`, `commands.py`, `confinement.py`, `counter.py`, `counting.py`, `fingerprint.py`, `fix_check_command.py`, `fixtures.py`, `holdout_servers.py`, `images.py`, `markdown.py`, `provisioners.py`, `report.py`, `results.py`, `run.py`, `run_containers.py`, `solo.py`, `statistic.py`, `vet_command.py`, `vetting.py`, and `fix_checks/` unchanged. These are the run, the vet, the fix check and what all three share. A `run/` subpackage was considered and left out: `run.py` would become `run/run.py`, and `solo.py`, `backend_registry.py` and `images.py` serve the run, the vet and the gate alike.

### Imports to rewrite

Every `from evals.cve.nuisance.<moved> import ...` and `from evals.cve.nuisance import <moved>` in `evals/`, `src/` (expected: none) and `tests/` becomes `evals.cve.nuisance.gate.<moved>` or `evals.cve.nuisance.admission.<moved>`. Indented imports count: `if TYPE_CHECKING:` blocks import `admission` in `admission_records.py`, `admission_walk.py`, `backend_registry.py`, `counting.py` (see the decision above), `fingerprint.py`, `images.py`, `provisioners.py` and `run_containers.py`, so the rewrite script must not anchor its pattern at column 0. Outside the package, `evals/cve/fixture_sources.py` (`admission_records`), `evals/export.py` (`gate_session_model`) and `evals/run_nuisance.py` import moved modules.

Path depth in moved modules: `gate_baseline.py` sets `NUISANCE_GATE_BASELINE_DIRECTORY = Path(__file__).parents[2] / "baselines" / "nuisance"`, which becomes `parents[3]` once it sits in `gate/`. No other moved module computes a path from `__file__` (`admission.py` goes through `REPO_ROOT`). Dotted module strings in tests are rewritten the same way (`tests/unit/test_nuisance_re_admission_dossier.py` holds `"evals.cve.nuisance.fix_checks...."` strings, which do not move, so check rather than assume).

A move can create an import cycle that the flat package hid, for example `admission/__init__.py` being imported while `admission/admission.py` imports a root module that imports back from `admission`. The `__init__.py` files stay empty, so no new import happens at package import. If pyright or pytest reports a cycle, stop and report it: do not break it with a local import.

### Textual references in living files

- `evals/cve/nuisance/admission.py` docstring line 9 names `evals/cve/nuisance/unrecorded.py`: becomes `evals/cve/nuisance/admission/unrecorded.py`.
- `evals/cve/kit/backend_launch.py` names `evals/cve/nuisance/provisioners.py` (stays) and `evals/cve/nuisance/fix_checks/__init__.py` names `evals/cve/nuisance/fixtures.py` (stays): no change, listed so the implementer does not hunt for them.
- `CONTRIBUTING.md` names `evals/cve/nuisance/solo.py`, `counter.py` and `counting.py`, which stay: no change.
- Run `git grep -nE "evals/cve/nuisance/(gate|admission|walk|dossier|re_admission|holdout_target_reference|holdout_calibration_copies|unrecorded)[a-z_]*\.py|evals\.cve\.nuisance\.(gate|admission|walk|dossier|re_admission|holdout_target_reference|holdout_calibration_copies|unrecorded)" -- ':!plans' ':!docs/adr' ':!docs/*-log.md'` after the move: every hit outside the excluded paths is rewritten.

The dated logs (`docs/labeling-log.md`, `docs/nuisance-suite-log.md`, `docs/detection-suite-log.md`), the ADRs and the plans keep the paths of their date and are not edited. The two pre-registered rules name no module of `evals/cve/nuisance` (checked), so no rule version opens.

## Part 2: `tests/unit` gets one directory per area

### Target layout

```
tests/unit/
  conftest.py, __init__.py           (stay)
  support/                           (only the helpers shared across areas, see below)
  auditor/   + support/              tests of src/mcp_auditor
  evals/     + support/              shared eval machinery, honeypot suite, judge eval, model probe
  cve/       + support/              CVE benchmark shared code, grammar, planting, stand-ins, kit
  cve/backends/ + support/           backend provisioners and builders
  census/    + support/
  detection/ + support/
  nuisance/  + support/              run, vet, counter, fingerprint, shared nuisance code
  nuisance/admission/ + support/
  nuisance/fix_checks/ + support/
  nuisance/gate/ + support/
  project/   + support/              repository policies (glossary, README, workflow filters)
```

Every new directory, its `support/` included, gets an empty `__init__.py`, like `tests/unit/support/__init__.py` today, so the tests stay importable as `tests.unit.<area>...` packages. Each `test_X.py` moves to its area, and its `support/test_X_given.py` and `support/test_X_then.py` move to that area's `support/`. Test file names are kept, prefixes included, so `--lf` node ids, `git log --follow` and a search by name still work.

### Mapping (file stem after `test_`)

- **auditor (41)**: anthropic_structured_output, audited_server, chain_models, chain_nodes, chain_prompts, chat_model_factory, checkpointing, cli, config, config_file, confinement, console_display, console_findings, coverage, docker_client_env, export, generate_test_cases, graph, graph_throttling, host_paths, llm_adapter, llm_patience, llm_refusals, llm_throttling, log_redaction, missed_model_calls, model_inputs_golden, models, nodes, openrouter_models, owasp, payload_safety, progress, prompts, redaction, relayed_environment, rendering, server_execution, server_launch, stream_handler, throttling
- **evals (31)**: concurrency, declared_flips, draw_judge_cases, eval_baseline, eval_cell_grid, eval_display, eval_gate, eval_gate_outcome, eval_metrics, eval_recording, eval_session, fixture_contamination, honeypot_decision, honeypot_fault_fakes, honeypot_fault_harness, honeypot_fault_injection, honeypot_retest, judge_baseline, judge_display, judge_fixture, judge_gate, judge_metrics, judge_outcomes, judge_recording, judge_session, probe_analysis, probe_corpus, probe_subset, run_honeypot_suite, run_judge_eval, run_probe
- **cve (39)**: capture_kept_default, capture_stand_in, committed_stand_ins, cve_audit_progress, cve_closed_network, cve_closed_network_refusal, cve_compose_labels, cve_dossier_closure, cve_exchange_log, cve_failure_text, cve_fixture_provenance, cve_fixture_sources, cve_grammar, cve_grammar_boundary, cve_grammar_golden, cve_holdout_conditions, cve_holdout_hierarchical, cve_holdout_intervals, cve_holdout_statistic, cve_images, cve_keyed_stand_in_routes, cve_launch_audit, cve_launches, cve_layout, cve_places, cve_planting, cve_planting_endpoints, cve_planting_layout, cve_planting_stand_ins, cve_provider_errors, cve_public_stand_ins, cve_run_images, cve_sentinel_paths, cve_server_health, cve_strike, kit_benign_probe, kit_driver, kit_fix_check, kit_isolation
- **cve/backends (14)**: apify_backend, atlassian_backend, backend_hostnames, backend_lifecycle, ckan_holdout_builder, doris_backend, doris_serialization, facebook_ads_backend, gitlab_backend, httpbin_backend, kubernetes_backend, mcp_ssh_holdout_builder, node_sandbox_engine, searxng_backend
- **census (10)**: census, census_classification, census_draw_order, census_figures, census_grouping, census_identity, census_prefilter, census_sources, census_work, run_census
- **detection (29)**: detection_audit, detection_baseline, detection_calibration_check, detection_calibration_check_exit, detection_calibration_dossier, detection_console, detection_costs, detection_draw_record, detection_gate, detection_holdout_audit, detection_holdout_card_readiness, detection_holdout_fixture_sources, detection_holdout_pre_run_check, detection_holdout_report, detection_holdout_run, detection_holdout_run_interrupted, detection_holdout_targets, detection_layout_check, detection_oracle, detection_preflight, detection_recording, detection_replay, detection_route_check, detection_session, detection_survey, detection_targets, run_detection, run_detection_holdout, run_detection_holdout_run
- **nuisance (27)**: nuisance_assembly, nuisance_audit_once, nuisance_backend_registry, nuisance_backend_registry_built, nuisance_benign_call, nuisance_compose, nuisance_confinement, nuisance_counter, nuisance_counting, nuisance_fingerprint, nuisance_fixture_sources, nuisance_holdout_servers, nuisance_images, nuisance_report, nuisance_retry_policy, nuisance_run, nuisance_run_backends, nuisance_run_containers, nuisance_run_interrupted, nuisance_run_sweep, nuisance_solo, nuisance_statistic, nuisance_vet, nuisance_vetting, run_nuisance, run_nuisance_run, run_nuisance_vet
- **nuisance/admission (11)**: nuisance_admission, nuisance_admission_loads, nuisance_admission_records, nuisance_admission_walk, nuisance_dossier, nuisance_holdout_calibration_copies, nuisance_re_admission_dossier, nuisance_unrecorded, nuisance_walk, nuisance_walk_record, nuisance_walk_record_loads
- **nuisance/fix_checks (12)**: excel_witness_workbook, fix_check_resolver, geekgod_fs_fix_check_builder, googleapis_fix_check_builder, gravitino_fix_check_builder, jenkins_fix_check_builder, mcp_ssh_fix_check_builder, n8n_fix_check_builder, neo4j_fix_check_builder, nuisance_fix_check_command, nuisance_fix_checks, responder_fix_checks
- **nuisance/gate (9)**: nuisance_gate, nuisance_gate_baseline, nuisance_gate_console, nuisance_gate_recording, nuisance_gate_report, nuisance_gate_selection, nuisance_gate_session, nuisance_gate_sweep, run_nuisance_gate
- **project (3)**: glossary, readme_policy, workflow_path_filters

That is 226 test files. With `conftest.py` and `__init__.py`, it accounts for the 228 files of `tests/unit`. A test file that exists at implementation time and is absent from this list (one added since) goes to the area its prefix or its imports point to, and the implementer reports it.

### Support modules without a test file of their own

- `test_console_given.py` (used by four auditor tests): `auditor/support/`.
- `test_detection_layout_check_golden_given.py`, `test_detection_route_check_golden_given.py` and their goldens `detection_layout_check_golden.json`, `detection_route_check_golden.json`: `detection/support/`.
- `test_nuisance_admission_edits_given.py`: used by nuisance tests of every nuisance subdirectory and by `cve/backends/test_backend_lifecycle.py`, so it stays in `tests/unit/support/`.
- `test_nuisance_committed_admission_given.py` and `_then.py`: used by nuisance, `cve/backends` (`test_backend_hostnames_given`) and `cve` (`test_committed_stand_ins_given`) tests, so they stay in `tests/unit/support/`.
- The shared helpers `cve_grammar_golden_corpus.py`, `docker_argv.py`, `kit_isolation.py`, `recorded_subprocess.py`, `retired_word_exemptions.py`, `retired_word_scan.py`, `retired_words.py` stay in `tests/unit/support/`.
- The rule behind these choices, for a `test_*_given.py` or `test_*_then.py` without a test file of its own: it goes to the `support/` of the one area whose tests import it, and stays in `tests/unit/support/` when tests of two or more top-level areas import it (a nuisance subdirectory counts as `nuisance`, `cve/backends` as `cve`). `test_nuisance_admission_edits_given.py` is the one case where a nuisance-only module would fit `nuisance/support/`, except that `cve/backends` uses it too. The plain helpers (the modules not named `test_*`) all stay in `tests/unit/support/` as the shared library, even the ones a single area imports today (`cve_grammar_golden_corpus.py` by `cve`, the three `retired_word*` modules by `project`), so their `REPO_ROOT`/`parents[3]` and the `_SKIPPED` entries naming them do not move.
- A given or then that has a test file of its own follows that test file, even when other areas import it: `test_census_given` is imported by six areas, `test_detection_draw_record_given` by six, `test_nuisance_admission_given` by six, `test_cve_grammar_given` by three and by the integration support `test_detection_replay_given.py`, and so on. Those cross-area imports become `tests.unit.<owning area>.support...`, which is expected.
- The goldens move with their given: `cve_grammar_golden.json` to `cve/support/`, `model_inputs_golden.json` to `auditor/support/`. Their givens read them through `Path(__file__).parent`, so the path keeps working once both move together.

### What changes inside the moved files

- Imports: `import tests.unit.support.test_X_given as given` becomes `import tests.unit.<area>.support.test_X_given as given`, in `tests/unit` and in the integration supports that import unit supports (`tests/integration/support/test_detection_replay_given.py` imports `test_cve_grammar_given`, `test_mcp_client_transport_given.py` imports `test_graph_given`; `test_cve_layout_mount_given.py` imports `docker_argv`, which stays, so it is unchanged). The second form, `from tests.unit.support import test_X_given as alias` (about twenty sites, e.g. `test_cli_given.py`, `test_cve_launch_audit.py`, `test_detection_audit.py`, `test_nuisance_audit_once.py`), becomes `from tests.unit.<area>.support import test_X_given as alias`; the rewrite script handles both forms. After the rewrite, run `uv run ruff check --fix .` and `uv run ruff format .`: the new module paths change the isort order of the `tests.unit...` imports, and `ruff check` (rule `I`) fails on an unsorted block.
- Path depth: every `Path(__file__).parents[N]` or `.parent` that climbs to the repository root gains one level per added directory. Known sites: `tests/unit/support/cve_grammar_golden_corpus.py` (stays, unchanged), `retired_word_scan.py` (stays, unchanged), `support/test_fixture_contamination_given.py` (`parents[2]` toward `tests/`), `test_detection_holdout_targets.py`, `test_detection_targets.py`, `test_nuisance_fix_checks.py`, `test_readme_policy.py` (`parents[2]` to the root). Find them all with `git grep -n "__file__" tests/unit` after the move. A root path computed through a shared constant (such as `REPO_ROOT` in a support module that stays) is preferred over a new `parents[N]` count where one already exists in the given, but no new shared helper is introduced for this.
- `tests/unit/support/retired_word_exemptions.py` lists exempted files by path: `tests/unit/test_checkpointing.py`, `tests/unit/support/test_checkpointing_given.py`, `tests/unit/test_rendering.py`, `tests/unit/support/test_census_given.py`, `tests/unit/support/test_run_detection_holdout_run_given.py`, the glob `tests/unit/test_*baseline*.py` and the glob `tests/unit/test_run_*.py` (four entries: `--ungated`, `--cve`, `--calibrate`, `--readmission`). They become the new paths, and each glob becomes one that matches the moved tests (the `test_run_*` files land in `evals`, `census`, `detection`, `nuisance` and `nuisance/gate`, the `*baseline*` ones in `evals`, `detection` and `nuisance/gate`). `AllowedLine.allows` matches with `fnmatch`, whose `*` crosses `/`, so a glob such as `tests/unit/*/test_run_*.py` also matches `tests/unit/<area>/support/test_run_*_given.py`, which the old glob did not: each glob becomes one entry per area, naming that area's directory with no `*` across directories (for example `tests/unit/detection/test_run_*.py`), never a glob spanning areas. The retired word test must still pass with the same exemptions applied, neither more nor fewer lines exempted: check it with a throwaway script that lists the allowed hits (path mapped to its new path, line, pattern id) before and after, and compares the two sets.
- `tests/unit/support/retired_word_scan.py` stays, but its `_SKIPPED` tuple names `tests/unit/test_glossary.py` and `tests/unit/support/test_glossary_given.py`, which move to `tests/unit/project/` and `tests/unit/project/support/`: rewrite both entries, or the glossary test scans its own retired-word fixtures and fails.
- `test_fixture_contamination_given.py` uses `_TESTS_DIR` (`parents[2]`, to `tests/`) only to locate the three honeypot servers: once it sits in `tests/unit/evals/support/` it needs `parents[3]`, and the test then reads the same three files.

### Living docs

- `CLAUDE.md` Commands: `uv run python -m tests.unit.support.test_cve_grammar_golden_given` becomes `uv run python -m tests.unit.cve.support.test_cve_grammar_golden_given`, and `tests.unit.support.test_model_inputs_golden_given` becomes `tests.unit.auditor.support.test_model_inputs_golden_given`. The `tests/unit` commands of the short loop are unchanged.
- `CLAUDE.md` Testing standards: the example `import tests.unit.test_audit_given as given` stays an example of the pattern. Add one sentence after it: a unit test lives in the directory of its area under `tests/unit/`, its given and then in that directory's `support/`, and a helper shared across areas in `tests/unit/support/`.
- Living text that names a moved test path, each rewritten to the new path:
  - `CONTRIBUTING.md`: `tests/unit/test_cve_compose_labels.py` (line 14), `tests/unit/support/cve_grammar_golden.json` (line 50, to `tests/unit/cve/support/`), `tests/unit/test_fixture_contamination.py` (line 155, to `tests/unit/evals/`).
  - `CLAUDE.md` Landmines: `tests/unit/test_anthropic_structured_output.py` (to `auditor/`), `tests/unit/test_doris_backend.py` (to `cve/backends/`), `tests/unit/test_detection_holdout_targets.py` (to `detection/`).
  - `CHANGELOG.md` `[Unreleased]` (living): `tests/unit/test_cve_compose_labels.py` (to `cve/`).
  - `evals/cve/kit/__init__.py` docstring: `tests/unit/test_kit_isolation.py` (to `cve/`). A module docstring, so no fingerprint moves.
  - `evals/docker/compose.yml` comment: `tests/unit/test_cve_compose_labels.py` (to `cve/`).
  - `evals/fault_injection_method.md`: `tests/unit/test_honeypot_fault_injection.py` (to `evals/`).
  - The sweep that finds them all: `git grep -nE "tests[./]unit[./]" -- ':!tests/unit' ':!plans' ':!docs/adr' ':!docs/*-log.md'`, reading CHANGELOG.md hits only in `[Unreleased]`. Every hit that names a moved path is rewritten.
- No `CHANGELOG.md` entry: nothing user-facing changes. No glossary entry: no term is added or moved.
- `.github/workflows/ci.yml` runs `pytest tests/unit`, unchanged. No workflow path filter names a moved file (`detection-calibration-check.yml` filters `evals/cve/*.py` and `evals/cve/detection/*.py`, which this change does not touch), and `test_workflow_path_filters` guards it.

## What stays unchanged

- `evals/docker/`, `evals/stand_ins/`, `plans/`, `evals/cve/detection/`, `evals/cve/` root, `evals/cve/backends/`, `evals/cve/nuisance/fix_checks/`, `tests/integration/` layout, `src/`.
- `evals/cve/nuisance/confinement.py`, `counter.py`, `counting.py` stay in place (fingerprints).
- Module and test file names: none is renamed.
- Every command line of `CLAUDE.md`, `README.md` and `CONTRIBUTING.md` except the two golden regeneration commands.
- Every test's content apart from import lines, `__file__` depth, the exemption paths and the `_SKIPPED` paths of `retired_word_scan.py`.
- Records and dated text: `evals/census.json`, `evals/nuisance_admission.json`, `evals/nuisance_walk_record.json`, the logs, the ADRs, the plans, the two rules.

## Order

Part 1 (the nuisance subpackages) comes first, then Part 2 (the tests), so the test move rewrites imports once against their final module paths. Each part is one commit. Implementing a part as a scripted `git mv` plus a scripted import rewrite is expected; the script is a throwaway in the scratchpad and is not committed.

## Edge cases

- A module imported both as `from evals.cve.nuisance import gate_session` and as `from evals.cve.nuisance.gate_session import X`: both forms are rewritten.
- `pytest` collects test modules by package. Two test files with the same base name in two areas would only be possible if one were renamed, and none is, so no collision. Check with `uv run pytest --collect-only -q | tail -1` that the count is the same before and after.
- `pyright` strict reports an import it cannot resolve as an error: the full `uv run pyright` run with no argument is the guard.
- The `--lf` cache holds old node ids: the first run after the move is a full run, so nothing depends on it.
- A test that asserts on a module's file path (for example `Path(doris.__file__) in target.backend_sources`) reads the module's real path and keeps working, since `evals/cve/backends/` does not move.

## Test scenarios

No new behavior, so no new test. The existing suite is the specification: the same tests pass, collected in the same number.

## Verification

1. Before Part 1, record the baseline: `uv run pytest --collect-only -q | tail -1` (the number of tests), and every fingerprint, with a throwaway script in the scratchpad that prints, one per line: `fixture_fingerprint(target, places)` for each target of `ACCEPTANCE_TARGETS` (`evals/cve/detection/targets.py`) and `HOLDOUT_TARGETS` (`evals/cve/detection/holdout_targets.py`), with the places loaded as `evals/run_nuisance.py` and `evals/cve/detection/session.py` load them; `grammar_fingerprint()`; `counter_fingerprint()`; `nuisance_fixture_fingerprint(server)` for each admitted server of `evals/nuisance_admission.json`, loaded as `evals/cve/nuisance/run.py` loads it; `dockerfile_fingerprint(service)` for each compose service.
2. After each part: the same script, which prints one line per acceptance target, per holdout target, per admitted server and per compose service (count the lines against `len(ACCEPTANCE_TARGETS)`, `len(HOLDOUT_TARGETS)`, the admitted servers and the compose services, so a skipped item shows), its output identical byte for byte (`diff` empty), apart from the counter fingerprint after Part 1 (see the decision in the constraint section), whose two values go into the labeling log entry. Then `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` with no argument, all green, and the collected count identical to step 1.
3. After Part 2: `git grep -nE "tests\.unit\.support(\.| import )test_" -- tests` lists only the shared supports that stay (`test_nuisance_admission_edits_given`, `test_nuisance_committed_admission_given`, `test_nuisance_committed_admission_then`). `ls tests/unit/*.py` lists only `__init__.py` and `conftest.py`.
4. The two golden regeneration commands of `CLAUDE.md` run from the repository root and leave the goldens unchanged (`git status` clean after running them).
5. `git log --follow` on one moved test and one moved module shows its history (a check that each move is recorded as a rename, which a move with only import-line edits is).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by later passes. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- No external facts to verify: the plan cites and defers no third-party API, library version, CI action or platform fact. The tool behaviors it relies on (`fnmatch`'s `*` crossing `/`, ruff's isort rule `I`, pytest collection) are local and checked by its own verification steps; the counter fingerprint values it defers are computed by the repository, not external.

## Implementation steps

Both steps are scripted moves: the implementer writes a throwaway `git mv` script and a throwaway import-rewrite script in the scratchpad (never committed), and reads only the files whose content needs a hand edit. The large file count is therefore not a context risk, and each step matches one commit of the Order section.

### Step 1: `evals/cve/nuisance` gets its `gate/` and `admission/` subpackages

- **Files**:
  - Create `evals/cve/nuisance/gate/__init__.py` and `evals/cve/nuisance/admission/__init__.py` (both empty).
  - `git mv` the 9 gate modules into `evals/cve/nuisance/gate/` and the 11 admission modules into `evals/cve/nuisance/admission/` (lists in Part 1).
  - Rewrite imports in every importer under `evals/`, `src/` (expected none) and `tests/`, among them `evals/cve/fixture_sources.py`, `evals/export.py`, `evals/run_nuisance.py`, and the `TYPE_CHECKING` blocks of `admission_records.py`, `admission_walk.py`, `backend_registry.py`, `counting.py`, `fingerprint.py`, `images.py`, `provisioners.py`, `run_containers.py`.
  - Edit `evals/cve/nuisance/gate/gate_baseline.py` (`parents[2]` to `parents[3]`), the docstring of `evals/cve/nuisance/admission/admission.py` (line 9, path of `unrecorded.py`).
  - Append one entry to `docs/labeling-log.md`.
- **Do**:
  1. Before any move, record the baseline (Verification step 1): `uv run pytest --collect-only -q | tail -1`, and write the throwaway fingerprint script in the scratchpad that prints one line per acceptance target, per holdout target (`fixture_fingerprint(target, places)`, places loaded as `evals/run_nuisance.py` and `evals/cve/detection/session.py` load them), `grammar_fingerprint()`, `counter_fingerprint()`, one line per admitted server (`nuisance_fixture_fingerprint(server)`, loaded as `evals/cve/nuisance/run.py` loads it) and one per compose service (`dockerfile_fingerprint(service)`). Save its output to the scratchpad. The script must import moved modules through a path that works both before and after the move (resolve them dynamically or keep two import variants), so the same script produces the after output. Count its lines against the lengths of the four sets.
  2. `git mv` the 20 modules, add the two empty `__init__.py`.
  3. Run the import-rewrite script over `evals/`, `src/`, `tests/`: both forms (`from evals.cve.nuisance.<moved> import ...`, `from evals.cve.nuisance import <moved>`, including multi-name `from evals.cve.nuisance import a, b` lines that mix moved and unmoved modules, which must be split), patterns not anchored at column 0, so indented and `TYPE_CHECKING` imports are covered. Also rewrite dotted module strings naming a moved module (check `tests/unit/test_nuisance_re_admission_dossier.py`, whose `fix_checks` strings do not move).
  4. Fix `parents[2]` to `parents[3]` in `gate_baseline.py` and the docstring path in `admission/admission.py`.
  5. Run the sweep `git grep -nE "evals/cve/nuisance/(gate|admission|walk|dossier|re_admission|holdout_target_reference|holdout_calibration_copies|unrecorded)[a-z_]*\.py|evals\.cve\.nuisance\.(gate|admission|walk|dossier|re_admission|holdout_target_reference|holdout_calibration_copies|unrecorded)" -- ':!plans' ':!docs/adr' ':!docs/*-log.md'` and rewrite every stale hit. Do not edit dated logs, ADRs, plans, rules or records.
  6. Run `uv run ruff check --fix .` and `uv run ruff format .` (isort order of the rewritten imports).
  7. Rerun the fingerprint script and `diff` against the baseline: only the counter fingerprint line may differ. If any other line differs, stop and report.
  8. Write the `docs/labeling-log.md` entry, shaped like the existing module-path fingerprint entries (grammar fingerprint around line 833, counter fingerprint around line 869): **State**, **What changes**, **Fingerprint** (the counter fingerprint's before and after values copied from the script output, the grammar, detection fixture and nuisance fixture fingerprints unchanged), and the four ADR 016 questions, as Part 1's decision paragraph lays out.
  9. If pyright or pytest reports an import cycle, stop and report it, never break it with a local import.
- **Test**: no new test. The existing suite is the specification: same tests pass, same collected count.
- **Verify**: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no argument), all green. `uv run pytest --collect-only -q | tail -1` equals the baseline count. Fingerprint diff limited to the counter line. Stale-path sweep empty. `git log --follow evals/cve/nuisance/gate/gate_session.py` shows pre-move history.

### Step 2: `tests/unit` gets one directory per area

- **Files**:
  - Create the area directories of Part 2's target layout (`auditor`, `evals`, `cve`, `cve/backends`, `census`, `detection`, `nuisance`, `nuisance/admission`, `nuisance/fix_checks`, `nuisance/gate`, `project`), each with a `support/` subdirectory, every directory with an empty `__init__.py`.
  - `git mv` the 226 test files per Part 2's mapping, each one's `support/test_X_given.py` and `support/test_X_then.py` to its area's `support/`, plus the support modules without a test file and the goldens per "Support modules without a test file of their own".
  - Rewrite imports in `tests/unit/**` and in `tests/integration/support/test_detection_replay_given.py` and `tests/integration/support/test_mcp_client_transport_given.py`.
  - Hand edits: `tests/unit/support/retired_word_exemptions.py`, `tests/unit/support/retired_word_scan.py` (`_SKIPPED`), the `__file__` depth sites (among them `test_fixture_contamination_given.py`, `test_detection_holdout_targets.py`, `test_detection_targets.py`, `test_nuisance_fix_checks.py`, `test_readme_policy.py`).
  - Living docs: `CLAUDE.md` (two golden commands, one Testing standards sentence, three Landmines paths), `CONTRIBUTING.md` (lines 14, 50, 155), `CHANGELOG.md` `[Unreleased]` path, `evals/cve/kit/__init__.py` docstring, `evals/docker/compose.yml` comment, `evals/fault_injection_method.md`.
- **Do**:
  1. Rerun the Step 1 fingerprint script and record its output and the collected count as this step's baseline. Before any move, write a throwaway scratchpad script that lists the retired-word hits the exemptions allow (path, line, pattern id), and save its output.
  2. List `tests/unit/test_*.py` and check each against the mapping. A file absent from the mapping goes to the area its prefix or imports point to, and is reported in the final summary. Apply the placement rule of the support section to every `test_*_given.py`/`test_*_then.py` without a test file of its own (grep its importers), and leave the plain helpers in `tests/unit/support/`.
  3. Run the scripted `git mv`, then the import-rewrite script handling both `import tests.unit.support.test_X_given as given` and `from tests.unit.support import test_X_given as alias` (also multi-name `from tests.unit.support import a, b` lines, split when the names land in different areas). Leave untouched the three shared supports that stay (`test_nuisance_admission_edits_given`, `test_nuisance_committed_admission_given`, `test_nuisance_committed_admission_then`) and the plain helpers.
  4. Fix path depth: `git grep -n "__file__" tests/unit` and adjust every `parents[N]`/`.parent` chain that climbs to `tests/` or the repository root, preferring an existing `REPO_ROOT` constant from a support that stays over a new count, and introducing no new shared helper. Goldens read via `Path(__file__).parent` need no change since they move with their given.
  5. Rewrite `retired_word_exemptions.py`: each exact path to its new path, and the globs `tests/unit/test_*baseline*.py` and `tests/unit/test_run_*.py` to one entry per area that holds such files (no `*` spanning directories, e.g. `tests/unit/detection/test_run_*.py`). Rewrite the two `_SKIPPED` entries of `retired_word_scan.py` to `tests/unit/project/test_glossary.py` and `tests/unit/project/support/test_glossary_given.py`. Rerun the hit-listing script, map old paths to new, and confirm the allowed-hit sets are identical.
  6. Run `uv run ruff check --fix .` and `uv run ruff format .`.
  7. Living docs: rewrite the paths listed in Part 2's Living docs section, run the sweep `git grep -nE "tests[./]unit[./]" -- ':!tests/unit' ':!plans' ':!docs/adr' ':!docs/*-log.md'` (CHANGELOG.md hits only under `[Unreleased]`) and rewrite every hit that names a moved path. Add the Testing standards sentence to `CLAUDE.md` after the example. No CHANGELOG entry, no glossary entry.
  8. Run the two golden regeneration commands (`uv run python -m tests.unit.cve.support.test_cve_grammar_golden_given`, `uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given`) and check `git status` shows no golden change.
- **Test**: no new test. Same tests pass, same collected count, retired-word allowed hits identical before and after.
- **Verify**: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no argument), all green. Collected count equals the baseline. Fingerprint script output identical to this step's baseline (`diff` empty). `git grep -nE "tests\.unit\.support(\.| import )test_" -- tests` lists only the three shared supports. `ls tests/unit/*.py` lists only `__init__.py` and `conftest.py`. `git log --follow` on one moved test shows its history.
