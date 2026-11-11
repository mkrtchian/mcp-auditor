# Align the repository with the glossary

## Context

`docs/glossary.md` and `docs/glossary-log.md` (commit `e551cee`) fix the project's ubiquitous language: one bounded context, one meaning per term. They describe the target vocabulary. The code, the commands, the reports, the two rules and the other living docs still use the older words: "CVE benchmark" for the detection suite alone, "holdout" for the detection holdout layer alone, "replay" for a retest, "calibrate" for the no-LLM check, "dead", "figure", "report-only server", "target" for the audited server, `EvalResult`, `AuditStep`, and about seventy more. This plan brings every living file but the two rules in line with the glossary, so that a term means the same thing in a module name, a class, a flag, a report key and the README. The two rules follow in their own change (After this plan).

The migration happens now because no holdout run, no nuisance run and no detection or nuisance baseline exists yet. A rename after the first holdout run would force a choice between vocabulary and comparability, since several fingerprints hash the code it touches.

The closed tables this plan relies on (the module map, the test renames, the identifier renames, the data migrations, the visible surface, the rule substitutions, the retired-word patterns and the string references a move breaks) are its appendices A to H. A row of an appendix is part of the plan. Where an appendix row and the body disagree, the body wins.

## Invariants

These hold at every commit of the migration, and the steps below are ordered to keep them.

1. **Nothing that reaches the model under test changes.** No prompt text, no structured output schema: the six schemas of `evals/probe_corpus.py` (`TestCaseBatch`, `Judgment`, `AttackContext`, `ChainPlanBatch`, `StepObservation`, `AuditPayload`), their nested classes (`ChainGoal`, `AuditCategory`, `Severity`, `EvalVerdict`), their field names, their `Field(description=...)` and their class docstrings (pydantic turns those docstrings into `description` fields), the Anthropic wire models of `adapters/anthropic_structured_output.py` (their private class names are schema titles), `domain/category_guidance.py`, and the redaction marker. Python code that builds a prompt may change (a field access such as `case.eval_result` becomes `case.judge_result`), its output may not. A golden test proves it byte for byte (step 1).
2. **What the dossiers hand to agents changes only as declared.** The `CalibrationCard` and `Classification` schemas do not change at all, so no card field and no nested class of a card is renamed. The `FlawRecord` and `AdmittedServer` schemas change in exactly two ways, both in step 4: the `$defs` entry of `MechanismClass` becomes `FlawClass`, and the `source` enum value `holdout_calibration` becomes `detection_holdout_calibration`. The same golden test covers the four schemas. The prose of the dossiers (paths, the fixture format, the words "planting layer", "dead", "workshop") is living text and moves to the new vocabulary, reviewed in the diff.
3. **Every fingerprint moves at most once.** The fingerprints hash the syntax tree of their modules (`evals/baseline.py` `fingerprint_source` drops only comments and the module docstring), so an import line, a class or function docstring, an identifier and a string literal all count, and the path does not. Every file a fingerprint hashes is touched in one commit only, the last commit of step 4 (implementation step 9): the four files of `GRAMMAR_PATHS`, the twelve of `ENVIRONMENT_PATHS`, the two of `_COUNTER_PATHS`, `CONFINEMENT_SOURCE` and `_PUBLIC_NAME_SOURCES` of `nuisance_fingerprint.py`, the `served` files of every registered backend, the `backend_sources` of the two detection holdout targets that declare them (CVE-2025-66335 and GHSA-8g7g-hmwm-6rv2), the stand-in captures under `evals/stand_ins/` (hashed as raw text) and `evals/docker/Dockerfile.stand-in` (its instructions are hashed). Steps 2 and 3, and the first four commits of step 4, touch none of them: a rename whose identifier appears in one of these files waits for that last commit.
4. **The grammar grades the same.** The grammar golden master (`tests/unit/support/cve_grammar_golden.json`) and the route and layout check golden masters (`cve_route_golden.json`, `cve_layout_check_golden.json`) keep every value byte for byte. Their keys may be renamed through a written key map, never regenerated.
5. **The two rules are not edited by this plan.** They keep their words and their paths, and the retired-word test exempts them, until detection suite rule v12 and nuisance suite rule v5 are made after this plan from the closed tables of Appendix F.
6. **Kept on purpose**, recorded in the glossary log's text where a reader could look for them: the salt literal `mcp-auditor-holdout:`, the Docker label `mcp-auditor-cve`, the compose services `holdout-*` and their `Dockerfile.holdout-*` (the census cards cite them), the `replay_rule` key of the two committed baselines (read through an alias, see step 3), the data tokens `arbitrary_read`, `command_execution` and `internal_fetch` and every reach and class token, the `reachable_by` key of `evals/detection_places.json`, the `cve_id` values of the census (they are CVE IDs), `EvalVerdict`, the `cases` of `TestCaseBatch`, and every committed record's historical words (census cards and calibration records, the admission and walk records, the dated log entries). Everything else living follows the glossary whoever wrote it, the comments and docstrings the calibration and admission agents wrote (`Dockerfile.holdout-*` and every other Dockerfile, `holdout_fixtures/`, `fix_checks/`, the kit) included, while the committed records (census cards and calibration records in the census file, the admission and walk records, baselines, stand-in captures, fixtures, goldens), the dated log entries, the ADRs, the plans and the published CHANGELOG sections stay as written, since each was correct at its date and the glossary log maps its words.

## Settled decisions

The glossary settles the words. These are the decisions of form the glossary leaves to the code, settled here.

**Packages.** The evals code moves into packages, the prefix of a module dropped inside its package (`evals/cve/detection/gate.py`, not `detection_gate.py`):

- `evals/cve/`: what both suites of the CVE benchmark share: the grammar, proofs and units, the planting code, the places and layout loaders (the shared planting code imports both), the stand-ins, closed networks, images, the holdout-role modules both suites share (`holdout_statistic`, `holdout_intervals`, `holdout_hierarchical`, `holdout_conditions`), and the modules only CVE code imports (run files, run images, provider errors, failure text, server health, audit attempts, launch audit).
- `evals/cve/backends/<key>.py`: every backend and responder, by its registry key, since three places import a backend from its key as a string and doris serves both suites. The registry `nuisance_backends.py` becomes `evals/cve/nuisance/backend_registry.py`.
- `evals/cve/kit/`: the kit (was `evals/holdout_kit/`), which serves the calibration of a detection holdout target and the nuisance fix check and benign probe.
- `evals/cve/census/`: the census, its classification, sources, grouping, identity, exclusions, prefilter and work directory code.
- `evals/cve/detection/`: the detection suite, both layers: targets, oracle, gate, baseline, session, calibration check, layout and route checks, survey, replay, the draw record (`census_draw.py` becomes `detection/draw_record.py`: it holds the detection walk, the cards and the drawn targets), the holdout run, report and pre-run check, and the package `evals/cve/detection/holdout_fixtures/` (was `evals/holdout_fixtures/`).
- `evals/cve/nuisance/`: the nuisance suite, and the package `evals/cve/nuisance/fix_checks/` (was `evals/nuisance_fix_checks/`).
- `evals/honeypot/`, `evals/judge/`, `evals/probe/`: the modules of those instruments.
- `evals/` top level keeps the modules several instruments share (generic gate, baseline, recording, metrics, cell grid, console, export, concurrency, declared flips, and the three honeypot-named foundations `honeypots.py`, `eval_session.py`, `ground_truth.py`, which every instrument imports for `REPO_ROOT`, `Refused`, `TreeState` and the `GroundTruth` type), the command entry points, every data file and the method notes.
- Imports that go from `evals/cve/` up into a suite package, or across instruments, stay as they are today and are listed in Appendix A.4. Fixing them is structure, not vocabulary.

**Commands.** Entry points stay at `evals/` top level, so `python -m evals.X` keeps working: `evals.run_detection` (was `run_cve_benchmark`), `evals.run_detection_holdout` (was `run_holdout`; its `draw-order` subcommand moves to `evals.run_census draw-order`), `evals.run_census`, `evals.run_nuisance`, `evals.run_honeypot_suite` (was `run_evals`), `evals.run_judge_eval`, `evals.run_probe`, `evals.detection_preflight` (was `cve_preflight`: it checks the acceptance targets' images), `evals.capture_stand_in`, `evals.capture_probe_corpus`, `evals.draw_judge_cases`. The kit's `python -m evals.cve.kit.benign_probe` runs inside an exported dossier. Flags: `--calibrate` becomes `--calibration-check`, `run_detection_holdout calibrate` becomes `calibration-check`, `run_nuisance calibrate` becomes `fix-check`, `--cve ID` becomes `--flaw ID` (help: "a CVE ID, or the GHSA ID of a flaw without one"), `--readmission` becomes `--re-admission`, `--ungated` becomes `--no-baseline` (honeypot suite, judge eval, detection suite), `draw_judge_cases --cve-export` becomes `--detection-export`. Help texts say "retests" for the retest rule, "runs and retests alike" for `--concurrency`.

**Data files and outputs.** `evals/holdout_census.json` becomes `evals/census.json`, `evals/holdout_places.json` becomes `evals/detection_places.json`, `evals/holdout_census_method.md` becomes `evals/census_method.md`, `evals/baselines/honeypot_e2e.json` becomes `evals/baselines/honeypot.json`, `evals/baselines/judge_isolation.json` becomes `evals/baselines/judge.json`, the detection baseline directory constant becomes `evals/baselines/detection/` (absent today). These are `git mv` with content unchanged, so neither baseline is reset and both stay confirmed (ADR 020 resets a baseline on a change to a fixture, the scoring code's grading, the model, runs or budget, and a path is none of them). The gitignored work directory `output/holdout_census/` becomes `output/census/` (exports already downloaded are moved by hand), and the default outputs follow the instruments: `output/eval_report.json` becomes `output/honeypot_report.json`, `output/cve_report.json` becomes `output/detection_report.json`, `output/cve_judged_cases.jsonl` becomes `output/detection_judged_cases.jsonl` (its `cve_id` key becomes `flaw_id`), `output/holdout_report.json` becomes `output/detection_holdout_report.json`. The workflow `.github/workflows/cve-calibration.yml` becomes `detection-calibration-check.yml`, its path filters translated to the new paths with today's trigger coverage, never widened to the whole `evals/cve/` tree (a filter left on the old paths would stop triggering the job silently, E.5), and the honeypot job `e2e-eval` becomes `honeypot-suite` (changes are committed to `main`, so no required status check names it).

**Identifiers follow the terms.** Every code name that names a glossary concept with another word is renamed to the term, apart from Invariant 1 and 6. The central ones, the full list being Appendix C:

- Auditor core: `EvalResult` to `JudgeResult` (its `payload` field, which holds only the arguments, to `arguments`), `eval_result` to `judge_result`, `AuditStep` to `ModelCallKind` (`ModelCall.kind`, `MissedModelCall.kind`, `JUDGE_CALLS`, `CHAIN_CALLS`), `MissedStep` to `MissedModelCall`, `missed_steps` to `missed_model_calls`, `judged_cases` to `processed_cases`, `chain_step_missed` to `chain_model_call_missed`, `ExecutionConfig` to `AuditRunOptions` (the field `AuditConfig.execution` to `run_options`), `TargetExecution` to `ServerExecution`, the audited-server `target` (state channel, `ServerLaunch`, report key, Markdown line) to `server_command`, `ExecutionRecord.relayed_variables` to `redacted_variables`, `MCP_AUDITOR_OPENROUTER_HOSTS` and `openrouter_hosts` to `MCP_AUDITOR_OPENROUTER_PROVIDERS` and `openrouter_providers`.
- CVE benchmark: `CVETarget` to `Target`, `CVE_TARGETS` to `ACCEPTANCE_TARGETS`, `cve_id` to `flaw_id` (the kit's `KitTarget` mirror field included), `CVEStatus` to `TargetStatus` (after the alias `cve_oracle.TargetStatus` becomes `ResultStatus`), `MechanismClass` to `FlawClass`, `mechanisms` to `classes`, `FixCheckTarget.mechanism` to `effect_class`, `MissClass` to `MissKind`, `REACHABLE_BY` and `Place.reachable_by` to `REACHES` and `reaches` (the JSON key `reachable_by` is still what the loader reads), `PlantKind` to `PlaceKind`, `entry_id` to `place_id`, `HOLDOUT_PLACES` to `DETECTION_PLACES`, `HoldoutCensus` to `Census`, `NuisanceCensus` to `WalkInputs`, `dead_conditions` and `patched_dead_conditions` to `not_live_reasons` and `not_fixed_reasons` (their union is the out-of-calibration reasons), `confirm_admission` to `check_layouts_and_routes`, `holdout_vetting.vet_all` to `check_before_run` (the pre-run check), `FixCheckTarget` to `FixCheckFixture`, `StandInRoute.target` and `probed_target` to `request_target` and `probed_request_target`, `version_setting` to `candidate_counted_flaws`, `acceptance_servers()` (which includes dropped targets) to `acceptance_target_servers()` with its current-target subset `nuisance_acceptance_servers()`, `ServerMark.ACCEPTANCE` to `ACCEPTANCE_TARGET_SERVER` (one value, so the published exits table keeps one row), `primary_number` to `holdout_detection_rate`, the nuisance report keys `figure` and `outside_figure` to `holdout_nuisance_rate` and `exits`, `not_run_conditions` to `not_run_reasons`, `miss_causes` to `missed_call_causes`.
- Gates and baselines: `ReplayRule` to `RetestRule` (`decide_replays` to `decide_retests`, `pending_replay` to `pending_retest`, `replay_observations` to `retest_observations`), `settle` in the three gates to `apply_retests`, `GateVerdict` and `CVEGateVerdict` to the one `GateOutcome`, a gate result's `verdict` to `outcome`, `ConclusionVerdict` to `Conclusion`, `judge_gate()` and `judge_runs()` and the gates' `judge` to `decide` verbs, `BaselineStatus.EXPLORATORY` to `UNCONFIRMED` (no committed baseline carries it), `CellTag.FIXED` to `IMPROVED` and `CellTag.ALARM` to `FALSE_POSITIVE` (values `improved` and `false_positive`), `GateRow.target` to `subject`.
- "Recording" names only a baseline recording: `RecordingClient` becomes `ExchangeLog` (module `evals/cve/exchange_log.py`, it keeps each call and response), the kit's `KitRecorder` becomes `KitExchangeLog`, the probe's `RecordingLLM` becomes `CapturingLLM`.
- `Settlement.verdict` (a committed key, 14 times in the census and 31 in the walk record) becomes `ruling` in Python with `Field(validation_alias="verdict", serialization_alias="verdict")` and `model_config = ConfigDict(validate_by_name=True, serialize_by_alias=True)` (pydantic 2.14 here), so the committed key stays on read and on every write. A plain `Field(alias="verdict")` is not enough: `model_dump_json()` writes the field name by default, so `run_census assemble` and the round trip of `tests/unit/support/test_nuisance_walk_given.py:160` (`record.model_dump_json()`, then a reload) would write `ruling` and fail to load it back, and pyright reads `alias` as the constructor keyword, so Python code would have to keep writing `verdict=`. With `validation_alias`, Python constructs and reads `ruling` (`tests/unit/support/test_nuisance_walk_record_given.py:53` follows), and a unit test dumps a `Settlement` and asserts the key `verdict`.

**Serialized forms.**

- The `replay_rule` key (and its inner `replays`) of the two committed gate baselines is read through `AliasChoices("retest_rule", "replay_rule")` and written as `retest_rule`. The next legitimate re-recording from a green gate migrates both files, and the alias goes with it. `evals/fixtures/fault_injection_baseline.json`, a test fixture, is rewritten in step 3.
- The stand-in captures are rewritten, not aliased: `target` becomes `request_target` (68 keys) and `probed_target` becomes `probed_request_target` (48 keys) in the 24 files, with their reader, their writer (`capture_stand_in`) and the `Dockerfile.stand-in` entry point, in step 4.
- The 17 fix check records whose `source` is `holdout_calibration` become `detection_holdout_calibration`, in step 4 (the glossary's Code).
- The census draw record keeps its `grammar_fingerprint`: the detection suite rule says the census "records the grammar fingerprint at the draw", and the recorded value is the one of the first draw, kept through every grammar change since. Only the admission's `grammar_fingerprint`, which the admission check compares to the current one, is recorded again.

**The auditor's checkpoints.** A renamed field is dropped silently when LangGraph revives a stored pydantic value (`extra="ignore"`), so a resumed pre-migration audit would report its judged cases as unjudged. A resume across the migration is refused, never migrated: `_EARLIER_VERSION_CHANNELS` (`src/mcp_auditor/checkpointing.py`) gains `target`, `judged_cases`, `missed_steps` and `chain_step_missed`, and the refusal also reads the keys of the `__start__` input of a thread interrupted before its first checkpoint. The refusal message is unchanged.

**The rules.** The word "walk" is qualified everywhere, the rules included, as the glossary says. "Step of a census" is a sense of "step" the glossary gains (census step). "The holdout" alone stays only in the detection suite's own text. The phrase "step refused by the model provider" becomes "model call the model provider refused", not "missed model call": a missed model call also covers throttling past every retry, which both rules treat differently (retried, then not run). "A target of the CVE benchmark" in the detection suite rule's draw-order exclusion becomes "an acceptance target", since "a target of the detection suite" would include the holdout targets the draw takes. These choices are fixed here for the rule versions that follow this plan. Every hand-rewritten sentence is listed with its reason in Appendix F, and none changes a decision.

**Facts the migration absorbs.** These inconsistencies are vocabulary and are fixed by the renames: the two meanings of "acceptance server" (current target, or current or past), "nothing is drawn" in the nuisance fix check (it becomes "no server is admitted"), "the oracle's fingerprint" in the README (grammar fingerprint), the contradictory "flaw that sets the version" in the CHANGELOG (counted flaw), the `rule_commit` of the admission and walk record still at the nuisance rule's v2 (pinned to v5 after this plan), the `run_holdout` parser description, "fix-check" against "fix check" (the noun is "fix check", the command `fix-check`), `relayed_variables` holding only the `--env` names, and the two checks called "vet". The other inconsistencies found on the way (exit codes, the pre-run check of a graded detection run that skips the layout and route checks, the census draw record's `rule_commit` still at the detection rule's v7, the googleapis fix check passing a class token as a reach, and the rest) are not vocabulary and go to separate small changes.

## Steps

Each step is one commit, apart from step 1 (two commits) and step 4 (five commits), as the Implementation steps at the end of the plan cut them. Each commit is test-first: it first adds its rows to the retired-word test (or its new assertions) and runs them red, then renames. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright`, and updates the living docs of what it renames (CLAUDE.md Commands, CONTRIBUTING, the README lines that cite a command, flag, env var, report key or path it renames, the `Code:` fields of `docs/glossary.md` that cite a path or command it moves, the `docs/glossary-log.md` lines of its renames (E.9), the `[Unreleased]` section of CHANGELOG.md). README.md's presentation is rewritten in step 5.

A mechanical rename is done by a codemod kept outside the repository, driven by the appendices: `git mv` per Appendix A, then a rewrite of `from evals.X import`, `import evals.X` and dotted module names in strings (importlib calls, closure roots, isolation scans, `subprocess` argv), then word-boundary replacements for the distinctive identifiers of Appendix C, in the order the table gives (longer names first). Generic names (`target`, `cve_id`, `verdict`, `mechanisms`, `payload`) are renamed by hand, file by file, with pyright strict as the net. Bare "replay" (about 1,100 occurrences mixing the ADR 030 resend, retests, sends and serves) and bare "the holdout" are reviewed by hand in the step that owns their file, since no pattern can tell their senses apart.

### Step 1: safety nets

- `tests/unit/test_model_inputs_golden.py`, `tests/unit/support/test_model_inputs_golden_given.py` and `tests/unit/support/model_inputs_golden.json`, with the regeneration entry point `python -m tests.unit.support.test_model_inputs_golden_given` on the pattern of `tests/unit/support/test_cve_grammar_golden_given.py`, and its line in the CLAUDE.md Commands beside the grammar golden master's. The golden records, under stable keys sorted at the top level only:
  - the output of every prompt builder and prompt constant of `graph/prompts.py` and `graph/chain_prompts.py`, `with_redaction_notice`, the redaction marker and `CATEGORY_GUIDANCE`, on fixed inputs: the given-modules already in `tests/unit/support/` for the generation, extraction, chain planning, step planning, step observation and chain judge builders, and the 78 cases of `evals/fixtures/judge_cases.json` through the public judging path for the judge prompt;
  - a graph-level capture of every prompt `FakeLLM` receives on one small audit, plain and with a relayed `--env` value, so a prompt assembled outside the builders is covered too;
  - `model_json_schema()` of the six schemas, as the string pydantic produces (key order kept, since it is part of what is sent), the request body the OpenAI adapter sends for each (`tests/unit/support/test_llm_adapter_given.the_openai_request_body`, langchain's strict transform included), and the Anthropic wire schemas;
  - `model_json_schema()` of `Classification`, `CalibrationCard`, `FlawRecord` and `AdmittedServer`, as the dossiers embed them.
  The given-module builds every domain object through one helper per type, so a constructor keyword renamed later (`EvalResult(payload=...)`, `TestCase(eval_result=...)`, the state keys of the initial state) changes one line. The module docstring says the golden is regenerated only in a commit that changes what reaches a model or an agent, never in a rename, and names step 4's two declared dossier-schema diffs as the one exception of this migration.
- `tests/unit/test_glossary.py` with its `tests/unit/support/test_glossary_given.py`: the machinery of the retired-word test and every pattern of Appendix G, each tagged with the step that migrates it. Living files are the code under `src/`, `evals/` and `tests/` (identifiers, docstrings, comments, strings, and file paths), README.md, CLAUDE.md, CONTRIBUTING.md, the `[Unreleased]` section of CHANGELOG.md, `docs/glossary.md`, the two rules, `.github/workflows/`, and the method notes `evals/*.md`. Historical files are skipped: `docs/adr/`, `plans/`, `docs/glossary-log.md`, the published sections of CHANGELOG.md, the dated entries of the three logs, and the committed records (`evals/*.json` records, baselines, captures, fixtures, and `tests/unit/support/*.json` goldens). Two explicit tuples carry the migration: `_NOT_YET_RENAMED` (pattern ids, emptied step by step) and `_NOT_YET_MIGRATED` (the two rules and the living preambles of their logs, still listed when the plan ends and emptied by the rule versions after it). An allowlist of `(path glob, pattern id, line substring, reason)` covers the kept items of Invariant 6 and the glossary's own mentions of retired words, and the test fails on an allowlist entry that no longer matches anything, so each entry lands in the commit that creates its line (G.1). A second assertion checks that CLAUDE.md still carries the `@docs/glossary.md` line. In this commit every pattern id is in `_NOT_YET_RENAMED`, so the test is green, and a unit test of the machinery proves a pattern fires on a living file and is skipped on a historical one.
- No production code changes. The golden is generated once from this tree and committed.

### Step 2: the auditor core

Renames in `src/mcp_auditor/` and their call sites in `tests/` and in evals modules that no fingerprint hashes, for every core identifier no hashed module references: `AuditStep`, `MissedStep`, `missed_steps` (JSON key `missed_model_calls`, under `[Unreleased]` only, so the existing entry is edited in place), `chain_step_missed`, `judged_cases`, `ExecutionConfig` and `AuditConfig.execution`, `TargetExecution`, the `target` state channel, `ServerLaunch.target`, the report key `target` and the Markdown line "Target" (to `server_command` and "Server command"), `relayed_variables`, `MCP_AUDITOR_OPENROUTER_HOSTS`. Before renaming one, the implementer greps the hashed files of Invariant 3 for it: a name found there moves to step 4. `EvalResult`, `eval_result` and `JudgeResult.arguments` go to step 4 for that reason (`cve_report_units.py` and `nuisance_counter.py` read them).

- Checkpoint refusal as settled above, with the parametrized cases of `tests/unit/test_checkpointing.py` extended to the four old channels and one case for a `__start__`-only thread, and the comment at the top of `_EARLIER_VERSION_CHANNELS` rewritten (a renamed field is dropped on revive, so earlier verdicts would vanish). One unit test resumes a checkpoint written with the old class names and asserts the refusal, since LangGraph revives a missing class as a dict.
- Tests renamed with their identifiers: `test_missed_steps.py`, `test_target_execution.py` and their companions.
- CHANGELOG `[Unreleased]`: the Breaking entry that already carries the report changes gains `server_command`, "Server command", `redacted_variables`, and the refused resume of an audit interrupted before the change. The `missed_steps` and `MCP_AUDITOR_OPENROUTER_HOSTS` entries are edited in place.
- Golden stays green with no regeneration.

### Step 3: the honeypot suite, the judge eval, the model probe and the shared gate code

- Package moves of Appendix A for `evals/honeypot/`, `evals/judge/` and `evals/probe/`, and the renames of Appendix C for those instruments and for the shared top-level modules (`gate.py`, `baseline.py`, `eval_display.py`, `cell_grid.py`, `metrics.py`, `recording.py`, `declared_flips.py`): `RetestRule` with its read alias, `apply_retests`, `GateOutcome`, `outcome`, `decide` verbs, `UNCONFIRMED`, the grid tags, `CapturingLLM`, `run_honeypot_suite`, `--no-baseline` on the honeypot suite and the judge eval, the report columns "Retests" and progress "Retesting", `output/honeypot_report.json`, `--detection-export` and its output name. CVE modules that import these shared names are updated at their call sites only if no fingerprint hashes them (none of the shared names above is referenced by a hashed module, the implementer confirms by grep).
- `git mv` of the two baselines to `evals/baselines/honeypot.json` and `evals/baselines/judge.json`, with `BASELINE_PATH`, `JUDGE_BASELINE_PATH` and the `--record-baseline` help. A unit test loads each committed baseline through the alias and asserts it gates, and another writes a baseline and asserts it carries `retest_rule` and `retests`.
- `evals/fixtures/fault_injection_baseline.json` rewritten to `retest_rule` and `retests`.
- `docs/labeling-log.md`: one entry stating that the scoring code of the honeypot suite and the judge eval moved and was renamed with no change to what it grades (the ground truth fingerprint and the judge inputs fingerprint unchanged, both baselines moved by `git mv`, confirmed, not reset), and that `replay_rule` is read through an alias until the next re-recording.
- CLAUDE.md Commands, CONTRIBUTING, `.github/workflows/evals.yml` and `eval-command.yml` follow.
- Test files renamed by the rule of Appendix B.

### Step 4: the CVE benchmark (five commits, the last the one commit of the hashed files)

Everything under the CVE benchmark moves and is renamed in this step, in five commits (implementation steps 5 to 9). The first four move and rename the census, the detection acceptance layer with the shared CVE plumbing, the detection holdout layer with the kit, and the nuisance suite. They touch no file a fingerprint hashes, no module a hashed file imports (`nuisance_admission.py`, `docker_paths.py` and `backend_lifecycle.py` keep their path until the last commit) and no identifier a hashed file defines or references, so every fingerprint is byte-identical before and after each of them. The last commit moves and edits every hashed file and lands every rename deferred to it, so that every fingerprint moves once and the recorded copies are written once. The bullets below describe the whole step, and the Implementation steps assign each to its commit.

- Package moves of Appendix A for `evals/cve/`, `evals/cve/backends/`, `evals/cve/kit/`, `evals/cve/census/`, `evals/cve/detection/` (with `holdout_fixtures/`) and `evals/cve/nuisance/` (with `fix_checks/`), and every rename of Appendix C for the CVE benchmark, the core renames left from step 2 (`EvalResult`, `eval_result`, `arguments`, with the Markdown line "Payload" becoming "Arguments" and the Breaking CHANGELOG entry gaining `judge_result` and `arguments`), and the class and function docstrings and string literals of the hashed modules (Appendix C.10). Module docstrings and comments of those files are fixed in the same commit, so they are touched once. A hashed docstring that cites a rule cites it by name and section ("the detection suite rule, Deployment layout"), never by file path or line, so the rule rename after this plan leaves no dangling path.
- Every `Path(__file__)`-relative data lookup is re-anchored on `evals/` (Appendix H.1), so the data files stay at the top level and the exported kit tree, which mirrors `evals/`, still resolves them.
- In `evals/calibration_dossier.copy_clean_sources`, the module copies (`CLEAN_MODULES`, `KIT_DIR`, the flat `KIT_MODULES` copies, the `holdout_kit` mkdir, the lone `evals/__init__.py` copy) are replaced by `dossier_closure.copy_closure` over the kit's root modules (`evals.cve.kit.client`, `.launch`, `.target`, `.driver`, plus `.fix_check` for the nuisance dossier, which calls it at `nuisance_dossier.py:49`), which copies their transitive repository imports and every `__init__.py` on the way (`evals/cve/__init__.py` included). At `e551cee` the closure of those roots is exactly `CLEAN_MODULES` plus the kit modules, so the exported tree holds the same code. The function keeps copying `evals/stand_ins/` and `Dockerfile.sentinel` and `Dockerfile.stand-in` into the exported tree, which the closure does not cover. `dossier_closure.REPO_ROOT` is imported from `evals.honeypots` (H.1), so it no longer depends on the module's depth. The dossier texts that cite paths, the two import lines of the transplant and `python -m evals.cve.kit.benign_probe` follow (Appendix H.4). The test that runs an exported dossier stays green.
- String references a move breaks silently are fixed with an assertion that would have caught them (Appendix H): the import scans of `test_holdout_targets.py`, `test_nuisance_fix_checks.py` and the kit isolation test, the string-built module names of the backend loaders and the re-admission dossier root, the workflow path filters, and the pyproject and pytest configuration.
- Data migrations of Appendix D: `git mv` of the census, the places file and the method note, the stand-in keys with their reader, writer and `Dockerfile.stand-in`, the 17 `source` values, the grammar golden keys through the key map (18 `dead_conditions/` to `not_live_reasons/`, 18 `patched_dead_conditions/` to `not_fixed_reasons/`, 173 `miss_class` to `miss_kind`) with a one-off comparison that loads the old and new files, maps the keys and asserts the values identical. The CLAUDE.md line on the golden regeneration follows.
- Golden of step 1: regenerated for `FlawRecord` and `AdmittedServer` only, and the diff of `model_inputs_golden.json` shows exactly the `MechanismClass` to `FlawClass` entry (key, title, references) and the `holdout_calibration` enum value in those two schemas. Every other entry is unchanged.
- Recorded values, computed on this tree with no Docker:
  - `evals/nuisance_admission.json` `grammar_fingerprint` set to `grammar_fingerprint()`;
  - the 17 `holdout_fingerprint` values set to the current `fixture_fingerprint` of the drawn target each copy resolves to through `copy_targets` (sixteen targets, the two sibling copies included), so `stale_holdout_copies` and `unrecorded_fields` report nothing.
- The nine Dockerfile comment lines that cite a moved module (`Dockerfile.apify:6`, `Dockerfile.ckan:4`, `Dockerfile.ckan-vuln:4`, `Dockerfile.gravitino:3`, `Dockerfile.gravitino-instance:5`, `Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect:6`, `Dockerfile.n8n:6`, `Dockerfile.n8n-instance:16`, `Dockerfile.neo4j-backend:1`) are rewritten to the new paths, and every other Dockerfile comment that carries a retired or moved word is reworded to the glossary in the same commit, the comments the calibration agents wrote in `Dockerfile.holdout-*` included (Appendix I counts them). The comments that cite a rule or a log wait for the rule versions after this plan, which rename them. A comment is outside every Dockerfile hash: `cve_images.dockerfile_instructions` drops `#` lines, and both the image label that decides a rebuild (`stale_services`) and every fixture fingerprint read Dockerfiles through it, so no image is rebuilt and no fingerprint moves.
- The comments and docstrings the agents wrote in the transplanted modules (`holdout_fixtures/`, `fix_checks/`, the kit) are living code with no exemption: they follow the glossary in the commit of step 4 that moves them, and at the latest in its last commit.
- Docker checks, run on this tree before the commit (Docker Engine 28.0 or later, no LLM). The stand-in image is rebuilt, its Dockerfile's instructions having changed. No other Dockerfile instruction changes, so no other image goes stale. The checks build every image they need that is absent locally, about 40 at `e551cee`: the 37 vulnerable images of the holdout targets and `fetch-patched`, `filesystem-patched` and `kubernetes-patched` of the acceptance targets. The frogman FreePBX stack is built cold first, as CLAUDE.md says (`docker compose -f evals/docker/compose.yml build --no-cache holdout-2026-46514-frogman holdout-2026-46514-frogman-patched`), and the checks' preflight builds the others. The Docker disk clause of the Implementation steps is lifted for this commit only: these builds are expected, since they are the images the first holdout run needs anyway (the cleanup of existing images is left to the maintainer). All three checks run in full:
  - `uv run python -m evals.run_detection --calibration-check`: the four acceptance targets live and fixed;
  - `uv run python -m evals.run_detection_holdout calibration-check`: the 37 holdout targets green, which covers the sixteen targets whose calibrations the nuisance suite copies (the positive control of each copy) and exercises the moved planting code on every target;
  - `uv run python -m evals.run_nuisance vet`: every admitted server lists its counted tools and answers its benign calls through the moved launch path.
  The checks stay blocking. A target out of calibration, or a server that fails its benign call, stops the step: the migration must change no behavior, so the cause is found and fixed in this commit, never logged as a new state.
- Log entries, written in the current logs (`docs/holdout-log.md`, `docs/nuisance-log.md`, renamed after this plan), in their style:
  - detection log: the shared CVE benchmark code moved into packages and was renamed with no change to what it plants, launches or grades, so the fixture fingerprint of every acceptance and holdout target moves with no fixture changed and the grammar fingerprint moves with the grammar golden master's values unchanged; no detection baseline exists, so nothing resets, and no holdout run has taken place, so no holdout detection rate becomes exploratory; the calibration checks above ran green on this tree; the stand-in captures' keys were renamed; the census and places files were renamed with their content unchanged (the places file's pinned SHA-256 holds);
  - nuisance log: the grammar change applies the eligibility again and moves no decision (the grammar grades the same, golden master), the admission's grammar fingerprint and the 17 `holdout_fingerprint` copies are recorded again (values given), the counter fingerprint and every nuisance fixture fingerprint move with no fixture changed, no nuisance gate baseline exists and no nuisance run has taken place, the `source` value is renamed, the vet ran green;
  - labeling log: the detection suite's scoring code moved and was renamed with no change to what it grades (grammar golden master values identical, keys renamed through the map).
- CLAUDE.md (Commands, Landmines' module paths), CONTRIBUTING and `.github/workflows/detection-calibration-check.yml` follow.

### Step 5: the living docs

- README.md: a presentation of the CVE benchmark, its census and its two suites, with the glosses of the glossary at their first mention, the two published numbers named (holdout detection rate, holdout nuisance rate "at most"), the instruments counted as the glossary counts them (the sentence "Three instruments" goes), a link to `docs/glossary.md`, every command and flag of the migration, and the phrases the glossary log retires ("dead on its patched one", "A CI gate replays", "calibration workshop") gone.
- CONTRIBUTING.md and CLAUDE.md: what steps 2 to 4 left, the bare "replay" and "holdout" reviewed by hand.
- CHANGELOG.md `[Unreleased]`: the entries of Appendix E consolidated (one Breaking entry for the product report and the resume, the eval command and file renames as Changed), the published sections untouched.
- `docs/glossary.md`: the census step added to "step", and a check that steps 3 and 4 left no `Code:` field citing a moved path or command (for example `evals/closed_network.py`, which step 4 turns into `evals/cve/closed_network.py`). `docs/glossary-log.md`: a check that the lines of Appendix E.9 landed with their renames in steps 3 and 4.
- The method notes `evals/*.md` and the living preambles of `docs/labeling-log.md`. The labeling rubric clauses J0, J4 and J10, which write "sentinel" for the nonce and "CVE" alone, are reworded under a labeling log entry stating that every stored label scores the same. They are normative text the labelers read, as is `evals/judge_labeling_brief.md`, so before the commit a fresh independent reviewer agent (a strong model, started for this check only, not the implementer) checks that every stored label scores the same under the reworded text and that its wording follows the glossary, and the maintainer fixes or rules on each finding before the commit.
- The retired-word test now enforces every pattern on every living file but the rules and their log preambles, apart from `holdout-rule-log` and `nuisance-rule-log`: the rule and log paths they catch, and the `NUISANCE_RULE` constant, change only after this plan. When the plan ends, those two ids are the only ones left in `_NOT_YET_RENAMED`, `_NOT_YET_MIGRATED` still holds the two rules and the living preambles of their logs, and the test is green with them.

## After this plan

The two rule versions, detection suite rule v12 and nuisance suite rule v5, are not part of this plan. They are made in their own change after the last step, from the closed tables of Appendix F, in one commit that renames the four rule and log files (`docs/holdout-rule.md` to `docs/detection-suite-rule.md`, `docs/holdout-log.md` to `docs/detection-suite-log.md`, `docs/nuisance-rule.md` to `docs/nuisance-suite-rule.md`, `docs/nuisance-log.md` to `docs/nuisance-suite-log.md`), applies the tables, writes the two log entries, updates the code and tests that cite the rule and log paths (`NUISANCE_RULE` and the file name the nuisance dossier writes, its two dossier tests, the docstrings and comments citing those paths, CLAUDE.md, CONTRIBUTING, README, `docs/glossary.md`, the links between the logs, and the Dockerfile comments that cite a rule or log: the four citing `docs/nuisance-log.md` and the six that say "holdout log"), empties `_NOT_YET_MIGRATED` and removes `holdout-rule-log` and `nuisance-rule-log` from `_NOT_YET_RENAMED`. A follow-up commit pins the versions' commit in the two logs and in `rule_commit` of `evals/nuisance_admission.json` and `evals/nuisance_walk_record.json`. Appendix F is that change's fixed input: its tables, its counts and its verification procedure.

## What stays unchanged

- Prompt text, model-facing schemas, `domain/category_guidance.py`, the redaction marker (Invariant 1). The `CalibrationCard` and `Classification` schemas (Invariant 2).
- What the grammar grades, what the checks decide, what the counter counts, what any fixture plants, seeds, serves or launches. No Dockerfile instruction other than `Dockerfile.stand-in`'s changes (every Dockerfile comment that carries a retired or moved word is rewritten, in step 4 or, for a rule or log citation, after this plan, and comments are outside every Dockerfile hash), so no image other than the stand-in's goes stale. The images step 4's checks need that are absent locally are built, which changes no image.
- ADRs, plans, the published CHANGELOG sections, the dated log entries, the census cards and records, the admission and walk records apart from the values step 4 records. The two rules and the paths of the four rule and log files (After this plan).
- The test tree stays flat: `tests/unit/` and `tests/integration/` gain no subfolder, files are only renamed.
- The salt, the draw order, the drawn targets, the admitted servers, the run conditions in `evals/holdout_conditions.json`, `NUISANCE_RUNS`, `HOLDOUT_RUNS`.
- Out of scope: the inconsistencies listed above as not vocabulary, moving the draw register out of the census file, unifying the settlements, `evals/models.json`, splitting the detection suite rule, renaming model-facing schemas, and subfolders for the tests.

## Edge cases

- A resumed audit started before step 2: refused with the existing message, whether its thread has a step 0 checkpoint or only its `__start__` input.
- A detection or nuisance command run after step 4 and until the rule versions that follow this plan: it works on the new paths, and the rules still cite the old ones. Inside step 4 the CVE benchmark is partly moved, the hashed modules still flat until its last commit. The window runs from implementation step 5 to that change, with no run planned in it.
- An exported kit written before step 4 (outside the repository): keeps its old paths and names, and a kit exported after step 4 runs on its own tree. The dossier tests cover the new tree only.
- A capture recorded by `capture_stand_in` after step 4 writes `request_target`, and the loader refuses a file with the old `target` key with an error naming the key.
- A baseline written after step 3 carries only the new keys (`retest_rule`, `retests`), the committed ones only the old keys, and no code writes both.
- A checkpoint written by a tree between step 2 and the last commit of step 4 carries the new channel names and the old `eval_result` field, so the channel refusal does not catch it and a resume after step 4 drops its verdicts silently.
- Risks the maintainer accepts: no audit is resumed across implementation steps 3 to 9 and no release is cut between them, and the product report's renamed keys and Markdown lines keep no alias, a break the Breaking entry of the CHANGELOG announces (E.8).
- `CellTag` values `improved` and `false_positive` are wider than `fixed` and `alarm`: the grid prints the glossary values, and a short label in the display styles is acceptable if the width matters. `alarm` and `fixed` are never kept.
- A `$defs` collision after a rename would make pydantic put module paths into the schema keys, and the package move would then leak into a dossier schema. The golden test of step 1 catches it.

## Test scenarios

- Golden (step 1): every prompt, schema and request body byte-identical at steps 2, 3 and 5, and at step 4 apart from the two declared dossier-schema diffs, which land in its last commit.
- Retired words: each step's patterns red before its renames and green after, and the machinery test (a pattern fires on a living file, is skipped on a historical one, a stale allowlist entry fails).
- Checkpoints: a checkpoint holding each of `target`, `judged_cases`, `missed_steps`, `chain_step_missed` is refused, a `__start__`-only thread with the old `target` key is refused, a current checkpoint resumes, the pinned thread id of the unconfined regime is unchanged.
- Baselines: the two committed baselines load through the alias and gate, a written baseline carries the new keys, the fault-injection fixture loads.
- Grammar, route and layout golden masters: values identical, keys mapped.
- Admission: the admission check passes with the recorded grammar fingerprint, `stale_holdout_copies` and `unrecorded_fields` empty against the current fixture fingerprints.
- Stand-ins: every committed capture loads under the new keys, the stand-in container serves a captured route and the default (integration, Docker), a capture with the old key is refused.
- Dossiers: the exported calibration kit and the exported nuisance dossier run with no repository on the path and carry the package tree (integration test that runs an exported dossier).
- CLI: each renamed command and flag parses, each old flag is refused by argparse (no alias is kept for an old flag).
- Report keys: the product's JSON report carries `server_command`, `judge_result`, `arguments`, `redacted_variables`, `missed_model_calls`, and none of the old keys.

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
uv run pytest tests/unit/test_model_inputs_golden.py tests/unit/test_glossary.py -n 0
uv run python -m evals.run_detection --calibration-check        # last commit of step 4, Docker
uv run python -m evals.run_detection_holdout calibration-check  # last commit of step 4, Docker
uv run python -m evals.run_nuisance vet                         # last commit of step 4, Docker
```

No eval that calls a model runs: the golden test proves that nothing reaching the model changed, and an eval run would measure the same system under test.

# Appendices

Reference data for the implementation. The decisions to review are in the body, and Appendix I lists the naming choices the body does not state.

Line numbers in the appendices are as of `e551cee`.

Hashed-by codes, used in A and C: **G** the grammar fingerprint (`GRAMMAR_PATHS`, `evals/cve_baseline.py:43`), **E** every detection fixture fingerprint (`ENVIRONMENT_PATHS`, `evals/cve_baseline.py:51`), **C** the counter fingerprint (`_COUNTER_PATHS`, `evals/nuisance_counter.py:19`), **CONF** every nuisance fixture fingerprint (`CONFINEMENT_SOURCE`, `evals/nuisance_fingerprint.py:37`), **P** the nuisance fixture fingerprint of a backend-less server with public names (`_PUBLIC_NAME_SOURCES`, `evals/nuisance_fingerprint.py:42`), **served** the nuisance fixture fingerprint of a server whose registered backend serves the file (`BACKENDS[*].served`, `evals/nuisance_backends.py`), **BS** the detection fixture fingerprint of a holdout target that names the file in its `backend_sources` (CVE-2025-66335, GHSA-8g7g-hmwm-6rv2), **D** Dockerfile instructions, **stand-in text** a capture hashed as raw text. Every source hash is a syntax-tree hash (`baseline.fingerprint_source`), so an import line, a class or function docstring, an identifier and a string literal count, and the path does not. "ref" in C means a hashed file references a name defined elsewhere.

## Appendix A. Module map

### A.1 Placement principles

1. **Owner first.** A module goes to the package of the concept it serves: the census (`evals/cve/census/`), the detection suite (`evals/cve/detection/`), the nuisance suite (`evals/cve/nuisance/`), both suites (`evals/cve/`), or one other instrument (`evals/honeypot/`, `evals/judge/`, `evals/probe/`).
2. **Shared stays up.** A module several instruments use stays at `evals/` top level: the generic gate, baseline, recording, metrics, cell grid, console, export, concurrency and declared flips, and the three honeypot-named foundations (`honeypots.py` for `REPO_ROOT`, `eval_session.py` for `Refused` and `TreeState`, `ground_truth.py` for the `GroundTruth` type).
3. **Importers decide among CVE packages.** A CVE benchmark module that only CVE modules import (provider errors, failure text, server health, run files, run images, run interruption, audit progress, audit attempts, launch audit) goes to `evals/cve/`, not to the top level.
4. **The move keeps today's import graph.** The imports that go up from `evals/cve/` into a suite or across instruments are listed in A.4 and left as they are.
5. **The prefix is dropped inside a package** (`cve_gate.py` becomes `cve/detection/gate.py`). Inside `detection/`, `holdout_` stays to mark the modules of the holdout layer.
6. **A retired or moved word in a module name is renamed** by what the module does (calibration check, route check, pre-run check, fix check, re-admission, holdout calibration copies, exchange log, retest, gate outcome).
7. **Backends live in one package by registry key** (`evals/cve/backends/<key>.py`), since three places build a backend's module name from its key and doris serves both suites. The registry becomes `evals/cve/nuisance/backend_registry.py`, so that "backends" names one thing.
8. **Data files and method notes stay at `evals/` top level**, and every `Path(__file__)`-relative lookup is re-anchored on `evals/` (H.1), so the exported kit tree, which mirrors `evals/`, still resolves them.
9. **Entry points stay at `evals/` top level**, so `python -m evals.X` keeps working. Only the kit's `benign_probe` runs inside an exported dossier, as `python -m evals.cve.kit.benign_probe`.
10. **Steps.** The honeypot, judge and probe packages, the shared top-level renames and the two baseline files move in step 3. Every CVE benchmark move lands in step 4, the commit of the hashed files, since every hashed module imports another moved module (A.5).

### A.2 Destination tables

Every tracked file under `evals/` (619 at `e551cee`) appears once: one row per file, or one row for a directory whose files move or stay together. New package files (`__init__.py`, empty): `evals/honeypot/`, `evals/judge/`, `evals/probe/` in step 3, `evals/cve/`, `evals/cve/backends/`, `evals/cve/census/`, `evals/cve/detection/`, `evals/cve/nuisance/` in step 4. The three other `__init__.py` (`cve/kit/`, `cve/detection/holdout_fixtures/`, `cve/nuisance/fix_checks/`) come with their `git mv`. The dossier closure copies a package only when it has an `__init__.py`, and pyright strict needs them too.

### A.2.1 `evals/` top level

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/__init__.py` | (unchanged) |  | - |  |
| `evals/baseline.py` | (unchanged) |  | - | generic baseline of every gate |
| `evals/cell_grid.py` | (unchanged) |  | - | grid of the four gates' consoles |
| `evals/concurrency.py` | (unchanged) |  | - | honeypot, judge, detection and nuisance |
| `evals/declared_flips.py` | (unchanged) |  | - | honeypot and judge gates |
| `evals/eval_display.py` | (unchanged) |  | - | the shared console |
| `evals/eval_session.py` | (unchanged) |  | - | shared `Refused`, `TreeState`, `read_tree`, git helpers, `BASELINE_PATH` value becomes `baselines/honeypot.json` |
| `evals/export.py` | (unchanged) |  | - | per-case export of the honeypot, detection and nuisance gates |
| `evals/gate.py` | (unchanged) |  | - | generic cell gate |
| `evals/gate_verdict.py` | `evals/gate_outcome.py` |  | 3 | `GateVerdict` to `GateOutcome`, `judge_gate` to `decide_gate` |
| `evals/ground_truth.py` | (unchanged) |  | - | GroundTruth type read by baseline, gate, metrics |
| `evals/honeypots.py` | (unchanged) |  | - | REPO_ROOT and HONEYPOTS read by every instrument |
| `evals/metrics.py` | (unchanged) |  | - | recall/precision and SessionThrottles, every instrument |
| `evals/recording.py` | (unchanged) |  | - | baseline recording rules of every gate |

### A.2.2 Entry points

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/capture_probe_corpus.py` | (unchanged) |  | - | entry point |
| `evals/capture_stand_in.py` | (unchanged) |  | - | entry point, copied into the nuisance dossier |
| `evals/draw_judge_cases.py` | (unchanged) |  | - | entry point |
| `evals/run_census.py` | (unchanged) |  | - | entry point, gains draw-order |
| `evals/run_cve_benchmark.py` | `evals/run_detection.py` |  | 4 | entry point |
| `evals/run_evals.py` | `evals/run_honeypot_suite.py` |  | 3 | entry point |
| `evals/run_holdout.py` | `evals/run_detection_holdout.py` |  | 4 | entry point, draw-order leaves for run_census |
| `evals/run_judge_eval.py` | (unchanged) |  | - | entry point |
| `evals/run_nuisance.py` | (unchanged) |  | - | entry point |
| `evals/run_probe.py` | (unchanged) |  | - | entry point |
| `evals/cve_preflight.py` | `evals/detection_preflight.py` |  | 4 | logic and `__main__` in one module, as `capture_stand_in` |

### A.2.3 Data files and method notes

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/holdout_census.json` | `evals/census.json` |  | 4 |  |
| `evals/holdout_places.json` | `evals/detection_places.json` |  | 4 | SHA-256 pinned by a unit test: content unchanged |
| `evals/holdout_conditions.json` | (unchanged) |  | - |  |
| `evals/nuisance_admission.json` | (unchanged) |  | - |  |
| `evals/nuisance_walk_record.json` | (unchanged) |  | - |  |
| `evals/declared_flips.json` | (unchanged) |  | - |  |
| `evals/holdout_census_method.md` | `evals/census_method.md` |  | 4 |  |
| `evals/fault_injection_method.md` | (unchanged) |  | - |  |
| `evals/judge_fixture_method.md` | (unchanged) |  | - |  |
| `evals/judge_labeling_brief.md` | (unchanged) |  | - |  |
| `evals/probe_method.md` | (unchanged) |  | - | the glossary's Defined by |
| `evals/baselines/honeypot_e2e.json` | `evals/baselines/honeypot.json` |  | 3 | `git mv`, content unchanged, not a reset |
| `evals/baselines/judge_isolation.json` | `evals/baselines/judge.json` |  | 3 | `git mv`, content unchanged, not a reset |
| (absent) `evals/baselines/cve/` | `evals/baselines/detection/` |  | 4 | no committed file, only the constants change: `cve_baseline.py:40`, `cve_gate.py:19`, `cve_recording_console.py:12`, `cve_console.py:58`, `run_cve_benchmark.py:155,162` |

### A.2.4 `evals/honeypot/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/eval_report.py` | `evals/honeypot/report.py` |  | 3 | `EvalReport` to `HoneypotReport` |
| `evals/eval_runs.py` | `evals/honeypot/runs.py` |  | 3 | `run_all`, `tracing_enabled` also read by the holdout and nuisance runs (A.4) |
| `evals/judging.py` | `evals/honeypot/decision.py` |  | 3 | `judge_runs` to `decide_runs` |
| `evals/replay.py` | `evals/honeypot/retest.py` |  | 3 | `Replayer` to `Retester` |
| `evals/fault_catalog.py` | `evals/honeypot/fault_catalog.py` |  | 3 | fault injection on the honeypot gate |
| `evals/fault_harness.py` | `evals/honeypot/fault_harness.py` |  | 3 |  |
| `evals/fault_injection.py` | `evals/honeypot/fault_injection.py` |  | 3 |  |

### A.2.5 `evals/judge/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/judge_baseline.py` | `evals/judge/baseline.py` |  | 3 | JUDGE_BASELINE_PATH -> baselines/judge.json |
| `evals/judge_display.py` | `evals/judge/display.py` |  | 3 |  |
| `evals/judge_draw_checks.py` | `evals/judge/draw_checks.py` |  | 3 |  |
| `evals/judge_fixture.py` | `evals/judge/fixture.py` |  | 3 |  |
| `evals/judge_gate.py` | `evals/judge/gate.py` |  | 3 |  |
| `evals/judge_metrics.py` | `evals/judge/metrics.py` |  | 3 |  |
| `evals/judge_outcomes.py` | `evals/judge/outcomes.py` |  | 3 |  |
| `evals/judge_recording.py` | `evals/judge/recording.py` |  | 3 | baseline recording, legit sense |
| `evals/judge_replay.py` | `evals/judge/retest.py` |  | 3 | retests of flipped judge cases |
| `evals/judge_session.py` | `evals/judge/session.py` |  | 3 |  |
| `evals/judge_session_model.py` | `evals/judge/session_model.py` |  | 3 |  |
| `evals/judge_session_recording.py` | `evals/judge/session_recording.py` |  | 3 |  |

### A.2.6 `evals/probe/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/probe.py` | `evals/probe/analysis.py` |  | 3 | `call_cost` read by the detection and nuisance costs |
| `evals/probe_candidates.py` | `evals/probe/candidates.py` |  | 3 | Prices read by detection and nuisance |
| `evals/probe_corpus.py` | `evals/probe/corpus.py` |  | 3 | the six schemas that reach the model: content frozen |
| `evals/probe_subset.py` | `evals/probe/subset.py` |  | 3 |  |

### A.2.7 `evals/cve/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/cve_grammar.py` | `evals/cve/grammar.py` | G | 4 |  |
| `evals/cve_proofs.py` | `evals/cve/proofs.py` | G | 4 |  |
| `evals/cve_units.py` | `evals/cve/units.py` | G | 4 |  |
| `evals/cve_report_units.py` | `evals/cve/report_units.py` | G | 4 |  |
| `evals/cve_places.py` | `evals/cve/places.py` | E | 4 | HOLDOUT_PLACES -> DETECTION_PLACES, parents[1] / detection_places.json |
| `evals/cve_layout.py` | `evals/cve/layout.py` | E | 4 | imported by the planting code |
| `evals/cve_environments.py` | `evals/cve/environments.py` | E | 4 | Launch, TOOL_CALL_TIMEOUT read by the nuisance suite and launch_audit |
| `evals/cve_planting.py` | `evals/cve/planting.py` | E, P | 4 |  |
| `evals/cve_planting_base.py` | `evals/cve/planting_base.py` | E, P | 4 |  |
| `evals/cve_planting_spec.py` | `evals/cve/planting_spec.py` | E, P | 4 |  |
| `evals/cve_planting_docker.py` | `evals/cve/planting_docker.py` | E, P | 4 | logger name changes |
| `evals/cve_planting_stand_ins.py` | `evals/cve/planting_stand_ins.py` | E, P | 4 |  |
| `evals/cve_endpoint_address.py` | `evals/cve/endpoint_address.py` | E, P | 4 |  |
| `evals/public_stand_ins.py` | `evals/cve/public_stand_ins.py` | E, P | 4 | STAND_INS_DIRECTORY -> parents[1] / stand_ins |
| `evals/closed_network.py` | `evals/cve/closed_network.py` | E, P, served | 4 | glossary and CLAUDE.md name the path |
| `evals/cve_images.py` | `evals/cve/images.py` |  | 4 | imports image_tag from detection/targets |
| `evals/cve_recording_client.py` | `evals/cve/exchange_log.py` |  | 4 | `RecordingClient` to `ExchangeLog` |
| `evals/docker_paths.py` | `evals/cve/docker_paths.py` |  | 4 | DOCKER_DIRECTORY -> parents[1] / docker |
| `evals/dossier_closure.py` | `evals/cve/dossier_closure.py` |  | 4 | REPO_ROOT -> parents[2] |
| `evals/launch_audit.py` | `evals/cve/launch_audit.py` |  | 4 | shared by both suites |
| `evals/audit_attempts.py` | `evals/cve/audit_attempts.py` |  | 4 | detection and nuisance audits, imports detection/targets |
| `evals/audit_progress.py` | `evals/cve/audit_progress.py` |  | 4 | detection and nuisance commands |
| `evals/failure_text.py` | `evals/cve/failure_text.py` |  | 4 |  |
| `evals/provider_errors.py` | `evals/cve/provider_errors.py` |  | 4 | importers are CVE benchmark modules only |
| `evals/server_health.py` | `evals/cve/server_health.py` |  | 4 |  |
| `evals/run_files.py` | `evals/cve/run_files.py` |  | 4 | holdout and nuisance runs, imports both suites' results |
| `evals/run_images.py` | `evals/cve/run_images.py` |  | 4 | both run orchestrators, imports CVETarget |
| `evals/run_interruption.py` | `evals/cve/run_interruption.py` |  | 4 |  |
| `evals/fixture_provenance.py` | `evals/cve/fixture_provenance.py` |  | 4 | census cards and nuisance admission |
| `evals/fixture_sources.py` | `evals/cve/fixture_sources.py` |  | 4 | holdout and nuisance fixtures, imports nuisance SeedRecord |
| `evals/holdout_conditions.py` | `evals/cve/holdout_conditions.py` |  | 4 | CONDITIONS_PATH -> parents[1] / holdout_conditions.json |
| `evals/holdout_intervals.py` | `evals/cve/holdout_intervals.py` |  | 4 |  |
| `evals/holdout_hierarchical.py` | `evals/cve/holdout_hierarchical.py` |  | 4 |  |
| `evals/holdout_statistic.py` | `evals/cve/holdout_statistic.py` |  | 4 | imports detection/holdout_results |

### A.2.8 `evals/cve/backends/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/backend_lifecycle.py` | `evals/cve/backends/lifecycle.py` |  | 4 |  |
| `evals/responder_backend.py` | `evals/cve/backends/responder.py` | served | 4 |  |
| `evals/doris_backend.py` | `evals/cve/backends/doris.py` | BS, served | 4 | both suites |
| `evals/ckan_backend.py` | `evals/cve/backends/ckan.py` | served | 4 | nuisance |
| `evals/n8n_backend.py` | `evals/cve/backends/n8n.py` | served | 4 | nuisance |
| `evals/gravitino_backend.py` | `evals/cve/backends/gravitino.py` | served | 4 | nuisance |
| `evals/mcp_ssh_sshd_backend.py` | `evals/cve/backends/mcp_ssh_sshd.py` | served | 4 | nuisance |
| `evals/jenkins_backend.py` | `evals/cve/backends/jenkins.py` | served | 4 | nuisance |
| `evals/atlassian_backend.py` | `evals/cve/backends/atlassian.py` | served | 4 | nuisance |
| `evals/gitlab_backend.py` | `evals/cve/backends/gitlab.py` | served | 4 | nuisance |
| `evals/googleapis_backend.py` | `evals/cve/backends/googleapis.py` | served | 4 | nuisance |
| `evals/facebook_ads_backend.py` | `evals/cve/backends/facebook_ads.py` | served | 4 | nuisance |
| `evals/n8n_instance_backend.py` | `evals/cve/backends/n8n_instance.py` | BS | 4 | detection only (GHSA-8g7g holdout target) |
| `evals/apify_backend.py` | `evals/cve/backends/apify.py` |  | 4 | nuisance fix check only, unregistered |
| `evals/neo4j_backend.py` | `evals/cve/backends/neo4j.py` |  | 4 | nuisance fix check only, unregistered |

### A.2.9 `evals/cve/kit/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/holdout_kit/__init__.py` | `evals/cve/kit/__init__.py` |  | 4 |  |
| `evals/holdout_kit/benign_probe.py` | `evals/cve/kit/benign_probe.py` |  | 4 | run inside an exported dossier: `python -m evals.cve.kit.benign_probe` |
| `evals/holdout_kit/fix_check.py` | `evals/cve/kit/fix_check.py` |  | 4 | imported by the 58 fix-check modules |
| `evals/holdout_kit/kit_backend_launch.py` | `evals/cve/kit/backend_launch.py` |  | 4 | dynamic import `f"evals.{key}_backend"` becomes `f"evals.cve.backends.{key}"` |
| `evals/holdout_kit/kit_backends.py` | `evals/cve/kit/backends.py` |  | 4 | copied only for a server admitted with a backend |
| `evals/holdout_kit/kit_client.py` | `evals/cve/kit/client.py` |  | 4 |  |
| `evals/holdout_kit/kit_driver.py` | `evals/cve/kit/driver.py` |  | 4 |  |
| `evals/holdout_kit/kit_launch.py` | `evals/cve/kit/launch.py` |  | 4 |  |
| `evals/holdout_kit/kit_target.py` | `evals/cve/kit/target.py` |  | 4 |  |

### A.2.10 `evals/cve/census/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/holdout_census.py` | `evals/cve/census/census.py` |  | 4 | HoldoutCensus -> Census |
| `evals/census_classification.py` | `evals/cve/census/classification.py` |  | 4 |  |
| `evals/census_figures.py` | `evals/cve/census/figures.py` |  | 4 | 'census figures' is a qualified use |
| `evals/census_grouping.py` | `evals/cve/census/grouping.py` |  | 4 |  |
| `evals/census_identity.py` | `evals/cve/census/identity.py` |  | 4 |  |
| `evals/census_prefilter.py` | `evals/cve/census/prefilter.py` |  | 4 |  |
| `evals/census_progress.py` | `evals/cve/census/progress.py` |  | 4 |  |
| `evals/census_sources.py` | `evals/cve/census/sources.py` |  | 4 |  |
| `evals/census_work.py` | `evals/cve/census/work.py` |  | 4 |  |
| `evals/holdout_draw.py` | `evals/cve/census/draw_order.py` |  | 4 |  |
| `evals/holdout_exclusions.py` | `evals/cve/census/exclusions.py` |  | 4 |  |

### A.2.11 `evals/cve/detection/` with `holdout_fixtures/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/census_draw.py` | `evals/cve/detection/draw_record.py` |  | 4 | the draw record (detection walk, cards, drawn targets), `census/census.py` loads it |
| `evals/admission_calibration.py` | `evals/cve/detection/calibration_check_exit.py` |  | 4 | exit rule of the calibration check ("admission" is the nuisance admission only) |
| `evals/cve_audit.py` | `evals/cve/detection/audit.py` |  | 4 | build_auditor, RunOverrides read by the nuisance suite |
| `evals/cve_baseline.py` | `evals/cve/detection/baseline.py` |  | 4 | holds GRAMMAR_PATHS, ENVIRONMENT_PATHS, directory -> baselines/detection |
| `evals/cve_benchmark_modes.py` | `evals/cve/detection/no_llm_modes.py` |  | 4 | the no-LLM modes of `run_detection` |
| `evals/cve_calibration.py` | `evals/cve/detection/calibration_check.py` |  | 4 | the no-LLM check |
| `evals/cve_console.py` | `evals/cve/detection/console.py` |  | 4 |  |
| `evals/cve_costs.py` | `evals/cve/detection/costs.py` |  | 4 |  |
| `evals/cve_exploits.py` | `evals/cve/detection/exploits.py` |  | 4 |  |
| `evals/cve_gate.py` | `evals/cve/detection/gate.py` |  | 4 | _BASELINE_DIRECTORY string |
| `evals/cve_layout_check.py` | `evals/cve/detection/layout_check.py` |  | 4 |  |
| `evals/cve_markdown.py` | `evals/cve/detection/markdown.py` |  | 4 |  |
| `evals/cve_measurement.py` | `evals/cve/detection/measurement.py` |  | 4 |  |
| `evals/cve_oracle.py` | `evals/cve/detection/oracle.py` |  | 4 |  |
| `evals/cve_recording.py` | `evals/cve/detection/recording.py` |  | 4 | baseline recording, legit sense |
| `evals/cve_recording_console.py` | `evals/cve/detection/recording_console.py` |  | 4 | _BASELINES string |
| `evals/cve_replay.py` | `evals/cve/detection/replay.py` |  | 4 | the ADR 030 replay, legit sense |
| `evals/cve_route.py` | `evals/cve/detection/route_check.py` |  | 4 | glossary 'route check' |
| `evals/cve_session.py` | `evals/cve/detection/session.py` |  | 4 |  |
| `evals/cve_session_model.py` | `evals/cve/detection/session_model.py` |  | 4 |  |
| `evals/cve_session_recording.py` | `evals/cve/detection/session_recording.py` |  | 4 |  |
| `evals/cve_survey.py` | `evals/cve/detection/survey.py` |  | 4 |  |
| `evals/cve_targets.py` | `evals/cve/detection/targets.py` |  | 4 | CVETarget, image_tag, CVE_TARGETS (acceptance) |
| `evals/calibration_dossier.py` | `evals/cve/detection/calibration_dossier.py` |  | 4 | kit export, see H.4 |
| `evals/holdout_assembly.py` | `evals/cve/detection/holdout_assembly.py` |  | 4 |  |
| `evals/holdout_audit.py` | `evals/cve/detection/holdout_audit.py` |  | 4 |  |
| `evals/holdout_card_readiness.py` | `evals/cve/detection/holdout_card_readiness.py` |  | 4 |  |
| `evals/holdout_environments.py` | `evals/cve/detection/holdout_environments.py` | E | 4 |  |
| `evals/holdout_markdown.py` | `evals/cve/detection/holdout_markdown.py` |  | 4 |  |
| `evals/holdout_not_run.py` | `evals/cve/detection/holdout_not_run.py` |  | 4 |  |
| `evals/holdout_report.py` | `evals/cve/detection/holdout_report.py` |  | 4 | ConclusionLine, IntervalModel read by nuisance |
| `evals/holdout_results.py` | `evals/cve/detection/holdout_results.py` |  | 4 |  |
| `evals/holdout_run.py` | `evals/cve/detection/holdout_run.py` |  | 4 | HOLDOUT_BUDGET read by nuisance |
| `evals/holdout_targets.py` | `evals/cve/detection/holdout_targets.py` |  | 4 | isolation test matches its dotted name |
| `evals/holdout_vetting.py` | `evals/cve/detection/holdout_pre_run_check.py` |  | 4 | the pre-run check ("vet" is the nuisance check only) |
| `evals/holdout_fixtures/` (38 files: `__init__.py` and one module per holdout target, named by its flaw ID) | `evals/cve/detection/holdout_fixtures/` (same file names) | the fields of each target, through `fixture_fingerprint` | 4 | the doris and n8n modules name their `backend_sources` by `Path(<module>.__file__)`, which follows the move, the import scans of H.6 name the package |

### A.2.12 `evals/cve/nuisance/` with `fix_checks/`

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/nuisance_admission.py` | `evals/cve/nuisance/admission.py` |  | 4 |  |
| `evals/nuisance_admission_records.py` | `evals/cve/nuisance/admission_records.py` |  | 4 |  |
| `evals/nuisance_admission_walk.py` | `evals/cve/nuisance/admission_walk.py` |  | 4 |  |
| `evals/nuisance_assembly.py` | `evals/cve/nuisance/assembly.py` |  | 4 |  |
| `evals/nuisance_audit.py` | `evals/cve/nuisance/audit.py` |  | 4 |  |
| `evals/nuisance_backends.py` | `evals/cve/nuisance/backend_registry.py` |  | 4 | BACKENDS, avoids a second 'backends' beside cve/backends/ |
| `evals/nuisance_benign_call.py` | `evals/cve/nuisance/benign_call.py` |  | 4 |  |
| `evals/nuisance_calibrate_command.py` | `evals/cve/nuisance/fix_check_command.py` |  | 4 | 'calibrate' -> fix-check |
| `evals/nuisance_commands.py` | `evals/cve/nuisance/commands.py` |  | 4 | CENSUS_PATH value -> census.json |
| `evals/nuisance_confinement.py` | `evals/cve/nuisance/confinement.py` | CONF | 4 | imported by the backends and the kit |
| `evals/nuisance_counter.py` | `evals/cve/nuisance/counter.py` | C | 4 | holds _COUNTER_PATHS |
| `evals/nuisance_counting.py` | `evals/cve/nuisance/counting.py` | C | 4 |  |
| `evals/nuisance_dossier.py` | `evals/cve/nuisance/dossier.py` |  | 4 | admission dossier, see H.4 |
| `evals/nuisance_fingerprint.py` | `evals/cve/nuisance/fingerprint.py` |  | 4 | holds CONFINEMENT_SOURCE, _PUBLIC_NAME_SOURCES |
| `evals/nuisance_fixtures.py` | `evals/cve/nuisance/fixtures.py` |  | 4 |  |
| `evals/nuisance_gate.py` | `evals/cve/nuisance/gate.py` |  | 4 |  |
| `evals/nuisance_gate_baseline.py` | `evals/cve/nuisance/gate_baseline.py` |  | 4 | directory -> parents[2] / baselines / nuisance |
| `evals/nuisance_gate_command.py` | `evals/cve/nuisance/gate_command.py` |  | 4 |  |
| `evals/nuisance_gate_console.py` | `evals/cve/nuisance/gate_console.py` |  | 4 |  |
| `evals/nuisance_gate_recording.py` | `evals/cve/nuisance/gate_recording.py` |  | 4 |  |
| `evals/nuisance_gate_report.py` | `evals/cve/nuisance/gate_report.py` |  | 4 |  |
| `evals/nuisance_gate_session.py` | `evals/cve/nuisance/gate_session.py` |  | 4 |  |
| `evals/nuisance_gate_session_model.py` | `evals/cve/nuisance/gate_session_model.py` |  | 4 |  |
| `evals/nuisance_gate_session_recording.py` | `evals/cve/nuisance/gate_session_recording.py` |  | 4 |  |
| `evals/nuisance_holdout_copies.py` | `evals/cve/nuisance/holdout_calibration_copies.py` |  | 4 | glossary 'holdout calibration copy' |
| `evals/nuisance_holdout_reference.py` | `evals/cve/nuisance/holdout_target_reference.py` |  | 4 | `HOLDOUT_FIXTURES` path, bare "holdout" inside `nuisance/` would read as the nuisance holdout layer |
| `evals/nuisance_images.py` | `evals/cve/nuisance/images.py` |  | 4 |  |
| `evals/nuisance_markdown.py` | `evals/cve/nuisance/markdown.py` |  | 4 |  |
| `evals/nuisance_population.py` | `evals/cve/nuisance/holdout_servers.py` |  | 4 | the servers a nuisance run audits and the standing exits |
| `evals/nuisance_provisioners.py` | `evals/cve/nuisance/provisioners.py` |  | 4 |  |
| `evals/nuisance_readmission_docs.py` | `evals/cve/nuisance/re_admission_docs.py` |  | 4 | readmission -> re-admission |
| `evals/nuisance_readmission_dossier.py` | `evals/cve/nuisance/re_admission_dossier.py` |  | 4 | readmission -> re-admission |
| `evals/nuisance_report.py` | `evals/cve/nuisance/report.py` |  | 4 |  |
| `evals/nuisance_results.py` | `evals/cve/nuisance/results.py` |  | 4 |  |
| `evals/nuisance_run.py` | `evals/cve/nuisance/run.py` |  | 4 |  |
| `evals/nuisance_run_containers.py` | `evals/cve/nuisance/run_containers.py` |  | 4 |  |
| `evals/nuisance_solo.py` | `evals/cve/nuisance/solo.py` |  | 4 |  |
| `evals/nuisance_statistic.py` | `evals/cve/nuisance/statistic.py` |  | 4 |  |
| `evals/nuisance_unrecorded.py` | `evals/cve/nuisance/unrecorded.py` |  | 4 |  |
| `evals/nuisance_vet_command.py` | `evals/cve/nuisance/vet_command.py` |  | 4 |  |
| `evals/nuisance_vetting.py` | `evals/cve/nuisance/vetting.py` |  | 4 | 'vet' is the nuisance sense, docstring loses 'pre-run check' |
| `evals/nuisance_walk.py` | `evals/cve/nuisance/walk.py` |  | 4 |  |
| `evals/nuisance_walk_record.py` | `evals/cve/nuisance/walk_record.py` |  | 4 |  |
| `evals/nuisance_fix_checks/` (58 files: `__init__.py`, one module per fix check, `excel_witness_workbook.py`, `mcp_ssh_fix_check.py`, `n8n_redirect_stand_in.py`) | `evals/cve/nuisance/fix_checks/` (same file names) |  | 4 | `pkgutil.iter_modules(fix_checks.__path__)` follows the package, the `__init__` docstring names `evals.holdout_kit`, `evals.cve_*` and `evals/holdout_fixtures/`, rewritten |

### A.2.13 Directories that stay whole

| old path | new path | hashed by | step | note |
|---|---|---|---|---|
| `evals/docker/` (232 files) | (unchanged) | D (Dockerfile instructions) | 4 (content) | compose services keep their names, `Dockerfile.stand-in` changes in step 4 (D, image rebuilt), `compose.yml` comments at lines 96 and 105 and nine Dockerfile comment lines (step 4 body) cite moved modules and are rewritten, and every other comment carrying a retired or moved word is reworded (Appendix I), with no rebuild (comments are outside D) |
| `evals/stand_ins/` (24 captures, `facebook-ads-responder/graph.facebook.com.captures.json`, `tls/` 53 files) | (unchanged) | stand-in text, TLS files by SHA-256 | 4 (content) | captures rewritten in place in step 4 (D): `target` to `request_target`, `probed_target` to `probed_request_target` |
| `evals/fixtures/fault_injection_baseline.json`, `evals/fixtures/judge_cases.json`, `evals/fixtures/probe_corpus.json` | (unchanged) |  | 3 (content) | the keys of `fault_injection_baseline.json` are rewritten in step 3 (D), the two others unchanged |
| `evals/probe_runs/2026-09-25_adr-019.json`, `evals/probe_runs/2026-09-25_adr-021.json` | (unchanged) |  | - |  |

### A.3 Commands

| old | new |
|---|---|
| `python -m evals.run_evals` (`--ungated`) | `python -m evals.run_honeypot_suite` (`--no-baseline`) |
| `python -m evals.run_judge_eval --ungated` | `python -m evals.run_judge_eval --no-baseline` |
| `python -m evals.draw_judge_cases --cve-export PATH` | `python -m evals.draw_judge_cases --detection-export PATH` |
| `python -m evals.run_cve_benchmark` (`--calibrate`, `--ungated`, `--cve ID`) | `python -m evals.run_detection` (`--calibration-check`, `--no-baseline`, `--flaw ID`) |
| `python -m evals.cve_preflight` | `python -m evals.detection_preflight` |
| `python -m evals.run_holdout draw-order` | `python -m evals.run_census draw-order` |
| `python -m evals.run_holdout calibration-dossier --cve ID --out DIR` | `python -m evals.run_detection_holdout calibration-dossier --flaw ID --out DIR` |
| `python -m evals.run_holdout calibrate` (`--cve ID`) | `python -m evals.run_detection_holdout calibration-check` (`--flaw ID`) |
| `python -m evals.run_holdout run` | `python -m evals.run_detection_holdout run` |
| `python -m evals.run_nuisance calibrate` (`--cve ID`) | `python -m evals.run_nuisance fix-check` (`--flaw ID`) |
| `python -m evals.run_nuisance nuisance-dossier --readmission` | `python -m evals.run_nuisance nuisance-dossier --re-admission` |
| `python -m evals.holdout_kit.benign_probe` (inside an exported dossier) | `python -m evals.cve.kit.benign_probe` |
| `python -m tests.unit.support.test_cve_layout_check_golden_given` | `python -m tests.unit.support.test_detection_layout_check_golden_given` |
| `python -m tests.unit.support.test_cve_route_golden_given` | `python -m tests.unit.support.test_detection_route_check_golden_given` |

Unchanged: `evals.run_census` (prefilter, status, classify-dossier, assemble, gaining draw-order), `evals.run_nuisance` (walk, nuisance-dossier, run, vet, gate), `evals.run_judge_eval`, `evals.run_probe`, `evals.capture_stand_in` (the nuisance dossier copies it by closure, and 12 committed captures and the admission record it as their `command`), `evals.capture_probe_corpus`, `evals.draw_judge_cases`, and `python -m tests.unit.support.test_cve_grammar_golden_given`. No subprocess in `evals/` or `tests/` runs `python -m evals.X`. Argparse keeps no alias for an old flag.

### A.4 Cross-package and upward imports left as they are

Fixing these is structure, not vocabulary. Nuisance code importing detection code (the holdout targets, the holdout statistic) matches the suites' real dependency and is not listed.

- From the shared `cve/` package up into a suite: `cve.audit_attempts`, `cve.images` and `cve.run_images` import `cve.detection.targets`, `cve.holdout_statistic` imports `cve.detection.holdout_results`, `cve.run_files` imports `cve.detection.holdout_results` and `cve.nuisance.results`, `cve.fixture_sources` imports `cve.nuisance.admission_records` (`SeedRecord`).
- From the shared backends into the nuisance suite: `cve.backends.ckan`, `.doris`, `.gravitino`, `.jenkins`, `.mcp_ssh_sshd`, `.n8n` and `.responder` import `cve.nuisance.confinement` (the memory bound).
- From the census into the detection suite: `cve.census.census` imports `cve.detection.draw_record`.
- From the kit into suite code: `cve.kit.benign_probe` imports `cve.nuisance.confinement`, `cve.kit.backends` imports `cve.backends.doris`, `cve.kit.backend_launch` imports `cve.backends.lifecycle` and loads a backend by its key.
- From the CVE benchmark into other instruments: `cve.detection.costs`, `cve.detection.holdout_assembly` and `cve.nuisance.assembly` import `probe.analysis` (`call_cost`) and `probe.candidates` (`Prices`), `cve.detection.measurement` and `cve.holdout_conditions` import `probe.candidates`, `cve.detection.holdout_run` and `cve.nuisance.run` import `honeypot.runs` (`tracing_enabled`), and `cve.nuisance.run` also `probe.candidates`.
- From shared top-level modules into packages: `eval_display` imports `honeypot.report`, `export` imports `cve.detection.session_model` and `cve.nuisance.gate_session_model`.

### A.5 Hashed modules and the evals modules they import

Every row moves in the last commit of step 4 (implementation step 9), together with every module it imports that is not at the top level for good (`nuisance_admission.py`, `docker_paths.py`, `backend_lifecycle.py`, list M9 of the Implementation steps), so each fingerprint moves once. At `e551cee` a hashed module imports no other evals module but these, other hashed modules and `evals/baseline.py`, which stays. The modules that hold the path lists (`cve/detection/baseline.py`, `cve/nuisance/fingerprint.py`, `cve/nuisance/backend_registry.py`) are not hashed themselves, and refer to each hashed module by `Path(<module>.__file__)`, which follows the move with no edit beyond the import line.

| hashed module (new path under `evals/`) | hashed by | evals modules it imports (new names) |
|---|---|---|
| `cve/grammar.py` | G | `cve.proofs`, `cve.units` |
| `cve/proofs.py` | G | `cve.units` |
| `cve/units.py` | G | none |
| `cve/report_units.py` | G | `cve.units` |
| `cve/environments.py` | E | `cve.layout`, `cve.places`, `cve.planting`, `cve.planting_docker` |
| `cve/detection/holdout_environments.py` | E | `cve.backends.doris`, `cve.backends.n8n_instance`, `cve.environments`, `cve.layout`, `cve.planting`, `cve.planting_base`, `cve.planting_docker` |
| `cve/layout.py` | E | `cve.places`, `cve.planting_base` |
| `cve/places.py` | E | none |
| `cve/planting.py` | E, P | `cve.layout`, `cve.planting_base`, `cve.planting_docker`, `cve.planting_spec`, `cve.planting_stand_ins`, `cve.public_stand_ins` |
| `cve/planting_base.py` | E, P | `cve.places` |
| `cve/planting_spec.py` | E, P | `cve.endpoint_address`, `cve.layout`, `cve.places`, `cve.planting_base` |
| `cve/planting_docker.py` | E, P | `cve.closed_network`, `cve.planting_base` |
| `cve/endpoint_address.py` | E, P | `cve.planting_base` |
| `cve/public_stand_ins.py` | E, P | `cve.planting_base` |
| `cve/planting_stand_ins.py` | E, P | `cve.planting_base`, `cve.public_stand_ins` |
| `cve/closed_network.py` | E, P, served | `cve.planting_base` |
| `cve/nuisance/counter.py` | C | `baseline`, `cve.nuisance.counting`, `cve.units` |
| `cve/nuisance/counting.py` | C | `cve.grammar`, `cve.nuisance.admission`, `cve.units` |
| `cve/nuisance/confinement.py` | CONF | `cve.planting`, `cve.planting_base`, `cve.planting_docker`, `cve.public_stand_ins` |
| `cve/backends/doris.py` | served, BS | `cve.backends.lifecycle`, `cve.closed_network`, `cve.nuisance.confinement`, `cve.planting`, `cve.planting_base` |
| `cve/backends/ckan.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.closed_network`, `cve.docker_paths`, `cve.nuisance.confinement`, `cve.planting_base`, `cve.public_stand_ins` |
| `cve/backends/n8n.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.closed_network`, `cve.docker_paths`, `cve.nuisance.confinement`, `cve.planting_base` |
| `cve/backends/gravitino.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.closed_network`, `cve.docker_paths`, `cve.nuisance.confinement`, `cve.planting_base` |
| `cve/backends/mcp_ssh_sshd.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.closed_network`, `cve.docker_paths`, `cve.nuisance.confinement`, `cve.planting_base` |
| `cve/backends/jenkins.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.closed_network`, `cve.docker_paths`, `cve.nuisance.confinement`, `cve.planting_base` |
| `cve/backends/atlassian.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.docker_paths`, `cve.planting_base` |
| `cve/backends/gitlab.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.docker_paths`, `cve.planting_base` |
| `cve/backends/googleapis.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.docker_paths`, `cve.planting_base` |
| `cve/backends/facebook_ads.py` | served | `cve.backends.lifecycle`, `cve.backends.responder`, `cve.docker_paths`, `cve.planting_base` |
| `cve/backends/responder.py` | served | `cve.closed_network`, `cve.docker_paths`, `cve.nuisance.confinement`, `cve.planting_base` |
| `cve/backends/n8n_instance.py` | BS | `cve.planting`, `cve.planting_base` |

## Appendix B. Test renames

Rule: a test file is named `test_<package>_<module><rest>.py`, where `<package>` is `cve` (a module of `evals/cve/`), `census`, `detection`, `nuisance`, `kit`, `honeypot`, `judge` or `probe`, and `<rest>` is the existing suffix (`_golden`, `_interrupted`, `_built`, `_refusal`). `census/census.py` gives `test_census.py`. A backend reads as `<key>_backend` (`lifecycle` reads as `backend_lifecycle`, `responder` as `responder_backend`). A test of a top-level module keeps its form (`test_eval_gate.py`, `test_export.py`, `test_run_<command>.py`), and a test of an `src/` module follows its module. The `_given` and `_then` companions under `support/` follow their test, and so do the golden files and their regeneration modules. The tree stays flat: no new subfolder. The three `stub` files of `tests/integration/support/` are renamed because "stub" is retired.

Names the rule keeps: `test_cve_grammar*` with `cve_grammar_golden.json`, `cve_grammar_golden_corpus.py` and the regenerator `test_cve_grammar_golden_given.py`, `test_cve_places`, `test_cve_layout`, `test_cve_planting*`, `test_cve_images`, `test_cve_launches`, `test_cve_strike`, `test_cve_sentinel_paths`, `test_cve_compose_labels`, `test_cve_layout_mount`, `test_census_classification/figures/grouping/identity/prefilter/sources/work`, `test_kit_driver`, every `test_nuisance_*` whose module keeps its stem (`test_nuisance_fix_checks` included), the `*_backend` tests, `test_backend_lifecycle`, `test_backend_hostnames`, the `<server>_fix_check_builder` tests, `test_fix_check_resolver`, `test_responder_fix_checks`, `test_excel_witness_workbook`, `test_doris_serialization`, `test_nuisance_doris_backend`, `test_nuisance_public_names`, `test_fixture_contamination`, `test_gate_fault_injection`, `test_eval_baseline/cell_grid/display/gate/metrics/recording/session`, `test_judge_*`, `test_probe_corpus`, `test_probe_subset`, `test_run_census`, `test_run_judge_eval`, `test_run_nuisance*`, `test_run_probe`, `test_draw_judge_cases`, `test_capture_stand_in`.

`tests/integration/`:

| old | new | step |
|---|---|---|
| `test_closed_networks.py` | `test_cve_closed_networks.py` | 4 |
| `test_cve_calibration.py` | `test_detection_calibration_check.py` | 4 |
| `test_cve_replay.py` | `test_detection_replay.py` | 4 |
| `test_holdout_kit.py` | `test_kit.py` | 4 |
| `test_holdout_kit_client.py` | `test_kit_client.py` | 4 |

`tests/integration/support/`:

| old | new | step |
|---|---|---|
| `cve_replay_stub_server.py` | `detection_replay_read_server.py` | 4 |
| `cve_stub_server.py` | `detection_read_server.py` | 4 |
| `cve_stub_target.py` | `detection_fake_targets.py` | 4 |
| `test_closed_networks_given.py` | `test_cve_closed_networks_given.py` | 4 |
| `test_closed_networks_then.py` | `test_cve_closed_networks_then.py` | 4 |
| `test_cve_calibration_given.py` | `test_detection_calibration_check_given.py` | 4 |
| `test_cve_replay_given.py` | `test_detection_replay_given.py` | 4 |
| `test_cve_replay_then.py` | `test_detection_replay_then.py` | 4 |

`tests/unit/`:

| old | new | step |
|---|---|---|
| `test_admission_calibration.py` | `test_detection_calibration_check_exit.py` | 4 |
| `test_audit_launch.py` | `test_cve_launch_audit.py` | 4 |
| `test_audit_progress.py` | `test_cve_audit_progress.py` | 4 |
| `test_benign_probe.py` | `test_kit_benign_probe.py` | 4 |
| `test_calibration_dossier.py` | `test_detection_calibration_dossier.py` | 4 |
| `test_census_draw.py` | `test_detection_draw_record.py` | 4 |
| `test_closed_network.py` | `test_cve_closed_network.py` | 4 |
| `test_closed_network_refusal.py` | `test_cve_closed_network_refusal.py` | 4 |
| `test_cve_audit.py` | `test_detection_audit.py` | 4 |
| `test_cve_baseline.py` | `test_detection_baseline.py` | 4 |
| `test_cve_calibration.py` | `test_detection_calibration_check.py` | 4 |
| `test_cve_console.py` | `test_detection_console.py` | 4 |
| `test_cve_costs.py` | `test_detection_costs.py` | 4 |
| `test_cve_gate.py` | `test_detection_gate.py` | 4 |
| `test_cve_layout_check.py` | `test_detection_layout_check.py` | 4 |
| `test_cve_oracle.py` | `test_detection_oracle.py` | 4 |
| `test_cve_preflight.py` | `test_detection_preflight.py` | 4 |
| `test_cve_recording.py` | `test_detection_recording.py` | 4 |
| `test_cve_recording_client.py` | `test_cve_exchange_log.py` | 4 |
| `test_cve_replay.py` | `test_detection_replay.py` | 4 |
| `test_cve_route.py` | `test_detection_route_check.py` | 4 |
| `test_cve_session.py` | `test_detection_session.py` | 4 |
| `test_cve_survey.py` | `test_detection_survey.py` | 4 |
| `test_cve_targets.py` | `test_detection_targets.py` | 4 |
| `test_dossier_closure.py` | `test_cve_dossier_closure.py` | 4 |
| `test_eval_fault_fakes.py` | `test_honeypot_fault_fakes.py` | 3 |
| `test_eval_fault_harness.py` | `test_honeypot_fault_harness.py` | 3 |
| `test_eval_fault_injection.py` | `test_honeypot_fault_injection.py` | 3 |
| `test_eval_gate_verdict.py` | `test_eval_gate_outcome.py` | 3 |
| `test_eval_judging.py` | `test_honeypot_decision.py` | 3 |
| `test_eval_replay.py` | `test_honeypot_retest.py` | 3 |
| `test_failure_text.py` | `test_cve_failure_text.py` | 4 |
| `test_fix_check.py` | `test_kit_fix_check.py` | 4 |
| `test_fixture_provenance.py` | `test_cve_fixture_provenance.py` | 4 |
| `test_fixture_sources.py` | `test_cve_fixture_sources.py` | 4 |
| `test_holdout_audit.py` | `test_detection_holdout_audit.py` | 4 |
| `test_holdout_card_readiness.py` | `test_detection_holdout_card_readiness.py` | 4 |
| `test_holdout_census.py` | `test_census.py` | 4 |
| `test_holdout_conditions.py` | `test_cve_holdout_conditions.py` | 4 |
| `test_holdout_draw.py` | `test_census_draw_order.py` | 4 |
| `test_holdout_fixture_sources.py` | `test_detection_holdout_fixture_sources.py` | 4 |
| `test_holdout_hierarchical.py` | `test_cve_holdout_hierarchical.py` | 4 |
| `test_holdout_intervals.py` | `test_cve_holdout_intervals.py` | 4 |
| `test_holdout_kit_isolation.py` | `test_kit_isolation.py` | 4 |
| `test_holdout_report.py` | `test_detection_holdout_report.py` | 4 |
| `test_holdout_run.py` | `test_detection_holdout_run.py` | 4 |
| `test_holdout_run_interrupted.py` | `test_detection_holdout_run_interrupted.py` | 4 |
| `test_holdout_statistic.py` | `test_cve_holdout_statistic.py` | 4 |
| `test_holdout_targets.py` | `test_detection_holdout_targets.py` | 4 |
| `test_holdout_vetting.py` | `test_detection_holdout_pre_run_check.py` | 4 |
| `test_missed_steps.py` | `test_missed_model_calls.py` | 2 |
| `test_nuisance_backends.py` | `test_nuisance_backend_registry.py` | 4 |
| `test_nuisance_backends_built.py` | `test_nuisance_backend_registry_built.py` | 4 |
| `test_nuisance_calibrate_command.py` | `test_nuisance_fix_check_command.py` | 4 |
| `test_nuisance_holdout_copies.py` | `test_nuisance_holdout_calibration_copies.py` | 4 |
| `test_nuisance_population.py` | `test_nuisance_holdout_servers.py` | 4 |
| `test_nuisance_readmission_dossier.py` | `test_nuisance_re_admission_dossier.py` | 4 |
| `test_probe.py` | `test_probe_analysis.py` | 3 |
| `test_provider_errors.py` | `test_cve_provider_errors.py` | 4 |
| `test_public_stand_ins.py` | `test_cve_public_stand_ins.py` | 4 |
| `test_run_cve_benchmark.py` | `test_run_detection.py` | 4 |
| `test_run_evals.py` | `test_run_honeypot_suite.py` | 3 |
| `test_run_holdout.py` | `test_run_detection_holdout.py` | 4 |
| `test_run_holdout_run.py` | `test_run_detection_holdout_run.py` | 4 |
| `test_run_images.py` | `test_cve_run_images.py` | 4 |
| `test_server_health.py` | `test_cve_server_health.py` | 4 |
| `test_target_execution.py` | `test_server_execution.py` | 2 |

`tests/unit/support/`:

| old | new | step |
|---|---|---|
| `cve_layout_check_golden.json` | `detection_layout_check_golden.json` | 4 |
| `cve_route_golden.json` | `detection_route_check_golden.json` | 4 |
| `holdout_kit_isolation.py` | `kit_isolation.py` | 4 |
| `test_admission_calibration_given.py` | `test_detection_calibration_check_exit_given.py` | 4 |
| `test_audit_launch_given.py` | `test_cve_launch_audit_given.py` | 4 |
| `test_audit_progress_given.py` | `test_cve_audit_progress_given.py` | 4 |
| `test_benign_probe_given.py` | `test_kit_benign_probe_given.py` | 4 |
| `test_calibration_dossier_given.py` | `test_detection_calibration_dossier_given.py` | 4 |
| `test_census_draw_given.py` | `test_detection_draw_record_given.py` | 4 |
| `test_closed_network_given.py` | `test_cve_closed_network_given.py` | 4 |
| `test_closed_network_refusal_given.py` | `test_cve_closed_network_refusal_given.py` | 4 |
| `test_closed_network_refusal_then.py` | `test_cve_closed_network_refusal_then.py` | 4 |
| `test_closed_network_then.py` | `test_cve_closed_network_then.py` | 4 |
| `test_cve_audit_given.py` | `test_detection_audit_given.py` | 4 |
| `test_cve_baseline_given.py` | `test_detection_baseline_given.py` | 4 |
| `test_cve_console_given.py` | `test_detection_console_given.py` | 4 |
| `test_cve_costs_given.py` | `test_detection_costs_given.py` | 4 |
| `test_cve_gate_given.py` | `test_detection_gate_given.py` | 4 |
| `test_cve_layout_check_golden_given.py` | `test_detection_layout_check_golden_given.py` | 4 |
| `test_cve_oracle_given.py` | `test_detection_oracle_given.py` | 4 |
| `test_cve_recording_given.py` | `test_detection_recording_given.py` | 4 |
| `test_cve_replay_given.py` | `test_detection_replay_given.py` | 4 |
| `test_cve_route_golden_given.py` | `test_detection_route_check_golden_given.py` | 4 |
| `test_cve_session_given.py` | `test_detection_session_given.py` | 4 |
| `test_cve_session_then.py` | `test_detection_session_then.py` | 4 |
| `test_eval_fault_fakes_given.py` | `test_honeypot_fault_fakes_given.py` | 3 |
| `test_eval_fault_harness_given.py` | `test_honeypot_fault_harness_given.py` | 3 |
| `test_eval_fault_harness_then.py` | `test_honeypot_fault_harness_then.py` | 3 |
| `test_eval_fault_injection_given.py` | `test_honeypot_fault_injection_given.py` | 3 |
| `test_eval_fault_injection_then.py` | `test_honeypot_fault_injection_then.py` | 3 |
| `test_eval_gate_verdict_given.py` | `test_eval_gate_outcome_given.py` | 3 |
| `test_eval_judging_given.py` | `test_honeypot_decision_given.py` | 3 |
| `test_eval_replay_given.py` | `test_honeypot_retest_given.py` | 3 |
| `test_fix_check_given.py` | `test_kit_fix_check_given.py` | 4 |
| `test_holdout_census_given.py` | `test_census_given.py` | 4 |
| `test_holdout_draw_given.py` | `test_census_draw_order_given.py` | 4 |
| `test_holdout_fixture_sources_then.py` | `test_detection_holdout_fixture_sources_then.py` | 4 |
| `test_holdout_run_given.py` | `test_detection_holdout_run_given.py` | 4 |
| `test_holdout_targets_given.py` | `test_detection_holdout_targets_given.py` | 4 |
| `test_holdout_vetting_given.py` | `test_detection_holdout_pre_run_check_given.py` | 4 |
| `test_holdout_vetting_then.py` | `test_detection_holdout_pre_run_check_then.py` | 4 |
| `test_nuisance_calibrate_command_given.py` | `test_nuisance_fix_check_command_given.py` | 4 |
| `test_nuisance_holdout_copies_given.py` | `test_nuisance_holdout_calibration_copies_given.py` | 4 |
| `test_nuisance_readmission_dossier_given.py` | `test_nuisance_re_admission_dossier_given.py` | 4 |
| `test_probe_given.py` | `test_probe_analysis_given.py` | 3 |
| `test_probe_then.py` | `test_probe_analysis_then.py` | 3 |
| `test_provider_errors_given.py` | `test_cve_provider_errors_given.py` | 4 |
| `test_public_stand_ins_given.py` | `test_cve_public_stand_ins_given.py` | 4 |
| `test_run_cve_benchmark_given.py` | `test_run_detection_given.py` | 4 |
| `test_run_evals_given.py` | `test_run_honeypot_suite_given.py` | 3 |
| `test_run_holdout_run_given.py` | `test_run_detection_holdout_run_given.py` | 4 |
| `test_run_images_given.py` | `test_cve_run_images_given.py` | 4 |
| `test_target_execution_given.py` | `test_server_execution_given.py` | 2 |

## Appendix C. Identifier renames

### C.0 Columns, steps and the order of the codemod

A visible string of an unhashed module (help text, console line, report or Markdown text) is listed once, in E, and not repeated here. Columns: the current name with its file:line, the new name, where it is serialized (with its committed count), whether it reaches a model or an agent, whether a hashed file defines or references it (code of the header), whether a user sees it, and the step. A "-" means no. Steps follow the plan: step 2 for the `src/` core renames that no hashed file references, with their call sites in tests and in unhashed evals modules, step 3 for the honeypot, judge, probe and shared top-level renames that no hashed file references, with their call sites in unhashed CVE modules, step 4 for everything else in the CVE benchmark and every name a hashed file references (`EvalResult`, `eval_result`, `JudgeResult.arguments` and the Markdown "Payload" line included). At `e551cee` no step 2 or step 3 name occurs in a hashed file (checked by grep over the files of the header's lists), and `CVETarget` occurs in `cve_environments.py` only in a comment, which moves nothing but is still fixed in step 4.

Order of the codemod:

1. `git mv` per A.2, then the module paths: `from evals.X import`, `import evals.X` and dotted names in strings (importlib calls, closure roots, isolation scans, `monkeypatch.setattr` targets, logger names), longest old name first (`evals.cve_planting_stand_ins` before `evals.cve_planting`, `evals.nuisance_gate_session_model` before `evals.nuisance_gate_session` before `evals.nuisance_gate`), and the three packages (`evals.holdout_kit.`, `evals.holdout_fixtures.`, `evals.nuisance_fix_checks.`) before any module stem.
2. Word-boundary replacements of the distinctive identifiers, longer and more specific names first: `CVETargetBaseline` before `CVETarget`, `FixCheckCalibrationDeps` and `default_fix_check_calibration_deps` before `CalibrationDeps` and `default_calibration_deps`, `FIX_CHECK_TARGETS` before the per-module `TARGET`/`TARGETS`, `version_setting_flaws` before `version_setting`, `FigureExitLine` before `FigureExit`, `patched_dead_conditions` before `dead_conditions`, `eval_results` before `eval_result`, `judge_exploratory_commit_refusal` before `exploratory_commit_refusal`, `MissedStep` before `missed_step`.
3. A rename that frees a name runs before the rename that takes it: `cve_oracle.TargetStatus` to `ResultStatus` before `CVEStatus` to `TargetStatus`, `GateVerdict` to `GateOutcome` (step 3) before `CVEGateVerdict` is dropped for `GateOutcome` (step 4), `current_acceptance_servers` to `nuisance_acceptance_servers` before `acceptance_servers` to `acceptance_target_servers`.
4. By hand, file by file, with pyright strict as the net: the generic names `target`, `cve_id` (but `VulnerableMcpEntry.cve_id`, which holds CVE IDs, C.11), `verdict` (gate results to `outcome`, `Settlement.verdict` to `ruling`), `mechanisms`, `payload`, `figure`, `outside_figure` (to `exits`, which already names locals in tests, such as `tests/unit/test_nuisance_run.py:31`), `settle`, the gates' `judge`, `ServerMark.ACCEPTANCE`, `replays`, `entry_id` (to `place_id`, a name `cve_places.py` and the card models already use, so a local may clash), and `StandInRoute.target` (to `request_target`, already a function of `cve_planting_spec.py:60`). The prompt text "Target category:" (`graph/chain_prompts.py:150`) is model-facing and never touched.

### C.1 Auditor core (`src/mcp_auditor/`)

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `EvalResult` class, src/domain/models.py:109 | `JudgeResult` | Class name: in checkpoints. Not in a committed file. | - | ref: evals/cve_report_units.py:10,47 (GRAMMAR_PATHS) and evals/nuisance_counter.py:15,39 (_COUNTER_PATHS) import and annotate it | - | 4 |
| References to `EvalResult`: src 27 in 7 files (models 5, progress 7, console 4, rendering 4, chain_nodes 3, nodes 2, domain/__init__ 2 incl. `__all__` string), evals 4 in 2 files (cve_report_units 2, nuisance_counter 2), tests 41 in 11 files | `JudgeResult` | - | - | as above | - | 4 |
| `EvalResult.payload` field, src/domain/models.py:112 | `arguments` | JSON report key `tool_reports[].cases[].eval_result.payload` and `...chains[].eval_result.payload` -> `judge_result.arguments`. Breaking report change, no committed occurrence. | - | - | JSON report key | 4 |
| `TestCase.eval_result` field, src/domain/models.py:139 | `judge_result` | JSON report key `cases[].eval_result` -> `judge_result`, in checkpoints as a dict key inside a dumped `TestCase` (refused on resume: a renamed field is silently dropped on revive) | - | ref: evals/cve_report_units.py:29 (GRAMMAR_PATHS), evals/nuisance_counter.py:33 (_COUNTER_PATHS) | JSON report key | 4 |
| `AttackChain.eval_result` field, src/domain/models.py:188 | `judge_result` | JSON report key `chains[].eval_result` -> `judge_result`, checkpoint as above | - | ref: evals/cve_report_units.py:40, evals/nuisance_counter.py:35 | JSON report key | 4 |
| `.eval_result` attribute uses: src 30 in 7 files (models 6, rendering 5, stream_handler 3, chain_nodes 3, graph/prompts.py 3 at :162-164, graph/chain_prompts.py 2 at :185-186, nodes 2), evals 23 in 4 files (export 7, metrics 7, cve_report_units 3, nuisance_counter 3), tests 66 in 21 files | `.judge_result` | - | prompts.py/chain_prompts.py: attribute access only, the prompt text they build is unchanged (the golden test must stay byte-identical) | ref as above | - | 4 |
| `ToolReport.eval_results` property, src/domain/models.py:239 | `judge_results` | - | - | - | - | 4 |
| `_chain_eval_result`, src/graph/chain_nodes.py:164, local `eval_result` nodes.py:176,184, chain_nodes.py:152-153 | `_chain_judge_result`, `judge_result` | - | - | - | - | 4 |
| `_render_result_section(result: EvalResult)`, `_render_chain_verdict(result: EvalResult)`, `_severity_breakdown(findings: list[EvalResult])`, src/domain/rendering.py:170,226,245, `_ResultTracker`, `format_failure_line`, `format_tool_summary`, `advance(result)` in src/progress.py:37,77,95-115, `_format_finding`, `_print_findings_recap_*` in src/console.py:119,125,204 | type annotations only change | - | - | - | - | 4 |
| `AuditReport.target` field, src/domain/models.py:345 | `server_command` | JSON report key `target` -> `server_command` (Breaking, CHANGELOG). Checkpoint: inside the dumped `AuditReport` of the `audit_report` channel. No committed file. | - | - | JSON report key | 2 |
| `GraphState.target` channel, src/graph/state.py:24, read src/graph/nodes.py:226 `state["target"]`, written as graph input src/audit.py:161, :187 (dry run, `""`), evals/launch_audit.py:73, evals/honeypots.py:125, tests/unit/support/test_graph_given.py:241 | `server_command` | checkpoint channel name (refused on resume, `_EARLIER_VERSION_CHANNELS`) | - | - | - | 2 |
| `ServerLaunch.target` property, src/adapters/server_launch.py:75 | `server_command` | - | - | - | - | 2 |
| CLI positional argument `target`, src/cli.py:47 (param `target` :109, `_run_audit(target, ...)` :175, `_decided_launch(target, ...)` :225) | `server_command` (click metavar becomes `SERVER_COMMAND`) | - | - | - | yes: `mcp-auditor run --help` usage line `SERVER_COMMAND...` and the docstring line "TARGET is the command to start the MCP server." (:127) -> "SERVER_COMMAND is ..." | 2 |
| `AuditDisplay.print_header(target_command, ...)`, src/console.py:48,51 | `server_command` | - | - | - | - | 2 |
| `Audit._probe_the_target`, src/audit.py:99,111 | `_probe_the_server` | - | - | - | - | 2 |
| `TargetExecution` class, src/target_execution.py:220 (and `__aenter__` return type :232) | `ServerExecution` | - | - | - | - | 2 |
| Module `src/mcp_auditor/target_execution.py` | `server_execution.py` | - | - | - | - | 2 |
| `AuditStep` enum, src/domain/models.py:300 | `ModelCallKind` | Values serialized under `missed_model_calls[].kind` (unchanged). Enum class name stored by msgpack in checkpoints (EXT_CONSTRUCTOR_SINGLE_ARG, module + name + value): a renamed enum revives as its bare value string with a warning (`_reconstruction_fallback`) | - | - | - | 2 |
| `JUDGE_STEPS`, src/domain/models.py:310 | `JUDGE_CALLS` | - | - | - | - | 2 |
| `is_judge_step`, src/domain/models.py:313 | `is_judge_call` | - | - | - | - | 2 |
| `CHAIN_STEPS`, src/domain/models.py:317 | `CHAIN_CALLS` | - | - | - | - | 2 |
| `is_chain_step`, src/domain/models.py:327 | `is_chain_call` | - | - | - | - | 2 |
| `MissedStep` class, src/domain/models.py:337, refs src 19 in 7 files, evals 2 (failure_text.py:131,144), tests 46 in 18 files | `MissedModelCall` | class name in checkpoints (pydantic EXT_PYDANTIC_V2: a renamed class revives as a plain dict, no warning) | - | - | - | 2 |
| `MissedStep.step` field, src/domain/models.py:339 | `kind` | JSON report key `missed_steps[].step` -> `missed_model_calls[].kind` | - | - | JSON report key | 2 |
| `AuditReport.missed_steps` field, src/domain/models.py:351 | `missed_model_calls` | JSON report key `missed_steps` -> `missed_model_calls` (still under [Unreleased], so nothing published breaks), checkpoint as part of `AuditReport` | - | - | JSON report key | 2 |
| `missed_steps` state channel: GraphState src/graph/state.py:34, AuditToolState :48, ChainAuditState :79, written by `Missed.state_update` graph/missed_steps.py:39, nodes.py:111, read nodes.py:235, chain_nodes, stream_handler.py:83, audit.py:199 (dry run result) | `missed_model_calls` | checkpoint channel name (refused on resume, `_EARLIER_VERSION_CHANNELS`) | - | - | - | 2 |
| `ModelCall.step` field, src/graph/missed_steps.py:25 (built nodes.py:66,172,215, chain_nodes.py:42,93,125,147) | `kind` | - | - | - | - | 2 |
| `Missed.missed_step` field, src/graph/missed_steps.py:32, local `step` :67 | `missed_call` | - | - | - | - | 2 |
| `GenerationOutcome.missed_steps` field, src/graph/nodes.py:76 (and :80, :93, :136) | `missed_model_calls` | - | - | - | - | 2 |
| Module `src/mcp_auditor/graph/missed_steps.py` | `graph/missed_model_calls.py` | - | - | - | - | 2 |
| `describe_missed_step`, src/domain/rendering.py:144 | `describe_missed_model_call` | - | - | - | - | 2 |
| `AuditDisplay.print_missed_steps`, src/console.py:104 | `print_missed_model_calls` | - | - | - | - | 2 |
| `_render_tool_section(..., missed_steps)` param and local, src/domain/rendering.py:49,148 | `missed_calls` | - | - | - | - | 2 |
| `graded_despite_missed_steps`, evals/audit_attempts.py:44 | `graded_despite_missed_model_calls` | - | - | - | - | 2 |
| `ReportDetail.missed_detail(missed: MissedStep)`, evals/failure_text.py:144 | `missed_call_detail`, `missed.kind` | - | - | - | - | 2 |
| `chain_step_missed` channel, src/graph/state.py:72 (chain_nodes.py:60,96,128,191,214,225, 9 test refs) | `chain_model_call_missed` | checkpoint channel name | - | - | - | 2 |
| `judged_cases` channel: GraphState src/graph/state.py:28, AuditToolState :47, ChainAuditState :63, ChainAuditInput :83, written nodes.py:108,155,174,186,196, read nodes.py:201, chain_nodes.py:31, stream_handler.py:69,75 (local `judged`) , tests 43 refs in 11 files (test_nodes 10, test_export 17 are the export, see Kept) | `processed_cases` | checkpoint channel name (refused on resume, `_EARLIER_VERSION_CHANNELS`) | - | - | - | 2 |
| `ExecutionRecord.relayed_variables`, src/domain/models.py:296 | `redacted_variables` | JSON report key `execution.relayed_variables` -> `redacted_variables`, no committed occurrence | - | - | JSON report key | 2 |
| `Settings.openrouter_hosts`, src/config.py:15 (env var `MCP_AUDITOR_OPENROUTER_HOSTS`, derived from `env_prefix`) , evals/probe_candidates.py:88,100 (`openrouter_hosts=` kwargs), tests 8 in 2 files | `openrouter_providers` -> env var `MCP_AUDITOR_OPENROUTER_PROVIDERS` | env var, not Breaking (under [Unreleased]) | - | - | yes: env var (README:224,231, CHANGELOG:15) | 2 |
| `Settings.resolve_openrouter_hosts`, src/config.py:36 | `resolve_openrouter_providers` | - | - | - | - | 2 |
| `_make_openrouter_model(model, reasoning, hosts)`, `_openrouter_body(reasoning, hosts)`, src/adapters/chat_model_factory.py:158-184 | param `providers` | - | - | - | - | 2 |
| `ExecutionConfig`, src/audit.py:41 (cli.py:21,137, tests 4 in 2 files: test_resume_earlier_checkpoint_given, test_mcp_client_transport_given) | `AuditRunOptions` | - | - | - | - | 2 |
| `AuditConfig.execution` field, src/audit.py:50 | `run_options` | - | - | - | - | 2 |
| `_EARLIER_VERSION_CHANNELS`, src/mcp_auditor/checkpointing.py:31 (`{"refused_steps", "chain_step_refused"}`) | gains `target`, `judged_cases`, `missed_steps`, `chain_step_missed`, the refusal also reads the keys of the `__start__` input, comment at :28-30 rewritten, message unchanged | checkpoint channels | - | - | yes: `--resume` refuses an audit interrupted before step 2 | 2 |

### C.2 Shared gate, baseline and display code (`evals/` top level)

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `ReplayRule` gate.py:43 | `RetestRule` | - | - | - | - | 3 |
| `ReplayRule.replays` gate.py:53 | `retests` | Yes: inner key of `replay_rule` in evals/baselines/honeypot_e2e.json 1, evals/baselines/judge_isolation.json 1, evals/fixtures/fault_injection_baseline.json 1 (value 5 each). Read alias `AliasChoices("retests", "replays")`. Writer writes `retests`. | - | - | baseline file | 3 |
| `ReplayRule.decide_replays` gate.py:70 | `decide_retests` | - | - | - | - | 3 |
| validator message "replay rule needs 1 <= required <= replays" gate.py:60 | "retest rule needs 1 <= required <= retests" | - | - | - | error text | 3 |
| `Baseline.replay_rule` baseline.py:56 | `retest_rule` | Yes: honeypot_e2e.json 1. Read alias `AliasChoices("retest_rule", "replay_rule")`. Writer writes `retest_rule`. | - | - | baseline file | 3 |
| `CellComparison.replays` gate.py:159 | `retests` | Yes: `gate.cells.<cell>.replays` in output/eval_report.json and `gate.cases.<id>.replays` in output/judge_eval_report.json (not committed) | - | - | report key | 3 |
| `settle(comparison, replays, rule)` gate.py:203 (param) | param `retests` | - | - | - | - | 3 |
| `GateRow.replays` eval_display.py:80, `OutcomeRow.replays` cell_grid.py:65, `JudgeOutcomeRow.replays` judge_outcomes.py:22 | `retests` | - | - | - | - | 3 |
| `replay_fraction` cell_grid.py:200 | `retest_fraction` | - | - | - | - | 3 |
| `BaselineStatus.EXPLORATORY = "exploratory"` baseline.py:26 | `UNCONFIRMED = "unconfirmed"` | Yes: baseline `status` and report `gate.baseline_status`. Committed occurrences 0: the three committed baseline files carry `"confirmed"`. No alias needed. | - | - | console "Baseline recorded (exploratory)" eval_display.py:274, report value | 3 |
| `exploratory_commit_refusal` recording.py:120 | `unconfirmed_commit_refusal` | - | - | - | refusal text "the exploratory baseline was recorded at" recording.py:128 -> "the unconfirmed baseline ..." | 3 |
| `_NEXT_STEP[BaselineStatus.EXPLORATORY]` eval_display.py:265, judge_display.py:26 | key `UNCONFIRMED` | - | - | - | console | 3 |
| `GateVerdict` gate_verdict.py:28 | `GateOutcome` | values `green`/`red`/`not_comparable` unchanged | - | - | - | 3 |
| `GateResult.verdict` gate_verdict.py:36, `JudgeGateResult.verdict` judge_gate.py:35 | `outcome` | Yes: report key `gate.verdict` in output/eval_report.json and output/judge_eval_report.json (not committed) | - | - | report key | 3 |
| locals `verdict` in `judge_gate` gate_verdict.py:66,69 and `judge_case_gate` judge_gate.py:63,68 | `outcome` | - | - | - | - | 3 |
| `print_verdict(verdict: GateVerdict, ...)` eval_display.py:70 | `print_outcome` | - | - | - | - | 3 |
| `_VERDICT_STYLES` eval_display.py:31, judge_display.py:19 | `_OUTCOME_STYLES` | - | - | - | - | 3 |
| `judge_gate(gate_input)` gate_verdict.py:63 | `decide_gate` | - | - | - | - | 3 |
| `CellTag.ALARM = "alarm"` cell_grid.py:26, uses cell_grid.py:184, eval_display.py:146,158 | `CellTag.FALSE_POSITIVE = "false_positive"` | Display only (grid and legend). Not written to a report or committed file. | - | - | console grid tag | 3 |
| `CellTag.FIXED = "fixed"` cell_grid.py:30, uses cell_grid.py:137, eval_display.py:150,164 | `CellTag.IMPROVED = "improved"` | Display only | - | - | console grid tag | 3 |
| `_MEANINGS[ALARM]` "not gated: PASS cell always flagged" eval_display.py:158, `_MEANINGS[FIXED]` "miss or alarm cell correct in every run of this one" eval_display.py:164 | "false positive: PASS cell judged FAIL in every baseline run", "miss or false-positive cell correct in every run of this one" | - | - | - | console legend | 3 |
| `EvalMetrics` metrics.py:48 (baseline, gate, gate_verdict, recording, judging, fault_harness) | `HoneypotMetrics` | - | - | - | - | 3 |
| `GateRow.target` eval_display.py:76, `gate_table(rows, target_header)` eval_display.py:84 | `GateRow.subject`, `subject_header` | - | - | - | - | 3 |
| `RunDetail.missed_steps` metrics.py:38, used metrics.py:244, eval_display.py:255 | `missed_model_calls` | Yes: `runs[].missed_steps` in output/eval_report.json (not committed) | - | - | report key | 2 |
| `PhaseUsage` metrics.py:191 | `UsageBreakdown` | - | - | - | - | 3 |
| `declared_flips.Suite` declared_flips.py:16, values `honeypot`, `judge` | `Instrument` (the judge eval is an instrument, not a suite) | enum name: no | - | - | - | 3 |
| `DeclaredFlip.suite` declared_flips.py:25, `declarations_of_head(Suite.X, ...)` eval_session.py:101, run_judge_eval.py:111 | `instrument` | Yes: entry key `suite` in evals/declared_flips.json. Committed occurrences 0 (`{"entries": []}`), so the format changes with no data to migrate. CONTRIBUTING documents the entry format | - | - | file format the maintainer writes | 3 |
| `cve_export_path`, evals/export.py:41 | `detection_export_path` | - | - | - | - | 3 |
| `export_cve_judged_cases`, evals/export.py:45 | `export_detection_judged_cases` | - | - | - | - | 3 |
| Export line key `"cve_id"`, evals/export.py:55 | `"flaw_id"` | detection export JSONL, read by evals/draw_judge_cases.py which writes the judge fixture, the committed `draw.quotas.cve_target` key of evals/fixtures/judge_cases.json stays | - | - | export file | 3 |

### C.3 Honeypot suite

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `ReplayAudit` replay.py:10 | `RetestAudit` | - | - | - | - | 3 |
| `Replayer` replay.py:14 | `Retester` | - | - | - | - | 3 |
| `Replayer._replay_or_fail` replay.py:54, `_replay_server` replay.py:65, local `replays` replay.py:73 | `_retest_or_fail`, `_retest_server`, `retests` | - | - | - | - | 3 |
| "Warning: a replay of {name} failed:", "a replay of {name} failed" replay.py:61,63 | "a retest of ..." | the second ends up in `gate.reasons` (report, not committed) | - | - | console, report reason | 3 |
| `replay_audit` run_evals.py:228 (inner `replay` :229), `_announce_replay` :235, `_warn_replay` :239, local `replayer` :167 | `retest_audit`, `retest`, `_announce_retest`, `_warn_retest`, `retester` | - | - | - | - | 3 |
| `judge_runs(..., replayer: Replayer)` judging.py:66 (param) | `retester: Retester` | - | - | - | - | 3 |
| `--concurrency` help "runs and replays alike" run_evals.py:129, run_judge_eval.py:181, docstring run_evals.py:199 | "runs and retests alike" | - | - | - | CLI help | 3 |
| "(exploratory, then confirmed)": `--record-baseline` help run_evals.py:136, run_judge_eval.py:188, `_RESET_PROCEDURE` recording.py:29, judge_recording.py:16 | "(unconfirmed, then confirmed)" | - | - | - | CLI help, refusal text | 3 |
| `--ungated` run_evals.py:140, run_judge_eval.py:192 (dest `ungated`) | `--no-baseline` (dest `no_baseline`) | - | - | - | CLI flag, help | 3 |
| `EvalOptions.ungated` eval_session.py:56, `JudgeOptions.ungated` judge_session_model.py:25, `select_mode(..., ungated)` eval_session.py:189, uses eval_session.py:94,100,106, judge_session.py:69,75, run_evals.py:153, run_judge_eval.py:101 | `no_baseline` | - | - | - | - | 3 |
| `EXIT_CODES` keyed by GateVerdict run_evals.py:59, `_EXIT_CODES` judge_session.py:39 | keys `GateOutcome.*` | - | - | - | exit code | 3 |
| `judge_runs(session, outcome, retester)` judging.py:66 | `decide_runs` | - | - | - | method note | 3 |
| `BASELINE_PATH = .../baselines/honeypot_e2e.json` eval_session.py:35 | `.../baselines/honeypot.json` (`git mv`) | file name, the content does not cite it | - | - | file name, help text | 3 |
| `--record-baseline` help "record evals/baselines/honeypot_e2e.json" run_evals.py:135 | "evals/baselines/honeypot.json" | - | - | - | CLI help | 3 |
| module `run_evals.py` and `run_evals` run_evals.py:158 | `run_honeypot_suite` | - | - | - | command | 3 |
| `EvalRunResult` run_evals.py:67 | `HoneypotRunResult` | - | - | - | - | 3 |
| `EvalOptions` eval_session.py:51 | `HoneypotOptions` | - | - | - | - | 3 |
| `EvalSession` eval_session.py:67 (judging, fault_harness) | `HoneypotSession` | - | - | - | - | 3 |
| `EvalReport` eval_report.py:8 | `HoneypotReport` | - | - | - | - | 3 |
| `_run_one_eval` eval_runs.py:75 | `_run_one` | - | - | - | - | 3 |
| `DEFAULT_REPORT_PATH = "output/eval_report.json"` run_evals.py:55 | `output/honeypot_report.json` | the default report path, not committed. The committed judge_cases.json `draw.sources` hold export paths (`.../judged_cases.jsonl`), not the report name | - | - | default `--report` path, CLAUDE.md | 3 |
| `fault_harness`: `Replayer(audit.replay, ...)`, `FaultedAudit.replay`, evals/fault_harness.py:37,70,152 | `Retester`, `FaultedAudit.retest` | - | - | - | - | 3 |
| `fault_harness`: `judge_runs(...)`, evals/fault_harness.py:71-73 | `decide_runs` | - | - | - | - | 3 |

### C.4 Judge eval

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `JudgeBaseline.replay_rule` judge_baseline.py:28 | `retest_rule` | Yes: judge_isolation.json 1, same alias | - | - | baseline file | 3 |
| `JudgeRecording.replay_rule` judge_recording.py:31, `_baseline_from(..., rule: ReplayRule)` recording.py:228, judge_recording.py:174 | `retest_rule`, `RetestRule` | - | - | - | - | 3 |
| `ReplayContext` judge_replay.py:20, `_replay_context` judge_session.py:189 | `RetestContext`, `_retest_context` | - | - | - | - | 3 |
| `replay_flips` judge_replay.py:30, `replay` judge_replay.py:47, local `replayed` judge_replay.py:41 | `retest_flips`, `retest`, `retested` | - | - | - | - | 3 |
| `JudgeGateInput.replays` judge_gate.py:54 | `retests` | - | - | - | - | 3 |
| `JudgeSessionResult.replay_observations` judge_session_model.py:63, local judge_session.py:52,59 | `retest_observations` | Yes: report key `replay_observations` run_judge_eval.py:218 in output/judge_eval_report.json (not committed) -> `retest_observations` | - | - | report key | 3 |
| `JudgeHarness.on_replays` judge_session_model.py:36, `JudgeCallTracking.on_replays` run_judge_eval.py:146, run_judge_eval.py:113, judge_session.py:195 | `on_retests` | - | - | - | - | 3 |
| `judge_exploratory_commit_refusal` judge_recording.py:111 | `judge_unconfirmed_commit_refusal` | - | - | - | refusal text judge_recording.py:115 | 3 |
| `judge_case_gate` judge_gate.py:59 | `decide_judge_gate` | - | - | - | - | 3 |
| `JUDGE_BASELINE_PATH = .../baselines/judge_isolation.json` judge_baseline.py:14 | `.../baselines/judge.json` (git mv) | file name | - | - | file name | 3 |
| `--record-baseline` help "record evals/baselines/judge_isolation.json" run_judge_eval.py:187 | "evals/baselines/judge.json" | - | - | - | CLI help | 3 |
| `CVE_TARGET_QUOTA` draw_judge_cases.py:41 | `TARGET_QUOTA` | - | - | - | - | 3 |
| `Strata.cve_targets` draw_judge_cases.py:51, uses :112, :228 | `targets` | - | - | - | - | 3 |
| `candidates_from_cve` draw_judge_cases.py:77 | `candidates_from_detection` | - | - | - | - | 3 |
| `line["cve_id"]`, local `cve_id` draw_judge_cases.py:80-82 | `line["flaw_id"]`, `flaw_id` | Reads the key the detection export writes (export.py:55). Rename together | - | - | export key | 3 |
| `--cve-export` draw_judge_cases.py:173 (dest `cve_export`, used :184,:188) | `--detection-export` (dest `detection_export`) | - | - | - | CLI flag (CLAUDE.md command line) | 3 |
| param `cve_lines` draw_judge_cases.py:220 | `detection_lines` | - | - | - | - | 3 |
| `with_name("cve_report.json")` draw_judge_cases.py:184, docstring judge_draw_checks.py:30 | `with_name("detection_report.json")` | - | - | - | - | 4 |
| `JudgeOutcomeRow.target` judge_outcomes.py:18, judge_outcomes.py:78, judge_display.py:125, column "Target" judge_display.py:108 | `tool_category`, column "Tool/category" | - | - | - | console column | 3 |

### C.5 Model probe

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `RecordingLLM` probe_corpus.py:54 | `CapturingLLM` | - | - | - | - | 3 |
| local `recording = AuditModels(...)` capture_probe_corpus.py:125, :131 | `capturing` | - | - | - | - | 3 |
| `_replay(corpus, models, sink)` run_probe.py:125, uses run_probe.py:76,103 | `_send_corpus` | - | - | - | - | 3 |
| `_cve_image_problems` capture_probe_corpus.py:96, `_cve_tools` :135, `_cve_generation_calls` :162, local `cve_calls` :106 | `_target_image_problems`, `_target_tools`, `_target_generation_calls`, `target_calls` (they list the acceptance targets' vulnerable images) | - | - | - | - | 3 |

### C.6 Shared CVE benchmark code (grammar, planting, places, stand-ins, holdout-role modules, audit plumbing)

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `ConclusionVerdict` holdout_statistic.py:87 | `Conclusion` | - | - | - | - | 4 |
| `primary_number` holdout_statistic.py:94 | `holdout_detection_rate` | - | - | - | - | 4 |
| `primary_controls` holdout_statistic.py:126 | `detection_rate_controls` | - | - | - | - | 4 |
| `hierarchical_interval(detected_per_target, ...)` param holdout_hierarchical.py:36 | `successes_per_member` | - | - | - | - | 4 |
| `MechanismClass` evals/cve_grammar.py:61 | `FlawClass` | Values (`read_outside_scope`, `command_execution`, `internal_fetch`) unchanged everywhere, the class name is serialized only as a `$defs` key | agent: `$defs.MechanismClass` of FlawRecord and AdmittedServer `model_json_schema` (via `FlawRecord.effect_class: MechanismClass \| None`, evals/nuisance_admission.py:68) becomes `$defs.FlawClass`, title too. Not in CalibrationCard (its `effect_class` is `str`) nor Classification | in G (grammar fingerprint moves), values hashed by the detection fixture fingerprint (`_class_part`, unchanged) | - | 4 |
| `GradedTarget.mechanisms` cve_grammar.py:101, `PlantedTarget.mechanisms` :112, arg `mechanisms` of `_category_counts` :281, `target.mechanisms` :224 (and `CVETarget.mechanisms` evals/cve_targets.py:83, `mechanisms=` in 37 holdout fixture modules and the acceptance targets, `_class_part(mechanisms)` evals/cve_baseline.py:177) | `classes` | - | - | in G (and ref from E? no: cve_targets is not hashed) | - | 4 |
| `CVEStatus` cve_grammar.py:71 | `TargetStatus` | Values `detected`, `reached_but_judged_pass`, `missed` unchanged (report JSON, holdout result files, golden master) | - | in G | - | 4 |
| `MissClass` cve_grammar.py:79, fields `RunGrade.miss_class` :129, `Resolution.miss_class` :150, `_miss_class` :245 | `MissKind`, `miss_kind`, `_miss_kind` | `miss_class` key: detection report JSON, holdout `.result.json`, detection baselines (none committed: `evals/baselines/cve/` absent), grammar golden master 173 keys (tests/unit/support/cve_grammar_golden.json). Values unchanged | - | in G | report key | 4 |
| `cve_report_units` references `EvalResult` (:9), `case.eval_result`, `chain.eval_result` (:28, :39), `_judgment(result: EvalResult)` (:47) | `JudgeResult`, `judge_result` | - | - | ref from G: the grammar fingerprint moves with the core rename alone | - | 4 |
| `proofs_in` docstring "keyed by its location id" cve_proofs.py:39 | "keyed by its place id" | - | - | in G (function docstring) | - | 4 |
| `HOLDOUT_PLACES` evals/cve_places.py:27 and its literal `"holdout_places.json"` | `DETECTION_PLACES`, `"detection_places.json"` | file rename only (git mv, content and pinned SHA-256 unchanged) | agent: the calibration kit copies it as `evals/holdout_places.json` (calibration_dossier.py:136) and dossier text names it (:119, :190, :253, :283): kit path changes | in E | file name | 4 |
| `REACHABLE_BY` cve_places.py:29 | `REACHES` | - | - | in E | - | 4 |
| `Place.reachable_by` cve_places.py:92, `_reachable_by` :172 | `Place.reaches`, `_reaches` (still reading the JSON key `"reachable_by"`, the error literals :174,:178,:181 name the JSON key and stay) | - | - | in E, `cve_baseline._record_parts` refs it (not hashed itself) | - | 4 |
| `PlantKind` cve_places.py:49 | `PlaceKind` | values unchanged (`kind` in holdout_places.json 36, fingerprint hashes `.value`) | - | in E | - | 4 |
| `entry_id` (place id) cve_places.py (71 occurrences), cve_planting_spec.py (8), cve_endpoint_address.py:39,51,78 (7) | `place_id` | - | - | in E, P | error messages read `<place id>: ...` unchanged | 4 |
| `PlantingDocker.probe_endpoint(target_args)` / `probe_listener(target_args)` cve_planting_base.py:191,195, `DockerPlanting` cve_planting_docker.py:120,128, `_probe_read`, `_probe_connect` :209,:221 | `server_args` | - | - | in E, P | - | 4 |
| `StandInRoute.target` evals/public_stand_ins.py:68 | `request_target` | key `target` of every route in evals/stand_ins/*.json: 68 occurrences in 24 files , changes, also read by `Dockerfile.stand-in` ENTRYPOINT (`r['target']`) | agent: the calibration and admission kits ship `evals/stand_ins/` and the capture tool (dossier files, not the four schemas) | in E, P, the capture files are hashed as raw text | capture file format, CLAUDE.md `capture_stand_in` line | 4 |
| `StandInDefault.probed_target` public_stand_ins.py:93 | `probed_request_target` | key `probed_target` of every default: 48 occurrences in 24 files, read by `Dockerfile.stand-in` (`default['probed_target']`) | agent: kits as above | in E, P | capture file format | 4 |
| validators `_quotes_its_target_only_where_the_stand_in_substitutes_it` :100, `_path_form_says_how_a_known_body_escaping_quotes_its_target` :121 | `..._its_request_target_...` | - | - | in E, P | - | 4 |
| literal "two routes answer one (scheme, method, target, action, form_field), so the stand-in could replay only one of them" :173 | "(scheme, method, request_target, action, form_field), so the stand-in could serve only one of them" | - | - | in E, P | load error | 4 |
| `CapturedResponse.target` evals/capture_stand_in.py:71, its writes `"target": response.target` :105, `"probed_target": plain.target` :119, `path_form` uses :131-138 | `request_target`, written keys `"request_target"`, `"probed_request_target"` | writes the capture files (above) | agent: the nuisance dossier ships the capture tool | - | capture output | 4 |
| `default_requests(host, probed_target)` :186, local `targets` :187, `probed_target` :230 | `probed_request_target`, `request_targets` | - | agent: shipped tool | - | - | 4 |
| literal "the form probe quotes its target ..." :144 | "... its request target ..." | - | - | - | error text | 4 |
| `unreplayed_captures(stand_in, replayer, root)` evals/fixture_sources.py:105, its docstring "replayed ... `replayer`" | `unserved_captures(stand_in, stand_in_dockerfile, root)` | - | - | - | - | 4 |
| `Dockerfile.stand-in` ENTRYPOINT: `r['target']`, `default['probed_target']`, handler class `Replay`, method `replay` | `r['request_target']`, `default['probed_request_target']`, `Serve`/`serve` (comments "replays one capture" -> "serves") | - | - | the ENTRYPOINT is an instruction: hashed by `dockerfile_instructions` for the stand-in image fingerprint (`cve_images.dockerfile_fingerprint`, image rebuilt) and by the nuisance fingerprint of a backend-less public-name server (`_SHARED_SERVICES`) | - | 4 |
| `AuditProgress._replaying`, progress task label `"Replaying"`, evals/audit_progress.py:14,37-39 | `_retesting`, `"Retesting"` | - | - | - | yes: live progress bar of the detection and nuisance modes | 3 |
| `run_images.target_services(targets: Sequence[CVETarget])`, evals/run_images.py:31 | type `Sequence[Target]`, name stays (detection targets) | - | - | - | - | 4 |

### C.7 Census

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `HoldoutCensus` evals/holdout_census.py:72 | `Census` | - | - | - | - | 4 |
| literal "invalid holdout census {path}" holdout_census.py:158 | "invalid census {path}" | - | - | - | error text | 4 |
| `census_identifier` evals/census_identity.py:20 | `flaw_id_of` | - | - | - | - | 4 |
| `BENCHMARK_FLAWS` evals/holdout_exclusions.py:18 (comment "a target of the CVE benchmark") | `ACCEPTANCE_TARGET_FLAWS` | - | - | - | - | 4 |
| `CENSUS_PATH` literal `"holdout_census.json"` run_census.py:49 | `"census.json"` | file rename (git mv) | - | - | file name, `assemble` help | 4 |
| `SOURCES`, `WORK` run_census.py:47-48 `output/holdout_census/{sources,work}` | `output/census/{sources,work}` | - | - | - | path in CLAUDE.md and `evals/holdout_census_method.md` | 4 |
| `DrawWalkStep` evals/census_draw.py:126 (and `DrawRecord.walk`) | `DetectionWalkStep` | - | - | - | - | 4 |
| `Settlement.verdict` census_draw.py:122 | `ruling`, with `Field(validation_alias="verdict", serialization_alias="verdict")` and `ConfigDict(validate_by_name=True, serialize_by_alias=True)` (body, Identifiers) | `verdict` key: evals/holdout_census.json 14, evals/nuisance_walk_record.json 31, kept | - | - | - | 4 |

### C.8 Detection suite (acceptance and holdout layers, kit)

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `CVETarget` cve_targets.py:80 | `Target` | - | agent: dossier text `calibration_dossier.py:215` ("wraps into a `CVETarget`") | - | - | 4 |
| `CVETarget.cve_id` cve_targets.py:81 (`cve_id` 601 refs / 120 files repo-wide, all areas) | `flaw_id` | - | agent: KitTarget mirror field (kit_target.py:57) and dossier text `calibration_dossier.py:219` ("`cve_id`: the drawn identifier") | - | indirectly (every console line prints it) | 4 |
| `CVETarget.mechanisms` cve_targets.py:83 (+ `mechanisms=` 52 refs / 45 files, `.mechanisms` 17 refs / 13 files) | `classes` | - | - | ref: must rename with `GradedTarget.mechanisms` cve_grammar.py:101 and `PlantedTarget.mechanisms` cve_grammar.py:112 (GRAMMAR_PATHS): grammar fingerprint moves, fixture fingerprint does not (values only, `_class_part`) | - | 4 |
| `CVE_TARGETS` cve_targets.py:202 | `ACCEPTANCE_TARGETS` | - | - | - | - | 4 |
| `OutOfScopeCVE` cve_targets.py:148 (+ `.cve_id` :149) | `OutOfScopeFlaw` (`.flaw_id`) | - | - | - | - | 4 |
| `OUT_OF_SCOPE_CVES` cve_targets.py:354 | `OUT_OF_SCOPE_FLAWS` | - | - | - | - | 4 |
| `CVEStatus` uses in cve_gate, cve_markdown, cve_baseline, cve_recording (defined at cve_grammar.py:71, C.6) | `TargetStatus` | values `detected`, `reached_but_judged_pass`, `missed` unchanged | - | defined in GRAMMAR_PATHS | values in report | 4 |
| `TargetStatus` type alias cve_oracle.py:22 (`CVEStatus \| UngradedStatus`, 2 refs) | `ResultStatus` (frees the name for `CVEStatus`) | - | - | - | - | 4 |
| `TargetInfo.cve_id`, `OutOfScopeInfo.cve_id` cve_oracle.py:30,45 | `flaw_id` | - | - | - | - | 4 |
| `TargetInfo.mechanisms` cve_oracle.py:34 | `classes` | - | - | - | - | 4 |
| `OutOfScopeInfo` docstring cve_oracle.py:42 "A CVE tracked" | "A flaw tracked" | - | - | - | - | 4 |
| `CVEResult` cve_oracle.py:52 | `TargetResult` | Report JSON `results[]` | - | - | - | 4 |
| `CVEResult.cve_id` :53 | `flaw_id` | Report JSON key `results[].cve_id` -> `flaw_id` (0 committed) | - | - | yes (report key) | 4 |
| `CVEResult.mechanisms` :56 | `classes` | Report JSON key -> `classes` (0 committed) | - | - | yes | 4 |
| `CVEResult.miss_class` :58 (type `MissClass`, cve_grammar.py:79) | `miss_kind` (type `MissKind`) | Report JSON key | - | `MissClass` in GRAMMAR_PATHS | yes ("Miss class" column) | 4 |
| `CVEResult.not_run_conditions` :68 (comment "the pre-run check's dead conditions") | `not_run_reasons` | Report JSON key -> `not_run_reasons` (0 committed) | - | - | yes | 4 |
| `CVEBenchmarkReport` cve_oracle.py:74 | `DetectionReport` | Report JSON root | - | - | - | 4 |
| `CVEBenchmarkReport.conditions: CVERunConditions` :75, `.costs` comment "ungated runs" :85, `.provider_usage` comment "replays included" :78 | type rename only, comments "no-baseline runs", "retests and replays included" | Report JSON keys unchanged | - | - | - | 4 |
| `CVEBenchmarkReport.gate: CVEGateResult` :82 | type rename only (`DetectionGateResult`) | Report JSON `gate` | - | - | - | 4 |
| `not_run(target, conditions)` cve_oracle.py:113 | param `reasons` | - | - | - | - | 4 |
| `out_of_scope_results(cves)` cve_oracle.py:125, loop var `cve` | param `flaws` | - | - | - | - | 4 |
| `TargetCost.cve_id` cve_costs.py:26 | `flaw_id` | Report JSON `costs[].cve_id` -> `flaw_id` (0 committed) | - | - | yes | 4 |
| `TargetCost.usage: PhaseUsage` cve_costs.py:27 (`PhaseUsage` metrics.py:191) | type `UsageBreakdown` | Report JSON | - | - | - | 3 |
| `_replay_credits_line` cve_markdown.py:89-93 local `refused`, label `refused (...)` | local `struck`, label `struck (...)` | Report .md / console | - | - | yes | 4 |
| `_render_gate` cve_markdown.py:126 `gate.verdict.value` | `gate.outcome.value` | Report .md "Gate: ..." | - | - | yes | 4 |
| `GATE_LEGEND` cve_markdown.py:136-140 "Replays: the miss reproduced in k of n replays." | "Retests: the miss reproduced in k of n retests." | Report .md / console | - | - | yes | 4 |
| `_render_gate_row` cve_markdown.py:149 `replay_fraction(comparison.replays)` (`replay_fraction` cell_grid.py:200) | `retest_fraction(comparison.retests)` | - | - | - | - | 4 |
| `_STATUS_LETTERS` cve_markdown.py:159 keyed by `CVEStatus` | key type rename | - | - | - | letters D/J/M unchanged | 4 |
| `print_cve_summary` cve_console.py:33 | `print_detection_summary` | - | - | - | - | 4 |
| `_print_verdict` cve_console.py:56, uses `GateVerdict(gate.verdict.value)` | `_print_outcome`, `GateOutcome(gate.outcome.value)` | - | - | - | - | 4 |
| `_gate_rows` cve_console.py:114 `GateRow(replays=replay_fraction(...))` (`GateRow` eval_display.py:75) | `retests=retest_fraction(comparison.retests)` | - | - | - | console column, header "Retests" (C.2) | 4 |
| `print_report_paths(report_path, cve_export_path(report_path))` cve_console.py:52 (`cve_export_path` export.py:41) and `DEFAULT_REPORT_PATH = "output/cve_report.json"` run_cve_benchmark.py:61 | `DEFAULT_REPORT_PATH = "output/detection_report.json"`, the call follows `detection_export_path` (C.2) | output file names | - | - | yes | 4 |
| `_BASELINE_DIRECTORY = "evals/baselines/cve"` cve_gate.py:19 (in `WHOLE_RESET` text) | `"evals/baselines/detection"` | - | - | - | yes (gate reason text) | 4 |
| `TargetOutcome.PENDING_REPLAY = "pending_replay"` cve_gate.py:30 (`PENDING_REPLAY` 23 refs / 8 files, incl. honeypot/judge/nuisance enums) | `PENDING_RETEST = "pending_retest"` | Report JSON `gate.targets[].outcome` value (0 committed) | - | - | yes (gate table Outcome cell, reasons) | 4 |
| `CVEGateVerdict` cve_gate.py:39 | dropped for the shared `GateOutcome` (same values) | values `green`/`red`/`not_comparable` unchanged | - | - | - | 4 |
| `TargetCandidate.cve_id` cve_gate.py:46 | `flaw_id` | - | - | - | - | 4 |
| `TargetComparison.cve_id` cve_gate.py:63 | `flaw_id` | Report JSON `gate.targets[].cve_id` -> `flaw_id` (0 committed) | - | - | yes | 4 |
| `TargetComparison.replays` cve_gate.py:67 | `retests` | Report JSON `gate.targets[].replays` -> `retests` (0 committed) | - | - | yes | 4 |
| `CVEGateResult` cve_gate.py:71 | `DetectionGateResult` | Report JSON `gate` | - | - | - | 4 |
| `CVEGateResult.verdict` cve_gate.py:72 | `outcome` | Report JSON `gate.verdict` -> `gate.outcome` (0 committed) | - | - | yes | 4 |
| `_file_name(cve_id)`, `target_reset(cve_id)` cve_gate.py:121,125 | param `flaw_id` | baseline file name `<flaw ID>.json` unchanged | - | - | reset text | 4 |
| `_why_not_gated` cve_gate.py:134-137 `BaselineStatus.EXPLORATORY`, text "exploratory baseline recorded at ..." | `BaselineStatus.UNCONFIRMED`, "unconfirmed baseline recorded at ..." | - | - | - | yes (gate detail) | 4 |
| `settle(comparison, replays, rule: ReplayRule)` cve_gate.py:142 (same name in gate.py:203) | `apply_retests(comparison, retests, rule: RetestRule)` ("settle" collides with settlement, the maintainer's ruling) | - | - | - | - | 4 |
| `rule.decide_replays(completed)` cve_gate.py:154 (gate.py:71) | `rule.decide_retests(completed)` | - | - | - | - | 4 |
| `judge(comparisons, mismatches)` cve_gate.py:161 | `decide(comparisons, mismatches)` | - | - | - | - | 4 |
| `_describe` cve_gate.py:187-194, local `replays`, text ", the miss reproduced in {k} of {n} replays" | `retests`, "... of {n} retests" | Report JSON `gate.reasons` | - | - | yes | 4 |
| `_result(verdict, ...)`, `exit_code(verdict)` cve_gate.py:208,214 | param `outcome` | - | - | - | - | 4 |
| `CVE_BASELINE_DIRECTORY` cve_baseline.py:40 (`baselines/"cve"`) | `DETECTION_BASELINE_DIRECTORY` (`baselines/"detection"`) | directory name (0 committed files) | - | - | yes (path) | 4 |
| `CVERunConditions` cve_baseline.py:66 | `DetectionRunConditions` | Baseline JSON / Report JSON `conditions` (keys unchanged) | - | - | - | 4 |
| `CVETargetBaseline` cve_baseline.py:93 | `DetectionBaseline` | Baseline JSON root | - | - | - | 4 |
| `CVETargetBaseline.cve_id` :94 | `flaw_id` | Baseline JSON key -> `flaw_id` (0 committed, no alias needed) | - | - | - | 4 |
| `CVETargetBaseline.status` :95 value `exploratory` | value `unconfirmed` (through `BaselineStatus`) | Baseline JSON value (0 committed) | - | - | yes ("Baseline recorded (unconfirmed)") | 4 |
| `CVETargetBaseline.replay_rule: ReplayRule` :98 | `retest_rule: RetestRule` (and its `replays` -> `retests`) | Baseline JSON keys (0 committed detection files, alias only needed for the shared class's honeypot/judge use) | - | - | - | 4 |
| `CVETargetBaseline.runs: list[CVEStatus]` :102 | type rename | values unchanged | - | - | - | 4 |
| `_class_part(mechanisms)` cve_baseline.py:177 | param `classes`, type `FlawClass` | hashed value unchanged | - | - | - | 4 |
| `fixture_fingerprint` docstring :121-142 ("patched twin", "holdout-rule.md", "admission reference arm", "sentinel") | text only: "patched image", "detection-suite-rule.md", "layout check's reference arm", sentinel stays (sidecar) | - | - | - | - | 4 |
| `_baseline_from(..., BaselineStatus.EXPLORATORY, ReplayRule)` cve_recording.py:43-44, `existing.replay_rule` :83,95, param `rule: ReplayRule` :133, `replay_rule=rule` :140 | `UNCONFIRMED`, `RetestRule`, `retest_rule` | Baseline JSON | - | - | - | 4 |
| `_BASELINES = "evals/baselines/cve/"`, `_RECORD_COMMAND = "uv run python -m evals.run_cve_benchmark --record-baseline"` cve_recording_console.py:12-13 | `"evals/baselines/detection/"`, `"... -m evals.run_detection --record-baseline"` | - | - | - | yes (next-step lines) | 4 |
| `WrittenBaseline.cve_id` cve_session_recording.py:31 | `flaw_id` | - | - | - | - | 4 |
| `session.options.ungated` cve_session_recording.py:49 | `no_baseline` | - | - | - | - | 4 |
| `CVESessionResult` cve_session.py:41 | `DetectionSessionResult` | - | - | - | - | 4 |
| `CVESessionResult.not_run` comment :45 "dead conditions", `.gate` comment :44 "None under --ungated" | comments "out-of-calibration reasons", "--no-baseline" | - | - | - | - | 4 |
| `_checked` cve_session.py:74 locals `conditions`, `target_conditions` | `reasons`, `target_reasons` | - | - | - | - | 4 |
| `_refuse_recording_of_not_run` :89 locals `conditions`/`condition` | `reasons`/`reason` | - | - | - | recording refusal lines | 4 |
| `_gate(...)` :134 calls `judge(...)` :156 | `decide(...)` | - | - | - | - | 4 |
| `_not_run_comparison(cve_id, conditions, baseline)` :159 | `(flaw_id, reasons, baseline)` | Report JSON `gate.targets[].detail` text unchanged | - | - | - | 4 |
| `_settled` cve_session.py:171 | `_with_retests` | - | - | - | - | 4 |
| `_replayed` cve_session.py:190, local `replays` :199, `settled` | `_retested`, `retests`, `retested` | - | - | - | - | 4 |
| `TargetOutcome.PENDING_REPLAY` :201, `baseline.replay_rule` :211 | `PENDING_RETEST`, `retest_rule` | - | - | - | - | 4 |
| `CVEOptions` cve_session_model.py:41 | `DetectionOptions` | - | - | - | - | 4 |
| `CVEOptions.ungated` :44 (`ungated` 75 refs / 20 files repo-wide) | `no_baseline` | - | - | - | - | 4 |
| `CVEOptions.targets` comment :42 "already filtered by --cve" | "--flaw" | - | - | - | - | 4 |
| `CVEHarness` cve_session_model.py:49 | `DetectionHarness` | - | - | - | - | 4 |
| `CheckTarget` docstring :32-35 "its dead conditions ... not a dead condition" | "its out-of-calibration reasons ... not an out-of-calibration reason" | - | - | - | - | 4 |
| `CVEAudit` cve_session_model.py:61 + `.cve_id` :62 | `DetectionAudit` (`.flaw_id`) | export rows (export.py) may carry the id: check key | - | - | - | 4 |
| `calibrate_all(targets, calibrate, ci)` cve_calibration.py:38, local `calibrated`, `verdicts`, `all_live` | `check_calibrations(targets, check, ci)`, locals `checked`, `passed`, `all_pass` | - | - | - | - | 4 |
| `dead_conditions(target, exploits, benign)` cve_calibration.py:62 | `not_live_reasons` (with `not_fixed_reasons`, the out-of-calibration reasons) | golden master keys `dead_conditions/...` (18 in tests/unit/support/cve_grammar_golden.json) -> renamed, values byte-identical | agent: kit_driver mirror (kit, calibration agents) | - | the reason strings unchanged | 4 |
| `patched_dead_conditions` cve_calibration.py:81 | `not_fixed_reasons` | golden keys `patched_dead_conditions/...` (18) -> renamed, values identical | agent: kit_driver mirror | - | strings "patched: ..." unchanged | 4 |
| `calibrate_one` cve_calibration.py:122 | `passes_calibration_check` | - | - | - | - | 4 |
| `_patched_conditions` cve_calibration.py:152 | `_not_fixed_reasons` | - | - | - | - | 4 |
| `_report_error(cve_id, ...)`, `_report_dead(cve_id, conditions, ...)` cve_calibration.py:213,238 | `_report_error(flaw_id, ...)`, `_report_out_of_calibration(flaw_id, reasons, ...)` | - | - | - | console "{id} dead:" :242 -> "{id} out of calibration:" | 4 |
| `CalibrationDeps` admission_calibration.py:16 | `CalibrationCheckDeps` | - | - | - | - | 4 |
| `CalibrationDeps.confirm_admission` :17 / `.calibrate_all` :18 | `.check_layouts_and_routes` / `.check_exploits` | - | - | - | - | 4 |
| `calibrate_admitted` admission_calibration.py:21, local `admission_failures` | `run_calibration_check`, `layout_and_route_failures` | - | - | - | - | 4 |
| `default_calibration_deps` :31, inner `admission`/`calibration` :32,35 | `default_calibration_check_deps`, inner `layouts_and_routes`/`exploits` | - | - | - | - | 4 |
| `cve_benchmark_modes.calibrate` cve_benchmark_modes.py:12, comment :13 "ADR 031 admission" | `calibration_check`, comment "ADR 031 layout and route checks" | - | - | - | - | 4 |
| `confirm_admission` cve_layout_check.py:167 | `check_layouts_and_routes` | - | - | - | - | 4 |
| `admission_gave_up` cve_layout_check.py:107 | `layout_check_gave_up` | - | - | - | - | 4 |
| `LayoutCheck` docstring :74 "The verdict `confirm_admission` computes", `layout_check` docstring :146 "The admission verdict" | "The result `check_layouts_and_routes` computes", "The layout check's result" | - | - | - | - | 4 |
| `_report_give_up(cve_id,...)`, `_report_break`, `_report_leak`, `_report_route(cve_id, place, admits)`, `_report_unkept_routes`, `_report_launch_error` cve_layout_check.py:201-292 | params `flaw_id`, `admits` -> `routed` | - | - | - | - | 4 |
| `route_admits(place, observations)` cve_route.py:53 | `has_route` | golden tests/unit/support/cve_route_golden.json (keys are case names, unaffected) | - | - | - | 4 |
| `TargetSurvey.cve_id` cve_survey.py:78 | `flaw_id` | - | - | - | survey header line | 4 |
| cve_survey.py docstring :3 "no live or dead verdict", :11 "location ids" | "no live or fixed result", "place ids" | - | - | - | - | 4 |
| `MEASUREMENT_UNGATED` cve_measurement.py:18 = "a measurement run is ungated: its conditions match no baseline" | `MEASUREMENT_NEEDS_NO_BASELINE` = "a measurement run reads no baseline: ..., run it with --no-baseline" | - | - | - | yes (refusal) | 4 |
| `MEASUREMENT_WITHOUT_AUDIT` cve_measurement.py:19 "--calibrate and --survey run no audit" | "--calibration-check and --survey run no audit" | - | - | - | yes | 4 |
| argument group cve_measurement.py:35 "measurement run (with --ungated only)" | "measurement run (with --no-baseline only)" | - | - | - | yes (help) | 4 |
| `measurement_refusal` cve_measurement.py:62 `args.ungated`, `args.calibrate` | `args.no_baseline`, `args.calibration_check` | - | - | - | - | 4 |
| `cost_pricing(conditions: HoldoutConditions, ...)` cve_measurement.py:85 | type from holdout_conditions (shared holdout role, keep) | - | - | - | - | 4 |
| `cve_preflight` docstring :1-7 "CVE calibration job" | "the calibration check job" | - | - | - | `python -m evals.detection_preflight` | 4 |
| `RecordingClient` cve_recording_client.py:19 | `ExchangeLog` (module `evals/cve/exchange_log.py`), attribute `exchanges` kept, `launch_audit.py:12,58` and `server_health.py:9` follow | - | agent: kit_driver.py docstring :3-4, :44 names it (kit text) | - | - | 4 |
| cve_recording_client docstring :4 "a dead fixture can be post-mortemed" | "a target out of calibration can be ..." | - | - | - | - | 4 |
| `KIT_DIR = EVALS / "holdout_kit"` calibration_dossier.py:30, `"holdout_kit"` literals :121,126 | `evals/cve/kit` | exported tree path | agent: the kit's own paths and the import lines of `_FIXTURE_FORMAT` (:207-213 `evals.holdout_kit.kit_client` ...) | - | yes (kit tree) | 4 |
| `write_kit(census: HoldoutCensus, cve: str, out)` :69, `_member(census, cve)` :77 | `write_kit(census: Census, flaw_id: str, out)`, `_member(census, flaw_id)` | - | - | - | - | 4 |
| refusal text :82-83 "Refused: {cve} is not a census member." / "The --cve argument must be ..." | "{flaw_id} ..." / "The --flaw argument must be the flaw ID of a census flaw." | - | - | - | yes | 4 |
| `cve_places.HOLDOUT_PLACES` :136 and dest name `"holdout_places.json"` :136, text :190,253,282 (`holdout_places.json`) | `DETECTION_PLACES`, `detection_places.json` | exported file name | agent: dossier text (layout.md, fixture_format.md, README) | - | yes | 4 |
| `CLEAN_MODULES` :33, `KIT_MODULES` :48 (module names) | replaced by `dossier_closure.copy_closure` over the kit's modules (H.4) | exported tree | agent: kit layout | - | - | 4 |
| `_LAYOUT` text :182 "as a dead condition", :180,187 "the planting layer" | "as an out-of-calibration reason", "the planting code" | - | agent: `layout.md` of the kit | - | - | 4 |
| `_FIXTURE_FORMAT` text :215 "wraps into a `CVETarget`", :219 "`cve_id`: the drawn identifier" | "`Target`", "`flaw_id`: the drawn flaw ID" | - | agent: `fixture_format.md` | - | - | 4 |
| `_README` text :259 "A self-contained workshop for calibrating one holdout candidate", :268-269 "the planting layer's sidecar", "the replay of a public service's capture" | "A self-contained kit for calibrating ...", "the planting code's sidecar", "serves a public service's capture" | - | agent: kit README | - | - | 4 |
| `--concurrency` (dest `concurrency`, `CVE_CONCURRENCY`) :121-126, help "Audits (or calibrations) in flight at once" | constant `DETECTION_CONCURRENCY`, help "Audits (or calibration checks) in flight at once, runs and retests alike" | - | - | - | yes (help) | 4 |
| `--calibrate` (dest `calibrate`) :127-134 | `--calibration-check` (dest `calibration_check`), help "No-LLM calibration check per target: ..." | - | - | - | yes (flag) | 4 |
| `--cve` (dest `cve`, metavar `CVE-ID`, help "Run only these CVE ids") :140-145 | `--flaw` (dest `flaw`, metavar `FLAW-ID`, help "Run only these flaw IDs (a CVE ID, or the GHSA ID of a flaw without one), repeatable") | recorded flags in next-step text | - | - | yes (flag) | 4 |
| `--ungated` (dest `ungated`) :159-163, help "without comparing to evals/baselines/cve/" | `--no-baseline` (dest `no_baseline`), help "... evals/baselines/detection/ (exit 0)" | - | - | - | yes (flag) | 4 |
| `_flag_refusal` strings :169-174 "--calibrate runs no audit ...", "--record-baseline cannot run --ungated ..." | "--calibration-check runs no audit ...", "... cannot run --no-baseline ..." | - | - | - | yes | 4 |
| `_run` comment :100-101 "reads as a dead fixture" | "reads as a target out of calibration" | - | - | - | - | 4 |
| `_run` :109 `confirm_admission(graded, places, ci=args.ci)` | `check_layouts_and_routes(...)` | - | - | - | - | 4 |
| `_cost_pricing(ungated, ...)` :220 | `_cost_pricing(no_baseline, ...)` | - | - | - | - | 4 |
| `_recorded_flags` :261-271, local `cve_ids`, text `f"--cve {cve_id}"` | `flaw_ids`, `f"--flaw {flaw_id}"` | - | - | - | yes (next-step command) | 4 |
| `_filter_by_cve` :279 | `_filter_by_flaw` | - | - | - | - | 4 |
| `_reject_unknown_cves` :286, console :292 "Unknown CVE id(s):" | `_reject_unknown_flaws`, "Unknown flaw ID(s):" | - | - | - | yes | 4 |
| `print_cve_summary`, `export_cve_judged_cases` :245-246 | `print_detection_summary` (the export call follows C.2) | output file | - | - | - | 4 |
| subcommand `draw-order` run_holdout.py:81, `_draw_order` :119 | moves to `python -m evals.run_census draw-order` | - | - | - | command | 4 |
| subcommand `calibrate` run_holdout.py:102-103, `_add_calibrate` :101, `_calibrate` :202, `_calibrate_targets` :220 | `calibration-check`, `_add_calibration_check`, `_calibration_check`, `_check_calibrations` | - | - | - | subcommand name, help "replay each drawn target's exploits and benign call, no LLM" -> "run each holdout target's exploits and benign call, no LLM" (`replays its exploits` -> runs, glossary log) | 4 |
| `--cve` of `calibration-dossier` run_holdout.py:89 (dest `cve`, read :130-131) | `--flaw` (dest `flaw`) | - | agent: the kit is written for that flaw ID (no field name changes) | - | flag, print "Calibration kit for {args.cve} written" -> args.flaw | 4 |
| `--cve` of `calibrate` run_holdout.py:106 (dest `cve`, read :205) | `--flaw` (dest `flaw`), help "calibrate only this CVE id, default: every drawn target" -> "check only this flaw ID (a CVE ID, or the GHSA ID of a flaw without one), default: every holdout target" | - | - | - | flag, help | 4 |
| parser description "Holdout draw commands." run_holdout.py:79 | "Detection holdout layer commands." | - | - | - | --help | 4 |
| `CENSUS_PATH = ... "holdout_census.json"` run_holdout.py:55 | `... "census.json"` | path | - | - | default of `--census` | 4 |
| `calibrate_admitted`, `default_calibration_deps` imported run_holdout.py:18 | `run_calibration_check`, `default_calibration_check_deps` | - | - | - | - | 4 |
| `DEFAULT_REPORT_PATH = "output/holdout_report.json"` run_holdout.py:56 | `output/detection_holdout_report.json` | - | - | - | default `--report` | 4 |
| `vet_all` holdout_vetting.py:27 | `check_before_run` (returns `PreRunCheck`, so not `pre_run_check`, which would read as the class) | - | - | - | - | 4 |
| `_vet` holdout_vetting.py:51 | `_check_one` | - | - | - | - | 4 |
| `vet_reason` holdout_vetting.py:61 | `not_run_reason` | - | - | - | - | 4 |
| `vet_reason` param/local `conditions` holdout_vetting.py:56,61,65 | `reasons` | - | - | - | - | 4 |
| reason text "dead on a version: " holdout_vetting.py:66 | "out of calibration: " | written in `not_run[].reason` of `<report>.result.json` and holdout_report.json (output/, none committed) | - | - | report line under "## Not run" | 4 |
| `HoldoutDeps.check` comment "the dead conditions on both versions" holdout_run.py:68 | comment -> "the out-of-calibration reasons on both versions" (field name `check` kept) | - | - | - | - | 4 |
| `HoldoutTargetResult.cve_id` holdout_results.py:35 | `flaw_id` | key `targets[].cve_id` of `<report>.result.json` (output/, 0 committed) changes | - | - | result file key | 4 |
| `NotRunTarget.cve_id` holdout_results.py:126 | `flaw_id` | key `not_run[].cve_id` of `<report>.result.json` (0 committed) changes | - | - | result file key | 4 |
| `HoldoutTargetResult.mechanism_labels` holdout_results.py:37 | `class_labels` | key `targets[].mechanism_labels` of `<report>.result.json` (0 committed) changes | - | - | result file key | 4 |
| `HoldoutRunStatus.miss_causes` holdout_results.py:30, `HoldoutTargetResult.incomplete_runs_by_cause` docstring :105 | `missed_call_causes` | key `targets[].statuses[].miss_causes` (0 committed) changes | - | - | result file key | 4 |
| `HoldoutReport.primary_number` holdout_report.py:120 (+ :163) | `holdout_detection_rate` | key `primary_number` of holdout_report.json (output/, 0 committed) changes | - | - | report key | 4 |
| `TargetLine.cve_id` holdout_report.py:79 (+ :261) | `flaw_id` | key `targets[].cve_id` (0 committed) | - | - | report key | 4 |
| `TargetLine.mechanism_labels` holdout_report.py:81 (+ :263) | `class_labels` | key (0 committed) | - | - | report key | 4 |
| `TargetRunLine.miss_causes` holdout_report.py:75 (+ :294) | `missed_call_causes` | key `targets[].per_run[].miss_causes` (0 committed) | - | - | report key | 4 |
| local `verdict` in `_conclusion_line` holdout_report.py:239-246 | `conclusion` | - | - | - | - | 4 |
| `line.cve_id`, `target.cve_id` holdout_markdown.py:78,106 | `flaw_id` | - | - | - | - | 4 |
| `NotRunLine.cve_id` holdout_not_run.py:15 (+ :21, :27) | `flaw_id` | key `not_run[].cve_id` of holdout_report.json (0 committed) | - | - | report key | 4 |
| `mechanism_labels=tuple(sorted(m.value for m in target.mechanisms))` holdout_assembly.py:34 | `class_labels=... target.classes` | via result | - | - | - | 4 |
| keyword `cve_id="CVE-..."` / `"GHSA-..."` in `TARGET = CVETarget(...)` of all 37 modules | `flaw_id=` | - | - | - | - | 4 |
| keyword `mechanisms=frozenset({MechanismClass.X})` in all 37 modules, import `from evals.cve_grammar import MechanismClass` | `classes=frozenset({FlawClass.X})`, import `from evals.cve.grammar import FlawClass` | - | - | values hashed (`_class_part` hashes `.value`, unchanged): fingerprint does not move | - | 4 |
| `CVETarget(` in all 37 modules | `Target(` | - | - | - | - | 4 |
| package `evals/holdout_kit/` | `evals/cve/kit/`, the dossier texts and import lines follow (H.4) | - | agent: every dossier (import paths in copied sources and in fixture_format.md) | - | dossier text | 4 |
| `KitTarget.cve_id` holdout_kit/kit_target.py:57 (documented at calibration_dossier.py:219 "`cve_id`: the drawn identifier") | `flaw_id` (field parity with CVETarget pinned by tests/unit/test_holdout_kit_isolation.py) | - | agent: calibration kit source and fixture_format.md (not the CalibrationCard schema) | - | - | 4 |
| `KitTarget.mechanisms: frozenset[MechanismClass]` holdout_kit/kit_target.py:58 | `classes: frozenset[FlawClass]` | - | agent: calibration kit source and fixture_format.md | - | - | 4 |
| `KitRecorder` holdout_kit/kit_driver.py:43, docstring "The role RecordingClient plays" | `KitExchangeLog` | - | agent: calibration kit source | - | - | 4 |
| `dead_conditions` holdout_kit/kit_driver.py:85 | `not_live_reasons` | - | agent: calibration kit source | - | - | 4 |
| `patched_dead_conditions` holdout_kit/kit_driver.py:104 | `not_fixed_reasons` | - | agent: calibration kit source | - | - | 4 |
| `check_target` docstring "The dead conditions of a target on both versions, empty when it is live" holdout_kit/kit_driver.py:61, local `conditions` :69-82 | "The out-of-calibration reasons ...", local `reasons` | - | agent: kit source | - | - | 4 |

### C.9 Nuisance suite (fix checks, re-admission, backends, counter)

| current (file:line) | new | serialized | model or agent | hashed | visible | step |
|---|---|---|---|---|---|---|
| `FixCheckTarget.mechanism: MechanismClass \| None` holdout_kit/fix_check.py:42 | `effect_class: FlawClass \| None` | - | agent: nuisance dossier source | - | - | 4 |
| local `target` throughout fix_check.py (:80-168) | `fixture` | - | agent: kit source | - | - | 4 |
| subcommand `calibrate` run_nuisance.py:131-135 (`commands.add_parser("calibrate", ...)`) | `fix-check` | - | - | - | CLI subcommand, CLAUDE.md Commands | 4 |
| `add_calibrate_arguments` nuisance_calibrate_command.py:39, run_nuisance.py:43,131 | `add_fix_check_arguments` | - | - | - | - | 4 |
| `calibrate(args)` nuisance_calibrate_command.py:48 (set as `command=`) | `fix_check(args)` | - | - | - | - | 4 |
| `--cve` flag, dest `cve`, help "calibrate only this flaw, default: every drawn fixture" nuisance_calibrate_command.py:41, uses :56-60 (`args.cve`) | `--flaw`, dest `flaw`, help "fix-check only this flaw, default: every admitted flaw" | - | - | - | CLI flag + help | 4 |
| `FixCheckCalibrationDeps` nuisance_calibrate_command.py:34 | `FixCheckDeps` | - | - | - | - | 4 |
| `default_fix_check_calibration_deps` nuisance_calibrate_command.py:72 | `default_fix_check_deps` | - | - | - | - | 4 |
| `calibrate_fixtures` nuisance_calibrate_command.py:79 | `check_fixes` | - | - | - | - | 4 |
| `_calibration_problems` nuisance_calibrate_command.py:107 | `_fix_check_problems` | - | - | - | - | 4 |
| `FixCheckTarget` holdout_kit/fix_check.py:40 (kit, , 66 files, 168 refs: every fix-check module, nuisance_fixtures, nuisance_readmission_dossier, dossier README) | `FixCheckFixture` | - | agent: admission dossier text | - | dossier text | 4 |
| `FixCheckTarget.mechanism` holdout_kit/fix_check.py:42 (set as `mechanism=MechanismClass.X` in 53 fix-check modules) | `effect_class` (as `FlawRecord.effect_class`, `mechanism` collides with the card's published-mechanism text) | - | agent: dossier README line "`mechanism`: the grammar `MechanismClass`" nuisance_dossier.py:121 | - | dossier text | 4 |
| `FIX_CHECK_TARGETS` nuisance_fixtures.py | `FIX_CHECK_FIXTURES` | - | - | - | - | 4 |
| per-module `TARGET` (44 modules) and `TARGETS` (54 modules), `ADD_COMMENT_TARGET`, `CREATE_ISSUE_TARGET` nuisance_fix_checks/cve_2025_53818_github_kanban.py:88,102 | `FIXTURE`, `FIXTURES`, `ADD_COMMENT_FIXTURE`, `CREATE_ISSUE_FIXTURE` | - | agent: re-admission README snippet `from evals.nuisance_fix_checks.<module> import TARGETS` / `TARGETS[0]` nuisance_readmission_docs.py:~190-200 | - | dossier text | 4 |
| `FixCheckRecord.source` Literal value `"holdout_calibration"` nuisance_admission.py:53, also `FixCheckResult.source` holdout_kit/fix_check.py:68, compared at nuisance_calibrate_command.py:136, nuisance_unrecorded.py:71, nuisance_readmission_dossier.py:125, nuisance_holdout_copies.py:36 | `"detection_holdout_calibration"` | yes: evals/nuisance_admission.json 17 values (verified with Python: 116 `fix_check`, 17 `holdout_calibration`), serialized form changes, no alias planned | agent: FlawRecord and AdmittedServer `$defs.FixCheckRecord.properties.source.enum` change, dossier README text nuisance_dossier.py:~217 | - | committed data, admission README | 4 |
| `--readmission` flag, dest `readmission` run_nuisance.py:119-121, `args.readmission` :179 | `--re-admission`, dest `re_admission` | - | - | - | CLI flag, CLAUDE.md | 4 |
| `_readmission_dossier` run_nuisance.py:188 | `_re_admission_dossier` | - | - | - | - | 4 |
| `write_readmission_dossier` nuisance_readmission_dossier.py:36 | `write_re_admission_dossier` | - | - | - | - | 4 |
| `readmission_dockerfiles` nuisance_readmission_dossier.py:66 | `re_admission_dockerfiles` | - | - | - | - | 4 |
| `readmission_readme` nuisance_readmission_docs.py:71 | `re_admission_readme` | - | - | - | - | 4 |
| `_holdout_twins` nuisance_readmission_dossier.py:87 | `_detection_holdout_targets` | - | - | - | - | 4 |
| local `calibrated` nuisance_readmission_dossier.py:124-133 (flaws whose fix check is a copy) | `copied` | - | - | - | - | 4 |
| `figure` nuisance_statistic.py:56, import nuisance_report.py:31 | `holdout_nuisance_rate` | - | - | - | - | 4 |
| `NuisanceReport.figure` nuisance_report.py:92, :135 | `holdout_nuisance_rate` | JSON key of `output/nuisance_report.json` (not committed) | - | - | report key | 4 |
| `FigureExit` nuisance_results.py:110 | `ServerExit` | via `outside_figure` below | - | - | - | 4 |
| `FigureExitLine` nuisance_report.py:82 | `ExitLine` | JSON model of the report | - | - | - | 4 |
| `outside_figure` field: NuisanceRunResult nuisance_results.py:138, RunPopulation nuisance_population.py:22, NuisanceReport nuisance_report.py:101, nuisance_run.py:293 | `exits` | JSON key in `<report>.result.json` and `nuisance_report.json` (not committed) | - | - | report key | 4 |
| `_outside_figure_section` nuisance_markdown.py:92, heading `"## Outside the figure"` :103, docstring of `_not_run_section` :110 ("Outside the figure") | `_exits_section`, `"## Exits"` | report .md | - | - | report heading | 4 |
| local `verdict = check_conclusion(...)` nuisance_report.py:207-214 | `conclusion` | - | - | - | - | 4 |
| `judge(comparisons, mismatches)` nuisance_gate.py:113, called nuisance_gate_session.py:~229 | `decide(...)` | - | - | - | - | 4 |
| `NuisanceGateResult.verdict: GateVerdict` nuisance_gate.py:50, `_result(verdict, ...)` :159, `exit_code(verdict: GateVerdict)` :164, `gate.verdict` nuisance_gate_console.py:33, nuisance_gate_report.py:72, nuisance_gate_session.py:151 | `outcome: GateOutcome` (params `outcome`) | JSON key `gate.verdict` of `output/nuisance_gate_report.json` (not committed) | - | - | report key | 4 |
| `ServerOutcome.PENDING_REPLAY = "pending_replay"` nuisance_gate.py:23 | `PENDING_RETEST = "pending_retest"` | JSON value in gate report (not committed) | - | - | report value, detail text | 4 |
| `ServerComparison.replays` nuisance_gate.py:45, `settle(comparison, replays, rule)` :94-110 incl. update keys `"replays"`, `_describe` :136-143, nuisance_gate_console.py:54, nuisance_gate_report.py:140, nuisance_gate_session.py:251-256 | `retests` | JSON key in `output/nuisance_gate_report.json` only (not committed) | - | - | report key | 4 |
| `NuisanceServerBaseline.replay_rule` nuisance_gate_baseline.py:81, reads nuisance_gate_recording.py:93,107,152, nuisance_gate_session.py:250 | `retest_rule` | key of `evals/baselines/nuisance/<server>.json`: no file committed (directory absent), so no read alias needed | - | - | baseline file key | 4 |
| `rule.decide_replays(...)` nuisance_gate.py:106 | `decide_retests` | - | - | - | - | 4 |
| literals `"a replay did not complete"` nuisance_gate.py:103, `", the alarm reproduced in {k} of {n} replays"` :139, column `"Replays"` nuisance_gate_report.py:118, legend `"Replays: the alarm reproduced in k of n replays."` :128-131, docstrings `GateAudit` nuisance_gate_session_model.py:59 ("never a replay"), `_settled` nuisance_gate_session.py:246 | "a retest did not complete", "... of {n} retests", "Retests", "Retests: the alarm reproduced in k of n retests.", "never a retest" | gate report text | - | - | report column/legend, gate reasons | 4 |
| `current_acceptance_servers` nuisance_walk.py:81 | `nuisance_acceptance_servers` | - | - | - | - | 4 |
| `NuisanceServer.version_setting` nuisance_walk.py:48, :105, run_nuisance.py:171 | `candidate_counted_flaws` | - | - | - | - | 4 |
| `version_setting_flaws` nuisance_walk.py:67, :95 | `candidate_counted_flaws` | - | - | - | - | 4 |
| `_sets_version` nuisance_walk.py:161 | `_may_count` | - | - | - | - | 4 |
| `acceptance_servers` nuisance_walk.py:75 | `acceptance_target_servers` | - | - | - | - | 4 |
| `ServerMark.ACCEPTANCE = "acceptance"` nuisance_walk.py:38 | `ACCEPTANCE_TARGET_SERVER = "acceptance_target_server"` | - | - | - | console tag | 4 |
| `_MARK_REASONS[ACCEPTANCE] = "an acceptance server"` nuisance_population.py:27 | `"the server of a current or dropped acceptance target"` | exit reason in run result/report JSON (not committed) | - | - | report text | 4 |
| `NuisanceCensus` nuisance_walk_record.py:46, `committed_nuisance_census` nuisance_commands.py:35, parameter/variable `nuisance_census` | `WalkInputs`, `committed_walk_inputs`, `walk_inputs` | - | - | - | - | 4 |
| `NuisanceRunStatus.miss_causes` nuisance_results.py:24, `incomplete_runs_by_cause` reads it | `missed_call_causes` | not in report keys directly (counted into `incomplete_runs_by_cause`) | - | - | - | 4 |
| literal `"Incomplete runs (a step refused or unreadable)"` nuisance_markdown.py:143, comment nuisance_results.py:19 | `"Incomplete runs (a model call refused or unreadable)"` | report .md | - | - | report label | 4 |
| `write_holdout_references` nuisance_holdout_reference.py:29, `holdout_references` nuisance_readmission_dossier.py:122 | `write_holdout_target_references`, `holdout_target_references` | - | - | - | - | 4 |
| `HOLDOUT_FIXTURES` nuisance_holdout_reference.py:21 (path `evals/holdout_fixtures`) | `evals/cve/detection/holdout_fixtures`, the dossier directory `reference/holdout_fixtures/` keeps its name | dossier dir name `reference/holdout_fixtures/` | agent: dossier layout (`reference/holdout_fixtures/`) | - | dossier tree | 4 |
| `stale_holdout_copies` nuisance_holdout_copies.py:28, `_refuse_stale_holdout_copies` run_nuisance.py:270 | `stale_holdout_calibration_copies`, `_refuse_stale_holdout_calibration_copies` | - | - | - | - | 4 |
| `CENSUS_PATH = .../holdout_census.json` nuisance_commands.py:16 | `.../census.json` | file rename | - | - | `--census` default | 4 |
| `_verdict_conflicts` nuisance_admission_records.py:92, `_verdict_key` :105, locals `verdict`/`verdicts` :60-69,93-101 | `_real_software_conflicts`, `_real_software_key`, `record`/`records` | - | - | - | - | 4 |
| literal `"tool {name!r} has differing real_software verdicts across flaws ..."` nuisance_admission_records.py:99 | `"... differing real_software records across flaws ..."` | - | - | - | load error | 4 |
| `_unverdicted_tools` nuisance_unrecorded.py:50 | `_tools_without_real_software` | - | - | - | - | 4 |
| `_print_verdicts` nuisance_vet_command.py:143 | `_print_vet_results` | - | - | - | - | 4 |
| `NUISANCE_RULE = docs/nuisance-rule.md` nuisance_dossier.py:34, copied as `nuisance-rule.md` :80, README mentions :190,205 | `NUISANCE_SUITE_RULE = docs/nuisance-suite-rule.md`, copied as `nuisance-suite-rule.md` | - | agent: dossier file name and README | - | dossier tree | after this plan |
| README `_README` nuisance_dossier.py:246+: "A self-contained workshop", "the planting layer's sidecar", "the stand-in image ... (the replay of a public service's ...)", "the format the stand-in replays", "not a holdout twin", "rule v3 and v4 fields" | "a self-contained kit", "the planting code's sidecar", "serves a public service's capture", "the format the stand-in serves", "not the server of a holdout target", "nuisance suite rule v3 and v4 fields" | - | agent: admission dossier README | - | dossier text | 4 |
| `fixture_format.md` literal nuisance_dossier.py:110-140: `FixCheckTarget` (x4), `KitTarget`, "`mechanism`: the grammar `MechanismClass`", "## Fields rule v3 adds", "## Fields rule v4 adds", "`source` is `holdout_calibration`" | follows the renames above (`FixCheckFixture`, `effect_class`, `FlawClass`, "nuisance suite rule v3", `detection_holdout_calibration`) | - | agent: dossier | - | dossier text | 4 |
| Doris paragraph nuisance_dossier.py:235 ("the holdout fixture's launch") | "the holdout target's launch" | - | agent | - | dossier text | 4 |
| `python -m evals.holdout_kit.benign_probe` literals nuisance_dossier.py:~193, nuisance_readmission_docs.py:168, `from evals.holdout_kit...` snippets nuisance_readmission_docs.py:157,190 | `evals.cve.kit.benign_probe`, `evals.cve.kit...` | - | agent: dossier commands | - | dossier text, CLAUDE.md | 4 |
| re-admission README nuisance_readmission_docs.py:134-144: "the first-admission workshop above", "of the holdout twin" | "the first-admission kit above", "of the holdout target" | - | agent | - | dossier text | 4 |
| `_replay_the_seed` gravitino_backend.py:286 (call :280) | `_send_the_seed` | - | - | in: gravitino served file (moves the gravitino server's nuisance fixture fingerprint) | - | 4 |
| arg `target` of `_read_only(host_path, target)` ckan_backend.py:85, loop var :80 (a bind-mount target path) | `container_path` | - | - | in: ckan served file | - | 4 |
| import and annotation `EvalResult` nuisance_counter.py:15,39 | `JudgeResult` | - | - | ref: `_COUNTER_PATHS` (moves the counter fingerprint) | - | 4 |
| attribute reads `case.eval_result`, `chain.eval_result` nuisance_counter.py:33,35 | `.judge_result` | - | - | ref: `_COUNTER_PATHS` | - | 4 |

### C.10 Docstrings, comments and string literals of the hashed modules

A class or function docstring and a string literal sit in the syntax tree and move the fingerprint. A module docstring and a comment do not, but the plan fixes them in the same commit, so each hashed file is touched once. A hashed docstring that cites a rule cites it by name and section ("the detection suite rule, Deployment layout"), never by path or line. Identifier rows are in C.1, C.6 and C.9.

| file (new path) | class and function docstrings, string literals (move the fingerprint) | module docstring, comments (outside the tree) | step |
|---|---|---|---|
| `evals/cve/grammar.py` (G) | 0 | "location" 1, "fresh" 1 (replay 2 in the ADR 030 sense, kept) | 4 |
| `evals/cve/proofs.py` (G) | `proofs_in` docstring :39 "location id" to "place id" (replay 3, kept) | "replayed twins" 1, to "paired units" | 4 |
| `evals/cve/units.py` (G) | 0 | "calibration" 2, to "calibration check" ("refused" 1 is a provider refusal, kept) | 4 |
| `evals/cve/report_units.py` (G) | 0 (identifiers only) | `eval_result` 2, to `judge_result` | 4 |
| `evals/cve/environments.py` (E) | `LaunchShape` docstring :99: "holdout-rule.md:159", "the break detector", "the benchmark" (3) | holdout 1, replay 2 ("a stand-in replaying a dated capture" to "serving", "`--calibrate`, which replays" to "`--calibration-check`, which runs"), calibrate 1, planting layer 1, comments: holdout-rule 1, holdout run 1, location id 1, `CVETarget` :132 | 4 |
| `evals/cve/detection/holdout_environments.py` (E) | 0 | "CVE environment builders", "CVE fixture", comments: planting layer 3, "calibration re-runs" 1 | 4 |
| `evals/cve/layout.py` (E) | `build_empty_layout` docstring :120: "holdout-rule.md:159", "the break detector" (2) | "version 11 of the holdout rule" 1, planting layer 1 | 4 |
| `evals/cve/places.py` (E) | literal `"holdout_places.json"` :27 (1, C.6) | `holdout_places.json` 1 | 4 |
| `evals/cve/planting.py` (E, P) | 0 | "frozen list's locations" 1, comments: calibration 1 (replay 1 in the ADR 030 sense, kept) | 4 |
| `evals/cve/planting_base.py` (E, P) | 0 | comments: "Rule v11" 1 (to "detection suite rule v11"), "CVE family" 1, "replayed verbatim" 1 (to "served verbatim") | 4 |
| `evals/cve/planting_spec.py` (E, P) | 0 | "one nonce per location" 1, to "per place" | 4 |
| `evals/cve/public_stand_ins.py` (E, P) | load-error literal :173 "replay" and two validator names (C.6) | replay 2, to "serve" | 4 |
| `evals/cve/closed_network.py` (E, P, served) | 0 | "calibration and nuisance dossiers" 1, to "calibration kits and admission dossiers" | 4 |
| `evals/cve/endpoint_address.py`, `evals/cve/planting_stand_ins.py`, `evals/cve/planting_docker.py` (E, P) | 0 | 0 | 4 |
| `evals/cve/nuisance/counter.py` (C) | identifiers only (C.9) | `eval_result.verdict` 2 | 4 |
| `evals/cve/nuisance/counting.py` (C) | 0 | 1 | 4 |
| `evals/cve/nuisance/confinement.py` (CONF) | 0 | 2 | 4 |
| `evals/cve/backends/gravitino.py` (served) | `_replay_the_seed` identifier (C.9) | comment 1, module docstring 1 | 4 |
| `evals/cve/backends/gitlab.py` (served) | 0 | "sentinel route" 2, to "the responder route that serves a witness" | 4 |
| `evals/cve/backends/ckan.py`, `evals/cve/backends/n8n.py` (served) | 0 | module docstring 1 each | 4 |
| the other served backends, `evals/cve/backends/responder.py`, `evals/cve/backends/n8n_instance.py` | 0 | 0 | 4 |

### C.11 Kept on purpose

- Auditor core: `EvalVerdict` and every model-facing schema, field, docstring and wire model (Invariant 1). `UnparseableOutput` (imported by `adapters/anthropic_structured_output.py`). `ExecutionConfig.budget` and `.chains` (they mirror `--budget`, `--chains` and the configuration keys). The redaction marker text. `ProviderRefusal`, `MissCause` and its values, and the provider-refusal labels (the reserved sense of refusal). `LaunchRefused`, `RelayRefusedError`, `CheckpointFromEarlierVersion` and the other "refuse" verbs of a command guard. `export_judged_cases` and `judged_cases.jsonl` (they hold only judged cases). `blocked_step_reason`, `ChainStep`, `max_chain_steps` and the node names (chain step, and node names are checkpoint data). "Relayed environment" in the Markdown report (it lists both `--env` and `--env-plain`).
- Shared and honeypot code: `Recording`, `RecordingRef`, `RecordingRefused`, `decide_recording`, `recording_refusals`, `fixture_refusals` and the rest of the baseline recording code (the reserved sense of "recording"). `ReplayRule.required` (becomes `RetestRule.required`, same field). `CellOutcome` members, `FlipCause`, `DeclaredFlip`, `DetectionCount`, `count_detections`, `GateMode` values, `ToolDistribution`. `SessionThrottles.by_target` (detection targets keyed by flaw ID).
- Judge eval and probe: `CaseSource.CVE` (18 judge cases) and the probe corpus `source` and `call_id` token `cve` (47), the data token of the CVE benchmark. The judge fixture's quota key `cve_target` (1, `draw.quotas`, a committed draw record, read as a `dict[str, int]`). `JudgeInputs` fields (they feed the judge prompt and `case_id`). `run_judge_gate`, `judge_one_case`, `judge_floor_breaches` ("judge" names the judge or qualifies the judge eval). `Candidate`, `CANDIDATES`, `CandidateStats.refusals`.
- Detection suite: the whole ADR 030 replay (`cve_replay.py` names, `replay_with_causes`, `ReplayOutcome`, `ReplayAttemptFailure`, `replay_attempt_failures`, `render_replay_credits`, "Replay credits (place ids):", "replay unchecked", "## Server health and replay", `RecordedCall`, `recorded_calls`). `TargetRecording`, `print_recording`, `recording_tree`. `image_tag` and the Docker tag family `mcp-auditor-cve-*`. `TargetOutcome` members other than `PENDING_REPLAY` (held, regression, not run, unchecked). `awaited_capability`. `HOLDOUT_TARGETS`, `HoldoutDeps`, `HoldoutRunResult`, `HoldoutTargetResult`, `HoldoutReport`, `HOLDOUT_RUNS`, `HOLDOUT_BUDGET`, `HOLDOUT_CONCURRENCY` (in `detection/`, "holdout" names the detection holdout layer). `HoldoutRunStatus`. `PreRunCheck`, `NotRunCause` values. `CARD_CHECK_RULE_VERSION = 11`. `cited_interval`, `Side`, `side_of`, `conclude`, `Contrast`, `Interval`, `wilson`, `newcombe`. `UngradedStatus`. The exploit and benign functions of `cve_exploits.py`. `TargetVersion`, `LaunchMode`, `FILESYSTEM_READ_TOOLS`. `acceptance_services()` (compose services of acceptance targets). `KitTarget` (a kit's target), the kit builders and `benign_probe` names and flags. The holdout fixture module names (named by flaw ID). `_BENCHMARKED`, `_refused_alone`, `measurement_refusal`, `_flag_refusal`.
- Shared CVE code and census: `HoldoutConditions`, `CONDITIONS_PATH`, `load_conditions` (the glossary keeps `evals/holdout_conditions.json`). `REACHED_BUT_JUDGED_PASS`. The sidecar names `SentinelIntent`, `start_sentinel`, `SENTINEL_SERVICE`, `SENTINEL_IMAGE`. `SentinelIntent.request_target`. Every builder function (`target.builder.__name__` is hashed). `LaunchShape`, `owned_layout`, `LayoutMount`, `PlantingHost`, `PublicNames`, `SymbolicUser` (agent-facing `$defs`), `LABEL = "mcp-auditor-cve"`. `CensusFigures`, `compute_figures`, the `figures` key (census counts, a qualified use). `Gap`, `Discovery.GAP` and `RecallFinding` (work-file models, not glossary concepts). `VulnerableMcpEntry.cve_id` (24 values, each a CVE ID). `DRAW_SALT`. The census keys `identifier`, `no_census_identifier`, `known_gap`, `draw`, `drawn` and the walk outcomes. The `CalibrationCard`, `Classification`, `StandInRecord`, `AgentRole` models and values (Invariant 2). The JSON key `reachable_by` and every reach and class token. `struck_by_replay`. `reachable` (census figures).
- Nuisance suite: `vet`, `vet_servers`, `VetDeps`, `VetResult` (the glossary's vet). `ToolVerdict`, `tool_verdicts` (PASS or FAIL verdicts). `holdout_fingerprint`, `copy_targets()` (detection holdout targets), `ServerOutcome`, `ServerComparison`, `standing_exit`, `NotRunServer`, `ServerMark.EXCLUDED`. Every `FlawRecord` and `AdmittedServer` field (`effect_class`, `declared_function_is_effect`, `fix_check`), apart from the two declared schema changes. The committed walk-record tokens and the admission's free text. The `/sentinel` routes a fixture serves. `REDIR_TARGET`, gravitino `location=`, the "calibration probe" issue body of the github-kanban fix check (fixture data). The fix-check module names.

## Appendix D. Data migrations

| file | change | occurrences | step | how verified |
|---|---|---|---|---|
| `evals/baselines/honeypot_e2e.json` | `git mv` to `evals/baselines/honeypot.json`, content unchanged, confirmed, not reset. `replay_rule` (and its `replays`) read through `AliasChoices("retest_rule", "replay_rule")` and `AliasChoices("retests", "replays")` until the next re-recording from a green gate | 1 + 1 | 3 | unit test: the committed file loads through the alias and gates, `git diff -M` shows a 100% rename |
| `evals/baselines/judge_isolation.json` | `git mv` to `evals/baselines/judge.json`, same alias | 1 + 1 | 3 | same |
| `evals/fixtures/fault_injection_baseline.json` | keys rewritten: `replay_rule` to `retest_rule`, `replays` to `retests` (a test fixture, not a gate baseline) | 1 + 1 | 3 | the fault-injection unit and integration tests load it |
| a baseline written after step 3 | written with `retest_rule` and `retests` only | - | 3 | unit test: a written baseline carries the new keys |
| `evals/declared_flips.json` | entry format `suite` to `instrument` (C.2), content `{"entries": []}` unchanged | 0 | 3 | loads, CONTRIBUTING documents the new key |
| `evals/holdout_census.json` | `git mv` to `evals/census.json`, content unchanged. `draw.grammar_fingerprint` is not recorded again: the detection suite rule records the grammar fingerprint at the draw, and the value is the one of the first draw. `verdict` (14) stays, read and written through `Settlement.ruling` with `Field(validation_alias="verdict", serialization_alias="verdict")` and `ConfigDict(validate_by_name=True, serialize_by_alias=True)` (body, Identifiers). `cve_id` (24) stays | 0 | 4 | `load_census` passes, `git diff -M` shows a 100% rename |
| `evals/holdout_places.json` | `git mv` to `evals/detection_places.json`, content unchanged, the `reachable_by` key (36) stays and the loader still reads it | 0 | 4 | the pinned SHA-256 still `240a7b83a977d0aca9e05952132d1d49acb581631360aee6793043fbff664f4b` |
| `evals/holdout_census_method.md` | `git mv` to `evals/census_method.md` (its words move in step 5) | - | 4 | - |
| `evals/stand_ins/*.json` (24 of the 25 capture files: `facebook-ads-responder/graph.facebook.com.captures.json` has neither key) | key `target` to `request_target`, key `probed_target` to `probed_request_target`, with the reader (`cve/public_stand_ins.py`), the writer (`capture_stand_in.py`) and `Dockerfile.stand-in` | 68 and 48 | 4 | every committed capture loads under the new keys, the integration test serves a captured route and the default, a capture with the old key is refused with an error naming it |
| `evals/docker/Dockerfile.stand-in` | ENTRYPOINT: `r['target']` to `r['request_target']`, `default['probed_target']` to `default['probed_request_target']`, handler `Replay`/`replay` to `Serve`/`serve`, comments "replays" to "serves" | 1 file | 4 | stand-in image rebuilt (its instruction fingerprint moves), the stand-in integration test |
| `evals/nuisance_admission.json` | `source` value `holdout_calibration` to `detection_holdout_calibration` (the 116 `fix_check` values unchanged), with `FixCheckRecord.source`, `FixCheckResult.source` and the 4 comparisons | 17 | 4 | the admission loads, the model-inputs golden shows the enum change in `FlawRecord` and `AdmittedServer` only |
| `evals/nuisance_admission.json` | `grammar_fingerprint` recorded again to `grammar_fingerprint()` of the step 4 tree | 1 | 4 | the admission check passes |
| `evals/nuisance_admission.json` | each `holdout_fingerprint` recorded again to the current `fixture_fingerprint` of the target its copy resolves to through `copy_targets` (sixteen targets, the two sibling copies included) | 17 | 4 | `stale_holdout_copies` (renamed `stale_holdout_calibration_copies`) and `unrecorded_fields` report nothing |
| `evals/nuisance_admission.json`, `evals/nuisance_walk_record.json` | `rule_commit` set to the commit of nuisance suite rule v5 (both still name `93de2d8`, the commit of v2) | 1 + 1 | after this plan | no code reads it, the logs name the commit |
| `evals/nuisance_walk_record.json` | none: `verdict` (31) stays through the alias | 0 | - | loads |
| `evals/fixtures/judge_cases.json`, `evals/fixtures/probe_corpus.json` | none: `draw.quotas.cve_target` (1), `source: "cve"` (18) and the corpus token `cve` (47) stay, `inputs_fingerprint` untouched | 0 | - | the judge eval and probe tests load them |
| `tests/unit/support/cve_grammar_golden.json` (name kept) | top-level key prefix `dead_conditions/` to `not_live_reasons/` (18), `patched_dead_conditions/` to `not_fixed_reasons/` (18), field key `miss_class` to `miss_kind` (173: 17 at depth 1, 156 at depth 2). Every value byte for byte, no regeneration. The case key `tests/nonce_only_in_the_report_target` keeps its name. `cve_grammar_golden_corpus.dead_conditions_units` becomes `not_live_reasons_units`, and the CLAUDE.md regeneration line follows | 209 | 4 | a one-off comparison outside the repository loads the old and new files, maps the keys and asserts every value identical, the golden test passes unregenerated |
| `tests/unit/support/cve_route_golden.json` | file renamed `detection_route_check_golden.json` with its regenerator, its 6 keys are case names with no retired word and do not change | 0 keys | 4 | the golden test passes unregenerated, values byte for byte |
| `tests/unit/support/cve_layout_check_golden.json` | file renamed `detection_layout_check_golden.json` with its regenerator, its 8 case keys and their `breaks` and `leaks` keys do not change | 0 keys | 4 | same |
| `tests/unit/support/model_inputs_golden.json` (new in step 1) | regenerated in step 4 for `FlawRecord` and `AdmittedServer` only: the `$defs` entry `MechanismClass` to `FlawClass` (key, title, references) and the `source` enum value | 2 schemas | 4 | the diff shows exactly those entries |

## Appendix E. Visible surface

"Published" means a released CHANGELOG section (0.1.0 to 0.4.0) shipped it. Only the product (`mcp-auditor`) carries **Breaking** marks. Eval commands, files and reports are contributor-facing and change under Changed. A name that exists only under `[Unreleased]` is edited in place and gets no rename entry.

### E.1 Product (`mcp-auditor`)

| file:line | current | new | glossary term | step |
|---|---|---|---|---|
| `src/mcp_auditor/domain/models.py:345` | JSON key `target` (published since 0.1.0) | `server_command` | server command | 2 |
| `src/mcp_auditor/domain/rendering.py:62` | Markdown `**Target**: ...` | `**Server command**: ...` | server command | 2 |
| `src/mcp_auditor/cli.py:47`, `:127` | positional `target`, usage `TARGET...`, help "TARGET is the command to start the MCP server." | `server_command`, `SERVER_COMMAND...`, "SERVER_COMMAND is ..." | server command | 2 |
| `src/mcp_auditor/audit.py:138` | "nothing to resume for this target, starting a fresh audit" | "nothing to resume for this server command, starting a fresh audit" | server command | 2 |
| `src/mcp_auditor/audit.py:173` | LangSmith trace metadata key `target` | `server_command` | server command | 2 |
| `src/mcp_auditor/domain/models.py:296` | JSON key `execution.relayed_variables` (published in 0.4.0) | `execution.redacted_variables` | redacted variables | 2 |
| `src/mcp_auditor/domain/models.py:351`, `:339` | JSON keys `missed_steps`, each entry's `step` (`[Unreleased]` only) | `missed_model_calls`, `kind` | missed model call, model call kind | 2 |
| `src/mcp_auditor/domain/rendering.py:90` | `**Refused by the model provider**: N step(s)` and the two other causes | `N model call(s)` | missed model call | 2 |
| `src/mcp_auditor/domain/rendering.py:197` | "the judgment step was missed, its cause is listed under the tool" | "the judgment model call was missed, its cause is listed under the tool" | missed model call | 2 |
| `src/mcp_auditor/console.py:85` | "audit incomplete, the steps warned about above were not done" | "audit incomplete, see the missed model calls and coverage gaps above" | missed model call, coverage gap | 2 |
| `src/mcp_auditor/config.py:15`, `.env.example:17` | env var `MCP_AUDITOR_OPENROUTER_HOSTS` (`[Unreleased]` only) | `MCP_AUDITOR_OPENROUTER_PROVIDERS` | OpenRouter provider | 2 |
| `src/mcp_auditor/checkpointing.py:31` | `--resume` resumes a thread whose channels are `target`, `judged_cases`, `missed_steps`, `chain_step_missed` | refused with the unchanged message `checkpoint written by an earlier version, run without --resume` | processed cases, missed model call, server command | 2 |
| `src/mcp_auditor/domain/models.py:139`, `:188` | JSON key `eval_result` on each case and chain (published since 0.1.0) | `judge_result` | judge result | 4 |
| `src/mcp_auditor/domain/models.py:112` | JSON key `payload` inside the judge result (the arguments only) | `arguments` | payload (moved meaning) | 4 |
| `src/mcp_auditor/domain/rendering.py:178`, `:187`, `:196`, README.md:140, :146 | Markdown `**Payload**: ...` (judged, blocked, not judged) | `**Arguments**: ...` | payload (moved meaning) | 4 (README in 5) |

Unchanged: `--env`, `--env-plain`, "Relayed environment", the `EvalVerdict` values, every prompt, `execution.plain_variables`, `coverage_gap`, `provider_usage`.

### E.2 Eval commands, flags and help texts

The commands themselves are in A.3. Help texts and refusals:

| file:line | current | new | glossary term | step |
|---|---|---|---|---|
| `evals/run_evals.py:121` | description "Run evals against the honeypots" | "Run the honeypot suite" | honeypot suite | 3 |
| `evals/run_evals.py:129`, `evals/run_judge_eval.py:181` | `--concurrency` help "... runs and replays alike ..." | "... runs and retests alike ..." | retest | 3 |
| `evals/run_evals.py:135-136`, `evals/run_judge_eval.py:187-188` | `--record-baseline` help "record evals/baselines/honeypot_e2e.json" / "judge_isolation.json" "(exploratory, then confirmed)" | "evals/baselines/honeypot.json" / "evals/baselines/judge.json" "(unconfirmed, then confirmed)" | baseline | 3 |
| `evals/run_evals.py:140`, `evals/run_judge_eval.py:192` | `--ungated` | `--no-baseline` (dest `no_baseline`) | `--no-baseline` | 3 |
| `evals/run_judge_eval.py:174` | description "Run the judge isolation eval" | "Run the judge eval" | judge eval | 3 |
| `evals/eval_session.py:97`, `evals/judge_session.py:71`, `evals/recording.py:139`, `evals/judge_recording.py:126` | "--record-baseline cannot run --ungated: ...", "... pass --ungated. ..." | "--no-baseline" | `--no-baseline` | 3 |
| `evals/draw_judge_cases.py:170`, `:173` | description "Draw the judge isolation cases into ...", flag `--cve-export` | "Draw the judge cases into ...", `--detection-export` (dest `detection_export`) | judge case, detection suite | 3 |
| `evals/run_probe.py:84` | description "Replay the probe corpus against every candidate" | "Send the probe corpus to every candidate model" | model probe | 3 |
| `evals/run_cve_benchmark.py:117` | description "Run the CVE validation benchmark" | "Run the detection suite of the CVE benchmark" | detection suite | 4 |
| `evals/run_cve_benchmark.py:125` | `--concurrency` help "Audits (or calibrations) in flight at once" | "Audits (or calibration checks) in flight at once, runs and retests alike" | calibration check, retest | 4 |
| `evals/run_cve_benchmark.py:127-134` | `--calibrate` | `--calibration-check` (dest `calibration_check`), help "No-LLM calibration check per target: ..." | calibration check | 4 |
| `evals/run_cve_benchmark.py:140-145` | `--cve`, metavar `CVE-ID`, help "Run only these CVE ids (repeatable), default: all." | `--flaw`, metavar `FLAW-ID`, help "Run only these flaws, by flaw ID: a CVE ID, or the GHSA ID of a flaw without one (repeatable). Default: all." | flaw ID | 4 |
| `evals/run_cve_benchmark.py:149` | `--ci` help "... for the CI calibration gate." | "... for the calibration check in CI." | calibration check | 4 |
| `evals/run_cve_benchmark.py:155-163` | `--record-baseline` help "evals/baselines/cve/ ... (exploratory, then confirmed)", `--ungated` help "without comparing to evals/baselines/cve/ (exit 0)" | "evals/baselines/detection/ ... (unconfirmed, then confirmed)", `--no-baseline` "... evals/baselines/detection/ (exit 0)" | baseline, `--no-baseline` | 4 |
| `evals/run_cve_benchmark.py:172`, `:174`, `evals/cve_session_recording.py:51` | "--calibrate runs no audit: ...", "--record-baseline cannot run --ungated: ..." | "--calibration-check runs no audit: ...", "... cannot run --no-baseline: ..." | calibration check | 4 |
| `evals/run_cve_benchmark.py:265`, `:292` | next-step flags `--cve {cve_id}`, "Unknown CVE id(s):" | `--flaw {flaw_id}`, "Unknown flaw ID(s):" | flaw ID | 4 |
| `evals/cve_measurement.py:18`, `:19`, `:35` | "a measurement run is ungated: its conditions match no baseline", "--calibrate and --survey run no audit", group "measurement run (with --ungated only)" | "a measurement run reads no baseline: ..., run it with --no-baseline", "--calibration-check and --survey run no audit", "measurement run (with --no-baseline only)" | measurement run | 4 |
| `evals/run_holdout.py:79` | description "Holdout draw commands." | "Commands of the detection holdout layer." | detection holdout layer | 4 |
| `evals/run_holdout.py:89`, `:106` | `--cve` of `calibration-dossier` and of `calibrate`, help "calibrate only this CVE id, default: every drawn target" | `--flaw`, help "check only this flaw ID (a CVE ID, or the GHSA ID of a flaw without one), default: every holdout target" | flaw ID | 4 |
| `evals/run_holdout.py:91` | `run` help "audit the drawn targets and report the capability" | "audit the holdout targets and report the holdout detection rate" | holdout detection rate | 4 |
| `evals/run_holdout.py:102-103` | subcommand `calibrate`, help "replay each drawn target's exploits and benign call, no LLM" | `calibration-check`, "run each holdout target's exploits and benign call, no LLM" | calibration check | 4 |
| `evals/run_holdout.py:163` | "drawn targets whose card is not ready under holdout rule v11" | "... under detection suite rule v11" | detection suite rule | 4 |
| `evals/run_holdout.py:216` | "Refused: a holdout fixture is misconfigured." | "Refused: a detection fixture of a holdout target is misconfigured." | detection fixture | 4 |
| `evals/run_holdout.py:55`, `evals/run_census.py:49`, `evals/nuisance_commands.py:16` | `--census` default `evals/holdout_census.json` | `evals/census.json` | census | 4 |
| `evals/run_census.py:47-48`, `:99` | `--sources`, `--work` defaults `output/holdout_census/{sources,work}`, description "Build the CVE holdout census." | `output/census/{sources,work}`, "Build the census of the CVE benchmark." | census | 4 |
| `evals/run_nuisance.py:119-121`, `:131-135` | `nuisance-dossier --readmission`, subcommand `calibrate` | `--re-admission` (dest `re_admission`), `fix-check` | re-admission, fix check | 4 |
| `evals/nuisance_calibrate_command.py:41`, `:53`, `:59` | `--cve` help "calibrate only this flaw, default: every drawn fixture", "nothing is drawn", "unknown flaw: ... matches no fix-check target" | `--flaw` "fix-check only this flaw, default: every admitted flaw", "no server is admitted", "... matches no fix-check fixture" | fix check, admission | 4 |
| `evals/run_nuisance.py:123`, `:137`, `:162`, `:171` | "report the figure", "audit the admitted acceptance servers ...", "... admitted and in the figure", "may set version, pending the admission's class: ..." | "report the holdout nuisance rate", "audit the admitted nuisance acceptance servers ...", "... admitted and in the nuisance holdout layer", "may count, pending the admission's class: ..." | holdout nuisance rate, nuisance acceptance server, counted flaw | 4 |
| `evals/run_nuisance.py:282` | "holdout calibrations copied from a fixture that has since changed or left the holdout" | "holdout calibration copies taken from a fixture that has since changed or left the detection holdout layer" | holdout calibration copy | 4 |
| `evals/nuisance_gate_command.py:116`, `:118` | "no acceptance server is admitted", "no admitted acceptance server can run in the gate" | "no nuisance acceptance server is admitted", "no admitted nuisance acceptance server can run in the gate" | nuisance acceptance server | 4 |
| `evals/nuisance_unrecorded.py:29`, `evals/nuisance_vet_command.py:154` | "fields rule v3 or v4 adds ..." | "fields nuisance suite rule v3 or v4 adds ..." | rule vN | 4 |
| `evals/holdout_kit/benign_probe.py:66` | `prog="python -m evals.holdout_kit.benign_probe"` | `python -m evals.cve.kit.benign_probe` | kit | 4 |
| `evals/calibration_dossier.py:82-83`, `evals/nuisance_dossier.py:44` | "The --cve argument must be ...", "... a server package the holdout census records." | "The --flaw argument must be the flaw ID of a census flaw.", "... the census records." | flaw ID, census | 4 |

### E.3 Console, Markdown and JSON report strings of the evals

| file:line | current | new | glossary term | step |
|---|---|---|---|---|
| `evals/eval_display.py:87`, `:232`, `evals/judge_display.py:111` | column `Replays` | `Retests` | retest | 3 |
| `evals/replay.py:79`, `evals/run_judge_eval.py:148`, `evals/audit_progress.py:38` | progress "Replaying ...", "  Replaying {name} ({attempt}/{n}), ...", "Replaying {count} flipped case(s)" | "Retesting ..." | retest | 3 |
| `evals/eval_display.py:163` | legend "reproduced on replay" | "reproduced on retest" | retest | 3 |
| `evals/gate.py:60` | "replay rule needs 1 <= required <= replays, got ..." | "retest rule needs 1 <= required <= retests, got ..." | retest rule | 3 |
| `evals/gate.py:159` | JSON `gate.cells.<cell>.replays` (honeypot report), `gate.cases.<id>.replays` (judge eval report) | `retests` | retest | 3 |
| `evals/run_judge_eval.py:218` | judge eval report key `replay_observations` (published 0.4.0) | `retest_observations` | retest | 3 |
| `evals/gate_verdict.py:36`, `evals/judge_gate.py:35` | JSON `gate.verdict` | `gate.outcome` | gate outcome | 3 |
| `evals/baseline.py:26` | baseline status value `exploratory` (no committed file carries it) | `unconfirmed` | baseline | 3 |
| `evals/eval_display.py:274`, `evals/recording.py:128`, `evals/judge_recording.py:115` | "Baseline recorded (exploratory)", "the exploratory baseline was recorded at ..." | "(unconfirmed)", "the unconfirmed baseline was recorded at ..." | baseline | 3 |
| `evals/cell_grid.py:26`, `:30`, `evals/eval_display.py:146-164` | grid tags `alarm`, `fixed`, legend "not gated: PASS cell always flagged", "miss or alarm cell correct in every run of this one" | `false_positive`, `improved`, "false positive: PASS cell judged FAIL in every baseline run", "miss or false-positive cell correct in every run of this one" | honeypot gate | 3 |
| `evals/eval_display.py:28` | metric label `Distribution` | `Distribution coverage` | distribution coverage | 3 |
| `evals/judge_display.py:108` | judge outcome column `Target` | `Tool/category` | judge case | 3 |
| `evals/metrics.py:38` | honeypot report `runs[].missed_steps` | `runs[].missed_model_calls` | missed model call | 2 |
| `evals/run_probe.py:244` | probe report key `openrouter_hosts` | `openrouter_providers` | OpenRouter provider | 2 |
| `evals/export.py:42`, `:55` | export `cve_judged_cases.jsonl` (published 0.4.0) and its line key `cve_id` | `detection_judged_cases.jsonl`, key `flaw_id` | detection suite, flaw ID | 3 |
| `evals/capture_probe_corpus.py:58`, `:138` | "the CVE images are not ready", "Listing the tools of {target.cve_id}..." | "the acceptance targets' images are not ready", `{target.flaw_id}` | target | 3 (the attribute in 4) |
| `evals/cve_calibration.py:42`, `:52`, `:57`, `:242` | "Calibration (no LLM): ...", `live` / `dead`, "Some fixtures calibrate dead: ...", "{cve_id} dead: {condition}" | "Calibration check (no LLM): exploits and benign call per target", `ok` / `out of calibration`, "Some targets are out of calibration: ...", "{flaw_id} out of calibration: {reason}" | out of calibration | 4 |
| `evals/cve_layout_check.py:174`, `:292` | "Admission (no LLM): layout break then discovery route", "{cve_id} admission launch error:" | "Layout and route checks (no LLM): layout break then discovery route", "{flaw_id} layout check launch error:" | layout check, route check | 4 |
| `evals/holdout_vetting.py:66` | not-run reason "dead on a version: " | "out of calibration: " | not run | 4 |
| `evals/cve_oracle.py:53`, `:56`, `:58`, `:68`, `evals/cve_costs.py:26` | detection report keys `results[].cve_id`, `mechanisms`, `miss_class`, `not_run_conditions`, `costs[].cve_id` | `flaw_id`, `classes`, `miss_kind`, `not_run_reasons`, `flaw_id` | flaw ID, class, not run | 4 |
| `evals/cve_markdown.py:16`, `evals/cve_console.py:79` | column "CVE", "Miss class" | "Flaw", "Miss kind" | flaw ID | 4 |
| `evals/cve_markdown.py:89-93` | "refused (...)" of the replay credits line | "struck (...)" | struck credit | 4 |
| `evals/cve_markdown.py:126-140`, `evals/nuisance_gate_report.py:72`, `:118`, `:128-131` | "Gate: ..." from `gate.verdict`, "Verdict: **...**", column `Replays`, legend "Replays: the miss (alarm) reproduced in k of n replays." | from `gate.outcome`, "Outcome: **...**", `Retests`, "Retests: the miss (alarm) reproduced in k of n retests." | retest, gate outcome | 4 |
| `evals/cve_gate.py:30`, `:63`, `:67`, `:72`, `evals/nuisance_gate.py:23`, `:45`, `:50` | JSON outcome value `pending_replay`, keys `gate.targets[].cve_id`, `replays`, `gate.verdict` | `pending_retest`, `flaw_id`, `retests`, `gate.outcome` | retest, gate outcome | 4 |
| `evals/cve_gate.py:136`, `:151`, `:187-194`, `evals/nuisance_gate.py:88`, `:103`, `:139`, `evals/cve_recording.py:79`, `evals/nuisance_gate_recording.py:89` | "exploratory baseline recorded at ...", "a replay did not complete", "... in {k} of {n} replays", "the exploratory baseline differs ..." | "unconfirmed ...", "a retest did not complete", "... of {n} retests", "the unconfirmed baseline differs ..." | baseline, retest | 4 |
| `evals/cve_session.py:207` | "a replay's status rests on credits the replay could not check" | "a retest's status rests on credits the replay could not check" | retest, replay | 4 |
| `evals/cve_console.py:58`, `evals/cve_recording_console.py:12-13` | "Ungated run: nothing compared to evals/baselines/cve/.", "evals/baselines/cve/", "uv run python -m evals.run_cve_benchmark --record-baseline" | "No-baseline run: nothing compared to evals/baselines/detection/.", "evals/baselines/detection/", "uv run python -m evals.run_detection --record-baseline" | `--no-baseline` | 4 |
| `evals/cve_targets.py:369` | report note "out-of-scope bare twin" | "out-of-scope bare repository" | bare repository | 4 |
| `evals/holdout_markdown.py:18`, `:22`, `:99` | "# Holdout capability", "Capability: {primary_number:.3f} ...", "Incomplete runs (a step refused or unreadable)" | "# Holdout detection rate", "Holdout detection rate: ...", "Incomplete runs (a model call refused or unreadable)" | holdout detection rate | 4 |
| `evals/holdout_report.py:75`, `:79`, `:81`, `:120`, `evals/holdout_not_run.py:15`, `evals/holdout_results.py:30`, `:35`, `:37`, `:126` | detection holdout report and result keys `primary_number`, `cve_id`, `mechanism_labels`, `miss_causes` | `holdout_detection_rate`, `flaw_id`, `class_labels`, `missed_call_causes` | holdout detection rate, flaw ID, class | 4 |
| `evals/holdout_conditions.py:49`, `:54`, `:73` | "holdout run conditions not ready", "holdout run conditions missing" | "run conditions not ready", "run conditions missing" | run conditions | 4 |
| `evals/holdout_card_readiness.py:35` | "card check at rule version {n}, below {m}" | "card check under detection suite rule v{n}, below v{m}" | detection suite rule | 4 |
| `evals/audit_attempts.py:62` | "a step missed at all N attempts" | "a model call missed at all N attempts" | missed model call | 2 |
| `evals/nuisance_markdown.py:19`, `:103`, `:143` | "Figure: at most ...", "## Outside the figure", "Incomplete runs (a step refused or unreadable)" | "Holdout nuisance rate: at most ...", "## Exits", "Incomplete runs (a model call refused or unreadable)" | holdout nuisance rate, exit | 4 |
| `evals/nuisance_report.py:92`, `:101` | nuisance report keys `figure`, `outside_figure` | `holdout_nuisance_rate`, `exits` | holdout nuisance rate, exit | 4 |
| `evals/nuisance_population.py:27` | exit reason "an acceptance server" | "the server of a current or dropped acceptance target" | exit | 4 |
| `evals/nuisance_walk.py:132`, `evals/nuisance_holdout_reference.py:69`, `evals/nuisance_readmission_dossier.py:130` | "the holdout walk reaches ...", "Refused: the holdout flaw ... matches ...", "has a holdout-calibration flaw with no target." | "the detection walk reaches ...", "Refused: the holdout target ... matches ...", "has a holdout calibration copy with no holdout target." | detection walk, holdout calibration copy | 4 |
| `evals/public_stand_ins.py:173`, `evals/capture_stand_in.py:144` | "... (scheme, method, target, action, form_field), so the stand-in could replay only one of them", "the form probe quotes its target ..." | "(scheme, method, request_target, action, form_field), so the stand-in could serve only one of them", "... its request target ..." | request target | 4 |

Kept: `replay_attempt_failures`, `replay_attempt_failures_by_cause`, `unchecked_reason`, the replay section of the detection reports (the ADR 030 replay), `struck_places`, the Docker label `mcp-auditor-cve`.

### E.4 Files, paths and default outputs

| current | new | glossary term | step |
|---|---|---|---|
| `evals/baselines/honeypot_e2e.json`, `evals/baselines/judge_isolation.json` | `evals/baselines/honeypot.json`, `evals/baselines/judge.json` | honeypot suite, judge eval | 3 |
| `output/eval_report.json` (default `--report` of the honeypot suite, read back by `draw_judge_cases.py:183`) | `output/honeypot_report.json` | honeypot suite | 3 |
| `output/cve_judged_cases.jsonl` (key `cve_id`) | `output/detection_judged_cases.jsonl` (key `flaw_id`) | detection suite | 3 |
| `evals/baselines/cve/` (constants only, no committed file) | `evals/baselines/detection/` | detection baseline | 4 |
| `output/cve_report.json` | `output/detection_report.json` | detection suite | 4 |
| `output/holdout_report.json` (with `<report>.result.json`) | `output/detection_holdout_report.json` | holdout run | 4 |
| `evals/holdout_census.json`, `evals/holdout_places.json`, `evals/holdout_census_method.md` | `evals/census.json`, `evals/detection_places.json`, `evals/census_method.md` | census, place | 4 |
| `output/holdout_census/{sources,work}/` (gitignored, exports already downloaded are moved by hand) | `output/census/{sources,work}/` | census | 4 |
| `evals/holdout_kit/`, `evals/holdout_fixtures/`, `evals/nuisance_fix_checks/` | `evals/cve/kit/`, `evals/cve/detection/holdout_fixtures/`, `evals/cve/nuisance/fix_checks/` | kit, holdout target, fix check | 4 |
| the exported kit tree (`out/evals/holdout_kit/`, `out/evals/holdout_places.json`, flat `out/evals/cve_*.py`) | `out/evals/cve/kit/`, `out/evals/detection_places.json`, `out/evals/cve/<module>.py` with every `__init__.py` | kit | 4 |
| `evals/stand_ins/*.json` keys `target`, `probed_target` | `request_target`, `probed_request_target` | request target | 4 |
| `docs/holdout-rule.md`, `docs/holdout-log.md`, `docs/nuisance-rule.md`, `docs/nuisance-log.md` | `docs/detection-suite-rule.md`, `docs/detection-suite-log.md`, `docs/nuisance-suite-rule.md`, `docs/nuisance-suite-log.md` | detection suite rule, nuisance suite rule | after this plan |
| `nuisance-rule.md` copied into an admission dossier (`evals/nuisance_dossier.py:80`) | `nuisance-suite-rule.md` | nuisance suite rule | after this plan |

Kept: the compose services `holdout-*` and their `Dockerfile.holdout-*`, the label `mcp-auditor-cve`, the salt `mcp-auditor-holdout:`, `evals/holdout_conditions.json`, `output/judged_cases.jsonl`, `output/nuisance_report.json`, `output/nuisance_gate_report.json`, the dossier directory `reference/holdout_fixtures/`.

### E.5 Workflows

| file:line | current | new | step |
|---|---|---|---|
| `.github/workflows/evals.yml:35` | comment "the e2e job runs alongside" | "the honeypot suite job runs alongside" | 3 |
| `evals.yml:38` | job `e2e-eval` | `honeypot-suite` (changes go to `main` directly, so no required status check names it) | 3 |
| `evals.yml:57`, `:62` | step "Run e2e evals", `python -m evals.run_evals` | "Run the honeypot suite", `python -m evals.run_honeypot_suite` | 3 |
| `evals.yml:64`, `:68`, `:70` | step "Upload e2e report", artifact `e2e-eval-report`, `output/eval_report.json` | "Upload honeypot suite report", `honeypot-suite-report`, `output/honeypot_report.json` | 3 |
| `.github/workflows/eval-command.yml:46` | PR comment "`/eval full` (judge + e2e)" | "(judge + honeypot suite)" | 3 |
| `eval-command.yml:137-138` | the "Report result" step reads `output/eval_report.json` (`[ -f ... ]` then `jq`), so a stale path drops the gate line from the PR comment silently | `output/honeypot_report.json` | 3 |
| `eval-command.yml:112-113`, `:121`, `:132`, `:152-154` | step "Run e2e eval", id `e2e`, `evals.run_evals`, env `E2E_EXIT_CODE`, "e2e red ...", "e2e not comparable ...", "e2e crashed ..." | "Run honeypot suite", id `honeypot`, `evals.run_honeypot_suite`, `HONEYPOT_EXIT_CODE`, "honeypot suite red ...", "... not comparable ...", "... crashed ..." | 3 |
| `.github/workflows/cve-calibration.yml` | file name, workflow `CVE Calibration` (:1) | `detection-calibration-check.yml`, `Detection calibration check` | 4 |
| `cve-calibration.yml:7-18`, `:22-32` | path filters `evals/docker/**`, `evals/cve_*.py`, `evals/holdout_places.json`, `evals/run_cve_benchmark.py`, `evals/closed_network.py`, `evals/public_stand_ins.py`, `evals/stand_ins/**`, `tests/integration/test_cve_planting.py`, `tests/integration/support/test_cve_planting_*.py`, `pyproject.toml`, `uv.lock`, and `.github/workflows/cve-calibration.yml` (push only) | today's coverage translated, never `evals/cve/**`: `evals/cve_*.py` becomes `evals/cve/*.py` (the shared modules, GitHub's `*` not crossing `/`), `evals/cve/detection/*.py` (the detection modules, not `holdout_fixtures/`) and `evals/detection_preflight.py` (today's glob covers `cve_preflight.py`), `evals/holdout_places.json` becomes `evals/detection_places.json`, `evals/run_cve_benchmark.py` becomes `evals/run_detection.py`, `evals/closed_network.py` and `evals/public_stand_ins.py` fall under `evals/cve/*.py`, the workflow's own entry becomes `.github/workflows/detection-calibration-check.yml` (push only, as today), and `evals/docker/**`, `evals/stand_ins/**`, `tests/integration/test_cve_planting.py`, `tests/integration/support/test_cve_planting_*.py`, `pyproject.toml` and `uv.lock` stay (H.5). The detection holdout modules now under `detection/`, and the few shared modules that join `evals/cve/` without a `cve_` prefix, add a small widening the maintainer accepted | 4 |
| `cve-calibration.yml:37`, `:55`, `:58`, `:60`, `:68`, `:70-74` | job `calibrate`, comment "not a dead fixture", step "Build CVE fixture images", `python -m evals.cve_preflight`, `pytest tests/integration/test_cve_planting.py`, comments "a fixture calibrated dead (the gate's real signal)", "keeping the gate green", step "Calibrate fixtures (no LLM)", `run_cve_benchmark --calibrate --ci` | job `calibration-check`, "not a target out of calibration", "Build detection fixture images", `python -m evals.detection_preflight`, unchanged (the test keeps its name), "a target out of calibration (the check's signal)", "keeping the check green", "Calibration check (no LLM)", `run_detection --calibration-check --ci` | 4 |

`ci.yml` and `publish.yml` name nothing that changes.

### E.6 CLAUDE.md Commands, line by line

| line | current | new | step |
|---|---|---|---|
| 9 | "the five Docker image tests (holdout kit, CVE planting, ...)" | "(kit, planting, ...)" | 4 |
| 13 | `evals.run_evals  # E2E evals (honeypot servers, ...)` | `evals.run_honeypot_suite  # Honeypot suite (the honeypot servers, ...)` | 3 |
| 14 | `evals.run_evals --record-baseline  # Record evals/baselines/honeypot_e2e.json ... (exploratory, then confirmed)` | `evals.run_honeypot_suite --record-baseline  # Record evals/baselines/honeypot.json ... (unconfirmed, then confirmed)` | 3 |
| 15 | `evals.run_evals --ungated` | `evals.run_honeypot_suite --no-baseline` | 3 |
| 16 | `evals.run_evals --concurrency N  # ... runs and replays alike ...` | `evals.run_honeypot_suite --concurrency N  # ... runs and retests alike ...` | 3 |
| 17 | `# Judge isolation eval` | `# Judge eval` | 3 |
| 18 | `Record evals/baselines/judge_isolation.json ... (exploratory, then confirmed)` | `Record evals/baselines/judge.json ... (unconfirmed, then confirmed)` | 3 |
| 19 | `evals.run_judge_eval --ungated` | `evals.run_judge_eval --no-baseline` | 3 |
| 21 | "runs and replays alike" | "runs and retests alike" | 3 |
| 22, 23 | `--cve-export PATH` | `--detection-export PATH` | 3 |
| 25 | "prerequisite for the CVE benchmark, whose preflight also rebuilds ...", "`evals/cve_planting_docker.py` (`LAYOUT_HELPER_IMAGE`)", "the first launch of the CVE benchmark, the holdout calibration and the nuisance fix checks" | "prerequisite for the detection suite, whose preflight ...", "`evals/cve/planting_docker.py`", "the first launch of the detection suite, the calibration check of the holdout targets and the nuisance fix checks" | 4 |
| 26 | `evals.cve_preflight  # Print the compose services the CVE benchmark's preflight expects ..., the set the CVE calibration CI job builds` | `evals.detection_preflight  # Print the compose services the detection suite's preflight expects ..., the set the calibration check job in CI builds` | 4 |
| 27 | `evals.run_cve_benchmark --calibrate  # CVE benchmark: confirm each fixture is live ...` | `evals.run_detection --calibration-check  # Detection suite: confirm each target is live ...` | 4 |
| 28 | `evals.run_cve_benchmark --survey  # CVE benchmark: ...` | `evals.run_detection --survey  # Detection suite: ...` | 4 |
| 29 | `evals.run_cve_benchmark  # CVE acceptance gate (...): compares each target to evals/baselines/cve/ ..., --calibrate and --survey included` | `evals.run_detection  # Detection gate (...): compares each target to evals/baselines/detection/ ..., --calibration-check and --survey included` | 4 |
| 30 | `--record-baseline  # ... evals/baselines/cve/ ... (exploratory, then confirmed), then commit evals/baselines/cve/` | `evals/baselines/detection/`, "(unconfirmed, then confirmed)" | 4 |
| 31 | `--ungated  # CVE graded run with no comparison to the baseline, exit 0` | `--no-baseline  # Detection suite graded run with no comparison to the baseline, exit 0` | 4 |
| 32 | `--concurrency N  # Audits (or calibrations) ... (combines with any graded mode and --calibrate)` | "Audits (or calibration checks) ... (combines with any graded mode and --calibration-check)" | 4 |
| 33 | `--ungated --chains N ...  # CVE measurement run: ...` | `--no-baseline --chains N ...  # Measurement run: ...` | 4 |
| 34 | `test_cve_grammar_golden_given  # Regenerate the CVE grammar golden master, ... what dead_conditions or patched_dead_conditions reports, ...` | "# Regenerate the grammar golden master, ... what not_live_reasons or not_fixed_reasons reports, ..." | 4 |
| 35 | "the stand-in replays for any request its routes lack", "the stand-in replays each answer's captured headers", the capture's keys | "the stand-in serves ...", "serves each answer's captured headers", `request_target` where the line names the route target | 4 |
| 37 | `run_census prefilter  # CVE holdout census: ... output/holdout_census/work/ (... evals/holdout_census_method.md ...)` | "# Census: ... output/census/work/ (... evals/census_method.md ...)" | 4 |
| 40 | "write evals/holdout_census.json" | "write evals/census.json" | 4 |
| 41 | `evals.run_holdout draw-order  # CVE holdout: ... (--census defaults to evals/holdout_census.json ...)` | `evals.run_census draw-order  # Census: ... (--census defaults to evals/census.json ...)` | 4 |
| 42 | `evals.run_holdout calibration-dossier --cve ID --out DIR  # CVE holdout: ...` | `evals.run_detection_holdout calibration-dossier --flaw ID --out DIR  # Detection holdout layer: ...` | 4 |
| 43 | `evals.run_holdout calibrate  # CVE holdout: confirm each drawn target is live on its vulnerable version and dead on its patched one, ... (--cve ID ...)` | `evals.run_detection_holdout calibration-check  # Detection holdout layer: confirm each holdout target is live on its vulnerable version and fixed on its patched one, ... (--flaw ID ...)` | 4 |
| 44 | `evals.run_holdout run  # CVE holdout capability run: ... report the capability number ...` | `evals.run_detection_holdout run  # Holdout run: ... report the holdout detection rate ...` | 4 |
| 45 | "the holdout walk's then the queue's ...", "the flaws that may set its version pending the admission's class" | "the detection walk's then the queue's ...", "the flaws that may count, pending the admission's class" | 4 |
| 46 | `[--readmission]`, "--readmission writes the re-admission dossier", "holdout-twin Dockerfiles", `python -m evals.holdout_kit.benign_probe` | `[--re-admission]`, "--re-admission writes ...", "the Dockerfiles of its holdout target", `python -m evals.cve.kit.benign_probe` | 4 |
| 47 | `evals.run_nuisance calibrate  # ... recopies its holdout twin's calibration, source holdout_calibration, ... (--cve ID ...)` | `evals.run_nuisance fix-check  # ... is a holdout calibration copy, source detection_holdout_calibration, ... (--flaw ID ...)` | 4 |
| 48 | "report the figure", "a counted flaw's holdout calibration was copied from a fixture ..." | "report the holdout nuisance rate", "a counted flaw's holdout calibration copy was taken from a fixture ..." | 4 |
| 50 | "Nuisance gate on the acceptance servers: audits the admitted acceptance servers ...", "no acceptance server is admitted yet" | "the nuisance acceptance servers" throughout | 4 |
| 51 | "one file per acceptance server ... (exploratory, then confirmed) ...", "no acceptance server is admitted yet" | "nuisance acceptance server", "(unconfirmed, then confirmed)" | 4 |
| 52 | "(Docker, the CVE images, ...)" | "(Docker, the images of the acceptance targets, ...)" | 4 |
| 53 | `evals.run_probe  # Model probe: replay the corpus against ...` | "# Model probe: send the corpus to ..." | 3 |
| new | none | `uv run python -m tests.unit.support.test_model_inputs_golden_given  # Regenerate the golden of what reaches a model or an agent, only in a commit that changes it` | 1 |

The `@docs/glossary.md` line stays, and the retired-word test checks it. CLAUDE.md outside the Commands block is in E.7.

### E.7 README, CONTRIBUTING, CLAUDE.md outside the Commands, method notes, labeling rubric, log preambles, compose comments

Lines a pattern of G catches, grouped by file and word. "By sense" means the line is read before it is rewritten. README.md is rewritten in step 5 as a whole (the body's step 5 lists what it must say), so its rows say what must go. The method notes and the labeling rubric move in step 5, the log preambles with their rules after this plan.

| file | lines | current | new | glossary term | step |
|---|---|---|---|---|---|
| CLAUDE.md | 61 | `server under audit` | audited server | audited server | 2 |
| CLAUDE.md | 131 | `reads dead` | is out of calibration | out of calibration | 4 |
| CLAUDE.md | 133, 134 | `cve target` | target | target | 4 |
| CLAUDE.md | 133 | `planting layer` | planting code | planting | 4 |
| CLAUDE.md | 133 | `cve family` | detection suite | detection suite | 4 |
| CONTRIBUTING.md | 14, 56 | `holdout calibration` | calibration check of the holdout targets, or holdout calibration copy, by sense | holdout calibration copy | 4 |
| CONTRIBUTING.md | 14, 56 | `holdout_kit` | `evals/cve/kit` | kit | 4 |
| CONTRIBUTING.md | 22, 23, 24, 25, 80, 88 | `run_evals` | `run_honeypot_suite` | honeypot suite | 3 |
| CONTRIBUTING.md | 22, 23, 24, 25, 77, 80, 82, 86, 88, 106, 112, 125, 127 | `e2e` | honeypot suite | honeypot suite | 3 |
| CONTRIBUTING.md | 24, 28, 45, 47, 106, 119 | `ungated` | `--no-baseline` | `--no-baseline` | 3 |
| CONTRIBUTING.md | 26, 77, 79, 104, 110, 112 | `judge isolation` | judge eval | judge eval | 3 |
| CONTRIBUTING.md | 37, 84, 169 | `acceptance gate` | detection gate (nuisance gate in nuisance text) | detection gate | 4 |
| CONTRIBUTING.md | 41, 50, 84 | `--calibrate` | `--calibration-check` | calibration check | 4 |
| CONTRIBUTING.md | 41, 42, 43, 44, 45, 46, 47, 84, 169 | `run_cve_benchmark` | `run_detection` | detection suite | 4 |
| CONTRIBUTING.md | 43, 44, 50 | `baselines/cve` | `baselines/detection` | baseline | 4 |
| CONTRIBUTING.md | 50, 54, 56 | `--cve` | `--flaw` | flaw ID | 4 |
| CONTRIBUTING.md | 50 | `refused and the unchecked credits` | struck and the unchecked credits | credit | 4 |
| CONTRIBUTING.md | 50 | `missed step` | missed model call | missed model call | 2 |
| CONTRIBUTING.md | 50, 88 | `first recording is exploratory` | first recording is unconfirmed | baseline | 3 |
| CONTRIBUTING.md | 50 | `step was missed` | model call was missed | missed model call | 2 |
| CONTRIBUTING.md | 52, 54 | `holdout_census` | `census` (`evals/census.json`, `output/census/`, `evals/census_method.md`) | census | 4 |
| CONTRIBUTING.md | 54 | `dead on its` | fixed on its | live / fixed | 4 |
| CONTRIBUTING.md | 54 | `run_holdout calibrate` | `run_detection_holdout calibration-check` | calibration check | 4 |
| CONTRIBUTING.md | 54 | `capability number` | holdout detection rate | holdout detection rate | 4 |
| CONTRIBUTING.md | 54 | `run_holdout` | `run_detection_holdout` (`draw-order` under `run_census`) | holdout run | 4 |
| CONTRIBUTING.md | 56 | `readmission` | re-admission | re-admission | 4 |
| CONTRIBUTING.md | 56 | `holdout walk` | detection walk | walk | 4 |
| CONTRIBUTING.md | 56 | `set its version` | counted flaw | counted flaw | 4 |
| CONTRIBUTING.md | 56, 58 | `acceptance servers` | nuisance acceptance servers, or the servers of acceptance targets, by sense | nuisance acceptance server | 4 |
| CONTRIBUTING.md | 56 | `the figure` | the holdout nuisance rate, or the nuisance holdout layer, by sense | holdout nuisance rate | 4 |
| CONTRIBUTING.md | 56 | `twin` | by sense (note below) | twin (retired) | 4 |
| CONTRIBUTING.md | 56 | `version-setting` | counted | counted flaw | 4 |
| CONTRIBUTING.md | 56 | `run_nuisance calibrate` | `run_nuisance fix-check` | fix check | 4 |
| CONTRIBUTING.md | 58, 170 | `acceptance server` | nuisance acceptance server, or the server of an acceptance target, by sense | nuisance acceptance server | 4 |
| CONTRIBUTING.md | 58 | `cve targets` | targets | target | 4 |
| CONTRIBUTING.md | 58 | `(exploratory, then confirmed)` | `(unconfirmed, then confirmed)` | baseline | 3 |
| CONTRIBUTING.md | 58 | `replay rule` | retest rule | retest | 3 |
| CONTRIBUTING.md | 58 | `exploratory recording` | unconfirmed recording | baseline | 3 |
| CONTRIBUTING.md | 84 | `calibration gate` | calibration check | calibration check | 4 |
| CONTRIBUTING.md | 88 | `honeypot_e2e` | `honeypot` (`evals/baselines/honeypot.json`) | honeypot suite | 3 |
| CONTRIBUTING.md | 93 | `exploratory baseline` | unconfirmed baseline | baseline | 3 |
| CONTRIBUTING.md | 108 | `refused chain steps` | chain steps whose model call the provider refused | missed model call | 2 |
| CONTRIBUTING.md | 112 | `cve runs` | detection suite runs | detection suite | 4 |
| CONTRIBUTING.md | 112, 125 | `judge_isolation` | `judge` (`evals/baselines/judge.json`) | judge eval | 3 |
| CONTRIBUTING.md | 169 | `cve acceptance` | detection acceptance layer, or detection gate | detection suite | 4 |
| README.md | 36, 43 | `missed step` | missed model call | missed model call | 5 |
| README.md | 43 | `missed_steps` | `missed_model_calls` | missed model call | 5 |
| README.md | 120 | `judge isolation` | judge eval | judge eval | 5 |
| README.md | 140, 146 | `**payload**` | `**Arguments**` | payload (moved meaning) | 5 |
| README.md | 154, 158 | `cve targets` | targets | target | 5 |
| README.md | 154 | `honeypot_e2e` | `honeypot` (`evals/baselines/honeypot.json`) | honeypot suite | 5 |
| README.md | 156 | `ci gates` | calibration checks | calibration check | 5 |
| README.md | 156 | `judge_isolation` | `judge` (`evals/baselines/judge.json`) | judge eval | 5 |
| README.md | 158 | `dead on its` | fixed on its | live / fixed | 5 |
| README.md | 158 | `holdout_census` | `census` (`evals/census.json`, `output/census/`, `evals/census_method.md`) | census | 5 |
| README.md | 158 | `fresh targets` | holdout targets | target | 5 |
| README.md | 158 | `ci gate` | calibration check | calibration check | 5 |
| README.md | 158 | `capability number` | holdout detection rate | holdout detection rate | 5 |
| README.md | 158 | `workshop` | kit | kit | 5 |
| README.md | 158 | `holdout-rule` | `detection-suite-rule` | detection suite rule | 5 |
| README.md | 158 | `replays the fixture` | runs the exploits | calibration check | 5 |
| README.md | 160 | `the figure` | the holdout nuisance rate, or the nuisance holdout layer, by sense | holdout nuisance rate | 5 |
| README.md | 160 | `nuisance-rule` | `nuisance-suite-rule` | nuisance suite rule | 5 |
| README.md | 172, 200 | `--calibrate` | `--calibration-check` | calibration check | 5 |
| README.md | 172, 175, 178, 181, 184, 187, 190, 193 | `run_cve_benchmark` | `run_detection` | detection suite | 5 |
| README.md | 177, 200 | `acceptance gate` | detection gate (nuisance gate in nuisance text) | detection gate | 5 |
| README.md | 180 | `(exploratory, then confirmed)` | `(unconfirmed, then confirmed)` | baseline | 5 |
| README.md | 180, 200 | `baselines/cve` | `baselines/detection` | baseline | 5 |
| README.md | 184, 190, 198, 200 | `ungated` | `--no-baseline` | `--no-baseline` | 5 |
| README.md | 192, 193, 200 | `--cve` | `--flaw` | flaw ID | 5 |
| README.md | 200 | `refused and the unchecked credits` | struck and the unchecked credits | credit | 5 |
| README.md | 200 | `first recording is exploratory` | first recording is unconfirmed | baseline | 5 |
| README.md | 200, 290 | `step was missed` | model call was missed | missed model call | 5 |
| README.md | 202 | `planting layer` | planting code | planting | 5 |
| README.md | 202 | `replaying a dated capture` | serving a dated capture | capture stand-in | 5 |
| README.md | 224, 231 | `openrouter_hosts` | `openrouter_providers` | provider | 5 |
| README.md | 298 | `server under audit` | audited server | audited server | 5 |
| docs/holdout-log.md | 1 | `holdout log` | detection suite log | detection suite rule | after this plan |
| docs/holdout-log.md | 1 | `cve holdout` | detection holdout layer | detection suite | after this plan |
| docs/holdout-log.md | 3 | `selection rule` | detection suite rule | detection suite rule | after this plan |
| docs/holdout-log.md | 3 | `holdout-rule` | `detection-suite-rule` | detection suite rule | after this plan |
| docs/labeling-log.md | 3, 29 | `judge isolation` | judge eval | judge eval | 5 |
| docs/labeling-log.md | 31 | `sentinel convention` | nonce convention | nonce | 5 |
| docs/labeling-log.md | 51 | `plants a sentinel` | plants a nonce | nonce | 5 |
| docs/nuisance-log.md | 3 | `nuisance-rule` | `nuisance-suite-rule` | nuisance suite rule | after this plan |
| evals/docker/compose.yml | 6, 7 | `twin` | by sense (note below) | twin (retired) | 4 |
| evals/docker/compose.yml | 12 | `holdout server` | detection holdout server, or nuisance holdout server, by sense | detection holdout server | 4 |
| evals/fault_injection_method.md | 11 | `runs and replays` | runs and retests | retest | 5 |
| evals/fault_injection_method.md | 28, 64 | `refused chain steps` | chain steps whose model call the provider refused | missed model call | 5 |
| evals/fault_injection_method.md | 36 | `gate_verdict` | `gate_outcome` (`GateOutcome`) | gate | 5 |
| evals/fault_injection_method.md | 47 | `replay rule` | retest rule | retest | 5 |
| evals/holdout_census_method.md | 1 | `holdout census` | census | census | 5 |
| evals/holdout_census_method.md | 1 | `cve holdout` | detection holdout layer | detection suite | 5 |
| evals/holdout_census_method.md | 3 | `holdout-rule` | `detection-suite-rule` | detection suite rule | 5 |
| evals/holdout_census_method.md | 9, 25, 33, 36, 37, 47, 55, 75, 81, 89, 105 | `holdout_census` | `census` (`evals/census.json`, `output/census/`, `evals/census_method.md`) | census | 5 |
| evals/holdout_census_method.md | 9 | `holdoutcensus` | `Census` | census | 5 |
| evals/holdout_census_method.md | 105 | `holdout-log` | `detection-suite-log` | detection suite rule | 5 |
| evals/judge_fixture_method.md | 1, 3 | `judge isolation` | judge eval | judge eval | 5 |
| evals/judge_fixture_method.md | 3, 70 | `judge_isolation` | `judge` (`evals/baselines/judge.json`) | judge eval | 5 |
| evals/judge_fixture_method.md | 7, 57, 58 | `run_evals` | `run_honeypot_suite` | honeypot suite | 5 |
| evals/judge_fixture_method.md | 7, 59 | `run_cve_benchmark` | `run_detection` | detection suite | 5 |
| evals/judge_fixture_method.md | 7, 57, 58, 59 | `ungated` | `--no-baseline` | `--no-baseline` | 5 |
| evals/judge_fixture_method.md | 17, 19 | `cve target` | target | target | 5 |
| evals/judge_fixture_method.md | 23 | `cve targets` | targets | target | 5 |
| evals/judge_labeling_brief.md | 1 | `judge isolation` | judge eval | judge eval | 5 |
| evals/judge_labeling_brief.md | 9 | `cve target` | target | target | 5 |
| evals/probe_method.md | 3 | `replays a frozen corpus` | sends a frozen corpus | model probe | 5 |
| evals/probe_method.md | 9 | `judge isolation` | judge eval | judge eval | 5 |
| evals/probe_method.md | 9 | `e2e` | honeypot suite | honeypot suite | 5 |
| evals/probe_method.md | 17 | `cve fixture` | detection fixture | detection fixture | 5 |
| evals/probe_method.md | 82, 88 | `challenger` | candidate model | candidate | 5 |

Twin, by sense: the patched or vulnerable image, the bare repository, the paired units of a replay, the repository module a kit module copies, or a detection holdout server.

The retest sense of a bare "replay", which no pattern catches (the ADR 030 sense stays):

| file:line | current | new | step |
|---|---|---|---|
| README.md:43 | "`--resume` does not replay a missed step" | "does not retry a missed model call" | 5 |
| README.md:54 | "It does not replay a full server-to-client attack" | "It does not stage a full ..." | 5 |
| README.md:158 | "missed again on replay turns the gate red" | "missed again on retest" | 5 |
| README.md:200 | "the target is replayed alone, ... reproduces in 4 replays out of at most 5", "a gated target's run or replay did not complete", "the refused and the unchecked credits" | "retested alone, ... 4 retests out of at most 5", "run or retest", "the struck and the unchecked credits" | 5 |
| CONTRIBUTING.md:50, 56, 58, 88, 102, 104, 108, 117, 119, 121 | "a miss on it is replayed alone", "audits and replays start once", "an alarm on it is replayed under the replay rule of ADR 016", "the replays as a fraction", "a flip on a stable cell is replayed", "such a replay as a failed replay", "is not replayed", "the fault staying active in the replays", "that flips is replayed", "in a run or a replay", "run and replay observations" | "retested", "retests" in each ("not replayed on the patched version" at :50 is the ADR 030 replay, kept) | 3 (the honeypot and judge lines), 4 (the detection and nuisance lines) |
| `evals/fault_injection_method.md:9`, 11, 23, 38, 43 (heading "Why the fault stays active in the replays"), 45, 47, 64, 66, 72 | "replays", "replay", "replaying it", "per replay", "the replay blind spot" | "retests", "retest", "retesting it", "per retest", "the retest blind spot" | 5 |
| `evals/judge_fixture_method.md:7` | "A CVE replay is not exported, since it runs only for a gated target" | "A retest is not exported, ..." | 5 |
| `evals/probe_method.md:3`, 13, 113 | "replays a frozen corpus", "the next probe run replays", "replay a slice of the corpus" | "sends", "sends", "send" | 5 |
| CHANGELOG.md:23, 36, 75, 98, 122, 133 (`[Unreleased]`) | "replayed under the replay rule", "the replays on the two gates", "a pass or a replay whose report holds", "the refused and the unchecked credits", "audits and replays start once", "`--resume` does not replay a throttled step" | "retested under the retest rule", "retests", "a run or a retest", "the struck and the unchecked credits", "audits and retests", "does not retry a throttled model call" | 5 |

Kept (ADR 030): README.md:200 "Every detecting run is also replayed", "A credit the replay could not check", CHANGELOG.md:37, 76, 92, 98 (first sentence), 132.

The labeling rubric (`docs/labeling-log.md:1-54`) and `evals/judge_labeling_brief.md` are what the labelers read: clauses J0, J4 and J10 move "sentinel" to "nonce" and "CVE" alone to "flaw" or "judge cases drawn from detection suite runs" (J10's title, the clause ID J10 kept), under a labeling log entry stating that every stored label scores the same (step 5).

### E.8 CHANGELOG `[Unreleased]` drafts

Breaking, for published product users: `target`, `eval_result`, `payload`, the Markdown "Target" and "Payload", `relayed_variables` (0.4.0), and the refused resume. Not Breaking: `missed_steps` and `MCP_AUDITOR_OPENROUTER_HOSTS`, which exist only under `[Unreleased]` (their entries at CHANGELOG.md:79 and :15 are edited in place), and every eval change.

The existing Breaking entry (CHANGELOG.md:79), rewritten in place across steps 2 and 4 and consolidated in step 5:

```markdown
- **Breaking.** The JSON report's `refused_steps` becomes `missed_model_calls`, and each entry carries its `kind` (the model call kind), a `cause` (`provider_refusal`, `unreadable_answer` or `provider_throttled`) and a `detail` (the provider's message, the number of attempts for an unreadable answer, or the seconds waited and the provider's message for a throttled model call) in place of `provider_message`. The report also names the audited server's command `server_command` (was `target`), each case's and chain's judgment `judge_result` (was `eval_result`), the arguments inside it `arguments` (was `payload`), and the `--env` names under `execution` `redacted_variables` (was `relayed_variables`). The Markdown report says `Server command` and `Arguments` where it said `Target` and `Payload`, and counts missed model calls where it counted steps. The honeypot suite report's `runs[*].refused_steps` becomes `runs[*].missed_model_calls`, and the detection holdout report's `refused_runs` and `refused_run_count` become `incomplete_runs` and `incomplete_run_count`. An audit interrupted under a previous version does not resume: `--resume` stops with `checkpoint written by an earlier version, run without --resume`, and the audit runs again without it.
```

The `MCP_AUDITOR_OPENROUTER_HOSTS` entry (CHANGELOG.md:15) names `MCP_AUDITOR_OPENROUTER_PROVIDERS` in place (step 2).

New entries:

```markdown
### Added

- `docs/glossary.md` defines the vocabulary the code, the docs and the rules share, one meaning per term, and `docs/glossary-log.md` maps the words of older ADRs and plans to the current terms.

### Changed

- The honeypot suite runs as `python -m evals.run_honeypot_suite` (was `evals.run_evals`), writes `output/honeypot_report.json` (was `output/eval_report.json`), and its baseline is `evals/baselines/honeypot.json` (was `honeypot_e2e.json`). The judge eval's baseline is `evals/baselines/judge.json` (was `judge_isolation.json`). Both baselines keep their content and stay confirmed.
- The detection suite of the CVE benchmark runs as `python -m evals.run_detection` (was `evals.run_cve_benchmark`), its no-LLM check as `--calibration-check` (was `--calibrate`), its filter as `--flaw ID` (was `--cve ID`), which takes a CVE ID or the GHSA ID of a flaw without one, its baselines live in `evals/baselines/detection/` (was `evals/baselines/cve/`), and it writes `output/detection_report.json` and `output/detection_judged_cases.jsonl` (was `output/cve_report.json` and `output/cve_judged_cases.jsonl`), whose lines carry `flaw_id` (was `cve_id`). `draw_judge_cases` reads that export with `--detection-export` (was `--cve-export`). `python -m evals.detection_preflight` replaces `evals.cve_preflight`.
- `--no-baseline` replaces `--ungated` on the honeypot suite, the judge eval and the detection suite.
- A flip, miss or alarm is retested, no longer replayed: the outcome tables say `Retests`, the progress says `Retesting`, the gate reports carry `retests`, `pending_retest` and `outcome` (was `verdict`), and the judge eval report `retest_observations` (was `replay_observations`). A baseline is written with `retest_rule` and still read from `replay_rule`. "Replay" now names only the resend of a detecting run's calls to the patched version (ADR 030).
- A first baseline recording is `unconfirmed` (was `exploratory`) until a second one at the same commit confirms it.
- The honeypot grid tags a cell `false_positive` (was `alarm`) and `improved` (was `fixed`), and the metric line says `Distribution coverage`.
- The evals code moves into packages (`evals/honeypot/`, `evals/judge/`, `evals/probe/`, `evals/cve/` with `census/`, `detection/`, `nuisance/`, `backends/` and `kit/`). The `python -m evals.X` commands stay at the top level.
```

Edited in place, since they exist only under `[Unreleased]`: every `run_holdout` line (`run_detection_holdout`, `calibration-check`, `--flaw`, `run_census draw-order`, "holdout detection rate", `output/detection_holdout_report.json`, the keys `holdout_detection_rate`, `flaw_id`, `class_labels`, `missed_call_causes`, `not_run_reasons`), the nuisance lines (`fix-check`, "holdout nuisance rate", `exits`, "counted flaw", "nuisance acceptance server", `--re-admission`, `detection_holdout_calibration`, "no server is admitted"), `evals/census.json`, `evals/detection_places.json`, `evals/cve/kit/` and `python -m evals.cve.kit.benign_probe`, the stand-in capture keys `request_target` and `probed_request_target`, and the word fixes of E.7. The rule and log file names change in the CHANGELOG with the rule versions after this plan.

### E.9 Glossary-log lines to add

In the log's format, inserted in its alphabetical order. Each line lands in the commit that makes its rename (step 3 for the honeypot, judge, probe and shared top-level renames, step 4 for the CVE benchmark's), and a line that groups renames of both steps lands with the later one. The existing line `` `evals/holdout_kit/` | kit `` becomes `` `evals/holdout_kit/` | kit (`evals/cve/kit/`) ``.

| Older word | Current term | Kind | Date |
|---|---|---|---|
| `acceptance_servers()`, `ServerMark.ACCEPTANCE` (the servers of current and dropped acceptance targets) | `acceptance_target_servers()`, `ServerMark.ACCEPTANCE_TARGET_SERVER`, the current-target subset is `nuisance_acceptance_servers()` | rename | 2026-11-11 |
| `.github/workflows/cve-calibration.yml` | `.github/workflows/detection-calibration-check.yml` | rename | 2026-11-11 |
| `CVETarget`, `CVE_TARGETS` | target (`Target`), `ACCEPTANCE_TARGETS` | rename | 2026-11-11 |
| `--cve-export` (`draw_judge_cases`) | `--detection-export` | rename | 2026-11-11 |
| `CVEStatus` | status (`TargetStatus`) | rename | 2026-11-11 |
| `e2e-eval` (the honeypot CI job) | `honeypot-suite` | rename | 2026-11-11 |
| `entry_id` (of a place) | place id (`place_id`) | rename | 2026-11-11 |
| `evals/baselines/honeypot_e2e.json` | `evals/baselines/honeypot.json` | rename | 2026-11-11 |
| `evals/baselines/judge_isolation.json` | `evals/baselines/judge.json` | rename | 2026-11-11 |
| `evals.cve_preflight` | `evals.detection_preflight` | rename | 2026-11-11 |
| `evals/holdout_census_method.md` | `evals/census_method.md` | rename | 2026-11-11 |
| `evals/holdout_fixtures/` | `evals/cve/detection/holdout_fixtures/` | rename | 2026-11-11 |
| `evals/nuisance_fix_checks/` | `evals/cve/nuisance/fix_checks/` | rename | 2026-11-11 |
| `figure`, `outside_figure` (nuisance report keys) | `holdout_nuisance_rate`, `exits` | rename | 2026-11-11 |
| `FixCheckTarget` | `FixCheckFixture` (the nuisance fixture of a fix check) | rename | 2026-11-11 |
| `HoldoutCensus` | census (`Census`) | rename | 2026-11-11 |
| `MechanismClass`, `mechanisms` | class (`FlawClass`, `classes`) | rename | 2026-11-11 |
| `MissClass`, `miss_class` | `MissKind`, `miss_kind` | rename | 2026-11-11 |
| `miss_causes` | `missed_call_causes` | rename | 2026-11-11 |
| `NuisanceCensus` (the census with the walk record) | `WalkInputs` | rename | 2026-11-11 |
| `output/cve_judged_cases.jsonl`, `output/cve_report.json` | `output/detection_judged_cases.jsonl`, `output/detection_report.json` | rename | 2026-11-11 |
| `output/eval_report.json` | `output/honeypot_report.json` | rename | 2026-11-11 |
| `output/holdout_census/` | `output/census/` | rename | 2026-11-11 |
| `output/holdout_report.json` | `output/detection_holdout_report.json` | rename | 2026-11-11 |
| `PlantKind` | `PlaceKind` | rename | 2026-11-11 |
| `primary_number`, primary number (detection suite rule v11) | holdout detection rate (`holdout_detection_rate`) | rename | 2026-11-11 |
| `probed_target` (stand-in captures) | `probed_request_target` | rename | 2026-11-11 |
| `REACHABLE_BY`, `Place.reachable_by` | reach (`REACHES`, `Place.reaches`), the JSON key `reachable_by` of `evals/detection_places.json` is kept | rename | 2026-11-11 |
| `--readmission` | `--re-admission` | rename | 2026-11-11 |
| `RecordingClient`, `KitRecorder`, `RecordingLLM` | `ExchangeLog`, `KitExchangeLog`, `CapturingLLM` ("recording" names only a baseline recording) | rename | 2026-11-11 |
| `settle` (in the gates) | `apply_retests` ("settle" names only a settlement) | rename | 2026-11-11 |
| `version_setting` | `candidate_counted_flaws` | rename | 2026-11-11 |

The kept items of the body's Invariant 6 are recorded in the log's introductory text, beside the words whose meaning moved: the salt literal `mcp-auditor-holdout:`, the Docker label `mcp-auditor-cve`, the compose services `holdout-*` and their `Dockerfile.holdout-*`, the `replay_rule` key of the two committed baselines (read through an alias until their next re-recording), the data tokens `arbitrary_read`, `command_execution`, `internal_fetch` and every reach and class token, the `reachable_by` key of `evals/detection_places.json`, the `cve_id` values of the census, `EvalVerdict`, the `cases` of `TestCaseBatch`, and the historical words of every committed record.

## Appendix F. The two rules

This appendix is the fixed input of the rule versions that follow this plan (After this plan). Each new version is the old text plus two closed lists, applied in this order: the hand pairs, each matching exactly once in the old text, then the table rows in order, each matching on the text the earlier edits left the count it gives. A hand pair is a sentence whose old word maps to more than one current term. Longer and more specific strings come first in each table, and no row matches the output of an earlier row. Both texts keep their line count (280 and 123). The texts at `e551cee` are detection suite rule v11 (`docs/holdout-rule.md`, last changed by `90b4bd9`) and nuisance suite rule v4 (`docs/nuisance-rule.md`, last changed by `c9b8093`). The column "in v(n-1)" counts the old string in the old text, and "applied" counts it where the row is applied. A difference is consumed by a hand pair, as noted under each table. The word "walk" is qualified wherever it stood alone, in both rules, as the glossary says. "Step of a census" stays: the glossary gains "census step" in step 5. Every count below was verified by replaying the lists on the two files at `e551cee`, and none changes a decision.

### F.1 Detection suite rule v12

Hand pairs:

| # | line | old | new |
|---|---|---|---|
| DH1 | 1 | `` # CVE holdout selection rule `` | `` # Detection suite rule `` |
| DH2 | 3 | `` This is the selection rule of the holdout layer of the CVE benchmark. `` | `` This is the rule of the census and of the holdout layer of the detection suite, one of the two suites of the CVE benchmark. `` |
| DH3 | 21 | `` Every MCP CVE that `vulnerablemcp.info` lists `` | `` Every MCP flaw with a CVE ID that `vulnerablemcp.info` lists `` |
| DH4 | 188 | `` it is a target of the CVE benchmark, now or before, or a sibling of one (the current targets are in `evals/cve_targets.py`, the dropped ones in the log). `` | `` it is an acceptance target, now or before, or a sibling of one (the current acceptance targets are in `evals/cve/detection/targets.py`, the dropped ones in the log). `` |
| DH5 | 266 | `` Holdout targets stay out of every other instrument (the acceptance gate of ADR 024, the draw of the judge fixture and the probe corpus), except that their servers enter the nuisance suite as report-only servers, audited under the discipline of this section. `` | `` Holdout targets stay out of every other instrument (the detection gate of ADR 024 and the draw of the judge fixture) and out of the corpus of the model probe, except that their servers enter the nuisance suite, audited under the discipline of this section. `` |
| DH6 | 266 | `` the text the excluded servers produced in the CVE cases of the judge fixture `` | `` the text the excluded servers produced in the judge cases drawn from detection suite runs `` |
| DH7 | 272 | `` and is a target of the CVE benchmark from then on. `` | `` and is an acceptance target from then on. `` |

| # | Why it cannot be a row | Decision changed? |
|---|---|---|
| DH1 | Title. | No. |
| DH2 | "CVE benchmark" moved meaning (now both suites). The sentence names the suite and the census the rule already governs, and keeps "the CVE benchmark" as an anchor, so that "the grammar of the benchmark" (192) and "the machine that runs the benchmark" (199, 202) stay true unedited. | No, it describes what the rule already covers. |
| DH3 | "CVE" alone is never a project term: "an MCP CVE" is a flaw with a CVE ID. | No, the same set of flaws checked against `vulnerablemcp.info`. |
| DH4 | "A target of the CVE benchmark, now or before" can only mean the targets of `evals/cve_targets.py`, current or dropped, which the parenthesis already says, so it becomes "an acceptance target". "A target of the detection suite" would include the holdout targets, and the draw-order criterion would then exclude the flaws it draws. The path follows A.2. | No. The other wording would. |
| DH5 | "Acceptance gate" becomes "detection gate". The model probe is not an instrument, so its corpus leaves the list of instruments and keeps its exclusion. "As report-only servers" is dropped rather than mapped to "nuisance holdout servers", which would be false for a detection holdout server that exits the nuisance holdout layer. | No. Every exclusion stays, and the reading discipline still covers every nuisance audit of these servers. |
| DH6 | "The CVE cases of the judge fixture" are the judge cases drawn from detection suite runs (holdout runs export nothing). | No, the same text set for the contamination test. |
| DH7 | The same reading as DH4: the flaw the acceptance layer takes becomes an acceptance target. | No. |

Substitutions:

| # | old | new | in v(n-1) | applied | lines in v(n-1) |
|---|---|---|---|---|---|
| DT1 | `` [`holdout-log.md`](holdout-log.md) `` | `` [`detection-suite-log.md`](detection-suite-log.md) `` | 1 | 1 | 3 |
| DT2 | `` [`nuisance-rule.md`](nuisance-rule.md) `` | `` [`nuisance-suite-rule.md`](nuisance-suite-rule.md) `` | 2 | 2 | 236, 266 |
| DT3 | `` `evals/holdout_census.json` `` | `` `evals/census.json` `` | 1 | 1 | 29 |
| DT4 | `` fragment for holdout-rule.md v5, `` | `` fragment for version 5 of this rule, `` | 2 | 2 | 64, 163 |
| DT5 | `` (a CVE or GHSA ID) `` | `` (a CVE ID or a GHSA ID) `` | 1 | 1 | 25 |
| DT6 | `` the known gap of the holdout `` | `` the known gap `` | 1 | 1 | 25 |
| DT7 | `` which refuses the credit `` | `` which strikes the credit `` | 1 | 1 | 35 |
| DT8 | `` the replay refuses the credits `` | `` the replay strikes the credits `` | 1 | 1 | 35 |
| DT9 | `` the replay can still refuse it `` | `` the replay can still strike it `` | 1 | 1 | 157 |
| DT10 | `` The replay cannot refuse the credit `` | `` The replay cannot strike the credit `` | 1 | 1 | 197 |
| DT11 | `` keeps or refuses each credit `` | `` keeps or strikes each credit `` | 1 | 1 | 243 |
| DT12 | `` the credits the replay refused `` | `` the credits the replay struck `` | 1 | 1 | 252 |
| DT13 | `` a unit being the case or chain `` | `` a unit being the test case or chain `` | 1 | 1 | 243 |
| DT14 | `` audits a holdout server at `` | `` audits a detection holdout server at `` | 1 | 1 | 236 |
| DT15 | `` a step refused by the model provider `` | `` a model call refused by the model provider `` | 1 | 1 | 262 |
| DT16 | `` whatever step was refused `` | `` whatever model call was refused `` | 1 | 1 | 262 |
| DT17 | `` A refused audit is not attempted again `` | `` An audit with a refused model call is not attempted again `` | 1 | 1 | 262 |
| DT18 | `` no step is refused `` | `` no model call is refused `` | 1 | 1 | 262 |
| DT19 | `` exports no judged case `` | `` exports no judged test case `` | 1 | 1 | 266 |
| DT20 | `` the holdout walk `` | `` the detection walk `` | 1 | 1 | 266 |
| DT21 | `` which a holdout server built `` | `` which a detection holdout server built `` | 1 | 1 | 266 |
| DT22 | `` or a case of the judge fixture `` | `` or a judge case `` | 1 | 1 | 268 |
| DT23 | `` A nuisance trace of a holdout server `` | `` A nuisance trace of a detection holdout server `` | 1 | 1 | 270 |
| DT24 | `` in the nuisance log as the nuisance rule prescribes `` | `` in the nuisance suite log as the nuisance suite rule prescribes `` | 1 | 1 | 270 |
| DT25 | `` in the holdout log `` | `` in the detection suite log `` | 1 | 1 | 270 |
| DT26 | `` The steps of a walk's calibration `` | `` The steps of the detection walk's calibration `` | 1 | 1 | 7 |
| DT27 | `` For the candidates a walk reaches `` | `` For the candidates the detection walk or the nuisance walk reaches `` | 1 | 1 | 23 |
| DT28 | `` The walk takes `` | `` The detection walk takes `` | 2 | 2 | 225, 232 |
| DT29 | `` while the flaws of a walk are being calibrated `` | `` while the flaws of the detection walk are being calibrated `` | 1 | 1 | 27 |
| DT30 | `` a sibling of a flaw a walk excluded at calibration `` | `` a sibling of a flaw the detection walk excluded at calibration `` | 1 | 1 | 228 |
| DT31 | `` the walk `` | `` the detection walk `` | 8 | 8 | 276, 280, 280, 280, 280, 280, 280, 280 |
| DT32 | `` This is version 11. `` | `` This is version 12. `` | 1 | 1 | 280 |

Every row matches all its occurrences. DT15 to DT18 turn "step" into "model call", not "missed model call": a missed model call also covers throttling past every retry, which the rule's log entries of 2026-10-17 treat as an infrastructure failure, retried, then not run, so "missed model call" would count a throttled audit as not detected without retry. DT7 to DT12 turn "refuse" into "strike" for the replay only, and "a run refuses to start" and the provider's refusal (line 7) stay. DT26 to DT31 qualify the walk: the detection walk, except in the Census section's settlements (DT27), which cover the flaws either walk reaches, since the nuisance suite rule settles its flaws under the first step of Draw. Kept: bare "the holdout", "holdout layer" and "acceptance layer" (the detection suite's own text), "walks" (266, a verb), "re-walk", "step" in the census sense (line 7), the cited words `stub`, `probe`, `calibration`, `benign`, `seed`, `leak` (199), "census identifier", "coverage figures" (29), "known gap", the card field names, the salt literal, `fail_without_proof`, the reach tokens, and `DETECTION_RUNGS` (250), which no code rename touches. The two HTML provenance comments (64, 163) change by DT4 and the fragments under them are not touched. The places projection `evals/holdout_places.json` is not cited by the rule.

### F.2 Nuisance suite rule v5

Hand pairs:

| # | line | old | new |
|---|---|---|---|
| NH1 | 9 | `` **The walk.** Servers enter `` | `` **The nuisance walk.** Servers enter `` |
| NH2 | 11 | `` The walk reaches at least every flaw the holdout walk has reached, so every holdout server is reached. `` | `` The nuisance walk reaches at least every flaw the detection walk has reached, so every detection holdout server, the server of a holdout target, is reached. `` |
| NH3 | 11 | `` The walk then stops once that many more servers have entered the figure. A server enters the figure once its admission is committed and no exit of the list below holds for it. A server that leaves the figure later is not replaced, `` | `` The nuisance walk then stops once that many more servers have entered the nuisance holdout layer. A server enters the nuisance holdout layer, as a **nuisance holdout server**, once its admission is committed and no exit of the list below holds for it. A server that leaves the nuisance holdout layer later is not replaced, `` |
| NH4 | 13 | `` A **graded class** is a class of the grammar of the CVE oracle (`evals/cve_grammar.py`), `` | `` A **graded class** is a class of the grammar of the oracle (`evals/cve/grammar.py`), `` |
| NH5 | 15 | `` **The flaws that set the version of a server** are its census flaws `` | `` **The counted flaws of a server** are its census flaws `` |
| NH6 | 17 | `` A **counted flaw** is a flaw that sets the version of its server. A **counted tool** `` | `` A **counted tool** `` |
| NH7 | 19 | `` or those of the holdout card whose calibration it reuses. `` | `` or those of the card of the holdout target whose calibration it reuses. `` |
| NH8 | 25 | `` An **acceptance server** is the server of a target of the acceptance layer of the CVE benchmark, current or past: the current targets are in `evals/cve_targets.py`, the dropped ones in the holdout log. Its traces may be read (see Reading), so it never counts in the figure, even when the walk reaches it. A nuisance run does not audit it. The acceptance servers with a current target go through the admission, outside the walk, and are audited by the gate in a run of its own (see Run conditions and statistic). `` | `` The server of a current or dropped acceptance target of the detection suite (the current targets are in `evals/cve/detection/targets.py`, the dropped ones in the detection suite log) has traces that may be read (see Reading), so it never enters the nuisance holdout layer, even when the nuisance walk reaches it. A nuisance run does not audit it. The server of a current acceptance target goes through the admission, outside the nuisance walk, and once admitted is a **nuisance acceptance server**, audited by the gate in a run of its own (see Run conditions and statistic). `` |
| NH9 | 29 | `` - no flaw sets its version. `` | `` - it has no counted flaw. `` |
| NH10 | 30 | `` - a flaw that sets its version is never fixed. `` | `` - one of its counted flaws is never fixed. `` |
| NH11 | 34 | `` unless it is an acceptance server, which has its own row below. `` | `` unless it is the server of a current or dropped acceptance target, which has its own row below. `` |
| NH12 | 35 | `` - it is an acceptance server. `` | `` - it is the server of a current or dropped acceptance target. `` |
| NH13 | 56 | `` When the patched version of a holdout server is the one its holdout calibration checks, `` | `` When the patched version of a detection holdout server is the one the calibration of its holdout target checks, `` |
| NH14 | 62 | `` and a holdout calibration whose positive control rests on such a stand-in is not reused `` | `` and the calibration of a holdout target is not reused when its positive control rests on such a stand-in `` |
| NH15 | 68 | `` This is the holdout's calibration applied here, without its constraint that the witness sit at a place of the holdout's list or deployment layout: the witness is planted at the flaw's own location, which is why a server the holdout dropped for reaching none of those places can still enter. `` | `` This is the calibration check of the detection holdout layer applied here, without its constraint that the witness sit at a place of the detection suite's list of places or deployment layout: the witness is planted at the flaw's own location, which is why a server whose flaw the detection walk took out for reaching none of those places can still enter. `` |
| NH16 | 68 | `` A flaw that no release clears does not set the version of its server, and neither does a flaw whose exploits `` | `` A flaw that no release clears is not a counted flaw, and neither is a flaw whose exploits `` |
| NH17 | 68 | `` A holdout server whose patched version is the one its holdout calibration already checks `` | `` A detection holdout server whose patched version is the one the calibration of its holdout target already checks `` |
| NH18 | 97 | `` The servers outside the figure: no flaw that sets the version, a flaw that sets the version never fixed, no counted tool left, a server that does not run over stdio, a patched version that does not run under Docker, an excluded server, an acceptance server, and a server spent by a reading (see Reading). `` | `` The servers outside the nuisance holdout layer: no counted flaw, a counted flaw never fixed, no counted tool left, a server that does not run over stdio, a patched version that does not run under Docker, an excluded server, a server of a current or dropped acceptance target, and a server spent by a reading (see Reading). `` |
| NH19 | 107 | `` **Only the acceptance servers with a current target are gated.** The gate audits them in a run of its own, under the run conditions its baseline records, as the CVE acceptance gate does (ADR 024). `` | `` **Only the nuisance acceptance servers are gated.** The gate audits them in a run of its own, under the run conditions its baseline records, as the detection gate does (ADR 024). `` |
| NH20 | 113 | `` The traces of the acceptance servers may be opened and their alarms analyzed, and a gate run writes their per-case report as a graded CVE run writes it. Every other server is report-only, audited under the reading discipline of the holdout rule (its Reading section). `` | `` The traces of the nuisance acceptance servers may be opened and their alarms analyzed, and a gate run writes their per-case report as a graded run of the detection acceptance layer writes it. Every nuisance holdout server is audited under the reading discipline of the detection suite rule (its Reading section). `` |
| NH21 | 115 | `` A report-only server whose trace is read anyway is spent. It leaves the report-only population and the figure from the next run, `` | `` A nuisance holdout server whose trace is read anyway is spent. It leaves the nuisance holdout layer from the next run, `` |
| NH22 | 117 | `` Changes to the auditor are decided on the honeypot suite, the judge isolation eval, the acceptance layer of the CVE benchmark and the gate of this suite on the acceptance servers. `` | `` Changes to the auditor are decided on the honeypot suite, the judge eval, the detection acceptance layer and the gate of this suite on the nuisance acceptance servers. `` |
| NH23 | 123 | `` A census flaw the acceptance layer takes makes its server an acceptance server from the next run, and opens no version. The acceptance layer never takes `` | `` A census flaw the detection acceptance layer takes makes its server the server of a current acceptance target from the next run, and opens no version. The detection acceptance layer never takes `` |

| # | Why it cannot be a row | Decision changed? |
|---|---|---|
| NH1 | Heading: names the nuisance walk. | No. |
| NH2 | "Holdout server" in the provenance sense becomes "detection holdout server", glossed once ("the server of a holdout target"), since the agents who get this rule never see the glossary. The walk is qualified. | No. |
| NH3 | "Figure" as a set, plus the definition of the new term "nuisance holdout server" at the sentence that already defines membership. The walk is qualified. | No, the same membership condition. |
| NH4 | "CVE oracle" becomes "oracle", and the path follows A.2. | No. |
| NH5, NH6 | "The flaws that set the version" is retired for "counted flaw". Version 4 already defines a counted flaw as a flaw that sets the version, so the two definitions merge and the redundant sentence goes. | No, the identical set. |
| NH7 | "Holdout card" becomes "the card of the holdout target". | No. |
| NH8 | The split of "acceptance server": version 4 names the server of a target of the acceptance layer, current or past. Under version 5 the server of a current or dropped acceptance target keeps every consequence (it never counts, a nuisance run does not audit it, with a current target it goes through admission and the gate), and only the server of a current acceptance target, once admitted, is a "nuisance acceptance server". "Past" becomes "dropped", the only way an acceptance target stops being current. The walk is qualified. | No. The same set excluded, the same set gated, and no such server is admitted yet. |
| NH9, NH10 | The exits "no flaw sets its version" and "a flaw that sets its version is never fixed", written on "counted flaw". | No. The existing tension with line 68 (a flaw no release clears does not set the version, while this exit counts such a flaw as never fixed) is carried over unchanged, as the nuisance log's reading of 2026-11-08 records. |
| NH11, NH12 | The exit for acceptance servers stays one exit, "the server of a current or dropped acceptance target", so the exits table every run publishes keeps its rows (NH18), and the code keeps one mark (`ServerMark.ACCEPTANCE_TARGET_SERVER`). | No. |
| NH13, NH17 | "Its holdout calibration checks" becomes "the calibration of its holdout target checks": "holdout calibration" moved meaning. | No. |
| NH14 | The same term. The clause stays "is not reused". | No. |
| NH15 | "The holdout's calibration" is the no-LLM check, so it becomes the calibration check of the detection holdout layer, "the holdout's list" becomes the detection suite's list of places, and "a server the holdout dropped" becomes a server whose flaw the detection walk took out. Bare "the holdout" is not written outside the detection suite's own text. | No. |
| NH16 | "Does not set the version of its server" becomes "is not a counted flaw" (NH5). | No. |
| NH18 | The exits table: three renamed terms in one enumeration (figure as a set, counted flaw, acceptance target). | No, the same reasons in the same order, the same count of rows. |
| NH19 | "Acceptance servers with a current target" become "nuisance acceptance servers", and "CVE acceptance gate" becomes "detection gate". | No. The gate can only audit an admitted server, so the two sets are equal. |
| NH20 | "Graded CVE run" becomes "graded run of the detection acceptance layer" ("of the detection suite" would include holdout runs, which write no per-case report), and "Every other server is report-only, audited under ..." becomes "Every nuisance holdout server is audited under ...". | No. A nuisance run audits only the servers no exit takes out, and the gate only the nuisance acceptance servers. |
| NH21 | "Report-only population and the figure" collapse into one term, the nuisance holdout layer. | No in effect: the only server the old wording covered and the new one does not is one that left the layer before its trace was read, and a nuisance run leaves no per-case output. |
| NH22 | "Judge isolation eval", "the acceptance layer of the CVE benchmark" and "acceptance servers" become "judge eval", "detection acceptance layer" and "nuisance acceptance servers". | No. |
| NH23 | "Makes its server an acceptance server" becomes "makes its server the server of a current acceptance target", the description NH8 attaches the consequences to. Bare "acceptance layer" in this rule would read as the nuisance one, so both occurrences are qualified. | No. |

Substitutions:

| # | old | new | in v(n-1) | applied | lines in v(n-1) |
|---|---|---|---|---|---|
| NT1 | `` [`nuisance-log.md`](nuisance-log.md) `` | `` [`nuisance-suite-log.md`](nuisance-suite-log.md) `` | 1 | 1 | 3 |
| NT2 | `` [holdout rule](holdout-rule.md) `` | `` [detection suite rule](detection-suite-rule.md) `` | 1 | 1 | 7 |
| NT3 | `` `evals/holdout_census.json` `` | `` `evals/census.json` `` | 1 | 1 | 7 |
| NT4 | `` the holdout walk `` | `` the detection walk `` | 4 | 3 | 9, 11, 11 |
| NT5 | `` holdout rule `` | `` detection suite rule `` | 12 | 10 | 7, 9, 9, 9, 68, 89, 91, 93, 115, 115 |
| NT6 | `` A server leaves the figure when `` | `` A server leaves the nuisance holdout layer when `` | 1 | 1 | 27 |
| NT7 | `` not out of the figure `` | `` not out of the nuisance holdout layer `` | 1 | 1 | 38 |
| NT8 | `` leaves the figure, logged `` | `` leaves the nuisance holdout layer, logged `` | 1 | 1 | 121 |
| NT9 | `` Two figures are compared `` | `` Two holdout nuisance rates are compared `` | 1 | 1 | 103 |
| NT10 | `` keeps the figures before and after `` | `` keeps the holdout nuisance rates before and after `` | 1 | 1 | 121 |
| NT11 | `` keeps figures across `` | `` keeps holdout nuisance rates across `` | 1 | 1 | 121 |
| NT12 | `` The published figure `` | `` The published holdout nuisance rate `` | 1 | 1 | 93 |
| NT13 | `` the holdout's detection rate `` | `` the holdout detection rate `` | 1 | 1 | 105 |
| NT14 | `` The figure `` | `` The holdout nuisance rate `` | 4 | 4 | 89, 101, 105, 105 |
| NT15 | `` the figure `` | `` the holdout nuisance rate `` | 14 | 4 | 11, 78, 79, 91 |
| NT16 | `` report-only server `` | `` nuisance holdout server `` | 4 | 3 | 95, 117, 117 |
| NT17 | `` a case or a chain of its audit `` | `` a test case or a chain of its audit `` | 1 | 1 | 87 |
| NT18 | `` number of cases and chains judged FAIL `` | `` number of test cases and chains judged FAIL `` | 1 | 1 | 95 |
| NT19 | `` exports no judged case `` | `` exports no judged test case `` | 1 | 1 | 113 |
| NT20 | `` or a case of the judge fixture `` | `` or a judge case `` | 1 | 1 | 115 |
| NT21 | `` in the holdout log `` | `` in the detection suite log `` | 2 | 1 | 115 |
| NT22 | `` an excluded server of the holdout log `` | `` an excluded server of the detection suite log `` | 1 | 1 | 34 |
| NT23 | `` as the CVE Dockerfiles do `` | `` as the Dockerfiles of the detection suite do `` | 1 | 1 | 72 |
| NT24 | `` refused a step or a step came back unreadable `` | `` refused a model call or a model call came back unreadable `` | 1 | 1 | 101 |
| NT25 | `` whatever step was refused `` | `` whatever model call was refused `` | 1 | 1 | 101 |
| NT26 | `` An acceptance server not flagged `` | `` A nuisance acceptance server not flagged `` | 1 | 1 | 107 |
| NT27 | `` is re-tested under the replay rule `` | `` is retested under the retest rule `` | 1 | 1 | 107 |
| NT28 | `` out of the holdout, `` | `` out of the detection holdout layer, `` | 1 | 1 | 68 |
| NT29 | `` as if a holdout trace had been read `` | `` as if a trace of a holdout run had been read `` | 1 | 1 | 115 |
| NT30 | `` The walk takes the flaws `` | `` The nuisance walk takes the flaws `` | 1 | 1 | 9 |
| NT31 | `` the walk `` | `` the nuisance walk `` | 9 | 7 | 9, 9, 9, 11, 11, 89, 121 |
| NT32 | `` This is version 4. `` | `` This is version 5. `` | 1 | 1 | 121 |

Occurrences consumed elsewhere: NT4 `the holdout walk`, all but the first occurrence of line 11 (NH2). NT5 `holdout rule`, all but the link text of line 7 (NT2) and line 113 (NH20). NT15 `the figure`, applied only where it is the number (11 "(the figure, a side", 78, 79, 91), the set senses going to the nuisance holdout layer through NH3, NH8, NT6, NT7, NH18, NH21, NT8 and NT10. NT16 `report-only server`, all but line 115 (NH21). NT21 `in the holdout log`, all but line 25 (NH8). NT31 `the walk`, all but the two of line 25 (NH8, which writes them as "the nuisance walk"). NT24 and NT25 turn "step" into "model call", not "missed model call", for the reason of F.1 (a throttled call is retried and leaves N, `evals/nuisance_audit.py`). The glossary's "at most" qualifies a published holdout nuisance rate (line 89 already says so), not its definitional uses, so no row adds it. Kept: `stub` (62, a cited word), "admitted again" (123), "graded class" (13), the data tokens `read_outside_scope`, `command_execution`, `internal_fetch`, `fix_commit`, everyday "case" and "per-case", and "that walk" (11), whose antecedent is the detection walk. Version 5 adds no field, so "The fields a new version adds are recorded" does not fire, and the refusal "while a field rule v3 or v4 adds is unrecorded" stays.

### F.3 Replay procedure and versioning

1. Before freezing a table, resolve every path from A.2 (done above: `evals/cve/detection/targets.py`, `evals/cve/grammar.py`) and add a row for any symbol the rule cites that a step 4 rename changes (none: `DETECTION_RUNGS`, the only symbol cited, keeps its name).
2. With a one-off script outside the repository, read the old file, apply each hand pair once (asserting exactly one match), then each row in order (asserting its count), and write the new file. The result must equal the text the verification above produced, line count kept.
3. In the same commit: `git mv docs/holdout-rule.md docs/detection-suite-rule.md`, `git mv docs/holdout-log.md docs/detection-suite-log.md`, `git mv docs/nuisance-rule.md docs/nuisance-suite-rule.md`, `git mv docs/nuisance-log.md docs/nuisance-suite-log.md`, the replayed texts, the two living preambles (detection suite log line 1 "# Detection suite log" and line 3 "Changes to the census and to the detection suite that the [detection suite rule](detection-suite-rule.md) keeps outside its own text.", nuisance suite log line 3 linking `nuisance-suite-rule.md`), and the code, tests and other living files that cite the rule and log paths (`NUISANCE_RULE` renamed `NUISANCE_SUITE_RULE`, the copied name `nuisance-suite-rule.md`, its two byte-for-byte dossier tests, the rest as the section After this plan lists it).
4. `CARD_CHECK_RULE_VERSION` stays 11: version 12 adds no card field and changes no check, so the 37 card checks made under version 11 stand.
5. A follow-up commit pins both versions: each log's version entry gains `Commit \`<hash>\`.`, and `rule_commit` of `evals/nuisance_admission.json` and `evals/nuisance_walk_record.json` becomes the commit of v5 (short form, as `93de2d8` is). The census draw record's `rule_commit` (still at the commit of version 7) is out of scope and goes to a separate small change.

The two log entries are written in that change, not drafted here. The tables nest in them as an indented sub-block under the entry (a blank line, then the tables indented two spaces, which GitHub renders inside a list item), with old and new in double-backtick code spans so the raw Markdown stays replayable.

## Appendix G. Retired-word patterns

The patterns of `tests/unit/test_glossary.py`. Living files are the code under `src/`, `evals/` and `tests/` (with their paths, where `_`, `/`, `.` and `-` count as word boundaries), README.md, CLAUDE.md, CONTRIBUTING.md, the `[Unreleased]` section of CHANGELOG.md (cut at the next `## [`), `docs/glossary.md`, the two rules, the living preambles of the three logs (the labeling rubric up to its `## Entries`, the two other logs up to their first dated entry), `.github/workflows/`, `.env.example`, the method notes `evals/*.md` and `evals/docker/**`. Historical files are never read: `docs/adr/`, `plans/`, `docs/glossary-log.md`, the published CHANGELOG sections, the dated log entries, the committed records (`evals/*.json`, `evals/baselines/`, `evals/stand_ins/*.json`, `evals/fixtures/`, `evals/probe_runs/`), the `tests/unit/support/*.json` goldens, `docs/demo/`, and binary and key files. The test file itself is skipped, with its `given` (and `then`) module under `tests/unit/support/`, since they hold the patterns, the old test stems of `moved-test` and the machinery's fixture words. Counts are hits in living files at `e551cee`, the two rules and the log preambles included (they are exempt through `_NOT_YET_MIGRATED` until the rule versions after this plan).

The step column is the step that removes the id from `_NOT_YET_RENAMED`: the last step that rewrites a hit outside the rules and the log preambles. A pattern with hits in README.md, a method note, the labeling rubric, the glossary or the CHANGELOG is enforced from step 5, since those are rewritten there. The two patterns that a rule or log path trips (`holdout-rule-log`, `nuisance-rule-log`) are tagged "after this plan" and stay in `_NOT_YET_RENAMED` when the plan ends, since a citation of `docs/holdout-rule.md` and the others, and the `NUISANCE_RULE` constant, stay until the rule versions after this plan rename the rules. A pattern with no living hit outside the rules is removed in step 2. In a regex cell, `\|` is a `|` of the regex. Flags: I for `re.IGNORECASE`, - for none.

Bare "replay" (about 1,100 occurrences mixing the ADR 030 resend, retests, sends and serves) and bare "the holdout" (allowed only in the detection suite's own text) have no pattern and are reviewed by hand in the step that owns their file (E.7 lists the prose ones). Moved meanings with no distinctive old form are reviewed the same way: "acceptance layer", "oracle" on the honeypot suite, "calibration" for the check, "CVE benchmark" in the narrow sense, "vet" for the pre-run check, "payload" for the arguments outside the forms listed, "target" for the audited server outside the identifiers listed, "report-only" and "exploratory" outside the forms listed.

| id | regex (Python `re`) | flags | step | current hits (living files, by area) | known false positives, allowlist |
|---|---|---|---|---|---|
| acceptance-gate | `\bacceptance gates?\b` | I | 5 | 16 in 11 files: evals 4, CHANGELOG 3, CONTRIBUTING 3, README 2, rules 2, ... | none found |
| acceptance-test | `\bacceptance tests?\b` | I | 2 | 4 in 4 files: tests 3, src 1 | none found |
| bare-acceptance-server | `(?<!nuisance )\bacceptance[ -]servers?\b` | I | 5 | 49 in 18 files: evals 13, rules 10, tests 10, CLAUDE.md 6, CONTRIBUTING 5, ... | docs/glossary.md:29 quotes the bare word to forbid it: allowlist |
| twin | `twins?\b\|_twin\|Twin` | - | 5 | 73 in 37 files: evals 26, docker 15, CHANGELOG 14, tests 14, CLAUDE.md 2, ... | Dockerfile and `compose.yml` comments rewritten in step 4 (no allowlist) |
| admission-cve | `admission_calibration\|confirm_admission\|AdmissionCalibration\|admission (bars?\|probe)` | I | 4 | 30 in 11 files: tests 18, evals 12 | none found |
| alarm-tag | `CellTag\.ALARM\b\|\bALARM = \"alarm\"\|PASS cell always flagged` | - | 3 | 6 in 3 files: evals 5, tests 1 | none found |
| audit-step | `\bAuditStep\b\|\bMissedStep\b\|\bJUDGE_STEPS\b\|\bCHAIN_STEPS\b\|is_(judge\|chain)_step\b\|describe_missed_step\|print_missed_steps` | - | 2 | 178 in 34 files: tests 119, src 57, evals 2 | none found |
| missed-steps | `missed_steps?\b\|\bmissed steps?\b\|\brefused[ _](chain )?steps?\b\|step (was\|is) missed\|chain_step_missed` | I | 5 | 183 in 52 files: tests 80, src 50, evals 30, CHANGELOG 11, README 7, ... | the old channel names in `_EARLIER_VERSION_CHANNELS` and in the checkpoint tests: allowlist |
| calibrate-cmd | `--calibrate\b\|\b(run_holdout\|run_nuisance) calibrate\b\|nuisance_calibrate\|calibrate_command` | - | 5 | 63 in 14 files: tests 24, CHANGELOG 17, evals 7, CLAUDE.md 6, CONTRIBUTING 6, ... | the CLI test that the old flag is refused: allowlist |
| calibration-gate | `\bcalibration gate\b\|\bCI gates?\b` | I | 5 | 4 in 3 files: README 2, CONTRIBUTING 1, evals 1 | none found |
| workshop | `\bworkshops?\b` | I | 5 | 5 in 5 files: evals 4, README 1 | none found |
| capability | `\bcapability (figure\|number\|rate)s?\b\|\bholdout figures?\b\|capability_(number\|figure\|rate)` | I | 5 | 8 in 7 files: evals 3, README 2, CHANGELOG 1, CLAUDE.md 1, CONTRIBUTING 1 | none found |
| challenger | `\bchallengers?\b` | I | 5 | 2 in 1 files: notes 2 | `evals/probe_method.md:82,88` cite ADR 019's list: reworded in step 5 |
| cve-family | `\bCVE family\b` | - | 4 | 2 in 2 files: CLAUDE.md 1, evals 1 | none found |
| cve-x | `\bCVE (gates?\|oracles?\|grammars?\|baselines?\|fixtures?\|runs?\|targets?\|holdout\|validation benchmark\|acceptance)\b` | - | 5 | 63 in 27 files: CHANGELOG 22, evals 10, CLAUDE.md 9, notes 6, tests 5, ... | none found |
| cve-ident | `\bCVE(?:Targets?\|Status\|Result\|BenchmarkReport\|GateResult\|GateVerdict\|RunConditions\|TargetBaseline\|SessionResult\|Options\|Harness\|Audit)\b\|\bCVE_(?:TARGETS\|RUNS\|TEST_BUDGET\|CONCURRENCY)\b\|\bOutOfScopeCVE\b\|\bOUT_OF_SCOPE_CVES\b` | - | 4 | 821 in 124 files: tests 424, evals 397 | none (the prompt text "Target category:" is not matched) |
| cve-flag | `--cve(?![-\w])` | - | 5 | 30 in 13 files: evals 8, tests 7, CHANGELOG 4, CONTRIBUTING 4, README 4, ... | the CLI test that the old flag is refused: allowlist |
| dead | `dead[ _]conditions?\|patched_dead\|calibrat\w* dead\|\breads? dead\b\|\bdead fixtures?\b\|\bdead on (a\|its\|the\|both)\b\|\blive (or\|and\|/) dead\b\|\[red\]dead\|_report_dead\|\btargets? dead\b\|\bdead targets?\b\|\bdead:` | - | 5 | 82 in 27 files: tests 38, evals 31, CHANGELOG 5, CLAUDE.md 4, workflows 2, ... | process-death senses (`dead_sentinels`, `dead_stand_ins`, "dead server", "dead end") not matched |
| dfie | `\bdfie\b` | I | 2 | 0 in 0 files | none found |
| distribution-label | `\"Distribution\"` | - | 3 | 1 in 1 files: evals 1 | none found |
| e2e | `\be2e\b\|end-to-end evals?\b\|honeypot_e2e` | I | 5 | 37 in 10 files: CONTRIBUTING 14, workflows 12, tests 3, CHANGELOG 2, CLAUDE.md 2, ... | none found |
| eval-result | `\beval_results?\b\|\bEvalResults?\b` | - | 4 | 175 in 33 files: tests 93, src 55, evals 27 | the report-key test that the old keys are absent: allowlist |
| baselines-cve | `baselines/cve\b` | - | 5 | 21 in 11 files: tests 6, evals 5, CONTRIBUTING 4, CLAUDE.md 3, README 3 | none found |
| holdout-census | `holdout_census\|HoldoutCensus\|\bholdout census\b\|holdout's census\|HOLDOUT_CENSUS` | I | 5 | 240 in 51 files: tests 146, evals 63, notes 14, CHANGELOG 5, CLAUDE.md 5, ... | none found |
| holdout-kit | `holdout_kit\|holdout kit\b` | I | 5 | 265 in 98 files: evals 202, tests 57, CHANGELOG 2, CLAUDE.md 2, CONTRIBUTING 2 | none found |
| holdout-places | `holdout_places\|HOLDOUT_PLACES` | - | 4 | 46 in 20 files: tests 25, evals 19, workflows 2 | none found |
| run-cve-benchmark | `run_cve_benchmark` | - | 5 | 61 in 13 files: tests 20, CONTRIBUTING 10, README 8, CHANGELOG 7, CLAUDE.md 7, ... | none found |
| run-evals | `\brun_evals\b` | - | 5 | 18 in 7 files: CONTRIBUTING 6, CLAUDE.md 4, notes 3, workflows 2, evals 2, ... | none found |
| run-holdout | `\brun_holdout(\b\|_run)` | - | 5 | 83 in 11 files: tests 51, CHANGELOG 19, evals 5, CLAUDE.md 4, CONTRIBUTING 4 | none found |
| execution-config | `\bExecutionConfig\b` | - | 2 | 8 in 4 files: src 4, tests 4 | none found |
| exploratory-baseline | `BaselineStatus\.EXPLORATORY\|EXPLORATORY = \|\bexploratory baselines?\b\|\(exploratory, then confirmed\)\|exploratory recording\|recorded exploratory\|first recording is exploratory\|exploratory_commit_refusal` | I | 5 | 84 in 38 files: tests 37, evals 35, CONTRIBUTING 5, CLAUDE.md 4, README 2, ... | none found |
| figure | `(?i:\b(the\|nuisance\|holdout\|a server's) figure\b\|figure: at most)\|FigureExit\w*\|outside_figure\|\bdef figure\b\|figure=figure\|\bfigure\(` | - | 5 | 113 in 25 files: tests 45, evals 44, rules 17, CHANGELOG 3, CONTRIBUTING 2, ... | `census figures`, `CensusFigures` and a generic "a figure" are not matched |
| fixed-tag | `CellTag\.FIXED\|FIXED = \"fixed\"` | - | 3 | 5 in 3 files: evals 4, tests 1 | none found |
| version-setting | `version-setting\|\bsets? (the\|its) version\b(?! of its server)` | I | 5 | 16 in 8 files: rules 5, CHANGELOG 4, evals 4, CONTRIBUTING 2, CLAUDE.md 1 | docs/glossary.md:178 excluded by `(?! of its server)` |
| fresh-targets | `\bfresh targets?\b` | I | 5 | 1 in 1 files: README 1 | none found |
| gate-verdict | `GateVerdict\|gate_verdict\|\bgate verdicts?\b\|verdict of the gate` | I | 5 | 232 in 49 files: tests 151, evals 80, notes 1 | none found |
| holdout-calibration | `(?<!detection_)holdout_calibration\|\bholdout calibration\b(?! copy)` | I | 5 | 59 in 24 files: tests 25, evals 15, CHANGELOG 10, CLAUDE.md 3, CONTRIBUTING 3, ... | `holdout calibration copy` and `detection_holdout_calibration` excluded |
| holdout-rule-log | `holdout-(rule\|log)\|\bholdout (rule\|log)\b\|HOLDOUT_(RULE\|LOG)\b` | I | after this plan | 78 in 27 files: evals 35, rules 21, CHANGELOG 8, docker 6, notes 3, ... | the six Dockerfile comments ("holdout log", no path) are rewritten with the log rename after this plan (no allowlist) |
| bare-holdout-server | `(?<!detection )(?<!nuisance )\bholdout[ -]servers?\b` | I | 5 | 8 in 4 files: rules 6, glossary 1, docker 1 | docs/glossary.md:29 (same): allowlist, `evals/docker/compose.yml:12` is rewritten in step 4 |
| holdout-walk | `\bholdout walk\b\|holdout's draw order\|holdout_walk` | I | 5 | 24 in 15 files: tests 8, evals 6, rules 5, CHANGELOG 3, CLAUDE.md 1, ... | none found |
| holdout-vetting | `holdout_vetting\|pre-run vetting\|\bvet_all\b` | I | 4 | 19 in 7 files: tests 10, evals 9 | none found |
| judge-isolation | `judge[ _]isolation` | I | 5 | 42 in 20 files: evals 11, CONTRIBUTING 9, tests 7, notes 6, CHANGELOG 2, ... | none found |
| judged-cases | `\bjudged_cases\b(?!\.jsonl)` | - | 2 | 32 in 10 files: tests 19, src 13 | `judged_cases.jsonl` exports are excluded by the lookahead, the old channel name in `_EARLIER_VERSION_CHANNELS` and the checkpoint tests: allowlist |
| known-gap-holdout | `known gap of the holdout` | I | 4 | 2 in 2 files: rules 1, evals 1 | none found |
| location-id | `\blocation[ _]ids?\b` | I | 4 | 4 in 4 files: evals 4 | none found |
| openrouter-hosts | `OPENROUTER_HOSTS\|openrouter_hosts` | I | 5 | 20 in 9 files: tests 8, evals 4, src 4, README 2, .env.example 1, ... | none found |
| not-run-conditions | `not_run_conditions` | - | 4 | 6 in 4 files: evals 4, tests 2 | none found |
| nuisance-rule-log | `nuisance-(rule\|log)\b\|\bnuisance (rule\|log)\b\|NUISANCE_(RULE\|LOG)\b` | I | after this plan | 39 in 19 files: evals 13, rules 8, tests 8, docker 4, CHANGELOG 3, ... | the four Dockerfile comments cite the path `docs/nuisance-log.md` and are rewritten after this plan (no allowlist), `NUISANCE_RULE` is renamed `NUISANCE_SUITE_RULE` after this plan |
| oracle-version | `\boracle versions?\b` | I | 2 | 0 in 0 files | none found |
| payload-label | `\*\*Payload\*\*\|\bpayload=case\.payload\.arguments\|payload=last_payload\.arguments\|result\.payload\b` | - | 5 | 11 in 7 files: src 6, tests 3, README 2 | none found |
| replay-retest | `pending_replay\|replay_observations\|\breplay_rule\b\|\bReplayRule\b\|\breplay rules?\b` | I | 5 | 178 in 46 files: tests 92, evals 81, CHANGELOG 1, CONTRIBUTING 1, glossary 1, ... | docs/glossary.md:90 cites the name ADR 024 used: allowlist, the read alias lines of the two baseline models and the alias tests: allowlist |
| replay-retest-ident | `\bReplayer\b\|\b_?replayer\b\|a_replayer\|ReplayAudit\|replay_audit\|ReplayContext\|replay_flips\|decide_replays\|on_replays\|replay_fraction\|judge_replay\|evals/replay\.py\|evals\.replay\b\|\bReplays\b\|\bReplaying\b\|_replaying\|replays alike\|runs and replays` | - | 5 | 160 in 38 files: tests 81, evals 76, CLAUDE.md 2, notes 1 | none found |
| planting-layer | `\bplanting layer\b` | I | 5 | 21 in 17 files: evals 11, docker 6, CHANGELOG 1, CLAUDE.md 1, README 1, ... | Dockerfile comments rewritten in step 4 (no allowlist) |
| readmission | `readmission` | I | 5 | 56 in 11 files: tests 34, evals 17, CLAUDE.md 2, CONTRIBUTING 2, CHANGELOG 1 | the CLI test that the old flag is refused: allowlist |
| refused-credit | `\brefused (and the unchecked )?credits?\b\|credits? the replay refused\|the replay refused` | I | 5 | 6 in 6 files: evals 2, CHANGELOG 1, CONTRIBUTING 1, README 1, rules 1 | none found |
| relayed-variables | `relayed_variables` | - | 2 | 8 in 6 files: tests 5, src 3 | the report-key test: allowlist |
| replay-capture | `\b(stand-in\|it) replays\b\|replay(s\|ed\|ing)? (a\|the\|its\|each\|every) (dated )?(capture\|answer\|captured)\|unreplayed_captures\|replays? .{0,20}captured\|_replay_the_seed` | I | 5 | 24 in 16 files: evals 10, tests 8, CHANGELOG 2, CLAUDE.md 2, README 1, ... | Dockerfile comment of `Dockerfile.holdout-2026-5602-heim` rewritten in step 4 (no allowlist) |
| replay-corpus | `replay(s\|ed\|ing)? (the\|its\|a\|frozen) (frozen )?corpus\|replay the corpus` | I | 5 | 2 in 2 files: CLAUDE.md 1, notes 1 | none found |
| replayed-walk | `\breplayed walks?\b` | I | 2 | 0 in 0 files | none found |
| replays-exploits | `replay(s\|ed\|ing)? (its\|the\|each target's\|every fixture's\|hand-written\|every) ?(hand-written )?(exploits?\|fixture)` | I | 5 | 2 in 2 files: README 1, evals 1 | none found |
| report-only-set | `report-only (population\|servers?\|set\|layer)` | I | 2 | 6 in 2 files: rules 6 | none found |
| rubric-judge | `judge'?s? rubric\|rubric of the judge\|judging rubric` | I | 2 | 0 in 0 files | none found |
| selection-rule | `\bselection rule\b` | I | 2 | 3 in 2 files: rules 2, log preambles 1 | none found |
| sentinel-value | `(?i:sentinel (nonce\|value\|convention\|string)s?\|planted sentinels?\|plants? a sentinel\|sentinels? (surfaces?\|leaks?\|appears?)\b)\|\bSENTINEL\b` | - | 5 | 60 in 9 files: tests 57, rubric 2, evals 1 | `SENTINEL` is case-sensitive, so `SENTINEL_SERVICE`, `SENTINEL_IMAGE` and the sidecar sense do not match |
| sentinel-route | `\bsentinel routes?\b` | I | 4 | 2 in 1 files: evals 2 | none found |
| server-under-audit | `\bservers? under audit\b` | I | 5 | 8 in 8 files: src 3, evals 2, CLAUDE.md 1, README 1, docker 1 | Dockerfile comment of `Dockerfile.neo4j-backend` rewritten in step 4 (no allowlist) |
| stub | `\bstubs?\b\|_stub\b\|stub_` | I | 4 | 69 in 27 files: tests 51, docker 14, rules 2, evals 2 | the cited word in both rules: allowlist after this plan, the Dockerfile comments "no stub" rewritten in step 4 ("no stand-in"), npm's own "installer stub" in `Dockerfile.serverless`, `Dockerfile.serverless-vuln` and the serverless fix check docstring: allowlist, the test fakes `cve_stub_*` are renamed (B) |
| target-product | `\bTargetExecution\b\|target_execution\|launch\.target\b\|report\.target\b\|\"target\": ` | - | 4 | 57 in 24 files: tests 30, src 17, evals 10 | `evals/capture_stand_in.py:105` is the stand-in route key, a true hit of the request target rename, the test that a capture with the old key is refused: allowlist |
| target-route | `route\.target\b` | - | 2 | 0 in 0 files | none found |
| ungated | `\bungated\b` | I | 5 | 103 in 27 files: evals 43, tests 34, CONTRIBUTING 7, CHANGELOG 5, README 5, ... | the CLI test that the old flag is refused: allowlist |
| unread-targets | `\bunread targets?\b` | I | 2 | 0 in 0 files | none found |
| mechanism-class | `\bMechanismClass\b\|\.mechanisms\b\|\bmechanisms=\|\bmechanism_labels\b` | - | 5 | 377 in 135 files: evals 281, tests 95, CHANGELOG 1 | none found |
| plant-kind | `\bPlantKind\b` | - | 4 | 382 in 93 files: evals 297, tests 85 | none found |
| miss-class | `\bMissClass\b\|\bmiss_class\b` | - | 4 | 90 in 13 files: tests 69, evals 21 | none found |
| reachable-by | `\bREACHABLE_BY\b\|\.reachable_by\b\|\breachable_by=\|\b_reachable_by\b` | - | 4 | 93 in 71 files: evals 64, tests 29 | none found |
| entry-id | `\bentry_id\b` | - | 4 | 113 in 7 files: evals 87, tests 26 | every hit is the place id of `cve_places` and its users |
| cve-id | `\bcve_ids?\b` | - | 4 | 603 in 120 files: tests 359, evals 244 | `VulnerableMcpEntry.cve_id` (a CVE ID of vulnerablemcp.info) and its reads: allowlist |
| census-names | `\bNuisanceCensus\b\|\bnuisance_census\b\|\bcensus_identifier\b\|\bBENCHMARK_FLAWS\b\|\bDrawWalkStep\b` | - | 4 | 209 in 26 files: evals 148, tests 61 | none found |
| fix-check-target | `\bFixCheckTarget\b\|\bFIX_CHECK_TARGETS\b` | - | 4 | 187 in 68 files: evals 152, tests 34, CLAUDE.md 1 | none found |
| recording-names | `\bRecordingClient\b\|\bKitRecorder\b\|\bRecordingLLM\b\|cve_recording_client` | - | 4 | 43 in 16 files: evals 29, tests 14 | none found |
| verdict-names | `\bConclusionVerdict\b\|\bprint_verdict\b\|_VERDICT_STYLES` | - | 4 | 28 in 10 files: evals 17, tests 11 | none found |
| acceptance-mark | `ServerMark\.ACCEPTANCE\b\|\bcurrent_acceptance_servers\b\|\bacceptance_servers\(` | - | 4 | 18 in 8 files: evals 11, tests 7 | none found |
| version-setting-ident | `\bversion_setting\w*\|\b_sets_version\b` | - | 4 | 20 in 4 files: evals 10, tests 10 | none found |
| primary-number | `\bprimary_number\b\|\bprimary_controls\b` | - | 4 | 22 in 8 files: evals 12, tests 10 | none found |
| miss-causes | `\bmiss_causes\b\|describe_miss_causes` | - | 5 | 38 in 17 files: evals 23, tests 14, CHANGELOG 1 | none found |
| stand-in-target | `\bprobed_target\b\|\bStandInRoute\.target\b\|r\['target'\]` | - | 4 | 28 in 8 files: tests 14, evals 11, docker 3 | the refusal test of an old-key capture: allowlist |
| calibrate-ident | `\badmission_gave_up\b\|\broute_admits\b\|\bcalibrate_admitted\b\|\bcalibrate_all\b\|\bcalibrate_one\b\|\bCalibrationDeps\b\|\bdefault_calibration_deps\b\|\bcalibrate_fixtures\b\|\bFixCheckCalibrationDeps\b` | - | 4 | 96 in 18 files: tests 55, evals 41 | none found |
| eval-names | `\bEval(?:Report\|RunResult\|Options\|Session\|Metrics)\b` | - | 3 | 80 in 17 files: evals 59, tests 21 | none found |
| phase-usage | `\bPhaseUsage\b` | - | 3 | 21 in 5 files: evals 13, tests 8 | none found |
| suite-enum | `\bSuite\.(?:HONEYPOT\|JUDGE)\b\|\bdeclared_flips\.Suite\b` | - | 3 | 14 in 7 files: tests 12, evals 2 | none found |
| settle-gate | `\bsettle\(\|\b_settled\b` | - | 4 | 23 in 11 files: tests 12, evals 11 | settlement code uses "settlement", never `settle(` |
| moved-module | `evals[./](?:cve\|holdout\|nuisance\|census)_[a-z_]+(?:\.py)?\b(?!\.(?:json\|md))` | - | 5 | 1937 in 474 files: evals 1197, tests 712, CLAUDE.md 7, notes 6, CONTRIBUTING 5, ... | Dockerfile comments: rewritten in step 4 (no allowlist), the data files that stay (`evals/holdout_conditions.json`, `evals/nuisance_admission.json`, `evals/nuisance_walk_record.json`) are excluded by the `(?!\.(json|md))` lookahead |
| moved-module-other | `evals[./](?:replay\|judging\|gate_verdict\|eval_report\|eval_runs\|fault_(?:catalog\|harness\|injection)\|judge_[a-z_]+\|[a-z0-9_]+_backend\|backend_lifecycle\|public_stand_ins\|closed_network\|docker_paths\|dossier_closure\|launch_audit\|audit_(?:attempts\|progress)\|failure_text\|provider_errors\|server_health\|run_(?:files\|images\|interruption)\|fixture_(?:provenance\|sources)\|calibration_dossier\|admission_calibration)\b(?!\.(?:json\|md))\|evals[./]probe(?:_candidates\|_corpus\|_subset)?(?:\.py\b\|(?= import\b))` | - | 5 | 477 in 256 files: evals 238, tests 217, docker 9, notes 6, workflows 4, ... | Dockerfile comments: rewritten in step 4 (no allowlist), `evals/judge_fixture_method.md`, `evals/judge_labeling_brief.md` and `evals/probe_method.md` never match (the lookahead and the word boundary) |

### G.1 Allowlist

One tuple per entry. The test fails on an entry that no longer matches any line, so the list cannot rot. An entry is therefore added in the commit that creates the line it matches, never earlier: the tests the migration writes (the alias, checkpoint, CLI and report-key tests), the alias lines of step 3 (`evals/baseline.py`, `evals/judge/baseline.py`), the checkpoint channel lines of step 2, the moved paths of step 4 (`evals/cve/census/work.py`, `evals/cve/nuisance/fix_checks/...`) and the renamed rules after this plan. Step 1 commits only the entries whose line exists at `e551cee` (the glossary's own mentions, npm's "installer stub" in the two serverless Dockerfiles, and the CHANGELOG `(was ` lines once they exist).

| path glob | pattern id | line substring | reason |
|---|---|---|---|
| `docs/glossary.md` | bare-acceptance-server | `"holdout server" and "acceptance server" are always qualified` | the glossary quotes the bare words to forbid them |
| `docs/glossary.md` | bare-holdout-server | `"holdout server" and "acceptance server" are always qualified` | same |
| `docs/glossary.md` | replay-retest | `where it is called the replay rule` | the glossary cites the name ADR 024 used |
| `evals/baseline.py` | replay-retest | `AliasChoices("retest_rule", "replay_rule")` | read alias of the committed honeypot baseline until its next re-recording (Invariant 6) |
| `evals/judge/baseline.py` | replay-retest | `AliasChoices("retest_rule", "replay_rule")` | read alias of the committed judge baseline (Invariant 6) |
| `tests/unit/test_*baseline*.py` | replay-retest | `replay_rule` | the tests that a committed baseline loads through the alias |
| `src/mcp_auditor/checkpointing.py` | missed-steps | `_EARLIER_VERSION_CHANNELS` | the old channel names a resume across the migration is refused on (`refused_steps`, `missed_steps`, `chain_step_missed`) |
| `src/mcp_auditor/checkpointing.py` | judged-cases | `"judged_cases"` | same |
| `tests/unit/test_checkpointing.py` | missed-steps | `earlier_channel` | the parametrized refusal cases name the old channels |
| `tests/unit/test_checkpointing.py` | judged-cases | `"judged_cases"` | same |
| `tests/integration/support/test_resume_earlier_checkpoint_given.py` | missed-steps | `"refused_steps"` | writes a checkpoint of an earlier version |
| `tests/unit/test_run_*.py` | cve-flag | `"--cve"` | the CLI test that the old flag is refused |
| `tests/unit/test_run_*.py` | calibrate-cmd | `"--calibrate"` | same |
| `tests/unit/test_run_*.py` | ungated | `"--ungated"` | same |
| `tests/unit/test_run_*.py` | readmission | `"--readmission"` | same |
| the report-key test of steps 2 and 4 (its path named when written) | eval-result | `"eval_result"` | asserts that the product report carries none of the old keys |
| the same test | missed-steps | `"missed_steps"` | same |
| the same test | relayed-variables | `"relayed_variables"` | same |
| `tests/*/test_cve_*stand_ins*.py` | target-product | `"target": ` | the test that a capture with the old key is refused |
| `evals/cve/census/work.py` | cve-id | `cve_id: str` | `VulnerableMcpEntry.cve_id` holds the CVE IDs vulnerablemcp.info lists (Invariant 6) |
| `evals/cve/census/progress.py` | cve-id | `entry.cve_id` | reads of that field |
| `tests/unit/support/test_census_given.py` | cve-id | `VulnerableMcpEntry(cve_id=` | builds that record |
| `docs/detection-suite-rule.md` | stub | `` `stub` `` | a word the rule cites in its list of forbidden names (lands with the rule versions after this plan) |
| `docs/nuisance-suite-rule.md` | stub | `stub, calibration` | the same cited word (same) |
| `evals/cve/nuisance/fix_checks/cve_2025_69256_serverless.py` | stub | `installer stub` | npm's own word for the package |
| `evals/docker/Dockerfile.serverless*` | stub | `installer stub` | the same npm word, in the comments of `Dockerfile.serverless` and `Dockerfile.serverless-vuln` |
| `CHANGELOG.md` | each id the E.8 entries trip, one entry each (eval-result, relayed-variables, missed-steps, run-evals, run-cve-benchmark, cve-flag, cve-id, calibrate-cmd, baselines-cve, e2e, judge-isolation, ungated, replay-retest, moved-module) | `(was ` | a rename entry names the word it replaces |

The other kept items of Invariant 6 need no entry: no pattern matches the salt `mcp-auditor-holdout:`, the label `mcp-auditor-cve`, the compose services `holdout-*` and their Dockerfile names, the tokens `arbitrary_read`, `command_execution`, `internal_fetch`, the JSON key `"reachable_by"` the places loader reads, `EvalVerdict`, the `cases` of `TestCaseBatch`, `CaseSource.CVE` or the quota key `cve_target`, and the committed records are not read.

## Appendix H. String references a move breaks or turns vacuous

"Vacuous" means the reference keeps passing after the move while checking nothing. Each fix comes with an assertion that would have caught the break.

### H.1 `Path(__file__)`-relative data lookups (re-anchored on `evals/`)

| file:line | today | fix |
|---|---|---|
| `evals/cve_places.py:27` | `HOLDOUT_PLACES = Path(__file__).parent / "holdout_places.json"` | `DETECTION_PLACES = Path(__file__).parents[1] / "detection_places.json"` |
| `evals/public_stand_ins.py:50` | `STAND_INS_DIRECTORY` from `parent` | `parents[1] / "stand_ins"` |
| `evals/docker_paths.py:3` | `DOCKER_DIRECTORY` from `parent` | `parents[1] / "docker"` (the re-admission dossier copies Dockerfiles to `out/evals/docker`, still right in the exported tree) |
| `evals/holdout_conditions.py:15` | `CONDITIONS_PATH` from `parent` | `parents[1] / "holdout_conditions.json"` |
| `evals/cve_baseline.py:40` | `CVE_BASELINE_DIRECTORY = parent / "baselines" / "cve"` | `DETECTION_BASELINE_DIRECTORY = parents[2] / "baselines" / "detection"` |
| `evals/nuisance_gate_baseline.py:26` | `parent / "baselines" / "nuisance"` | `parents[2] / "baselines" / "nuisance"` |
| `evals/dossier_closure.py:13` | `REPO_ROOT = parents[1]` | import `REPO_ROOT` from `evals.honeypots`. A wrong anchor makes `_module_file` find nothing, so the closure silently drops every repository module: a test asserts that the closure of a kit root holds `evals/cve/__init__.py` and `evals/cve/places.py` |
| `evals/holdout_fixtures/cve_2025_66335_doris.py:78`, `ghsa_8g7g_hmwm_6rv2_n8n.py:97` | `backend_sources` by `Path(<module>.__file__)` | none, follows the move |
| `evals/honeypots.py:26`, `evals/run_judge_eval.py:52` | top-level modules | none |
| `tests/unit/support/test_cve_grammar_golden_given.py:33`, `test_cve_layout_check_golden_given.py:29`, `test_cve_route_golden_given.py:18` | `Path(__file__).parent / "<golden>.json"` | rename each golden with its given (B) |
| `tests/integration/support/test_cve_calibration_given.py:15`, `test_cve_replay_given.py:29`, `test_mcp_client_transport_given.py:17` | resolve `cve_stub_server.py`, `cve_replay_stub_server.py` by name | the new names of B |

### H.2 Path strings in evals code

| file:line | today | fix |
|---|---|---|
| `evals/run_holdout.py:55`, `evals/run_census.py:49`, `evals/nuisance_commands.py:16`, `tests/unit/support/test_fixture_contamination_given.py:19` | `CENSUS_PATH` to `evals/holdout_census.json` | `evals/census.json` |
| `evals/run_census.py:47-48` | `output/holdout_census/{sources,work}` | `output/census/{sources,work}` |
| `evals/eval_session.py:35`, `evals/judge_baseline.py:14` | `baselines/honeypot_e2e.json`, `baselines/judge_isolation.json` | `baselines/honeypot.json`, `baselines/judge.json` (step 3) |
| `evals/nuisance_holdout_reference.py:21`, `:70` | `HOLDOUT_FIXTURES = evals/holdout_fixtures` and its message | `evals/cve/detection/holdout_fixtures` (a stale path makes `glob` return nothing, and the dossier refuses every server: loud) |
| `evals/cve_gate.py:19`, `evals/cve_recording_console.py:12`, `evals/cve_console.py:58`, `evals/run_cve_benchmark.py:155`, `:162` | `evals/baselines/cve` | `evals/baselines/detection` |
| `evals/run_evals.py:55`, `evals/draw_judge_cases.py:183`, `:184`, `evals/judge_draw_checks.py:30`, `evals/run_cve_benchmark.py:61`, `evals/run_holdout.py:56`, `evals/export.py:42` | default outputs and their readers | E.4 |
| `evals/nuisance_dossier.py:34`, `:80` | `NUISANCE_RULE = docs/nuisance-rule.md`, copied as `nuisance-rule.md` | `NUISANCE_SUITE_RULE = docs/nuisance-suite-rule.md`, `nuisance-suite-rule.md` (after this plan, with `tests/unit/test_nuisance_dossier.py:41,47` and the re-admission dossier test) |
| `evals/docker/compose.yml:96`, `:105` | comments citing `evals/public_stand_ins.py`, `evals/holdout_targets.py` | the new paths (step 4, comments are outside the label fingerprint) |

### H.3 String-built module names

| file:line | today | fix |
|---|---|---|
| `evals/holdout_kit/kit_backend_launch.py:21` | `importlib.import_module(f"evals.{key}_backend")` | `f"evals.cve.backends.{key}"` |
| `tests/unit/support/test_backend_lifecycle_given.py:27` | same | same |
| `evals/nuisance_readmission_dossier.py:114-115`, `:118` | closure roots `"evals.holdout_kit.benign_probe"`, `"evals.holdout_kit.kit_backend_launch"`, `f"evals.{provisioner}_backend"` | `"evals.cve.kit.benign_probe"`, `"evals.cve.kit.backend_launch"`, `f"evals.cve.backends.{provisioner}"` (a stale root raises in `_source_file`: loud) |
| `evals/nuisance_readmission_dossier.py:105` (`fix_check_modules`) | `getattr(importlib.import_module(name), "TARGETS", ())`: after the per-module `TARGETS` become `FIXTURES`, a stale name returns `()` for every module and the dossier copies no fix-check module | `"FIXTURES"` (step 4, with the per-module rename, `tests/unit/test_nuisance_readmission_dossier.py:166` pins the modules found: loud) |
| `evals/nuisance_dossier.py:51`, `:52` | `"evals.holdout_kit.kit_backends"`, `"evals.holdout_kit.benign_probe"` | `"evals.cve.kit.backends"`, `"evals.cve.kit.benign_probe"` (`"evals.capture_stand_in"` unchanged) |
| `evals/calibration_dossier.py:116-131` (`copy_clean_sources`) | `EVALS / f"{module}.py"` over `CLEAN_MODULES` (:33-46, 13 flat stems), `KIT_DIR = EVALS / "holdout_kit"` (:30), `KIT_MODULES` (:47, also passed by `nuisance_dossier.py:49` as `(*KIT_MODULES, "fix_check")`), the `holdout_kit` mkdir (:121), the copy of `evals/__init__.py` only | the module copies replaced by `dossier_closure.copy_closure(out, kit roots)`, which copies the transitive repository imports and every `__init__.py` on the way, so a later import change cannot leave the tree stale. The copies of `evals/stand_ins/` and of the sentinel and stand-in Dockerfiles stay in the function |
| `tests/integration/test_cve_planting.py:127`, `:137` | `monkeypatch.setattr("evals.cve_planting_docker._SENTINEL_PROBE_BUDGET", ...)` | `"evals.cve.planting_docker._SENTINEL_PROBE_BUDGET"` (loud: the module is not found) |
| `tests/unit/test_nuisance_readmission_dossier.py:95-96`, `:167-168`, `:174`, `:266`, `tests/unit/test_nuisance_dossier.py:135-136` | expected closure roots as dotted strings | the new roots |
| `tests/unit/support/holdout_kit_isolation.py:43-58` | `python -c importlib.import_module(...)` over names derived from the exported tree | none, follows the move |

### H.4 Dossier and kit texts agents read

| file:line | today | new text |
|---|---|---|
| `evals/calibration_dossier.py:136`, `:190`, `:253`, `:282-284` | the kit copies the places to `out/evals/holdout_places.json` and its texts name `holdout_places.json` | `out/evals/detection_places.json`, `detection_places.json` |
| `evals/calibration_dossier.py:170-187` (`_LAYOUT`, `layout.md`) | "as a dead condition", "the planting layer", `cve_layout.owned_layout`, `cve_layout.layout_mount_args`, `cve_layout.WORK` | "as an out-of-calibration reason", "the planting code", `evals/cve/layout.py` (`owned_layout`, `layout_mount_args`, `WORK`) |
| `evals/calibration_dossier.py:207-213` (`_FIXTURE_FORMAT`) | the transplant target `evals/holdout_targets.py`, `from evals.holdout_kit.kit_client import KitClient`, `from evals.holdout_kit.kit_launch import Launch` transplanted as `evals.cve_environments.Launch` | `evals/cve/detection/holdout_targets.py`, `from evals.cve.kit.client import KitClient`, `from evals.cve.kit.launch import Launch` transplanted as `evals.cve.environments.Launch` |
| `evals/calibration_dossier.py:215`, `:219`, `:220` | "wraps into a `CVETarget`", "`cve_id`: the drawn identifier", "`mechanisms`: the `frozenset` of grammar `MechanismClass` values" | "wraps into a `Target`", "`flaw_id`: the drawn flaw ID", "`classes`: the `frozenset` of grammar `FlawClass` values" |
| `evals/calibration_dossier.py:259`, `:268-269` (`_README`) | "A self-contained workshop for calibrating one holdout candidate", "the planting layer's sidecar", "the replay of a public service's capture" | "A self-contained kit for calibrating one holdout candidate", "the planting code's sidecar", "serves a public service's capture" |
| `evals/nuisance_dossier.py:110-140` (`fixture_format.md`), `:113`, `:121` | `FixCheckTarget` (4), "Author a `FixCheckTarget`", "`mechanism`: the grammar `MechanismClass`, or `None`.", "## Fields rule v3 adds", "## Fields rule v4 adds", "`source` is `holdout_calibration`" | `FixCheckFixture`, "Author a `FixCheckFixture`", "`effect_class`: the grammar `FlawClass`, or `None`.", "## Fields nuisance suite rule v3 adds", "## Fields nuisance suite rule v4 adds", "`source` is `detection_holdout_calibration`" |
| `evals/nuisance_dossier.py:235` | "the holdout fixture's launch" | "the holdout target's launch" |
| `evals/nuisance_dossier.py:246-300` (`_README`) | "A self-contained workshop", "the planting layer's sidecar", "(the replay of a public service's ...)", "the format the stand-in replays", "not a holdout twin", "rule v3 and v4 fields", `python -m evals.holdout_kit.benign_probe` (:292) | "A self-contained kit", "the planting code's sidecar", "(serves a public service's ...)", "the format the stand-in serves", "not the server of a holdout target", "nuisance suite rule v3 and v4 fields", `python -m evals.cve.kit.benign_probe` (`python -m evals.capture_stand_in` at :296 unchanged) |
| `evals/nuisance_readmission_docs.py:74` | "`evals/{backend}_backend.py`" | "`evals/cve/backends/{backend}.py`" |
| `evals/nuisance_readmission_docs.py:134-145` | "the first-admission workshop above", "of the holdout twin", `evals/nuisance_fix_checks/` | "the first-admission kit above", "of the holdout target", `evals/cve/nuisance/fix_checks/` |
| `evals/nuisance_readmission_docs.py:157-158`, `:168`, `:190-200` | `from evals.holdout_kit...`, `kit_launch.build_images`, the benign probe command, `from evals.nuisance_fix_checks.<module> import TARGETS` and `TARGETS[0]` | `from evals.cve.kit...`, `launch.build_images`, `python -m evals.cve.kit.benign_probe`, `from evals.cve.nuisance.fix_checks.<module> import FIXTURES` and `FIXTURES[0]` |
| `evals/holdout_kit/*.py` docstrings (copied into every kit) | "acceptance twin", "twin", "the workshop", "dead_conditions", "dead fixture", "the kit calibrates one target", "the nuisance twin", "the twin is nuisance_provisioners", "the twin is `run_nuisance vet`", "The role RecordingClient plays" | "the repository module it copies" (or the module named), "the kit", `not_live_reasons`, "a target out of calibration", "checks one target's calibration", the module named, "The role ExchangeLog plays" |
| `evals/nuisance_fix_checks/__init__.py` docstring | `evals.holdout_kit`, `evals.cve_*`, `evals/holdout_fixtures/` | `evals.cve.kit`, `evals.cve.*`, `evals/cve/detection/holdout_fixtures/` |
| `evals/nuisance_holdout_reference.py:22`, `:30` | the dossier directory `reference/holdout_fixtures/` | kept (agents read it, the name says what it holds) |

The tests that assert on the exported trees follow: `tests/unit/test_calibration_dossier.py:24` (`out/"evals"/"cve_places.py"`), `:42`, `tests/unit/test_run_holdout.py:204-210`, `tests/unit/test_nuisance_dossier.py:30-53`, `:66-68`, `:94`, `tests/unit/test_nuisance_readmission_dossier.py:113`, `:116` (`f"{provisioner}_backend.py"`), `tests/unit/test_run_nuisance.py:143`, and `tests/unit/support/test_calibration_dossier_given.py:15`, which loads the copied places module by file path. The test that runs an exported dossier with no repository on the path stays green.

### H.5 CI, packaging and configuration

| file:line | today | fix |
|---|---|---|
| `.github/workflows/cve-calibration.yml:7-18`, `:22-32` | path filters `evals/cve_*.py`, `evals/holdout_places.json`, `evals/run_cve_benchmark.py`, `evals/closed_network.py`, `evals/public_stand_ins.py`, the workflow's own name | E.5. Vacuous otherwise: with stale globs the job stops triggering on fixture changes. A unit test asserts that every path filter of the workflow matches at least one tracked file |
| `.github/workflows/cve-calibration.yml:60`, `:68`, `:74`, `evals.yml:62`, `eval-command.yml:121` | the commands | E.5 |
| `tests/integration/conftest.py:6` | imports `tests.integration.support.cve_stub_target` | `tests.integration.support.detection_fake_targets` |
| `pyproject.toml:92` | per-file ignore on `evals/run_judge_eval.py` | none (the entry point keeps its path). There is no pyright include and no evals path in ruff, pytest has `testpaths = ["tests"]`, and `langgraph.json` names only `src/` |
| `evals/eval_session.py:267` (`last_commit`) | `git log -- <path>` with no `--follow` records `census_commit` | none: after the `git mv` it reports the rename commit, which is report-only provenance |

### H.6 Tests whose scan would pass while checking nothing

| file:line | today | fix |
|---|---|---|
| `tests/unit/test_holdout_targets.py:149`, `:152` | `node.module == "evals.holdout_targets"`: after the move no import matches, so "no instrument imports the holdout targets" passes whatever | `"evals.cve.detection.holdout_targets"`, and the test asserts the module it names exists |
| `tests/unit/test_holdout_targets.py:26-37`, `:141` | `_INSTRUMENTS` as flat stems read through `_EVALS / f"{name}.py"` | relative paths (`cve/detection/session_model.py`, `detection_preflight.py`, `draw_judge_cases.py`, `capture_probe_corpus.py`, `run_detection.py`, `cve/detection/no_llm_modes.py`, `cve/detection/calibration_check_exit.py`, `cve/launch_audit.py`), each asserted to exist |
| `tests/unit/test_nuisance_fix_checks.py:34` | `name == "evals.cve_environments"`: "no fix check imports the environments" stops checking | `"evals.cve.environments"`, asserted to be an importable module |
| `tests/unit/test_nuisance_fix_checks.py:16` | `_FIX_CHECK_DIR = .../evals/nuisance_fix_checks`: `rglob` on a missing directory yields nothing, and both scans pass on an empty set | `evals/cve/nuisance/fix_checks`, and the test asserts the scan is non-empty (a fixed count would break on every fix check an admission adds) |
| `tests/unit/test_holdout_kit_isolation.py:16` | `_KIT_DIR = REPO_ROOT / "evals" / "holdout_kit"`: `scan_tree` on an empty `rglob` passes (only the negative control at :31 fails loud) | `evals/cve/kit`, and the test asserts the tree is non-empty |
| `tests/integration/test_cve_planting_stand_ins.py:43` | `caplog.at_level(..., logger="evals.cve_planting_docker")`: a stale name sets the level of an unused logger, and capture then depends on the root's level | `logger=planting_docker.__name__`, so the name follows the module (the loggers are `getLogger(__name__)`: `cve_planting_docker.py:40`, `cve_planting_base.py:28`, `closed_network.py:27`) |
| `evals/dossier_closure.py:13` | H.1 | H.1 |
| `.github/workflows/cve-calibration.yml` path filters | H.5 | H.5 |

### H.7 Living references to renamed test files

No pattern of G catches a test file path, and the codemod rewrites only Python imports and dotted module names. These references name a test file Appendix B renames and are rewritten in the step of that rename, from a grep of every old stem of Appendix B over the living files (dated log entries left as they are):

| file:line | today | fix | step |
|---|---|---|---|
| `CLAUDE.md:136` (Landmines) | `tests/integration/test_closed_networks.py` | `tests/integration/test_cve_closed_networks.py` | 4 |
| `CLAUDE.md:138` (Landmines) | `tests/unit/test_holdout_targets.py` | `tests/unit/test_detection_holdout_targets.py` | 4 |
| `CONTRIBUTING.md:14` | `test_closed_networks.py`, `test_cve_calibration.py`, `test_holdout_kit.py` | `test_cve_closed_networks.py`, `test_detection_calibration_check.py`, `test_kit.py` | 4 |
| `evals/fault_injection_method.md:9` | `tests/unit/test_eval_fault_injection.py` | `tests/unit/test_honeypot_fault_injection.py` | 3 |
| `evals/holdout_kit/__init__.py:4`, `evals/holdout_kit/kit_target.py:8` (copied into every kit) | `test_holdout_kit_isolation` | `test_kit_isolation` | 4 |
| `tests/unit/support/holdout_kit_isolation.py:3` | `test_holdout_kit_isolation`, `test_run_holdout` | `test_kit_isolation`, `test_run_detection_holdout` | 4 |
| `tests/integration/support/cve_replay_stub_server.py:2` | `cve_stub_server` | `detection_read_server` | 4 |

A pattern `moved-test` joins G, built by the test from the old stems of Appendix B (word-bounded, `_` a word character), enforced from step 5, with no allowlist entry.

## Appendix I. Naming choices the body does not list

- `admission_calibration.py` becomes `cve/detection/calibration_check_exit.py`, since `cve_calibration.py` takes `calibration_check.py`.
- `holdout_vetting.py` becomes `cve/detection/holdout_pre_run_check.py`: inside `detection/`, `holdout_` marks the holdout-layer modules.
- `nuisance_holdout_reference.py` becomes `cve/nuisance/holdout_target_reference.py` (and `write_holdout_target_references`), since bare "holdout" inside `nuisance/` would read as the nuisance holdout layer.
- `judging.py` becomes `honeypot/decision.py`, `gate_verdict.py` stays shared as `evals/gate_outcome.py`, `probe.py` becomes `probe/analysis.py`.
- `dead_conditions` and `patched_dead_conditions` become `not_live_reasons` and `not_fixed_reasons` in both the calibration check and the kit, their union being the out-of-calibration reasons.
- `CVEGateVerdict` is dropped for the shared `GateOutcome`, and the detection results take the `Detection` prefix (`DetectionReport`, `DetectionGateResult`, `DetectionBaseline`, `DetectionRunConditions`, `DetectionSessionResult`, `DetectionOptions`, `DetectionHarness`), with `CVEAudit` becoming `DetectionAudit` rather than `TargetAudit`, which would sit beside `AuditTarget`, and `CVEResult` becoming `TargetResult`.
- `calibrate_admitted`, `default_calibration_deps`, `CalibrationDeps` become `run_calibration_check`, `default_calibration_check_deps`, `CalibrationCheckDeps`, and `calibrate_all`, `calibrate_one`, `route_admits`, `admission_gave_up` become `check_calibrations`, `passes_calibration_check`, `has_route`, `layout_check_gave_up`.
- `MissClass` becomes `MissKind` and `PlantKind` becomes `PlaceKind`, both in step 4, where their fingerprints move anyway.
- `census_identifier()` becomes `flaw_id_of()`, not `flaw_id()`, which names fields throughout. `DrawWalkStep` becomes `DetectionWalkStep`.
- `mechanism_labels` becomes `class_labels`, `primary_controls` becomes `detection_rate_controls`, `hierarchical_interval`'s `detected_per_target` becomes `successes_per_member`, and `stale_holdout_copies` becomes `stale_holdout_calibration_copies`.
- `PhaseUsage` becomes `UsageBreakdown` ("phase" has no identifier), and `declared_flips.Suite` becomes `Instrument` (the judge eval is an instrument, not a suite), with the entry key `suite` becoming `instrument` in a file of zero entries.
- "Incomplete runs (a step refused or unreadable)" becomes "Incomplete runs (a model call refused or unreadable)", not "(a missed model call)", for the reason the rules give: a throttled call is retried and leaves N.
- The nuisance exit reason reads "the server of a current or dropped acceptance target", the rule's wording, and the report's section is "## Exits". The walk line reads "may count, pending the admission's class". The console warning reads "audit incomplete, see the missed model calls and coverage gaps above".
- The detection export's key `flaw_id` and its reader in `draw_judge_cases` move in step 3 with the export file name, both top-level modules. The reader of `detection_report.json` moves in step 4 with its writer. The progress label "Retesting" of `audit_progress.py` moves in step 3, as the body's step 3 lists it, although the module moves in step 4.
- Kept rather than renamed: `ExecutionConfig.budget` and `.chains`, `acceptance_services()`, `Gap`, `RecallFinding`, `recording_refusals`, `fixture_refusals`, the judge fixture's quota key `cve_target`, the golden case key `tests/nonce_only_in_the_report_target`, and the dossier directory `reference/holdout_fixtures/`.
- Bare "walk" is qualified in both rules. In the detection suite rule this takes six rows (DT26 to DT31), lines 27 and 228 included, and the settlements of the Census section read "the detection walk or the nuisance walk". In the nuisance suite rule NH2, NH3 and NH8 qualify it and NT30 and NT31 do the rest, leaving "that walk" (11) to its antecedent. The tables now hold 32 rows each.
- Every Dockerfile comment that carries a retired or moved word is reworded to the glossary, the comments the calibration agents wrote in `Dockerfile.holdout-*` included. At `e551cee` a pattern of G catches 53 comment lines in 41 Dockerfiles: the nine that cite a moved module and 32 others (in 27 Dockerfiles, eight of the lines in `Dockerfile.holdout-*`) are rewritten in step 4, and any comment carrying a moved word no pattern catches is read by sense there too. The four that cite `docs/nuisance-log.md` and the six that say "holdout log" (lines 18 and 1453 of the three frogman Dockerfiles) are rewritten with the rule versions after this plan. Only npm's own "installer stub" in the two serverless Dockerfiles is allowlisted. A comment is outside every Dockerfile hash (`dockerfile_instructions` drops it), so no image rebuilds and no fingerprint moves.
- G adds patterns for the central identifier renames (`cve-ident`, `mechanism-class`, `plant-kind`, `miss-class`, `reachable-by`, `entry-id`, `cve-id`, `census-names`, `fix-check-target`, `recording-names`, `verdict-names`, `acceptance-mark`, `version-setting-ident`, `primary-number`, `miss-causes`, `stand-in-target`, `calibrate-ident`, `eval-names`, `phase-usage`, `suite-enum`, `settle-gate`) and two that catch any stale module path under `evals/` (`moved-module`, `moved-module-other`). The goldens under `tests/unit/support/*.json` are historical, so their keys are not counted.
- The glossary log gains, beyond the lines the plan names, a line for each central identifier an older plan cites (E.9).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, on 2026-11-11, so that the conclusion survives until implementation and the implementation-phase fact check can read it. It records what was concluded once, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- SETTLED: `Field(validation_alias="verdict", serialization_alias="verdict")` with `model_config = ConfigDict(validate_by_name=True, serialize_by_alias=True)` dumps `verdict`, loads `verdict` and accepts `ruling=` in Python (verified against the pydantic ConfigDict docs, both options added in 2.11, and a local run on the locked pydantic 2.14.1)
- SETTLED: a plain `Field(alias="verdict")` writes the field name from `model_dump_json()` by default (verified by a local run on pydantic 2.14.1)
- SETTLED: two models of one class name in different modules get module-qualified `$defs` keys (`a__mod__X`), and a class docstring becomes the schema `description` (verified by a local run on pydantic 2.14.1)
- SETTLED: langgraph-checkpoint 4.3.0 revives an `EXT_PYDANTIC_V2` value with `cls(**kwargs)`, so a renamed field is dropped under the default `extra="ignore"`, and a class it cannot import is returned as its kwargs dict (verified against the installed `langgraph/checkpoint/serde/jsonplus.py`, version locked in `uv.lock`)
- SETTLED: `com.docker.network.bridge.gateway_mode_ipv4=isolated` with `--internal`, Docker Engine 28.0 or later (verified against the Docker Engine 28 release notes, 28.0.0 Networking, and the port-publishing docs)
- SETTLED: `main` has no branch protection, required status check or ruleset, so renaming the job `e2e-eval` to `honeypot-suite` breaks no required check (verified against the GitHub REST API, branches/main and rulesets)
- SETTLED: argparse's default prefix matching cannot map an old flag (`--calibrate`, `--cve`, `--ungated`, `--readmission`, `--cve-export`) onto a remaining flag, since none is a prefix of another flag of its parser, so each old flag is refused (verified against the `add_argument` calls of `evals/` at `e551cee`)
- No deferred external fact: the values left to implementation (the admission's `grammar_fingerprint`, the 17 `holdout_fingerprint` values, the log entry dates) are computed from the repository, not taken from an outside source

## Implementation steps

Ten steps, one commit each. They follow the body's five steps, with two refinements:

| implementation step | body step | what |
|---|---|---|
| 1 | 1 | model-inputs golden |
| 2 | 1 | retired-word test |
| 3 | 2 | auditor core |
| 4 | 3 | honeypot suite, judge eval, model probe, shared gate code |
| 5 | 4 | census |
| 6 | 4 | detection acceptance layer and the shared CVE plumbing |
| 7 | 4 | detection holdout layer and the kit |
| 8 | 4 | nuisance suite |
| 9 | 4 | the hashed CVE benchmark code (the one commit of the hashed files) |
| 10 | 5 | living docs |

Body step 4 is too large for one agent session (about 150 modules and 96 fixture modules moved, about 90 test files renamed, some 330 identifier rows, and the Docker checks). It is cut along the line that Invariant 3 draws. Steps 5 to 8 touch no hashed file and move no fingerprint. Step 9 is the only commit that touches a hashed file, and it writes the recorded copies once. Invariant 3 still holds: every fingerprint moves once, in step 9. The body's step 4 states this split, and step 9's log entries cover the whole series. Body step 1 is cut in two because its two safety nets are independent and each is a full session's work.

### Rules common to every step

- **Tags.** Retired-word pattern tags and Appendix step columns use the body's step numbers (the table above maps them). A pattern tagged 4 leaves `_NOT_YET_RENAMED` in the implementation step (5 to 9) that clears its last living hit outside the rules. Step 9 removes every tag-4 id still listed. Tag 5 ids leave in step 10. The two ids tagged "after this plan" (`holdout-rule-log`, `nuisance-rule-log`) stay in `_NOT_YET_RENAMED` when the plan ends, and `_NOT_YET_MIGRATED` still holds the two rules and the living preambles of their logs, the retired-word test green with both: the rule and log paths they catch change only with the rule versions after this plan.
- **Test-first.** A step first removes from `_NOT_YET_RENAMED` the ids it clears, adds its new assertions (alias, CLI, report-key, refusal tests), and runs them red with `uv run pytest <files> -n 0`. Then it renames.
- **Codemod.** A one-off script in the session's scratchpad directory, never in the repository, driven by the Appendix rows the step owns, in the order of C.0: `git mv` first, then module paths in imports and in dotted strings (longest old name first), then the distinctive identifiers (longer names first), then the generic names by hand with pyright strict as the net.
- **Hashed files (list H).** Untouched by steps 1 to 8, neither edited nor moved: `evals/cve_grammar.py`, `cve_proofs.py`, `cve_units.py`, `cve_report_units.py`, `cve_environments.py`, `holdout_environments.py`, `cve_layout.py`, `cve_places.py`, `cve_planting.py`, `cve_planting_base.py`, `cve_planting_spec.py`, `cve_planting_docker.py`, `cve_endpoint_address.py`, `public_stand_ins.py`, `cve_planting_stand_ins.py`, `closed_network.py`, `nuisance_counter.py`, `nuisance_counting.py`, `nuisance_confinement.py`, every `evals/*_backend.py`, `evals/holdout_places.json`, everything under `evals/stand_ins/` and `evals/docker/` (Dockerfile and `compose.yml` comments included). The codemod of steps 3 to 8 skips these paths, and a hit of a step's rename inside one of them means that rename belongs to step 9 (for example the `CVETarget` comment in `cve_environments.py`).
- **Moved only in step 9 (list M9).** `evals/nuisance_admission.py`, `evals/docker_paths.py`, `evals/backend_lifecycle.py`: hashed modules import them, so they keep their path until step 9. An earlier rename may edit their content (for example `NuisanceCensus` in `nuisance_admission.py` in step 8).
- **Deferred to step 9.** Every identifier a hashed file defines or references, whatever module also uses it: `EvalResult`, `eval_result(s)`, `EvalResult.payload`, `MechanismClass`, `mechanisms` (on `CVETarget`, `KitTarget`, `TargetInfo`, `CVEResult`, the grammar models, and every `mechanisms=` keyword), `CVEStatus`, `MissClass` and `miss_class`, `HOLDOUT_PLACES`, `REACHABLE_BY`, `reachable_by`, `PlantKind`, `entry_id`, `target_args`, `StandInRoute.target`, `probed_target` (with `capture_stand_in.py`), `_replay_the_seed`, the ckan `_read_only` argument, and the names `docker_paths`, `backend_lifecycle` and `nuisance_confinement` define. Also deferred: `dead_conditions` and `patched_dead_conditions` (cve calibration and kit driver), since the grammar golden master's keys are mapped once, and the `holdout_calibration` source value, since the dossier-schema golden is regenerated once. A user-facing string around a deferred name (a console line, a report label) is not deferred. A living doc line that cites a deferred name or value changes for it in step 9 (for example the `source` value in CLAUDE.md Commands line 47 and in the CHANGELOG nuisance lines), so no doc names a value the code does not yet write.
- **Living mentions follow the rename.** A step updates every living mention of what it renames or moves: code, docstrings, comments, dossier and kit texts, the CLAUDE.md lines (E.6, E.7, H.7), CONTRIBUTING, the README lines that cite a command, flag, env var, report key or path it renames (README's presentation is rewritten in step 10), the `Code:` fields of `docs/glossary.md`, the `docs/glossary-log.md` lines of E.9 (a line that groups renames of several steps lands with its last rename), and the `[Unreleased]` entries of E.8. A citation of `docs/holdout-rule.md`, `docs/holdout-log.md`, `docs/nuisance-rule.md` or `docs/nuisance-log.md` stays until the rule versions after this plan, except in a hashed module, where step 9 rewrites it to the rule's name and section (C.10). Bare "replay" and bare "the holdout" in a file the step owns are read and rewritten by sense.
- **Allowlist entries** of G.1 land in the step that creates the line they match, never earlier, since the test fails on a stale entry. A step that writes a CHANGELOG `(was ` line for a pattern id adds that id's G.1 `(was ` entry in the same commit (step 3 for `relayed-variables`, whose id leaves `_NOT_YET_RENAMED` there, step 9 for `eval-result` at the latest), and step 10 adds the ones still missing.
- **Retired words in the files a step touches.** Before closing, a step runs every pattern of G, `_NOT_YET_RENAMED` ignored, over the `.py` files of its diff (the docs and method notes follow their E.7 rows, the Dockerfile comments step 9) and rewrites each hit there that an Appendix row or the sense of the line gives it, apart from a deferred name and a rule or log citation, which wait for step 9 and for the rule versions after this plan, so that step 10 finds code hits only in files no step touched. A comment or docstring an agent wrote (a holdout fixture, a fix check, the kit) has no exemption: it is living code (Invariant 6).
- **Fingerprint snapshot (steps 3 to 8).** Before the first edit, a scratchpad script run from the repository root (`PYTHONPATH=. uv run python <script>`) writes to the scratchpad a JSON of: `grammar_fingerprint()`, `counter_fingerprint()`, `fixture_fingerprint` of every acceptance and holdout target (places loaded as `cve_baseline` loads them), `nuisance_fixture_fingerprint` of every server of `evals/nuisance_admission.json`, `dockerfile_fingerprint` of the `stand-in` and `sentinel` services, the honeypot ground truth fingerprint and the judge fixture's `inputs_fingerprint`. After the step, the same script with its imports updated to the step's moves must print byte-identical values. `git status --porcelain` must name no file of list H.
- **Golden.** `tests/unit/test_model_inputs_golden.py` stays green unregenerated in every step after step 1 but step 9.
- **Docker disk.** No step grows the Docker disk use beyond what the plan names. The clause is lifted for step 9 only: it rebuilds the stand-in image and builds every image its three checks need that is absent locally (about 40 at `e551cee`), builds that are expected, since they are the images the first holdout run needs anyway. Cleaning existing images is left to the maintainer.
- **Line numbers** in the appendices and in these steps are as of `e551cee`. After earlier steps (step 1 already adds a CLAUDE.md Commands line, shifting every later line of that file by one), locate a row by its symbol or text.

### Verification commands

- Red/green loop on the files being written: `uv run pytest <test files> -n 0`.
- Short loop: `uv run pytest tests/unit -n auto --maxprocesses 6`, then `--lf` on failures, then the full short loop again.
- Type check of changed files in the loop: `uv run pyright <files>`.
- Closing check of every step, all green: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`, and `uv run pytest tests/unit/test_model_inputs_golden.py tests/unit/test_glossary.py -n 0` (from step 2 on).
- Step 9 also runs the Docker checks it lists.

### Step 1: model-inputs golden

- **Files**: create `tests/unit/test_model_inputs_golden.py`, `tests/unit/support/test_model_inputs_golden_given.py`, `tests/unit/support/model_inputs_golden.json`. Modify `CLAUDE.md` (one Commands line beside the grammar golden master's).
- **Do**:
  - Write the test first: it loads the committed JSON and compares it entry by entry with what the given-module produces, naming the first differing key.
  - The given-module records, under stable keys sorted at the top level only, everything listed in the body's step 1 first bullet: every prompt builder and prompt constant of `src/mcp_auditor/graph/prompts.py` and `graph/chain_prompts.py`, `with_redaction_notice`, the redaction marker and `CATEGORY_GUIDANCE` on fixed inputs (reuse the given-modules already in `tests/unit/support/`), the judge prompt for the 78 cases of `evals/fixtures/judge_cases.json` through the public judging path, a graph-level capture of every prompt `FakeLLM` receives on one small audit, plain and with a relayed `--env` value, `model_json_schema()` of the six model-facing schemas as the string pydantic produces (key order kept), the OpenAI request body per schema through `tests/unit/support/test_llm_adapter_given.the_openai_request_body`, the Anthropic wire schemas, and `model_json_schema()` of `Classification`, `CalibrationCard`, `FlawRecord` and `AdmittedServer`.
  - One builder helper per domain type, so a constructor keyword renamed later (`EvalResult(payload=...)`, `TestCase(eval_result=...)`, the initial state keys) changes one line.
  - Module docstring: the golden is regenerated only in a commit that changes what reaches a model or an agent, never in a rename, and the one exception of this migration is the regeneration of `FlawRecord` and `AdmittedServer` in step 9 (`MechanismClass` to `FlawClass`, `holdout_calibration` to `detection_holdout_calibration`).
  - Regeneration entry point `python -m tests.unit.support.test_model_inputs_golden_given` on the pattern of `tests/unit/support/test_cve_grammar_golden_given.py`. Generate the JSON once from this tree and commit it.
  - CLAUDE.md Commands: `uv run python -m tests.unit.support.test_model_inputs_golden_given  # Regenerate the golden of what reaches a model or an agent, only in a commit that changes it`.
  - No production code changes.
- **Test**: the golden test passes on the committed JSON. As a local sanity check, never committed: change one character of a prompt builder's output and of one `Field(description=...)`, see the test fail naming the key, revert. The JSON holds no module-qualified `$defs` key.
- **Verify**: closing check green, `git diff --stat` lists only the four files above.

### Step 2: retired-word test

- **Files**: create `tests/unit/test_glossary.py`, `tests/unit/support/test_glossary_given.py` (a `test_glossary_then.py` only if an assertion abstracts something).
- **Do**:
  - The machinery of the body's step 1 second bullet and Appendix G: the living and historical file sets as G's introduction defines them (paths count, with `_`, `/`, `.` and `-` as word boundaries), the `[Unreleased]` cut of CHANGELOG.md, the living preambles of the three logs, every pattern of G with its id, regex, flags and body-step tag, and the `moved-test` pattern of H.7 built from the old stems of Appendix B (tag 5).
  - `_NOT_YET_RENAMED` holds every pattern id. `_NOT_YET_MIGRATED` holds `docs/holdout-rule.md`, `docs/nuisance-rule.md` and the living preambles of `docs/holdout-log.md` and `docs/nuisance-log.md`.
  - The allowlist of `(path glob, pattern id, line substring, reason)`, with the G.1 entries whose line exists at this commit: the `docs/glossary.md` entries and npm's `installer stub` in the two serverless Dockerfiles. Every other G.1 entry lands later, with its line.
  - The test fails on an allowlist entry that matches no line, and asserts that CLAUDE.md carries the `@docs/glossary.md` line.
  - Sanity pass, not committed: run each pattern while ignoring `_NOT_YET_RENAMED` and compare with G's "current hits". A pattern with no hit, or far from its count, is a transcription error to fix.
- **Test**: green with every id exempt. Machinery cases on fixture trees built in the given-module: a pattern fires on a living file, is skipped on a historical one (an ADR, a plan, a dated log entry, a published CHANGELOG section), is skipped while in `_NOT_YET_RENAMED`, a file in `_NOT_YET_MIGRATED` is skipped, an allowlisted line passes, a stale allowlist entry fails, a missing `@docs/glossary.md` line fails.
- **Verify**: closing check green.

### Step 3: auditor core

- **Files**: `src/mcp_auditor/` (`domain/models.py`, `domain/rendering.py`, `domain/__init__.py`, `graph/state.py`, `graph/nodes.py`, `graph/chain_nodes.py`, `graph/stream_handler.py`, `graph/missed_steps.py` to `graph/missed_model_calls.py`, `audit.py`, `cli.py`, `console.py`, `progress.py`, `config.py`, `checkpointing.py`, `target_execution.py` to `server_execution.py`, `adapters/server_launch.py`, `adapters/chat_model_factory.py`), the evals call sites outside list H (`audit_attempts.py`, `failure_text.py`, `launch_audit.py`, `honeypots.py`, `metrics.py`, `eval_display.py`, `run_probe.py`, `probe_candidates.py`), `.env.example`, the tests that use the renamed names (`test_missed_steps.py` and `test_target_execution.py` with their companions renamed per B, `test_checkpointing.py`, and the call sites the codemod finds), `CLAUDE.md:61`, CONTRIBUTING (E.7 rows tagged 2), CHANGELOG `[Unreleased]`, `tests/unit/test_glossary.py`.
- **Do**: the body's step 2 and every C.1 row, C.2 and E rows tagged 2: `AuditStep` to `ModelCallKind` with `JUDGE_CALLS`, `CHAIN_CALLS`, `is_judge_call`, `is_chain_call`, `MissedStep` to `MissedModelCall` (field `step` to `kind`), `missed_steps` to `missed_model_calls` (field, channel, `RunDetail`, report key), `ModelCall.step` to `kind`, `Missed.missed_step` to `missed_call`, `chain_step_missed` to `chain_model_call_missed`, `judged_cases` to `processed_cases` (not `export_judged_cases` and `judged_cases.jsonl`, C.11), `ExecutionConfig` to `AuditRunOptions` and `AuditConfig.execution` to `run_options`, `TargetExecution` to `ServerExecution`, the audited-server `target` to `server_command` (state channel, `ServerLaunch`, CLI positional and `SERVER_COMMAND` usage, report key, LangSmith metadata key, Markdown "Server command", the resume message of `audit.py:138`), `relayed_variables` to `redacted_variables`, `openrouter_hosts` to `openrouter_providers` (env var `MCP_AUDITOR_OPENROUTER_PROVIDERS`, probe report key), and the E.1 strings tagged 2. Before each rename, grep list H: `EvalResult`, `eval_result` and `arguments` wait for step 9.
  - Checkpoint refusal as the body settles: `_EARLIER_VERSION_CHANNELS` gains `target`, `judged_cases`, `missed_steps`, `chain_step_missed`, the refusal also reads the keys of the `__start__` input, the comment above it rewritten (a renamed field is dropped on revive), the message unchanged.
  - CHANGELOG: the Breaking entry gains `server_command`, "Server command", `redacted_variables` and the refused resume, the `missed_steps` and `MCP_AUDITOR_OPENROUTER_HOSTS` entries edited in place (E.8).
  - G.1 allowlist entries for the checkpoint lines, the report-key test and the CHANGELOG `(was ` line of `relayed-variables`. Remove the tag-2 ids from `_NOT_YET_RENAMED` first, and rewrite every hit they then report, the tag-2 patterns with no C or E row included (for example the four comments `acceptance-test` finds in `src/mcp_auditor/adapters/server_launch.py` and three integration tests).
- **Test** (written first): parametrized refusal for a checkpoint holding each of `target`, `judged_cases`, `missed_steps`, `chain_step_missed`, a `__start__`-only thread with the old `target` key refused, one checkpoint written with the old class names refused, a current checkpoint resumes, the pinned unconfined thread id unchanged. A report-key test (path chosen here, named in its allowlist entry): the JSON report carries `server_command`, `redacted_variables`, `missed_model_calls` with `kind`, and none of `target`, `relayed_variables`, `missed_steps`. `mcp-auditor run --help` shows `SERVER_COMMAND`. The settings read `MCP_AUDITOR_OPENROUTER_PROVIDERS`.
- **Verify**: closing check green, fingerprint snapshot identical, no file of list H touched, golden green unregenerated.

### Step 4: honeypot suite, judge eval, model probe and shared gate code

- **Files**: the moves of A.2.4, A.2.5, A.2.6 and `gate_verdict.py` to `gate_outcome.py`, `run_evals.py` to `run_honeypot_suite.py`, new `evals/honeypot/__init__.py`, `evals/judge/__init__.py`, `evals/probe/__init__.py`, the shared top-level modules (`gate.py`, `baseline.py`, `eval_display.py`, `cell_grid.py`, `metrics.py`, `recording.py`, `declared_flips.py`, `eval_session.py`, `export.py`, `draw_judge_cases.py`, `run_judge_eval.py`, `run_probe.py`, `capture_probe_corpus.py`), the CVE call sites of the shared names outside list H, `git mv` of the two baselines (D), `evals/fixtures/fault_injection_baseline.json`, `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`, the test renames of B tagged 3, `docs/labeling-log.md`, `evals/fault_injection_method.md:9` (H.7 only), CLAUDE.md, CONTRIBUTING, CHANGELOG, `docs/glossary-log.md`, `tests/unit/test_glossary.py`.
- **Do**: the body's step 3, with every row tagged 3 of A, B, C (C.6's `AuditProgress._replaying` with its "Retesting" label and C.8's `TargetCost.usage` type included), D, E.2 to E.6, E.9 and H.7. In short: `RetestRule` (field `retests`, `decide_retests`) read through `AliasChoices("retest_rule", "replay_rule")` and `AliasChoices("retests", "replays")` and written with the new keys, `apply_retests`, `GateOutcome` and the result field `outcome`, the `decide` verbs (`decide_gate`, `decide_runs`, `decide_judge_gate`), `BaselineStatus.UNCONFIRMED`, `CellTag.FALSE_POSITIVE` and `IMPROVED` with their legends, `HoneypotMetrics`, `UsageBreakdown`, `declared_flips.Instrument` and the entry key `instrument`, `Retester` and the retest names, `GateRow.subject`, `CapturingLLM`, `--no-baseline` on the honeypot suite and the judge eval, the `--detection-export` flag with `output/detection_judged_cases.jsonl` and its `flaw_id` key (writer and reader together), `output/honeypot_report.json`, the columns "Retests", the progress "Retesting", the metric label "Distribution coverage". The codemod updates the call sites of the shared names in CVE modules (`cve_console`, `cve_markdown`, `cve_baseline`, `cve_costs`, the nuisance gate modules). No hashed module references any of them: confirm by grep over list H. `PENDING_REPLAY` waits for steps 6 and 8.
  - `docs/labeling-log.md`: one entry stating that the scoring code of the honeypot suite and the judge eval moved and was renamed with no change to what it grades (ground truth fingerprint and judge inputs fingerprint unchanged, both baselines moved by `git mv`, confirmed, not reset) and that `replay_rule` is read through an alias until the next re-recording.
  - Allowlist entries of G.1 for the alias lines (`evals/baseline.py`, `evals/judge/baseline.py`), the baseline tests and the CLI tests of the old flags.
- **Test** (written first): each committed baseline loads through the alias and gates, a written baseline carries `retest_rule` and `retests`, the fault-injection fixture loads, `run_honeypot_suite` and `run_judge_eval` parse `--no-baseline` and refuse `--ungated`, `draw_judge_cases` parses `--detection-export` and refuses `--cve-export`, the export writes `detection_judged_cases.jsonl` with `flaw_id` and `draw_judge_cases` reads it, the grid prints `false_positive` and `improved`, a declared-flip entry with `instrument` loads.
- **Verify**: closing check green, fingerprint snapshot identical (honeypot ground truth and judge inputs fingerprints included), `git diff -M --stat` shows both baselines as 100 % renames, no file of list H touched, golden green unregenerated.

### Step 5: census

- **Files**: new `evals/cve/__init__.py`, `evals/cve/census/__init__.py`, `evals/cve/detection/__init__.py`, the moves of A.2.10 and `census_draw.py` to `evals/cve/detection/draw_record.py`, `git mv evals/holdout_census.json evals/census.json` and `git mv evals/holdout_census_method.md evals/census_method.md`, `evals/run_census.py` (gains `draw-order`), `evals/run_holdout.py` (loses `draw-order`, census path), `evals/nuisance_commands.py` (census path), the census and draw-record call sites, the B rows of these modules (`test_census_draw.py`, `test_holdout_census.py`, `test_holdout_draw.py` with their givens), `tests/unit/support/test_fixture_contamination_given.py:19`, `tests/unit/support/test_nuisance_walk_record_given.py`, CLAUDE.md Commands lines 37, 40, 41, CONTRIBUTING lines 52 and 54 (census paths), CHANGELOG, `docs/glossary-log.md`, `tests/unit/test_glossary.py`.
- **Do**: the C.7 rows (`HoldoutCensus` to `Census`, its error literal, `census_identifier` to `flaw_id_of`, `BENCHMARK_FLAWS` to `ACCEPTANCE_TARGET_FLAWS` with its comment, `CENSUS_PATH` to `census.json` in the three modules, `SOURCES` and `WORK` to `output/census/{sources,work}`, `DrawWalkStep` to `DetectionWalkStep`), and `Settlement.verdict` to `ruling` with `Field(validation_alias="verdict", serialization_alias="verdict")` and `ConfigDict(validate_by_name=True, serialize_by_alias=True)` as the body settles. `run_holdout draw-order` becomes `run_census draw-order` (its tests move to `test_run_census.py`). `VulnerableMcpEntry.cve_id` and the census JSON's `cve_id` values stay (C.11), with their three G.1 allowlist entries (`evals/cve/census/work.py`, `evals/cve/census/progress.py`, `tests/unit/support/test_census_given.py`). The `run_census` descriptions of E.2. The E.9 lines `HoldoutCensus`, `evals/holdout_census_method.md`, `output/holdout_census/`. The method note's words wait for step 10.
- **Test** (written first): `load_census` passes on `evals/census.json`, a dumped `Settlement` carries the key `verdict` and reloads, Python constructs it with `ruling=`, the walk record round trip of `test_nuisance_walk_given.py:160` passes, `run_census draw-order` parses and prints the draw order, `run_holdout draw-order` is refused.
- **Verify**: closing check green, fingerprint snapshot identical, `git diff -M --stat` shows the census and the method note as 100 % renames, no file of list H touched.

### Step 6: detection acceptance layer and the shared CVE plumbing

- **Files**: the moves of A.2.2 `run_cve_benchmark.py` to `run_detection.py` and `cve_preflight.py` to `detection_preflight.py`, of A.2.7 `cve_images`, `cve_recording_client` (to `exchange_log`), `launch_audit`, `audit_attempts`, `audit_progress`, `failure_text`, `provider_errors`, `server_health`, `run_images`, and of A.2.11 `admission_calibration` (to `calibration_check_exit`), `cve_audit`, `cve_baseline`, `cve_benchmark_modes` (to `no_llm_modes`), `cve_calibration` (to `calibration_check`), `cve_console`, `cve_costs`, `cve_exploits`, `cve_gate`, `cve_layout_check`, `cve_markdown`, `cve_measurement`, `cve_oracle`, `cve_recording`, `cve_recording_console`, `cve_replay`, `cve_route` (to `route_check`), `cve_session`, `cve_session_model`, `cve_session_recording`, `cve_survey`, `cve_targets`. The B rows of these modules (unit, `tests/unit/support/`, and integration with `cve_replay_stub_server.py`, `cve_stub_server.py`, `cve_stub_target.py` and `tests/integration/conftest.py`), the layout check and route check goldens renamed with their regenerators (keys unchanged), `git mv .github/workflows/cve-calibration.yml .github/workflows/detection-calibration-check.yml`, the call sites in every other module outside list H (the 37 holdout fixture modules and the kit included), `tests/unit/test_holdout_targets.py` (`_INSTRUMENTS` as relative paths of H.6, each asserted to exist, since every module it lists moves here or keeps its top-level path), CLAUDE.md Commands lines 25 (wording, not the `planting_docker` path), 26 to 33 and 52, CONTRIBUTING (E.7 detection rows tagged 4: lines 37, 41 to 47, 50, 84, 112, 169, and the `test_cve_calibration.py` path of line 14, H.7), CHANGELOG, `docs/glossary-log.md`, `tests/unit/test_glossary.py`.
- **Do**: the C.8 rows of these modules and the E.2 to E.6 rows of `run_cve_benchmark`, `cve_measurement`, `cve_calibration`, `cve_layout_check`, `cve_oracle`, `cve_costs`, `cve_markdown`, `cve_console`, `cve_gate`, `cve_recording`, `cve_session`, `cve_recording_console`, `cve_targets` and `capture_probe_corpus` (`{target.flaw_id}`, line 52), apart from the deferred names. In short: `CVETarget` to `Target`, `CVETarget.cve_id` to `flaw_id` everywhere it is that field (every holdout fixture's `cve_id=`, `KitTarget.cve_id` for the isolation test's field parity, the dossier text that documents them), `CVE_TARGETS` to `ACCEPTANCE_TARGETS`, `OutOfScopeCVE`, `OUT_OF_SCOPE_CVES`, `cve_oracle.TargetStatus` to `ResultStatus` (frees the name, `CVEStatus` waits for step 9), `CVEResult` to `TargetResult` with its `flaw_id` and `not_run_reasons` keys, `CVEBenchmarkReport` to `DetectionReport`, `CVEGateVerdict` dropped for `GateOutcome`, `CVEGateResult` to `DetectionGateResult` with `outcome`, `TargetOutcome.PENDING_RETEST`, `retests`, `apply_retests`, `decide`, the `Detection` prefix of Appendix I, `DETECTION_BASELINE_DIRECTORY` (`parents[2] / "baselines" / "detection"`, H.1), `--calibration-check`, `--flaw`, `--no-baseline`, `DETECTION_CONCURRENCY`, the next-step flags, `output/detection_report.json` with its reader in `draw_judge_cases` and `judge_draw_checks`, the calibration-check and layout and route check names of C.8 (`check_calibrations`, `passes_calibration_check`, `run_calibration_check`, `default_calibration_check_deps`, `CalibrationCheckDeps`, `check_layouts_and_routes`, `layout_check_gave_up`, `has_route`, `_report_out_of_calibration`) and their console strings ("out of calibration", "Layout and route checks (no LLM)"), `ExchangeLog`, `MEASUREMENT_NEEDS_NO_BASELINE`, the "struck" credits label, the "bare repository" note, the docstrings and comments of C.8. Deferred to step 9: the deferred names of the common rules (here `mechanisms`, `MechanismClass`, `CVEStatus`, `miss_class` and the "Miss kind" column, `dead_conditions`, `patched_dead_conditions`). `VulnerableMcpEntry.cve_id` stays.
  - Workflow: the file, its name `Detection calibration check`, the job `calibration-check`, its steps and commands of E.5, `python -m evals.detection_preflight`, `run_detection --calibration-check --ci`. Path filters, today's coverage translated (E.5), never `evals/cve/**`: the new paths valid at this step (`evals/cve/*.py`, `evals/cve/detection/*.py`, `evals/run_detection.py`, `evals/detection_preflight.py`, the workflow's own new name in the push list), plus the old paths still valid until step 9 (`evals/cve_*.py`, `evals/closed_network.py`, `evals/public_stand_ins.py`, `evals/holdout_places.json`), and the filters that do not move. A new unit test asserts that every path filter of the workflow matches at least one tracked file (H.5).
  - E.9 lines `.github/workflows/cve-calibration.yml`, `CVETarget, CVE_TARGETS`, `evals.cve_preflight`, `output/cve_judged_cases.jsonl, output/cve_report.json`. G.1 allowlist entries for the CLI tests of `--calibrate`, `--cve` and `--ungated` on `run_detection`.
- **Test** (written first): `run_detection` parses `--calibration-check`, `--flaw ID`, `--no-baseline` and refuses `--calibrate`, `--cve`, `--ungated`, the detection report carries `flaw_id`, `not_run_reasons`, `outcome`, `retests`, `pending_retest`, the gate outcome of a candidate equals the shared `GateOutcome` value, the workflow path filter test, the layout and route check goldens pass unregenerated under their new names.
- **Verify**: closing check green, fingerprint snapshot identical (every acceptance and holdout fixture fingerprint included), no file of list H touched, golden green unregenerated.

### Step 7: detection holdout layer and the kit

- **Files**: the moves of A.2.2 `run_holdout.py` to `run_detection_holdout.py`, of A.2.7 `dossier_closure`, `run_files`, `run_interruption`, `fixture_provenance`, `fixture_sources`, `holdout_conditions`, `holdout_intervals`, `holdout_hierarchical`, `holdout_statistic`, of A.2.9 (the kit to `evals/cve/kit/`), of A.2.11 `calibration_dossier`, `holdout_assembly`, `holdout_audit`, `holdout_card_readiness`, `holdout_markdown`, `holdout_not_run`, `holdout_report`, `holdout_results`, `holdout_run`, `holdout_targets`, `holdout_vetting` (to `holdout_pre_run_check`) and the package `evals/holdout_fixtures/` (to `evals/cve/detection/holdout_fixtures/`). The B rows of these modules (with `tests/unit/support/holdout_kit_isolation.py` to `kit_isolation.py`, integration `test_holdout_kit.py`, `test_holdout_kit_client.py`), the import lines of the 58 fix-check modules, `evals/nuisance_dossier.py` and `evals/nuisance_readmission_dossier.py` and `nuisance_readmission_docs.py` and `nuisance_holdout_reference.py` (kit roots, kit text, `HOLDOUT_FIXTURES` path, at their old paths), the dossier tests (H.4), CLAUDE.md Commands lines 42 to 44 and Landmine line 138, CONTRIBUTING lines 14 and 54 and the `holdout_kit` path of line 56, CHANGELOG, `docs/glossary-log.md`, `tests/unit/test_glossary.py`.
- **Do**: the C.6, C.8 and E rows of these modules, apart from the deferred names: `ConclusionVerdict` to `Conclusion`, `primary_number` to `holdout_detection_rate` (report key), `primary_controls`, `successes_per_member`, `mechanism_labels` to `class_labels` (the value expression keeps `target.mechanisms` until step 9), `miss_causes` to `missed_call_causes` in the holdout results and report, `flaw_id` keys of the result and report files, `check_before_run`, `_check_one`, `not_run_reason` and the reason "out of calibration: ", `calibration-check` subcommand and `--flaw` flags of `run_detection_holdout`, its descriptions and refusals (E.2), `output/detection_holdout_report.json`, the holdout markdown headings (E.3), the run conditions messages, the card readiness message, `write_kit(census, flaw_id, out)` and its refusal, `KitExchangeLog`, `unserved_captures(stand_in, stand_in_dockerfile, root)`, `CONDITIONS_PATH` re-anchored (`parents[1]`, H.1).
  - Kit export: `copy_clean_sources` replaced by `dossier_closure.copy_closure` over the kit roots (`evals.cve.kit.client`, `.launch`, `.target`, `.driver`, plus `.fix_check` for the nuisance dossier), still copying `evals/stand_ins/`, `Dockerfile.sentinel` and `Dockerfile.stand-in`. `dossier_closure.REPO_ROOT` imported from `evals.honeypots` (H.1). At this step the hashed modules the kit imports are still flat (`evals/cve_places.py` and the rest), so the closure copies them at their current paths, and step 9 moves them.
  - Kit and dossier texts of H.4 for what this step moves: the kit's paths and import lines, `python -m evals.cve.kit.benign_probe`, `evals/cve/detection/holdout_targets.py` as the transplant target, the kit's own docstrings ("twin", "workshop", "the role RecordingClient plays", the isolation test name of H.7), "A self-contained kit". The texts that name a hashed module's path or `holdout_places.json` wait for step 9. Closure roots of H.3 for the kit (`evals.cve.kit.benign_probe`, `evals.cve.kit.backend_launch`, `evals.cve.kit.backends`), while `f"evals.{key}_backend"` waits for step 9.
  - H.2 `HOLDOUT_FIXTURES` to `evals/cve/detection/holdout_fixtures`. H.6 scans: `test_holdout_targets.py` matches `"evals.cve.detection.holdout_targets"` and asserts that module exists (its `_INSTRUMENTS` became relative paths in step 6), `test_holdout_kit_isolation.py`'s `_KIT_DIR` to `evals/cve/kit` with a non-empty assertion.
  - E.9 lines `evals/holdout_fixtures/`, `primary_number`, `output/holdout_report.json`, `RecordingClient, KitRecorder, RecordingLLM`, and the existing line `` `evals/holdout_kit/` | kit `` gaining its new path (E.9 introduction).
- **Test** (written first): the closure of a kit root holds `evals/cve/__init__.py`, `evals/cve/kit/__init__.py` and `evals/cve_places.py` (step 9 turns the last into `evals/cve/places.py`), the exported calibration kit and nuisance dossier run with no repository on the path (the existing test that runs an exported dossier), `run_detection_holdout` parses `calibration-check`, `--flaw` and `run`, and refuses `calibrate` and `--cve`, the holdout report and result files carry `holdout_detection_rate`, `flaw_id`, `class_labels`, `missed_call_causes`, the isolation scans are non-empty.
- **Verify**: closing check green, fingerprint snapshot identical, no file of list H touched, golden green unregenerated, and a one-off scratchpad check that the closure of the kit roots equals today's `CLEAN_MODULES` plus the kit modules and their `__init__.py` files (not committed: a committed list would break on every new kit import).

### Step 8: nuisance suite

- **Files**: the moves of A.2.12 apart from `nuisance_admission.py` (M9), `nuisance_confinement.py`, `nuisance_counter.py` and `nuisance_counting.py` (list H), with the package `evals/nuisance_fix_checks/` to `evals/cve/nuisance/fix_checks/` and new `evals/cve/nuisance/__init__.py`, `evals/run_nuisance.py`, `evals/nuisance_admission.py` (content only: its imports of the modules this step moves and `NuisanceCensus`), the kit's `fix_check.py` (`FixCheckTarget`), the B rows tagged 4 of these modules, `tests/unit/test_nuisance_fix_checks.py` (`_FIX_CHECK_DIR`), the nuisance tests the codemod finds, CLAUDE.md Commands lines 45 to 51 (line 47's `source` value waits for step 9) and the `FixCheckTarget` of Landmine line 133, CONTRIBUTING (lines 56, 58, 170), CHANGELOG, `docs/glossary-log.md`, `tests/unit/test_glossary.py`.
- **Do**: the C.9 rows and the E rows of these modules, apart from the deferred names (`MechanismClass`, `holdout_calibration`, `_replay_the_seed`, the ckan argument, the counter's `EvalResult`). In short: `fix-check` subcommand, `--flaw`, `--re-admission` with their help and refusal texts ("no server is admitted", "matches no fix-check fixture"), `FixCheckDeps`, `default_fix_check_deps`, `check_fixes`, `FixCheckTarget` to `FixCheckFixture`, its field `mechanism` to `effect_class` (the `mechanism=` keyword of the 53 fix-check modules, keeping `MechanismClass.X` until step 9), the local `target` to `fixture` in `fix_check.py`, `FIX_CHECK_FIXTURES`, the per-module `FIXTURE`, `FIXTURES` (with the `"TARGETS"` string of `fix_check_modules`, H.3), `ADD_COMMENT_FIXTURE`, `CREATE_ISSUE_FIXTURE`, the re-admission names, `holdout_nuisance_rate` and `exits` (report keys and `## Exits`), `ServerExit`, `ExitLine`, the gate's `outcome`, `PENDING_RETEST`, `retests`, `apply_retests`, `decide`, `retest_rule` of the nuisance baseline (no file committed, no alias), `nuisance_acceptance_servers` before `acceptance_target_servers`, `ServerMark.ACCEPTANCE_TARGET_SERVER`, the exit reason text, `candidate_counted_flaws`, `_may_count`, `WalkInputs`, `committed_walk_inputs`, `walk_inputs`, `missed_call_causes`, "a model call refused or unreadable", `write_holdout_target_references`, `stale_holdout_calibration_copies`, the `real_software` names, `_print_vet_results`, `parents[2] / "baselines" / "nuisance"` (H.1), the re-admission dossier and docs texts of H.4 for what this step moves (`evals/cve/nuisance/fix_checks/`, `FIXTURES`, "of the holdout target", "nuisance suite rule v3 and v4 fields"). `NUISANCE_RULE` and the copied rule's name wait for the rule versions after this plan. The E.2 strings of `run_nuisance`, `nuisance_gate_command`, `nuisance_unrecorded` and `nuisance_vet_command`.
  - H.6: `_FIX_CHECK_DIR` to `evals/cve/nuisance/fix_checks` with a non-empty scan assertion (no fixed count). The scan for `evals.cve_environments` waits for step 9.
  - The G.1 allowlist entries for `evals/cve/nuisance/fix_checks/cve_2025_69256_serverless.py` (`installer stub`) and the CLI tests of `--readmission` and `calibrate`.
  - E.9 lines `acceptance_servers()`, `evals/nuisance_fix_checks/`, `figure, outside_figure`, `FixCheckTarget`, `NuisanceCensus`, `--readmission`, `version_setting`, `settle`, `miss_causes`.
- **Test** (written first): `run_nuisance` parses `fix-check`, `--flaw`, `nuisance-dossier --re-admission`, and refuses `calibrate`, `--cve`, `--readmission`, the nuisance report carries `holdout_nuisance_rate` and `exits` and its Markdown `## Exits`, the gate report carries `outcome`, `retests`, `pending_retest`, `acceptance_target_servers()` includes a dropped target's server and `nuisance_acceptance_servers()` does not, the fix-check scan is non-empty.
- **Verify**: closing check green, fingerprint snapshot identical (every nuisance fixture fingerprint and the counter fingerprint included), no file of list H touched, `nuisance_admission.py`, `docker_paths.py` and `backend_lifecycle.py` still at their old paths, golden green unregenerated.

### Step 9: the hashed CVE benchmark code

The only commit that touches list H. Everything the body's step 4 lists and steps 5 to 8 left lands here.

- **Files**: the moves of A.2.7 for the hashed modules and `docker_paths.py`, of A.2.8 (every backend with `backend_lifecycle.py`, `apify_backend.py`, `neo4j_backend.py`, new `evals/cve/backends/__init__.py`), of A.2.11 `holdout_environments.py`, of A.2.12 `nuisance_admission.py`, `nuisance_confinement.py`, `nuisance_counter.py`, `nuisance_counting.py`, `git mv evals/holdout_places.json evals/detection_places.json`, `evals/capture_stand_in.py`, the 24 captures under `evals/stand_ins/`, `evals/docker/Dockerfile.stand-in`, the Dockerfile comment lines of Appendix I that step 9 rewrites (the nine citing a moved module and the 32 others) and `evals/docker/compose.yml` comments (lines 6, 7, 12, 96, 105), the agent-written comments and docstrings the last pass finds in `holdout_fixtures/`, `fix_checks/` and the kit, `evals/nuisance_admission.json`, `tests/unit/support/cve_grammar_golden.json` (keys), `tests/unit/support/cve_grammar_golden_corpus.py`, `tests/unit/support/model_inputs_golden.json` (two schemas), the core files of `EvalResult` (src, `export.py`, `metrics.py`, tests), the call sites of every deferred name, the B rows of `test_closed_network*`, `test_closed_networks*` and `test_public_stand_ins*`, the remaining H.1, H.3, H.4 and H.6 rows, the workflow path filters, `docs/holdout-log.md`, `docs/nuisance-log.md`, `docs/labeling-log.md`, CLAUDE.md (Commands lines 9, 25 path, 34, 35, Landmines 131 to 136), CONTRIBUTING, `docs/glossary.md` (`Code:` fields such as `evals/closed_network.py`), `docs/glossary-log.md`, CHANGELOG, `tests/unit/test_glossary.py`.
- **Do**:
  - Write first: the tests below, and remove every tag-4 id still in `_NOT_YET_RENAMED`.
  - Moves and every remaining rename: the core (`EvalResult` to `JudgeResult`, `payload` to `arguments`, `eval_result(s)` to `judge_result(s)`, `_chain_judge_result`, Markdown "Payload" to "Arguments", the Breaking CHANGELOG entry gaining `judge_result` and `arguments`), C.6 for the hashed modules (`FlawClass` everywhere including the 37 holdout fixtures and 53 fix checks, `classes`, `TargetStatus` for `CVEStatus`, `MissKind` and `miss_kind` with the report key and the "Miss kind" column, the proofs docstring, `DETECTION_PLACES` re-anchored on `parents[1] / "detection_places.json"`, `REACHES`, `Place.reaches` still reading the JSON key `reachable_by`, `PlaceKind`, `place_id`, `server_args`, `request_target` and `probed_request_target` with their validators and load-error literal, the capture writer and its messages, `STAND_INS_DIRECTORY` and `DOCKER_DIRECTORY` re-anchored), `not_live_reasons` and `not_fixed_reasons` in the calibration check and the kit driver with `not_live_reasons_units`, C.9's `_send_the_seed`, `container_path`, the counter's `JudgeResult`, C.10's docstrings, comments and string literals (a hashed docstring cites a rule by name and section, never by path), and `KitTarget.classes`.
  - The `source` value `holdout_calibration` to `detection_holdout_calibration`: `FixCheckRecord.source`, `FixCheckResult.source`, the four comparisons, the 17 values of `evals/nuisance_admission.json`, the dossier text.
  - The deferred H rows: `f"evals.cve.backends.{key}"` in `kit/backend_launch.py`, `test_backend_lifecycle_given.py` and the re-admission closure root, the expected roots in the dossier tests, the dossier texts that name a hashed module or the places file (`out/evals/detection_places.json`, `evals/cve/layout.py`, the transplanted `evals.cve.environments.Launch`), the closure test's `evals/cve/places.py`, `monkeypatch.setattr("evals.cve.planting_docker._SENTINEL_PROBE_BUDGET", ...)`, `caplog` on `planting_docker.__name__`, `"evals.cve.environments"` in `test_nuisance_fix_checks.py` asserted importable.
  - Data migrations of D for step 4: the stand-in keys (68 and 48) by a scratchpad script with the reader, the writer and the `Dockerfile.stand-in` ENTRYPOINT (`Serve`/`serve`), and the grammar golden keys through the key map (18 `dead_conditions/` to `not_live_reasons/`, 18 `patched_dead_conditions/` to `not_fixed_reasons/`, 173 `miss_class` to `miss_kind`), checked by a scratchpad comparison that loads the old and new files, maps the keys and asserts every value identical. Never regenerate the grammar, layout or route golden masters.
  - Model-inputs golden regenerated for `FlawRecord` and `AdmittedServer` only: its diff shows exactly the `MechanismClass` to `FlawClass` entry (key, title, references) and the `source` enum value, every other entry unchanged.
  - Recorded values, computed on this tree with no Docker: the admission's `grammar_fingerprint` set to `grammar_fingerprint()`, each of the 17 `holdout_fingerprint` set to the current `fixture_fingerprint` of the target its copy resolves to through `copy_targets` (sixteen targets), so `stale_holdout_calibration_copies` and `unrecorded_fields` report nothing. The census draw record's `grammar_fingerprint` stays.
  - Workflow path filters set to E.5's final list, today's coverage translated and never `evals/cve/**`: `evals/docker/**`, `evals/cve/*.py`, `evals/cve/detection/*.py`, `evals/detection_places.json`, `evals/run_detection.py`, `evals/detection_preflight.py`, `evals/stand_ins/**`, `tests/integration/test_cve_planting.py`, `tests/integration/support/test_cve_planting_*.py`, `pyproject.toml`, `uv.lock`, and `.github/workflows/detection-calibration-check.yml` in the push list. The old paths step 6 kept leave. The H.5 test still green.
  - Docker checks, Docker Engine 28.0 or later, no LLM: the stand-in image is rebuilt, and no other image may go stale. Every image the checks need that is absent locally is built (the Docker disk clause is lifted for this step only, see the common rules): about 40 at `e551cee`, the 37 vulnerable images of the holdout targets and `fetch-patched`, `filesystem-patched` and `kubernetes-patched`. First build the frogman FreePBX stack cold, as CLAUDE.md says: `docker compose -f evals/docker/compose.yml build --no-cache holdout-2026-46514-frogman holdout-2026-46514-frogman-patched`. The checks' preflight builds the others. All three checks run in full: `uv run python -m evals.run_detection --calibration-check` (the four acceptance targets live and fixed), `uv run python -m evals.run_detection_holdout calibration-check` (the 37 holdout targets, the sixteen copied ones among them), `uv run python -m evals.run_nuisance vet` (every admitted server). Send their output to scratchpad files and read the summary lines. The checks are blocking: a target out of calibration or a server that fails its benign call stops the step, and the cause is found and fixed here, never logged as a new state.
  - Log entries in the style of each log, drafted in the body's step 4: the detection log (the shared CVE benchmark code moved into packages and was renamed over this commit and the four before it with no change to what it plants, launches or grades, every fixture fingerprint and the grammar fingerprint moved with the grammar golden master's values unchanged, nothing reset, no holdout detection rate made exploratory, the checks that ran and on what, the stand-in keys renamed, the census and places files renamed with their content unchanged), the nuisance log (eligibility applied again with no decision moved, the admission's grammar fingerprint and the 17 copies recorded again with their values, the counter and nuisance fixture fingerprints moved with no fixture changed, the `source` value renamed, the vet result), the labeling log (the detection suite's scoring code moved and renamed with no change to what it grades, the golden keys renamed through the map).
  - Last pass over list H: every pattern of G, `_NOT_YET_RENAMED` ignored, run over the files of list H (the Dockerfile and `compose.yml` comments included) and over the transplanted modules (`holdout_fixtures/`, `fix_checks/`, the kit), and every hit rewritten here (C.10 lists the known ones, a module docstring or comment C.10 missed included, and a comment or docstring an agent wrote has no exemption), apart from the rule and log citations the rule versions after this plan rewrite (the four `docs/nuisance-log.md` paths and the six "holdout log" comments of the three frogman Dockerfiles) and npm's "installer stub", since no later step edits a hashed module.
  - The Dockerfile comments: the nine lines that cite a moved module, the `compose.yml` comments, and every other comment line that carries a retired or moved word, reworded to the glossary (Appendix I: 32 more lines a pattern catches at `e551cee`, eight of them in the `Dockerfile.holdout-*` the calibration agents wrote, plus any a reading by sense finds), "no stub" becoming "no stand-in". Comments are outside every Dockerfile hash, so none of them rebuilds an image. E.9 lines `CVEStatus`, `entry_id`, `MechanismClass, mechanisms`, `MissClass, miss_class`, `PlantKind`, `probed_target`, `REACHABLE_BY, Place.reachable_by`.
- **Test** (written first): every committed capture loads under the new keys, a capture with the old `target` key is refused with an error naming it (its G.1 allowlist entry), the stand-in integration test serves a captured route and the default, the report-key test of step 3 extended (`judge_result` and `arguments` present, `eval_result` absent, no `payload` in a judge result), the grammar golden test passes on the mapped keys unregenerated, the layout and route goldens unchanged, the admission check passes with the recorded grammar fingerprint, `stale_holdout_calibration_copies` and `unrecorded_fields` are empty against the current fixture fingerprints, the places file's pinned SHA-256 holds, `load_census` and the admission and walk records load.
- **Verify**: closing check green, the golden diff limited to the two declared changes, the key-map comparison passes, `git diff -M --stat` shows the places file as a 100 % rename, no tag-4 id left in `_NOT_YET_RENAMED`, the three Docker checks green on every acceptance target, every holdout target and every admitted server, the Docker disk grown only by the stand-in rebuild and the images the checks needed that were absent.

### Step 10: living docs

- **Files**: `README.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `CHANGELOG.md`, `docs/glossary.md`, `docs/glossary-log.md`, `docs/labeling-log.md`, `evals/census_method.md`, `evals/fault_injection_method.md`, `evals/judge_fixture_method.md`, `evals/judge_labeling_brief.md`, `evals/probe_method.md`, `tests/unit/test_glossary.py`.
- **Do**: the body's step 5 and every E.7 row tagged 5. README rewritten: a presentation of the CVE benchmark, its census and its two suites with the glossary's glosses at first mention, the two published numbers (holdout detection rate, holdout nuisance rate "at most"), the instruments counted as the glossary counts them (the sentence "Three instruments" goes), a link to `docs/glossary.md`, every command and flag of the migration, the retired phrases gone, the retest sense of bare "replay" rewritten (E.7 table) and the ADR 030 sense kept. CONTRIBUTING and CLAUDE.md: what steps 3 to 9 left, bare "replay" and "holdout" read by sense. CHANGELOG `[Unreleased]` consolidated per E.8 (one Breaking entry for the product report and the resume, the eval renames under Changed), with the G.1 `(was ` allowlist entries still missing, the published sections untouched. `docs/glossary.md`: the census step added to "step", no `Code:` field citing a moved path or command. `docs/glossary-log.md`: every E.9 line present, and the kept items of Invariant 6 in its introductory text. The method notes and the living preamble of `docs/labeling-log.md`. The labeling rubric clauses J0, J4 and J10 reworded ("sentinel" to "nonce", "CVE" alone to "flaw" or "judge cases drawn from detection suite runs") under a labeling log entry stating that every stored label scores the same. Review of that normative text, before the commit: a fresh independent reviewer agent (a strong model, started for this check only, not the implementer) checks the reworded clauses and the changes to `evals/judge_labeling_brief.md`, which the labelers also read, that every stored label scores the same under them and that their wording follows the glossary, and the maintainer fixes or rules on each finding before the commit. Every id but the two ids tagged "after this plan" leaves `_NOT_YET_RENAMED` (the `moved-test` pattern enforced), and the code hits they still report outside list H (comments, docstrings and test names in files no step touched) are rewritten here.
- **Test**: the retired-word test green with `_NOT_YET_RENAMED` holding only `holdout-rule-log` and `nuisance-rule-log` and `_NOT_YET_MIGRATED` the two rules and the living preambles of their logs, as they stay when the plan ends, the CLAUDE.md glossary-line assertion green.
- **Verify**: closing check green, no file of list H touched, no code changed but those comments, docstrings and test names and `tests/unit/test_glossary.py`, golden green unregenerated, the reviewer agent's findings on the labeling text fixed or ruled on by the maintainer, the two rules and their logs untouched.
