# Standards pass on the nuisance suite

## Context

The nuisance suite outside its fix checks was reviewed against the coding, testing and architecture standards of `CLAUDE.md`: `evals/cve/nuisance/` except `fix_checks/` (the audit, assembly, results, holdout run and its command, holdout servers, solo pass, vet, benign call, report, markdown, statistic, fixtures, fingerprint, backend registry, provisioners, containers, images, exits, commands and fix-check command, then `admission/` and `gate/`), the entry point `evals/run_nuisance.py`, their unit tests (`tests/unit/nuisance` except `fix_checks/`), `tests/integration/committed/nuisance` except `fix_checks/`, the integration tests `test_nuisance_doris_backend.py` and `test_nuisance_public_names.py`, and the fake `tests/fakes/benign_call.py`. That is 158 files. `confinement.py`, `counter.py` and `counting.py` are outside the pass, since an eval fingerprint hashes them.

A mechanical inventory listed the functions over 20 body lines, over 3 arguments and the files over 300 lines (61 items, 5 files over 300 lines). Seventeen reviewers then read the code, thirteen file by file and four across the whole area (architecture and responsibilities, duplication and missing concepts, ubiquitous language, the test suite as a whole), and reported 183 findings. Thirteen more verified each finding against the code, rejected those that did not hold or traded one standard for another, merged the duplicates, deferred what belongs to another area, and designed the fix of the rest. This plan carries the 95 fixes that survived, plus fix 7.6, the same defect as fix 7.5 on the detection command: 5 of high value, 28 of medium value and 63 of low value, 91 small and 5 medium in effort. Of the other findings, 79 are merged into a fix, 8 are rejected and 1 is deferred to the census and planting area.

The fixes fall into a few families:

- the mechanisms the pass on the detection suite extracted for both suites, which the nuisance suite still copies (`file_baselines.py`, `holdout_report_lines.py`, `RunInterrupted`, `print_report_incidents`, `backend_image_ids`, `RunOverrides.of_holdout`, `throttled_lines`, `AuditPrices`, the exporter in `evals/export.py`), and the helpers of `evals/` its gate re-implements;
- copies inside the suite (the container sequence of the run and the vet, the precedence of the drop causes, the tracing refusal, the parser's three committed inputs);
- modules that mix responsibilities (the live wiring in `holdout_run.py` and `gate_session.py`, the schema and the load checks in `admission.py`, the first-admission texts in `re_admission_docs.py`);
- two defects of the nuisance gate (what it rebuilds, a provider message that can reach stderr), the second also present in the detection command;
- names and test support (the retired sense of "settle", bare "the walk", two meanings of `BenignCall`, givens and builder parameters that abstract nothing).

## Approach

Each fix below is small and stands on its own, except where the order notes of its section say otherwise. They are grouped in thirteen sections, in the order they are implemented:

1. the gate adopts the shared helpers, first, since it shrinks the imports later sections move;
2. the nuisance gate's exporter leaves `evals/export.py`, and the throttle lines are shared;
3. the mechanisms the two holdout runs share;
4. the audit attempts, with `gate_run` on the shared loop and then moved to `gate/gate_audit.py`;
5. the container sequence, the vet and the benign call;
6. the nuisance holdout run's orchestrator (`NuisanceHoldoutRunInputs`, `default_deps` moved to the command), on top of sections 3 and 5;
7. the gate session and command, with the gate's two defects and the detection command's crash leak in commits of their own;
8. the gate tests and the retired sense of "settle";
9. the report, the markdown and the statistic;
10. the admission file and its load checks;
11. the nuisance walk and the commands;
12. the admission and re-admission dossiers, behind a byte comparison of the written kits;
13. the fingerprint, the backend registry and the fix-check command.

Within a section, the fixes are listed in the order the section's notes give. A reference such as "fix 5.2" names a fix of this plan. The notes and risks of a fix were written by its verifier before the sections were ordered, so a note that reads "another section", or that weighs a fix this plan rejects ("a rejected finding"), describes a neighbour, not a step to take: the order of the sections above wins. A rejected finding is never implemented, even when a note discusses how it would interact.

## Decisions

- **Five fixes change what a user or maintainer reads or what a command does, each with a line in the `[Unreleased]` section of `CHANGELOG.md`**: fix 7.3 (a gate rebuilds the built backend images, and the sentinel and stand-in images of a backend-less server with public names, as the run and the vet do), fix 7.5 (a fatal provider error during a gate prints the existing crash panel, with no provider message on stderr, exit code unchanged), fix 7.6 (the same on the detection command, with the panel `run_detection_holdout` prints), fix 11.2 (the `walk` line tags an excluded server `[excluded_server]`) and fix 11.15 (the refusals of the admission's walk checks and the `walk` header write "the nuisance walk"). Every other fix is a refactoring and keeps behavior, or corrects a false comment, docstring or line of documentation. Fix 11.7 also moves `--admission` in the `nuisance-dossier --help` listing, with no flag or default changed.
- **Fix 7.3 is an instrument change with no effect on any recorded result.** It changes which image a graded run audits: the gate could otherwise record a fixture fingerprint that names a new backend Dockerfile while auditing the old backend image. No nuisance acceptance server is admitted and `evals/baselines/nuisance/` does not exist, so nothing is reset. It lands in its own commit, with its own labeling-log entry answering the four questions of ADR 016.
- **One labeling-log entry covers the plan's moves of the nuisance suite's scoring code**, as the passes on the eval instruments and the detection suite did for theirs: the gate, recording and baseline code moves and is deduplicated (section 1), `gate_run` moves onto the shared attempt loop (fixes 4.3 and 4.4), a dropped run's precedence and its cost are each read from one place (fixes 3.1 and 3.5), the report lines and the controls of the holdout nuisance rate move to what both holdout runs share (fixes 9.1 and 9.2), the nuisance walk reads its criteria through `criteria_met` (fix 11.1), the fingerprint code takes its stand-ins directory and loses two helpers with every value unchanged (fixes 13.1, 13.4 and 13.6), the printed changes of fixes 7.5, 7.6, 11.2 and 11.15 are listed, nothing the counter counts moves, the baseline directory is absent and no baseline is reset. Fix 7.3 is outside this entry. The entry is written in the commit of fix 1.1 and lists the later fixes it covers. It states that the grammar fingerprint stays `58afe8a1926bf5fbffa78146b6e7e35d5d5d27797332aea1c829a503cc3e33d1`, the map of the 41 detection fixture fingerprints `689da547ef98cf466f67be55cdb28b319790d9e21b8ea6df2df85624c6dc420b`, the counter fingerprint `b6d3dc662faf2fb24b2b91ff0f7c7941d6927a7303cfab952f2cf5b41af54161` and the map of the 65 nuisance fixture fingerprints `0444a788e1477df424ea3b29ab0dc2a2c1bacf55746975126c0ae46e667cfc5d` (computed as in Verification), and answers the four questions of ADR 016.
- **A shared helper is adopted only where its output is byte-identical to the nuisance copy.** Where the words differ, the difference stays explicit: `gate_run` keeps its two phrases through `MissedCallWording` (fix 4.3), and the gate keeps its own container order, with no refusal and its removal inside the `try` (fix 5.2 leaves it out of `rebuilt_run_images`).
- **The import rewrites a fix causes outside this area land in the same commit as the fix**, in `evals/export.py`, `evals/cve/` (`audit_attempts.py`, `holdout_conditions.py`, `holdout_statistic.py`, `images.py`, `run_files.py`), `evals/run_detection.py` (fix 7.6), `evals/cve/detection/` (`audit.py`, `baseline.py`, `holdout_assembly.py`, `holdout_command_deps.py`, `holdout_run.py`, `measurement.py`), `tests/unit/cve`, `tests/unit/detection`, `tests/unit/evals` and `tests/unit/support`. No module an eval fingerprint hashes imports a name these fixes rename or move: the fingerprinted backends import only `evals.cve.nuisance.confinement`, and `counting.py` imports `AdmittedServer`, `FlawRecord` and `ToolRecord` from `admission.py`, where the schema stays (fix 10.1). A name moved out of a module that still imports it passes `pyrefly` as an implicit re-export, so every move is checked by an AST scan of its importers (see Verification).
- **Four terms enter the glossary**: **split flaw** (fix 9.6), **queue** (fix 11.11), **holdout target reference** (fix 12.8) and **dossier**, under "Words with several senses" (fix 12.11). The maintainer validated their wording on 2026-11-23. Before their commits, a fresh Opus agent that has not seen the plan checks each sentence against `docs/glossary.md` and the nuisance suite rule (style, one meaning per term, no clash with an existing sense), as the project does for normative text written outside its drafting skill.
- **The identifiers that plans cite get a line in `docs/glossary-log.md`**, across nine fixes, in the commit that renames them: `ProviderError` (fix 4.2), `reset_containers` and `backend_reset_containers` (fix 5.1), `_duplicate_benign_calls` (fix 10.5), `ServerMark` (fix 11.2), `holdout_target_references` (fix 12.7), `holdout reference` and the given of fix 12.8, `backend_content` (fix 13.4), `provisioner_of` and `BackendProvisioner` (fix 13.5), `_field_mismatches` (fix 13.7). Apart from that given, a renamed test or test helper takes no line, even when a plan cites it.
- **The follow-ups these fixes open elsewhere are left to the passes on those areas**, and listed here so they are not lost. The census and planting area: `GRAMMAR_CLASS_DEFINITIONS` and the grammar class text move out of `evals/run_census.py`, then `admission_docs.py` (fix 12.2) repoints its import. The shared test support area: the nuisance builders of `tests/unit/support/` are edited here only where a fix needs them. The eval instruments: `evals/run_honeypot_suite.py`, `evals/run_judge_eval.py` and `evals/honeypot/runs.py` print a traceback on any exception, and a separate small change checks whether a provider error reaches them.

## What stays unchanged

- Every module an eval fingerprint hashes (`evals/cve/nuisance/confinement.py`, `counter.py` and `counting.py` among them), the Dockerfiles and stand-in captures, `docs/adr/`, `plans/` and the two suite rules.
- The fixture fingerprint of every detection target, the grammar fingerprint, the counter fingerprint and the nuisance fixture fingerprint of every admitted server, checked before and after each section. `planting_host_parts` and `host_stand_in_files` stay in `evals/cve/detection/baseline.py`.
- The committed data and how it is read: `evals/nuisance_admission.json`, `evals/nuisance_walk_record.json`, `evals/census.json`, `evals/holdout_conditions.json`, `evals/baselines/nuisance/` and the golden files.
- The instrument's behavior under the nuisance suite rule and ADRs 016, 020, 028, 033, 034 and 036: the count of alarms, exits, eligibility, the vet and its second pass, the gate and retest rules, the absence of per-case output and the tracing refusal of a nuisance holdout run, magento2 played alone, the container hygiene, exit codes, refusal messages and command-line flags, apart from the five changes of Decisions.
- The keys of every written report, result file, baseline and export. `evals/export.py` writes the honeypot suite's JSONL byte for byte as before.
- What the kits ship: the dossiers' import closure and the bytes they write (section 12 compares them).
- `tests/unit/project/support/code_standards_debt.py`: no entry is added. The newspaper rule, the one given/then pair per test file and the absence of `monkeypatch.setattr` hold on every file this plan writes.

## Edge cases

- `rebuilt_run_images` (fix 5.2) has its `try` around the `yield` only: a refusal raised before it sweeps nothing, which `test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running` pins. A sync context manager around an `await` keeps the `finally` on cancellation.
- `NuisanceDeps` is built positionally in `default_deps` and `deps_reaching_nothing`, so `sweep` takes the position of the two fields it replaces.
- `default_deps` keeps `overrides.tool_call_timeout or TOOL_CALL_TIMEOUT` as it is when it moves (fix 6.1), so a timeout of 0 keeps its behavior.
- `NuisanceHoldoutRunInputs` is defined before `RunOrchestrator`, and `default_deps` before `RunCommandDeps`, since neither annotation is deferred.
- `gate_run`'s two phrases are pinned by new assertions, seen green on the old code before fix 4.3.
- The tests of fixes 7.5 and 7.6 raise `ProviderFatal(cause) from cause`, as the audits do. Without `from`, the traceback carries no secret and the test would pass on today's code.
- A new name is checked against the glossary and against the retired-word guard: `ReAdmissionPlan`, for one, matches the retired word `readmission`, so `ReAdmittedDossier` keeps its name.
- A nuisance holdout run writes no per-case output: no fix may add a print or a file that carries a payload, a response or a verdict to its path. Fix 4.1 keeps the report detail the auditor passes.

## Verification

**Run outputs stay closed.** No step opens anything under `output/`, a `*.result.json`, a `*_judged_cases.jsonl` or a holdout report, by hand or through an agent: reading a nuisance trace of a holdout server spends it and its holdout target, which cannot be undone. Every search is scoped to `evals tests docs`, since a plain `grep -r` from the root reads `output/`.

After each fix: the test files it touches with `uv run pytest <files> -n 0`, then the short loop `uv run pytest tests/unit -n auto --maxprocesses 6`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyrefly check`. A fix also runs the integration files it writes or that import a module it changes, and a fix that touches committed content runs `uv run pytest tests/integration/committed -n auto`. Each section closes with `uv run pytest -n auto`, `uv run ruff check .` and `uv run pyrefly check`, even right after a fix that ran them. `tests/unit/project/test_code_standards.py` passes at every step without new debt.

Before section 1 and after each section, the fingerprints are computed from the repository root and compared with the values of Decisions:

```python
import hashlib, json
from evals.cve.census.census import CENSUS_PATH
from evals.cve.detection.baseline import fixture_fingerprint, grammar_fingerprint
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.nuisance.admission.admission import ADMISSION_PATH
from evals.cve.nuisance.commands import WALK_RECORD_PATH, committed_admission, committed_walk_inputs
from evals.cve.nuisance.counter import counter_fingerprint
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.places import DETECTION_PLACES, load_places

digest = lambda values: hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
places = load_places(DETECTION_PLACES)
targets = {t.flaw_id: fixture_fingerprint(t, places) for t in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)}
admission = committed_admission(ADMISSION_PATH, committed_walk_inputs(CENSUS_PATH, WALK_RECORD_PATH))
servers = {s.server_package: nuisance_fixture_fingerprint(s) for s in admission.servers}
print(len(targets), grammar_fingerprint(), digest(targets))
print(len(servers), counter_fingerprint(), digest(servers))
```

(run with `PYTHONPATH=. uv run python`). After each move of sections 2, 3, 4, 5, 6, 7, 10 and 12, an AST scan of every Python file under `evals/` and `tests/` lists the `from X import name` lines that still name the old module of a moved name, and finds none.

After section 2, importing `evals.run_honeypot_suite` loads no `evals.cve` module:

```bash
PYTHONPATH=. uv run python -c "import sys, evals.run_honeypot_suite; assert not [m for m in sys.modules if m.startswith('evals.cve')]"
```

Before section 12 and after it, three dossiers are written (a first admission, a first admission with `--backend doris`, a re-admission) and compared with `diff -r`, which finds no difference. After section 6, `uv run python -m evals.run_nuisance vet --server PyPI:flyto-core` must exit 0 (Docker, no LLM), since the other checks prove the container sequence of fix 5.2 on fakes only.

## Fixes

### 1. The gate adopts the shared helpers

Order and interactions: this section comes first because it shrinks the imports later sections move. Fix 1.1 also carries the `_next_step` deletion. Fix 1.3 edits `_assemble_run` while it still reads `ctx`, and section 6 then renames that parameter.

Verifier's notes: Four confirmed fixes, independent of one another, all behavior-preserving: fix 1.1 (adopt file_baselines and the evals/baseline helpers), fix 1.2 (exit code), fix 1.3 (ModelConditions), fix 1.4 (comments). Suggested order: fix 1.1, then fix 1.2, then fix 1.1, then the comments. fix 1.1 and fix 1.2 both edit gate_session.py imports, and fix 1.1, fix 1.1 and the comments all edit gate_baseline.py, in different places. Other sections on the same modules: - another section: fix 1.1 is the same _next_step change as fix 1.1, apply it once. It also moves default_harness and GateCommandDeps and reshapes gate_command.py and gate_session.py (fix 7.3, fix 1.1, fix 1.1, fix 7.3, fix 1.4, fix 1.3). fix 7.4 edits _recordings in gate_session_recording.py. Do this section first, since it shrinks the imports those moves carry. - another section: fix 3.8 and fix 3.8 move HOLDOUT_TEST_BUDGET and grammar_fingerprint, changing the import block of gate_baseline.py. Textual conflict only. It also touches gate_session.py, gate_command.py and holdout_run.py. - another section: replaces or renames ctx in holdout_run.py. fix 1.3 must use the name then in force (ctx.settings today). fix 6.1 renames ctx to context. another section (a rejected finding) and another section also edit holdout_run.py. - another section: renames tests and locals in test_nuisance_gate_recording.py, test_nuisance_gate.py and gate_session.py. Near the decide_recordings tests deleted here, no semantic conflict. - another section, another section and another section edit gate_console.py. This section leaves it alone, since the _print_baselines move was rejected. - another section edits test_nuisance_re_admission_dossier.py, and another section (fix 13.10) edits test_nuisance_doris_backend.py: docstring lines only on this side. No fingerprinted module is touched, and no gate module is in a dossier closure.

#### Fix 1.1: `evals/cve/nuisance/gate/gate_baseline.py` `WHOLE_RESET, condition_mismatches and their copies in the gate modules` (duplication, refactoring)

Problem: The gate modules still carry their own copy of nearly everything file_baselines.py shares: WHOLE_RESET text (gate_baseline.py:29), the mismatch line (gate_baseline.py:136), the unconfirmed detail (gate.py:87-92), RUN_NOT_COMPLETED (gate_recording.py:20), leaves_gated_set (:55), decide_recordings = all_or_none (:62), the refused confirmation (:89), the red-gate reason (:127), BASELINE_FILES_CHANGED and load_checked (gate_session_recording.py:78, :82), next_recording_step (gate_command.py:213). Each text is byte-identical to the shared one.

Also covers: `evals/cve/nuisance/gate/gate_recording.py` (duplication): gate_recording.py still writes its own copy of what evals/cve/file_baselines.py now holds: decide_recordings (= all_or_none), leaves_gated_set (identical), the ADR 020 confirmation refusal text in _confirmation (= refused_confirmation), the ADR 016 red-gate sentence in _comparison_refusals (= red_gate_reason("server")), _FAILED_RUN (= RUN_NOT_COMPLETED, same string), and _ref (= RecordingRef.of). evals/cve/detection/recording.py already calls all of them. Each text is byte-identical today.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (duplication): WHOLE_RESET restates the text of file_baselines.whole_reset, and condition_mismatches restates the line format of condition_mismatches_by_file ('{file}: {field} is {recorded!r}, the run has {expected!r}'). The detection gate already keeps only a two-line wrapper over the shared function.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (duplication): write_baseline repeats write_json_atomically step for step (mkdir, .json.tmp, model_dump_json(indent=2), os.replace). baseline_integrity re-implements run_count_problems with a package prefix, including the ADR 023 rule that a confirmation holds twice the claimed runs. detection/baseline.py already delegates both. gate_session_recording.load_checked is the matching copy of file_baselines.load_checked, which takes a BaselineStore declared beside these two functions.

Also covers: `evals/cve/nuisance/gate/gate.py` (duplication): _why_not_gated restates the sentence of file_baselines.unconfirmed_baseline_detail. It also branches again on baseline.status although each of its two callers in compare_server has already decided that branch (line 73 for UNCONFIRMED, line 77 for a confirmed alarmed baseline).

Also covers: `evals/cve/nuisance/gate/gate_session_recording.py` (duplication): `load_checked` is a line-for-line copy of `file_baselines.load_checked`, with the same refusal text and integrity loop. The same module also consumes the nuisance copies `decide_recordings` (of `all_or_none`) and `leaves_gated_set` from gate_recording.py, which detection's session_recording.py takes from file_baselines.

Also covers: `evals/cve/nuisance/gate/gate_session_recording.py` (duplication): `recording_tree` restates the dirty-tree refusal literally (line 38) and `_recording_drift` restates the baseline-files-changed refusal literally (line 78). Both strings are byte-equal to the named constants that detection's session_recording.py imports.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (duplication): baseline_integrity re-implements evals.baseline.run_count_problems line for line, including the doubled count of a confirmation and both message texts.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (duplication): write_baseline hand-writes the atomic write (mkdir, `.json.tmp`, os.replace) that evals.baseline.write_json_atomically provides with the same temporary suffix and indent.

Also covers: `evals/cve/nuisance/gate/gate_recording.py` (duplication): _ref rebuilds RecordingRef field by field, which RecordingRef.of already does for any recorded baseline.

Also covers: `evals/cve/nuisance/gate/gate_session_recording.py` (duplication): The dirty-tree refusal is a literal identical to eval_session.DIRTY_TREE_REFUSAL, which the other instruments import. RECORD_WITHOUT_BASELINE does not apply here: the nuisance gate has no --no-baseline.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (duplication): The gate modules still write their own copy of what the detection gate now shares, with the same texts. In gate_baseline: `WHOLE_RESET`, the mismatch format of `condition_mismatches`, the atomic write, and the run-count check of `baseline_integrity`. In gate_recording: `_FAILED_RUN`, `decide_recordings`, `leaves_gated_set`, the refused-confirmation and red-gate texts, `_ref`. In gate_session_recording: `load_checked`, the dirty-tree text and the changed-files text. In gate.py: `exit_code`, plus the unconfirmed detail. In gate_command: `_next_step`. `gate_conditions` also resolves the model conditions by hand.

Also covers: `evals/cve/nuisance/gate/gate_command.py` (duplication): _next_step is a line-for-line copy of evals.cve.file_baselines.next_recording_step, the two sentences that tell the maintainer how to confirm a recording. The detection side already calls the shared function in recording_console.print_recording.

Why it was kept: True and the same knowledge: the gate modules copy the ADR 016, 020 and 023 recording rules and refusal texts that evals/cve/file_baselines.py and evals/baseline.py hold, and detection/recording.py, detection/session_recording.py, detection/gate.py and detection/baseline.py already call them. Compared by value at HEAD: WHOLE_RESET == whole_reset(_BASELINE_DIRECTORY), _FAILED_RUN == RUN_NOT_COMPLETED, the dirty-tree and changed-files literals equal DIRTY_TREE_REFUSAL and BASELINE_FILES_CHANGED, the red-gate text equals red_gate_reason("server"), condition_mismatches equals condition_mismatches_by_file on an unsorted two-package input, baseline_integrity equals the prefixed run_count_problems on 0, exact, wrong, confirmed and wrong-confirmed run counts. By reading: decide_recordings == all_or_none (its isinstance filter is the same partition), leaves_gated_set, refused_confirmation, unconfirmed_baseline_detail, load_checked, next_recording_step, write_json_atomically (same mkdir, .json.tmp via with_suffix, indent=2, os.replace) and RecordingRef.of are identical. One theoretical difference: keying by file name would collapse two packages with one file name, but load_baselines refuses a file not named after its package, so a directory cannot hold both, and the 119 packages of the admission file have no collision. Rejected parts: moving _print_baselines to gate_console.py is not duplication (gate_console's docstring states the split, gate_command is 229 lines, and the another section reshapes that module); replacing _why_not_gated by _flagged_detail is taste, detection/gate.py keeps the same two-branch helper.

Change: gate_baseline.py: WHOLE_RESET = whole_reset(_BASELINE_DIRECTORY) (importers unchanged). condition_mismatches keeps its signature: by_file = {baseline_file_name(package): b.conditions for package, b in sorted(baselines.items())}; return condition_mismatches_by_file(by_file, candidate). write_baseline: write_json_atomically(directory / baseline_file_name(baseline.server_package), baseline), drop `import os`. baseline_integrity: problems = run_count_problems(len(baseline.runs), baseline.conditions.runs, baseline.confirms); return [f"{baseline.server_package}: {problem}" for problem in problems]. At the end of the module, NUISANCE_GATE_BASELINE_STORE = BaselineStore(load_baselines, baseline_integrity), named after NUISANCE_GATE_BASELINE_DIRECTORY and NUISANCE_GATE_RUNS. gate.py: in _why_not_gated the unconfirmed branch returns unconfirmed_baseline_detail(baseline.commit), the helper and its two call sites stay. gate_recording.py: delete _FAILED_RUN, leaves_gated_set, decide_recordings, _ref and the Mapping import; use RUN_NOT_COMPLETED, refused_confirmation(differences), red_gate_reason("server") and RecordingRef.of(existing); keep _GREEN and the alarm sentence. gate_session_recording.py: delete load_checked and the Path, Baselines, load_baselines and baseline_integrity imports; import all_or_none, leaves_gated_set, load_checked and BASELINE_FILES_CHANGED from evals.cve.file_baselines and DIRTY_TREE_REFUSAL from evals.eval_session; _recording_drift calls load_checked(opened.harness.baselines, RECORDING_REFUSED, NUISANCE_GATE_BASELINE_STORE). gate_session.py: import load_checked from file_baselines, _open calls load_checked(harness.baselines, REFUSED_BEFORE_ANY_LLM_CALL, NUISANCE_GATE_BASELINE_STORE). gate_command.py: delete _next_step and print Text(next_recording_step(status, " ".join([_RECORD_COMMAND, *recorded_flags]), _BASELINES)), keeping Text so that a package or flag prints literally; drop the BaselineStatus import if nothing else uses it. This commit also adds the labeling-log entry that Decisions describes.

Files: `evals/cve/nuisance/gate/gate_baseline.py`, `evals/cve/nuisance/gate/gate.py`, `evals/cve/nuisance/gate/gate_recording.py`, `evals/cve/nuisance/gate/gate_session_recording.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_command.py`, `tests/unit/nuisance/gate/test_nuisance_gate_recording.py`, `docs/labeling-log.md`

Tests: test_nuisance_gate_recording.py: import leaves_gated_set from evals.cve.file_baselines and keep its two tests, which pin the nuisance gated() rule (an alarm leaves the gated set) through decide_recording. Delete only the two decide_recordings tests (lines 196-211): test_detection_recording.py covers all_or_none with the same two cases. The texts stay pinned by test_nuisance_gate.py (WHOLE_RESET), test_run_nuisance_gate.py (the next-step sentences) and the session tests. Behavior kept: full pytest, ruff, pyrefly. No fingerprinted module is touched and no gate module is in a dossier closure; the plan's before and after fingerprint check covers it.

Risks: No text, exit code or JSON key changes. Baselines under evals/baselines/nuisance/ are absent today and read the same once recorded. fix 1.1 (another section) is the same _next_step change: apply it once. Keep the sort by package before the file-name mapping, which fixes the order of the mismatch lines.

#### Fix 1.2: `evals/cve/nuisance/gate/gate_session.py` `_run_opened` (duplication, refactoring)

Problem: `exit_code=3 if refused else exit_code(gate.outcome)` uses a bare 3 and the nuisance copy `gate.exit_code`, whose table repeats `GateOutcome.exit_code` value for value. Detection deleted its copy and reads `gate.outcome.exit_code`.

Also covers: `evals/cve/nuisance/gate/gate.py` (duplication): gate.exit_code is a copy of the GateOutcome.exit_code property (green 0, red 1, not comparable 3). The detection gate deleted its copy. Its one caller is gate_session.py:147.

Also covers: `evals/cve/nuisance/gate/gate.py` (duplication): exit_code re-tabulates GateOutcome.exit_code, and gate_session.py:147 writes the not-comparable code as a bare literal: `exit_code=3 if refused else exit_code(gate.outcome)`.

Why it was kept: gate.exit_code repeats the GateOutcome.exit_code table value for value, its only caller is gate_session.py:147, no test imports it, and the detection session already reads gate.outcome.exit_code. NOT_COMPARABLE_EXIT is documented in evals/gate_outcome.py as also the exit code of a refusal, and run_detection.py returns it on a Refused, so this uses the existing name and adds no new shared exit code.

Change: Delete exit_code from gate.py. In gate_session._run_opened write exit_code=NOT_COMPARABLE_EXIT if refused else gate.outcome.exit_code, import NOT_COMPARABLE_EXIT from evals.gate_outcome, and drop the exit_code import from evals.cve.nuisance.gate.gate.

Files: `evals/cve/nuisance/gate/gate.py`, `evals/cve/nuisance/gate/gate_session.py`

Tests: No test changes: test_nuisance_gate_session.py and test_nuisance_gate_benign_calls.py pin session.exit_code == 3, and the green and red paths keep 0 and 1. Full pytest, ruff, pyrefly.

Risks: Exit codes are documented and do not change.

#### Fix 1.3: `evals/cve/nuisance/gate/gate_baseline.py` `gate_conditions, _assemble_run` (duplication, refactoring)

Problem: gate_conditions (gate_baseline.py:59-69) and holdout_run._assemble_run (holdout_run.py:291-298) each resolve provider, model, judge model and both reasoning levels by hand, the exact five fields ModelConditions.of returns, which the detection side already spreads in.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (duplication): gate_conditions resolves provider, model, judge model and both reasoning levels by hand, which is exactly ModelConditions.of(settings). detection/baseline.run_conditions already uses it.

Also covers: `evals/cve/nuisance/holdout_run.py` (duplication): _assemble_run resolves the provider, the two models and the two reasoning levels by hand, the exact content of ModelConditions.of, which the detection holdout run already spreads into its result.

Why it was kept: gate_conditions and holdout_run._assemble_run each resolve the five fields of ModelConditions.of, in the same order and with the same ValueError on a refused reasoning. detection/baseline.run_conditions and detection/holdout_run._assemble_run already spread it, into a pydantic model and a frozen dataclass respectively, the same two shapes as here. NuisanceGateConditions and NuisanceHoldoutRunResult carry the five field names and types, and serialization order follows their own field order, so the recorded conditions and the result file do not move.

Change: In gate_baseline.gate_conditions, delete the model and judge_model locals and replace the five keyword arguments with **ModelConditions.of(settings).model_dump(). In holdout_run._assemble_run, delete the settings, model and judge_model locals and replace the five keyword arguments with **ModelConditions.of(ctx.settings).model_dump(). Import ModelConditions from evals.model_conditions in both.

Files: `evals/cve/nuisance/gate/gate_baseline.py`, `evals/cve/nuisance/holdout_run.py`

Tests: No test changes: test_nuisance_gate_baseline.py pins what gate_conditions reads from the settings, and the nuisance holdout run tests pin the result. Full pytest, ruff, pyrefly. Condition field names and order are unchanged, so committed run conditions compare as before.

Risks: holdout_run.py is also touched by another section (ctx renamed or replaced by an inputs object): write the call on whatever name holds the settings at that point.

#### Fix 1.4: `evals/cve/nuisance/gate/gate_recording.py` `_GREEN` (ubiquitous-language, refactoring)

Problem: Four comments use a retired or unqualified word. gate_recording.py:21 "has no CVE counterpart" means the detection gate. tests/integration/test_nuisance_doris_backend.py:7 "as the holdout does by design" means the detection holdout layer. tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py:1 "rule v3's fields" is a bare rule version. gate_baseline.py:2 and holdout_run.py:5 say "sibling of" a module, in a suite where a sibling is a flaw (holdout_calibration_copies.py uses it in that sense).

Also covers: `evals/cve/nuisance/gate/gate_recording.py` (ubiquitous-language): The comment says 'INCONCLUSIVE has no CVE counterpart'. The nuisance suite is itself part of the CVE benchmark, so the phrase is both a forbidden use of the word and imprecise: the counterpart meant is the detection gate's.

Why it was kept: All the facts hold. Glossary: "CVE" is a term only inside "CVE ID" and "CVE benchmark", and "rule vN" is never written alone. The log marks bare "holdout" as a moved meaning. "sibling" names a sibling flaw, and the log already uses "the nuisance counterpart of a module". holdout_run.py:5 is also misleading: `holdout_run.run_holdout_targets` reads as this very module, while the function lives in evals.cve.detection.holdout_run. One correction to the finder's wording: the Doris cluster is left running by both holdout layers (detection's doris_db_env and the nuisance launch, whose final sweep covers only server and built backend images), so "the detection holdout layer" would be false. The glossary's "holdout run" means a run of either.

Change: Comments only. gate_recording.py:21: `# INCONCLUSIVE has no counterpart in the detection gate: a server already unstable stays recordable over.` test_nuisance_doris_backend.py:7: `as a holdout run does by design`. gate_baseline.py:2: `the counterpart of the baseline half of`. holdout_run.py:5: `The counterpart of `evals.cve.detection.holdout_run.run_holdout_targets`.` (rewrap).

Files: `evals/cve/nuisance/gate/gate_recording.py`, `tests/integration/test_nuisance_doris_backend.py`, `evals/cve/nuisance/gate/gate_baseline.py`, `evals/cve/nuisance/holdout_run.py`

Tests: Comments and docstrings only. tests/integration/committed/project covers the retired words. Full pytest, ruff, pyrefly.

### 2. Judged-case export and throttle lines

Verifier's notes: Two independent confirmed fixes, one commit each, in either order. Both edit gate_console.py, on different lines: fix 2.1 changes the import of nuisance_gate_export_path, fix 2.2 changes the gate_report import block and the throttle loop. Other sections on the same modules: - another section: fix 9.1 also lists the `_throttled_lines` and `render_throttled` adoption. That part is carried here, so that section must not redo it. Its other adoptions from holdout_report_lines rewrite neighbouring lines of render_markdown in nuisance/markdown.py, including `_incomplete_runs_lines` right above the throttle line. Keep `throttled_lines` in eval_display, never in holdout_report_lines (detection plan, fix 3.2). Either order works, with a textual rebase. - another section: fix 7.7 adds not_run_items and outside_gate_items in gate_report.py and gate_console.py, around the throttle call in print_nuisance_gate_summary and render_markdown. fix 7.7 reshapes _gate_rows. Several findings reshape gate_command.py (gate, _run_gate, _next_step, default_harness) and touch the import of export_nuisance_gate_judged_cases and its call at line 168: land this section first, since it is a one-line import change there. - another section: fix 1.1 moves `_print_baselines` into gate_console.py and edits gate_command.py. Only the import blocks are shared. - another section (NUISANCE_CONCURRENCY) and another section (_parser, committed_walk_inputs in gate_command.py, _reach_problems in markdown.py): import-level or neighbouring edits, no conflict. - another section touches test_nuisance_gate_console.py and test_nuisance_gate_report.py and their givens. This section changes none of those files, and their throttle assertions must keep passing as they are. No fix here touches a fingerprinted module, committed data, a kit or a dossier closure.

#### Fix 2.1: `evals/cve/nuisance/gate/gate_command.py` `export_nuisance_gate_judged_cases` (hexagonal-boundary, refactoring)

Problem: gate_command and gate_console import the nuisance gate's exporter and its path from evals/export.py, a module shared with the honeypot suite. evals/export.py imports GateAudit from evals.cve.nuisance.gate.gate_session_model for it, so every honeypot run loads the nuisance package. Detection already has its own evals/cve/detection/judged_cases_export.py.

Also covers: `evals/export.py` (hexagonal-boundary): The shared `evals/export.py` imports `GateAudit` from the nuisance gate and holds its exporter and path, so the honeypot suite loads `evals/cve/` through it. The detection side has already moved its own exporter to `detection/judged_cases_export.py`.

Also covers: `evals/export.py` (hexagonal-boundary): evals/export.py imports evals.cve.nuisance.gate.gate_session_model at its top, so run_honeypot_suite loads the CVE benchmark's nuisance code. Detection already has its own judged_cases_export.py.

Why it was kept: Fact checked. evals/export.py imports GateAudit from evals.cve.nuisance.gate.gate_session_model and holds export_nuisance_gate_judged_cases and nuisance_gate_export_path. Today `import evals.run_honeypot_suite` loads 99 evals.cve modules. With the exporter and that import stripped from evals.export in memory, it loads 0. run_honeypot_suite is the only importer of evals.export outside the two suites of the CVE benchmark, so the claim holds for the honeypot suite. The claim of fix 2.1 about 'judge tooling' is wrong: run_judge_eval does not import evals.export, and draw_judge_cases imports evals.cve.detection.targets directly and keeps doing so. Detection already moved its half (evals/cve/detection/judged_cases_export.py, commit ad55bca), and plan 2026-11-23_detection-suite-standards-pass fix 4.1 leaves this half to the nuisance area. The only callers are gate_command.py:62/168, gate_console.py:19/34 and tests/unit/evals/test_export.py. gate_session_model does not import evals.export, so the new module creates no cycle. No fingerprinted module, kit module or dossier imports evals.export.

Change: Create evals/cve/nuisance/gate/gate_judged_cases_export.py (the gate_ prefix every module of this directory carries, the same shape as detection/judged_cases_export.py). Move `export_nuisance_gate_judged_cases(audits: list[GateAudit], report_path: Path) -> None` verbatim with its docstring, then `nuisance_gate_export_path(report_path: Path) -> Path` below it. It imports GateAudit from gate_session_model and `case_lines, chain_lines, write_jsonl` from evals.export. In evals/export.py: delete both functions and the GateAudit import, and rename `_chain_lines` to `chain_lines` (its call in export_judged_cases too). No re-export. Repoint gate_command.py (`export_nuisance_gate_judged_cases`) and gate_console.py (`nuisance_gate_export_path`) to the new module. The function names, the file name nuisance_gate_judged_cases.jsonl and the JSONL lines do not change.

Files: `evals/export.py`, `evals/cve/nuisance/gate/gate_judged_cases_export.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/cve/nuisance/gate/gate_console.py`, `tests/unit/evals/test_export.py`, `tests/unit/evals/support/test_export_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_judged_cases_export.py`

Tests: Move test_each_nuisance_gate_line_carries_its_server_and_run_with_the_chains out of tests/unit/evals/test_export.py into a new tests/unit/nuisance/gate/test_nuisance_gate_judged_cases_export.py, with its assertions unchanged. Build its report the way tests/unit/detection/test_detection_judged_cases_export.py does, from tests.unit.support.grammar_inputs (`a_report([a_case(), a_case(verdict=None)], chains=[a_chain([a_step()])])`) and tests.unit.support.judged_case_exports, so it needs no given file. Delete a_report_with_a_judged_case_an_unjudged_case_and_a_chain from test_export_given.py (its only caller was this test), and the GateAudit and exporter imports from test_export.py. test_nuisance_gate_console.py keeps pinning the export path in the summary. Verify once by hand that `import evals.run_honeypot_suite` loads 0 evals.cve modules. No fingerprint is near: neither evals/export.py nor the gate modules are in the fingerprinted list.

Risks: No behavior change. evals/export.py is shared with the honeypot suite, whose JSONL must stay byte-identical: only the private name of chain_lines changes there. The old names appear in plans 2026-10-22 and 2026-11-23, but the two functions keep their names, so no glossary-log line is needed. They are not glossary terms.

#### Fix 2.2: `evals/cve/nuisance/markdown.py` `_throttled_lines, gate_report.render_throttled` (duplication, refactoring)

Problem: The throttle line is written twice more (markdown.py:190, gate_report.py:102), and gate_console.py:32-33 re-implements print_throttles.

Also covers: `evals/cve/nuisance/gate/gate_report.py` (duplication): render_throttled re-implements eval_display.throttled_lines with the same sentence, and the loop at gate_console.py:32-33 re-implements eval_display.print_throttles with the same yellow style. The detection console and markdown already use the shared pair.

Also covers: `evals/cve/nuisance/markdown.py` (duplication): _throttled_lines rewrites the condition and the sentence of evals.eval_display.throttled_lines, which the detection holdout markdown already calls.

Why it was kept: Fact checked. nuisance/markdown._throttled_lines and gate_report.render_throttled re-implement evals.eval_display.throttled_lines (same guard on 0, same sentence), and gate_console.py:32-33 re-implements print_throttles (same `Text(line, style="yellow")` on the same shared console). Compared in process on 0, 1, 12 and 1000000 requests: the three functions return equal lists. This is one piece of knowledge, the throttle line of a session, and the helper was created for this adoption (detection plan, fix 4.2). render_throttled has no caller outside gate_report and gate_console, and _throttled_lines none outside markdown.py. eval_display loads no evals.cve module, so no cycle. Neither the kit nor the admission dossiers import these modules.

Change: evals/cve/nuisance/markdown.py: delete `_throttled_lines`, import `throttled_lines` from evals.eval_display, and write `*throttled_lines(report.throttled_requests, report.concurrency)` in render_markdown. evals/cve/nuisance/gate/gate_report.py: delete `render_throttled`, import `throttled_lines`, and write the same line in render_markdown. evals/cve/nuisance/gate/gate_console.py: drop the `render_throttled` import, import `print_throttles` from evals.eval_display, and replace the two-line loop with `print_throttles(report.throttled_requests, report.concurrency)`. `Text` stays imported there, since _print_lines uses it. No new name.

Files: `evals/cve/nuisance/markdown.py`, `evals/cve/nuisance/gate/gate_report.py`, `evals/cve/nuisance/gate/gate_console.py`

Tests: No test changes. The existing tests pin the output byte for byte and must stay green: test_nuisance_report.py (the line after the incomplete runs, none at 0), test_nuisance_gate_report.py:64-65 and test_nuisance_gate_console.py:99-100. The console test captures through the shared eval_display.console, so print_throttles is captured too. No fingerprinted module is touched.

Risks: No behavior change: the markdown and the console output stay byte-identical. The published holdout report's markdown goes through this line, so the wording must not move. markdown.py gains an import of evals.eval_display (rich), already loaded by holdout_run_command, its only production importer.

### 3. Mechanisms the two holdout runs share

Order and interactions: fix 3.6 deletes `nuisance_overrides` and points the command at `RunOverrides.of_holdout`. Section 6 builds on that and does not delete it again. Fix 3.8 moves `HOLDOUT_TEST_BUDGET` to `evals/cve/holdout_conditions.py`. The planting-host move a reviewer attached to the same finding is rejected: `planting_host_parts` and `host_stand_in_files` stay in `evals/cve/detection/baseline.py`.

Verifier's notes: Eight fixes remain from the 27 findings: fix 3.1 (drop precedence), fix 3.2 (RunInterrupted), fix 3.3 (tracing refusal), fix 3.4 (backend_image_ids), fix 3.5 (AuditPrices), fix 3.6 (overrides and shape), fix 3.7 (NUISANCE_CONCURRENCY), fix 3.8 (HOLDOUT_TEST_BUDGET). All are behavior-preserving, none touches a fingerprinted module, a kit closure, a serialized field or a user-facing text. Order inside the section: the eight are independent, and most meet only on the import block of nuisance/holdout_run.py. Do fix 3.5 and fix 3.8 as separate commits, since both add to holdout_conditions.py and edit detection/holdout_run.py. fix 3.5 is split across fix 3.2, fix 3.4, fix 3.5 and, for _print_incidents, fix 4.1. Interactions with other sections: - another section is the main one. fix 6.1 and fix 6.1 also delete nuisance_overrides and make refuse_tracing public, so apply each once. Land this section first, then the orchestrator: its NuisanceHoldoutRunInputs replaces ctx in the audit_prices line of _run_all, its new holdout_run_command.py receives the backend_image_ids and HOLDOUT_TEST_BUDGET uses of default_deps, and making concurrency required removes NUISANCE_CONCURRENCY from holdout_run.py. fix 6.1 (ctx to context) touches the same lines. - another section edits nuisance/audit.py (print_report_incidents through fix 4.1, ProviderError, gate_run moved to gate_audit.py). fix 3.1 and fix 3.6 touch other lines of audit_once and nuisance_audit, so land them first or rebase. fix 4.2 changes the unions, not from_causes. - another section touches holdout_run.py and holdout_run_command.py (ContainerSweep, committed_run_population in commands.py), and another section also edits commands.py: textual conflicts only with fix 3.7. - another section edits gate_baseline.py and gate_session.py, another section and another section edit gate_session.py: import-line conflicts with fix 3.8 and fix 3.4. - another section edits fix_check_command.py (import line of fix 3.7) and carries the planting_host_parts move (a rejected finding), which fix 3.8 also asked for. Its grammar_fingerprint move is not retained here. fix 10.2 keeps reading detection_baseline.grammar_fingerprint(). Verification for the plan: after fix 3.5 and fix 3.8, recompute the 41 detection fixture fingerprints, the grammar fingerprint, counter_fingerprint and the 65 nuisance_fixture_fingerprint values. After the two constant moves, grep that no import of HOLDOUT_TEST_BUDGET from detection.holdout_run or of NUISANCE_CONCURRENCY from nuisance.holdout_run remains, since pyrefly does not flag an implicit re-export.

#### Fix 3.1: `evals/cve/nuisance/holdout_run.py` `_DROP_PRECEDENCE` (duplication, refactoring)

Problem: The precedence of a dropped run (throttled, then provider error, then launch failure) is written twice in the nuisance suite: _DROP_PRECEDENCE in holdout_run.py with its loop in _run_server, and an identical _DROP_PRECEDENCE in audit.py with `next(cause for cause in _DROP_PRECEDENCE if cause in causes)`. Detection folded the same logic into DroppedRun.from_causes, used at both levels.

Also covers: `evals/cve/nuisance/audit.py` (duplication): The nuisance drop precedence (throttled, then provider error, then launch failure) is declared twice with the same tuple: audit.py:164 for one run, holdout_run.py:75 for a server's runs, each with its own selection code (next(...) at audit.py:161, a for loop at holdout_run.py:271). The detection side already holds this rule once, on DroppedRun.from_causes (evals/cve/detection/holdout_audit.py:42).

Also covers: `evals/cve/nuisance/holdout_run.py` (duplication): The precedence that decides why a server drops (throttled, then provider error, then launch failure) is written twice inside the nuisance suite: in audit.py for one run's attempts and in holdout_run.py for a server's runs. A change to one makes a run and its server report different causes. Detection names this once with `DroppedRun.from_causes`.

Also covers: `evals/cve/nuisance/holdout_run.py` (duplication): The precedence of a dropped run's cause is declared twice in the suite (holdout_run.py:75, audit.py:164), each with its own `next`/loop over it (holdout_run.py:269-271, audit.py:161). A change to one would classify a server's dropped run differently from its runs' own.

Why it was kept: True. The tuple (THROTTLED, PROVIDER_ERROR, LAUNCH_FAILURE) is declared at audit.py:164 and holdout_run.py:75, with two selection codes (next(...) at audit.py:161, a for loop at holdout_run.py:271). It is one rule of the suite, the reason a server is reported not run, so this is the same knowledge and not a lookalike shape. Detection already holds it once on DroppedRun.from_causes (detection/holdout_audit.py:42), used at run and target level. The two NotRunCause enums stay separate.

Change: In evals/cve/nuisance/audit.py add to DroppedRun `@classmethod def from_causes(cls, causes: Collection[NotRunCause]) -> "DroppedRun"` with the docstring "Throttled, else provider error, else launch failure.", returning `cls(next(cause for cause in _DROP_PRECEDENCE if cause in causes))`. Keep the private _DROP_PRECEDENCE where it is and import Collection. nuisance_audit ends with `return DroppedRun.from_causes(causes)`. In holdout_run._run_server: `causes = {...}`, `if causes: return DroppedRun.from_causes(causes)`, then the list, the shape of detection's _run_target. Delete _DROP_PRECEDENCE and the NotRunCause import from holdout_run.py (it has no other use there).

Files: `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/holdout_run.py`

Tests: No test changes. test_throttled_wins_over_a_launch_failure and test_a_provider_error_wins_over_a_launch_failure (test_nuisance_holdout_run.py) pin the server level, and test_nuisance_retry_policy.py pins the run level. Both must stay green.

Risks: from_causes raises StopIteration on an empty set, so _run_server keeps its `if causes` guard. nuisance_audit always has at least one cause after its loop. another section edits the same module (ProviderError, gate_run).

#### Fix 3.2: `evals/cve/nuisance/holdout_run.py` `_run_surviving` (duplication, refactoring)

Problem: holdout_run raises evals.cve.nuisance.results.RunInterrupted, a verbatim copy of evals.cve.run_files.RunInterrupted, whose type already accepts NuisanceHoldoutRunResult. Because of the copy, partial_result_kept must catch `(RunInterrupted, nuisance_results.RunInterrupted)`.

Also covers: `evals/cve/nuisance/results.py` (duplication): results.py keeps a verbatim copy of run_files.RunInterrupted, whose partial is already typed for both suites. Because of the copy, run_files imports the nuisance results module only to catch the second class in partial_result_kept: except (RunInterrupted, nuisance_results.RunInterrupted).

Also covers: `evals/cve/nuisance/results.py` (duplication): results.RunInterrupted is a copy of evals.cve.run_files.RunInterrupted, whose type already accepts a NuisanceHoldoutRunResult, and partial_result_kept has to catch both classes (run_files.py:50).

Also covers: `tests/unit/nuisance/test_run_nuisance_holdout_run.py` (duplication): This command's `partial_result_kept` still has to catch two exception classes because the nuisance holdout run raises its own `results.RunInterrupted`, a copy of `run_files.RunInterrupted`, and this test imports that copy.

Why it was kept: True. nuisance/results.py:172 is a verbatim copy of run_files.RunInterrupted (same message, same two attributes), and the run_files class already types partial as DetectionHoldoutRunResult | NuisanceHoldoutRunResult. The copy is the only reason run_files imports `results as nuisance_results`, and partial_result_kept catches two classes (run_files.py:50). A class missed there would lose a paid partial result. No cycle: run_files imports only the two results modules, and holdout_run_command already imports it.

Change: Delete RunInterrupted from evals/cve/nuisance/results.py. In nuisance/holdout_run.py, drop it from the results import and add `from evals.cve.run_files import RunInterrupted`. In evals/cve/run_files.py, narrow to `except RunInterrupted as interrupted:` and delete `from evals.cve.nuisance import results as nuisance_results`, keeping the import of NuisanceHoldoutRunResult. Repoint the three test modules to evals.cve.run_files.

Files: `evals/cve/nuisance/results.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/run_files.py`, `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`, `tests/unit/nuisance/test_nuisance_holdout_run_interrupted.py`, `tests/unit/nuisance/test_run_nuisance_holdout_run.py`

Tests: Import lines only in the three test files. test_run_nuisance_holdout_run.py (partial result written, cause re-raised) is the guard that the narrowed except still catches the nuisance run's interruption.

Risks: The partial result's file and fields do not change. run_files.py is outside the fingerprinted list and outside every kit closure (checked with import_closure).

#### Fix 3.3: `evals/cve/nuisance/holdout_run.py` `_refuse_tracing` (duplication, refactoring)

Problem: _refuse_tracing is written identically in holdout_run.py and holdout_run_command.py, and the title "nuisance holdout run refused" is the private _REFUSAL here and four more literals in the command. The tracing refusal is a guarantee of the nuisance holdout run (no per-case output), so a divergence between its two copies would be silent. Detection exports refuse_tracing and DETECTION_HOLDOUT_RUN_REFUSED and its command imports them.

Also covers: `evals/cve/nuisance/holdout_run_command.py` (duplication): _refuse_tracing exists twice with the same text (holdout_run.py:189, holdout_run_command.py:120), and the title is a private constant in holdout_run.py:74 and four literals in the command (:93, :104, :123, :137). Detection exports refuse_tracing and DETECTION_HOLDOUT_RUN_REFUSED for this.

Also covers: `evals/cve/nuisance/holdout_run_command.py` (duplication): `_refuse_tracing` is a byte-for-byte copy of `holdout_run._refuse_tracing` (holdout_run.py:189), and the title "nuisance holdout run refused" is written three more times in this command (lines 93, 104, 123, 137) beside the private `_REFUSAL` of holdout_run.py:74. The detection side already has the one-copy shape: `DETECTION_HOLDOUT_RUN_REFUSED` and a public `refuse_tracing` in `detection/holdout_run.py`, imported by its command.

Why it was kept: True. _refuse_tracing is written identically at holdout_run.py:189 and holdout_run_command.py:120, and the title is the private _REFUSAL plus literals at command lines 93, 104, 123 and 137. The tracing refusal is a guarantee of the nuisance holdout run (no per-case output, ADR 015 and the nuisance suite rule), so it is one piece of knowledge. Detection has the exact target shape: DETECTION_HOLDOUT_RUN_REFUSED and a public refuse_tracing imported by its command.

Change: In evals/cve/nuisance/holdout_run.py rename _REFUSAL to NUISANCE_HOLDOUT_RUN_REFUSED and _refuse_tracing to refuse_tracing. In holdout_run_command.py import both from holdout_run, delete its _refuse_tracing and the `from evals.tracing import TRACING_ON, tracing_enabled` line, call refuse_tracing() in run, and use the constant at lines 93, 104 and 137. Keep both calls to the check (command, before reading the admission, and orchestrator), as detection does. vet_command's own _REFUSAL is another title and stays.

Files: `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`

Tests: No test changes. test_run_refuses_tracing_before_reading_the_admission (test_run_nuisance.py) and test_tracing_refuses_before_the_tree_is_read (test_nuisance_holdout_run.py) keep both call sites pinned, and the text is byte-identical.

Risks: The refusal text is documented and user-facing: it stays identical, so no CHANGELOG line.

#### Fix 3.4: `evals/cve/nuisance/holdout_run.py` `default_deps` (duplication, refactoring)

Problem: The live deps wire nuisance_images.backend_image_ids, a line-for-line copy of evals.cve.images.backend_image_ids (same docker inspect, same check=False provenance policy). holdout_run.py already imports image_ids from evals.cve.images.

Also covers: `evals/cve/nuisance/images.py` (duplication): The function is byte-for-byte the one in evals/cve/images.py:40, comment included.

Also covers: `evals/cve/nuisance/images.py` (duplication): `backend_image_ids` is a copy of `evals.cve.images.backend_image_ids` (images.py:40), same command, same `check=False`, same comment apart from one word. It is the only reason this module imports `subprocess`.

Also covers: `evals/cve/nuisance/gate/gate_session.py` (duplication): The harness wires `backend_image_ids` from evals/cve/nuisance/images.py, a verbatim copy of `evals.cve.images.backend_image_ids`, although this module already imports `image_ids` from evals.cve.images.

Why it was kept: True. Compared line by line: nuisance/images.py:22 and evals/cve/images.py:40 run the same `docker image inspect --format {{.Id}}` with check=False, capture_output, text, keep only returncode 0 and strip stdout. Only one word of the comment differs (server, target). Its only callers are holdout_run.default_deps and gate_session.default_harness. It is the only use of subprocess in nuisance/images.py. Neither module is fingerprinted or in a kit closure.

Change: Delete backend_image_ids and `import subprocess` from evals/cve/nuisance/images.py (Sequence stays for backend_images). In nuisance/holdout_run.py import it with image_ids: `from evals.cve.images import backend_image_ids, image_ids`, and wire `backend_image_ids` in default_deps. In gate/gate_session.py do the same and keep `from evals.cve.nuisance.images import image_tag`. In evals/cve/images.py make the comment true of both suites: "A target or server dropped before launch never reaches assembly, so its backend image is never looked up."

Files: `evals/cve/nuisance/images.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/images.py`

Tests: No test changes: the fakes inject backend_image_ids through NuisanceDeps and the gate harness, and test_nuisance_images.py does not test it. The Docker-backed integration paths keep the same command.

Risks: If fix 6.1 lands first, default_deps lives in the new holdout_run_command.py and the import goes there.

#### Fix 3.5: `evals/cve/nuisance/holdout_run.py` `_prices` (duplication, refactoring)

Problem: _prices is a copy of detection's holdout_prices that returns an anonymous tuple[Prices, Prices], which assemble_server unpacks as gen_price, judge_price and bills with two call_cost calls. AuditPrices.cost already names that pair and that sum. _prices is also recomputed for each server inside the loop of _run_all.

Also covers: `evals/cve/nuisance/assembly.py` (duplication): assemble_server takes prices: tuple[Prices, Prices], an unnamed pair whose order is known only by unpacking it (gen_price, judge_price), then rewrites AuditPrices.cost inline over five lines. holdout_run._prices builds the same anonymous pair. The detection counterpart assemble_target already takes AuditPrices. This also takes the function to 21 body lines (inventory).

Also covers: `evals/cve/nuisance/results.py` (duplication): Four mechanisms shared by the holdout runs are still copied on the nuisance side: `results.RunInterrupted` (which forces `partial_result_kept` to catch two classes and run_files.py to import `nuisance_results`), `audit._print_incidents` (same as `launch_audit.print_report_incidents`), `images.backend_image_ids` (same as `evals.cve.images.backend_image_ids`), and the `(Prices, Prices)` tuple of `holdout_run._prices` with `assemble_server`'s hand-written sum, where detection uses `AuditPrices`.

Also covers: `evals/cve/nuisance/assembly.py` (missing-concept): assemble_server takes `tuple[Prices, Prices]`, unpacked by position (:34), and recomputes the audit cost by hand (:44-45). holdout_run._prices (:277) copies detection's holdout_prices.

Why it was kept: True. holdout_run._prices (:277) returns an anonymous tuple[Prices, Prices], assemble_server unpacks it by position and rewrites AuditPrices.cost over five lines (assembly.py:34, 43-47), and it is recomputed per server in the loop. Published costs are at stake, so a silent swap of generator and judge is a real defect risk. The float result is identical: AuditPrices.cost is call_cost(generator) + call_cost(judge), the same two terms in the same order inside the same sum. I place the pair on HoldoutConditions rather than importing detection's holdout_prices: `prices` is a field of that dataclass, the same `AuditPrices(prices[a], prices[b])` is written a third time in detection/measurement.py:92, and the import would add a nuisance to detection edge for what is a shared run condition. A method taking the two model ids keeps holdout_conditions.py free of a direct mcp_auditor.config import. holdout_conditions is in no kit closure (checked).

Change: In evals/cve/holdout_conditions.py import AuditPrices and add to HoldoutConditions, above _chain_reasons, `def audit_prices(self, model: str, judge_model: str) -> AuditPrices: return AuditPrices(self.prices[model], self.prices[judge_model])`. Delete holdout_prices and its HoldoutConditions and Settings imports from detection/holdout_assembly.py (AuditPrices stays for assemble_target). detection/holdout_run.py: `prices = inputs.conditions.audit_prices(inputs.settings.resolve_model(), inputs.settings.resolve_judge_model())`, import only assemble_target. detection/measurement.py: `generator, judge = models`, `return CostPricing(conditions.audit_prices(generator, judge), conditions.prices_as_of)`, dropping the prices local and the AuditPrices import. nuisance/assembly.py: `prices: AuditPrices`, delete the unpacking, `run_cost=sum(prices.cost(report.generator_usage, report.judge_usage) for report in reports)`, import AuditPrices in place of Prices and call_cost. nuisance/holdout_run.py: delete _prices and the Prices import, compute `prices = ctx.conditions.audit_prices(ctx.settings.resolve_model(), ctx.settings.resolve_judge_model())` once in _run_all before the loop, and pass it to assemble_server.

Files: `evals/cve/holdout_conditions.py`, `evals/cve/detection/holdout_assembly.py`, `evals/cve/detection/holdout_run.py`, `evals/cve/detection/measurement.py`, `evals/cve/nuisance/assembly.py`, `evals/cve/nuisance/holdout_run.py`, `tests/unit/nuisance/test_nuisance_assembly.py`, `tests/unit/cve/test_cve_holdout_conditions.py`

Tests: Test first: one test in tests/unit/cve/test_cve_holdout_conditions.py, a file with two models at different prices, asserting audit_prices(model, judge) puts each on its own side, red until the method exists. test_nuisance_assembly.py: `_PRICES = AuditPrices(holdout_runs.LUNA_PRICE, holdout_runs.LUNA_PRICE)`, `one_run = _PRICES.cost(generator, judge)`, drop the call_cost import. Detection cost tests stay green unchanged. Check the detection fixture_fingerprint and grammar_fingerprint maps: no hashed module is touched.

Risks: Touches three non-fingerprinted detection modules by one line each (the detection area is done). The price lookup in _run_all now happens once even if no server assembles: require_ready has already refused a model with no price, so no new KeyError path. total_cost and run_cost keep their float values. fix 6.1 replaces ctx with inputs and fix 6.1 renames ctx: same line.

#### Fix 3.6: `evals/cve/nuisance/holdout_run.py` `nuisance_overrides, audit_once's AuditShape` (duplication, refactoring)

Problem: nuisance_overrides is RunOverrides.of_holdout with the same assert, and audit_once (audit.py:91-93) spells out the AuditShape that overrides.shape(None) builds.

Also covers: `evals/cve/nuisance/audit.py` (duplication): audit_once rebuilds AuditShape(None, overrides.chain_budget, overrides.max_chain_steps, overrides.tool_call_timeout) by hand, which is RunOverrides.shape(None). The four lines also separate the comment on entered_in_thread (lines 88-89) from the call it explains.

Also covers: `evals/cve/nuisance/holdout_run_command.py` (duplication): The command builds its overrides with `nuisance_overrides` (holdout_run.py:205), a line-for-line copy of `RunOverrides.of_holdout` (launch_audit.py:94), which the detection holdout command already uses.

Why it was kept: True. nuisance_overrides (holdout_run.py:205) is RunOverrides.of_holdout (launch_audit.py:94) line for line, assert included, and the detection holdout command already calls of_holdout. audit_once (audit.py:90-93) spells out AuditShape(None, chain, steps, timeout), which is overrides.shape(None) for either value of audit_every_tool. This is the one mapping from the run conditions to an audit's shape, shared by the two holdout layers.

Change: Delete nuisance_overrides from holdout_run.py. holdout_run_command._audit_admitted_servers calls `RunOverrides.of_holdout(ready.conditions)`, and the fallback at holdout_run.py:151 does the same until fix 6.1 removes it. In nuisance/audit.py delete the `overrides` and `shape` locals and the AuditShape import, and write inside the try `audit = await audit_launch(launch, auditor.auditor, auditor.overrides.shape(None))`, so the comment on entered_in_thread sits directly above the try it explains.

Files: `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`, `evals/cve/nuisance/audit.py`

Tests: No test changes: test_nuisance_audit_once.py passes real RunOverrides, and no test imports nuisance_overrides.

Risks: fix 6.1 and fix 6.1 (another section) also ask to delete nuisance_overrides: apply it once.

#### Fix 3.7: `evals/cve/nuisance/holdout_run.py` `NUISANCE_CONCURRENCY` (other, refactoring)

Problem: The default concurrency of every nuisance subcommand is defined in the nuisance holdout run's orchestrator, so `vet_command`, `gate_command` and `fix_check_command` each import the nuisance holdout run's module for one integer. The fix check, which runs no audit, thereby depends on that run's audit stack.

Also covers: `evals/cve/nuisance/holdout_run.py` (other): The default concurrency of every nuisance subcommand lives in the nuisance holdout run's orchestrator, so vet_command.py:38, gate_command.py:57 and fix_check_command.py:39 import the whole orchestrator, and its auditor wiring, for one integer.

Also covers: `evals/cve/nuisance/fix_check_command.py` (other): The default `--concurrency` shared by `fix-check`, `vet`, `gate` and `run` is defined in holdout_run.py. The no-LLM fix-check command therefore imports the nuisance holdout run's orchestrator, with its auditor, pricing, tracing and settings dependencies, only to read one integer. The vet and gate commands do the same.

Why it was kept: True, and measured: fix_check_command imports holdout_run only for this integer (:39) and loads 2,130 modules with LangChain and LangGraph. With that import stubbed it loads 837 and neither, and the fix check uses no LLM. commands.py documents what the subcommands share and does not import holdout_run, so no cycle. vet_command and gate_command keep the LLM stack through other imports, but stop depending on the orchestrator for a constant.

Change: Move `NUISANCE_CONCURRENCY = 6` to evals/cve/nuisance/commands.py and extend its docstring: "What the nuisance subcommands share: the walk record path, the admission they read, their default concurrency and their exit codes." Repoint with no re-export, since holdout_run keeps importing the name until its defaults go and pyrefly would not flag a stale import: holdout_run.py, holdout_run_command.py, vet_command.py, gate/gate_command.py, fix_check_command.py and tests/unit/nuisance/test_run_nuisance_vet.py. Afterwards grep that no `holdout_run import` still names it.

Files: `evals/cve/nuisance/commands.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/cve/nuisance/fix_check_command.py`, `tests/unit/nuisance/test_run_nuisance_vet.py`

Tests: Import line of test_run_nuisance_vet.py only. Every --concurrency default stays 6.

Risks: If fix 6.1 makes concurrency required first, holdout_run.py drops the name altogether. another section and another section (fix 5.6) also edit commands.py.

#### Fix 3.8: `evals/cve/nuisance/gate/gate_baseline.py` `HOLDOUT_TEST_BUDGET` (other, refactoring)

Problem: The nuisance gate's baseline module imports evals.cve.detection.holdout_run for one integer. Measured: every other import of gate_baseline loads 728 modules with no LangChain or LangGraph, and this import adds 1,281 more (langchain_core, langgraph, openai, rich), so the pure decision modules gate.py and gate_recording.py load the detection holdout run and the LLM stack. The value is a run condition both holdout runs share, and evals/cve/holdout_conditions.py, which gate_baseline already imports, is its natural home.

Also covers: `evals/cve/nuisance/gate/gate_baseline.py` (hexagonal-boundary): Three names both suites depend on live in detection modules. `HOLDOUT_TEST_BUDGET` sits in the detection holdout orchestrator, so the nuisance gate baseline loads that orchestrator for one integer. `grammar_fingerprint` sits in `detection/baseline.py`, so `admission.py` and `gate_baseline.py` load the detection baseline and its environment modules for it. `planting_host_parts` and `host_stand_in_files`, which hash a planting host for both fixture fingerprints, sit there too.

Why it was kept: True, and measured. gate_baseline loads 2,011 modules with LangChain and LangGraph because of `from evals.cve.detection.holdout_run import HOLDOUT_TEST_BUDGET`. With that one module stubbed, gate_baseline, gate and gate_recording load 731 to 733 modules and neither library, so the pure comparison and recording code really is tied to the LLM stack by one integer. The value is a run condition shared by both holdout runs and the nuisance gate, and evals/cve/holdout_conditions.py, which gate_baseline already imports, is its home. Not fingerprinted, not in a kit closure, name unchanged.

Change: Move `HOLDOUT_TEST_BUDGET = 10` to evals/cve/holdout_conditions.py with its comment, extended: "detection-suite-rule.md, Run conditions and statistic, a constant, not a flag. The nuisance holdout run and the nuisance gate take it too, since the holdout nuisance rate is read beside the holdout detection rate." Delete the comment at nuisance/holdout_run.py:76-79, which that sentence replaces. Repoint with no re-export (detection/holdout_run.py keeps using the name, so pyrefly would not flag a stale import): detection/holdout_run.py, detection/holdout_command_deps.py, nuisance/holdout_run.py, nuisance/gate/gate_baseline.py, tests/unit/nuisance/test_nuisance_holdout_run.py, tests/unit/nuisance/gate/test_nuisance_gate_baseline.py, tests/unit/nuisance/gate/support/nuisance_gate_baselines.py. Afterwards grep that no `detection.holdout_run import` names it.

Files: `evals/cve/holdout_conditions.py`, `evals/cve/detection/holdout_run.py`, `evals/cve/detection/holdout_command_deps.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/gate/gate_baseline.py`, `tests/unit/nuisance/test_nuisance_holdout_run.py`, `tests/unit/nuisance/gate/test_nuisance_gate_baseline.py`, `tests/unit/nuisance/gate/support/nuisance_gate_baselines.py`

Tests: Import lines of the three test modules only. The value 10 and the serialized `budget` keys do not move, so the conditions of evals/baselines/nuisance/ still compare. Check the fingerprint maps before and after: no hashed module changes.

Risks: If fix 6.1 lands first, the default_deps use lives in holdout_run_command.py. another section edits gate_baseline.py's imports.

### 4. Audit attempts

Order and interactions: fix 4.3 reshapes `gate_run` first, then fix 4.4 moves it unchanged to `gate/gate_audit.py`, so the move stays a pure move.

Verifier's notes: Confirmed: fix 4.3 (gate_run on the shared loop, bytes kept through MissedCallWording), fix 4.1 (carries fix 4.1), fix 4.2, fix 4.5, fix 4.4. Rejected: a rejected finding. Order inside the section. All are on evals/cve/nuisance/audit.py except a rejected finding, which is independent (test only). 1) fix 4.1, one call swapped. 2) fix 4.2, type swap in the unions. 3) fix 4.3, with the pinning assertions added and seen green on the old code first. 4) fix 4.4, which moves the reshaped gate_run. fix 4.3 and fix 4.4 can land as one commit, but keeping them apart makes the move a pure move. If fix 4.4 were dropped, _GATE_WORDING and gate_run stay in audit.py and nothing else changes. fix 4.2 and fix 4.3 do not conflict: gate_run never sees a provider error, since nuisance_audit turns it into a DroppedRun first. Interactions with other sections of this plan: - another section edits the same audit.py: fix 3.1, fix 3.1, fix 3.1 and fix 3.1 (DroppedRun.from_causes, _DROP_PRECEDENCE, right beside _cause_of and _failure, which fix 4.2 retypes); fix 3.6 and fix 3.6 (overrides.shape(None) in audit_once, the function fix 4.1 and fix 4.2 edit). It also touches test_nuisance_assembly.py (fix 3.5, fix 3.5, fix 3.5), the file of fix 4.5. Plan them in sequence on audit.py. - another section fix 6.1 also edits audit_once (shape), and fix 6.5 touches test_nuisance_solo_given.py, whose GateRun import fix 4.4 repoints. - another section fix 13.5 renames provisioner_of, called in nuisance_environment of audit.py: a one-line overlap. - another section, another section and another section reshape gate_session.py, and another section also gate_session_model.py and nuisance_gate_sessions.py. fix 4.4 changes only their import lines there, so do it before those sections or rebase the imports. another section also edits gate_session_model.py (the BenignCall alias). No fingerprinted module changes, no kit imports the modules touched, and no console text, exit code, record field or committed data moves.

#### Fix 4.1: `evals/cve/nuisance/audit.py` `_print_incidents` (duplication, refactoring)

Problem: _print_incidents is a line-for-line copy of launch_audit.print_report_incidents, the same two console lines with the label in place of server.server_package. The detection side already calls the shared function.

Also covers: `evals/cve/nuisance/audit.py` (duplication): _print_incidents is a line-for-line copy of launch_audit.print_report_incidents, with server.server_package in place of the label.

Why it was kept: Compared byte for byte. nuisance _print_incidents (audit.py:131) and launch_audit.print_report_incidents (launch_audit.py:187) print the same missed-call line, with the same escape(detail.missed_call_detail(missed)) inside the same yellow markup, then the same throttle line under the same condition, in the same order. The only difference is that the nuisance copy holds the escaped text in a local. The detection side already calls the shared function, and the detection pass created it for this adoption (HANDOFF: fix 3.4, 'E replaces nuisance audit._print_incidents with the same call'). On a holdout run this is the function that applies TYPES_ONLY to provider text, so one definition has real value.

Change: Delete _print_incidents from evals/cve/nuisance/audit.py. In audit_once call `print_report_incidents(server.server_package, audit.report, auditor.auditor.report_detail)` at the same place, before print_lost_connections, importing it from evals.cve.launch_audit. Drop the `ReportDetail` import, whose only use was this function. `escape` stays for _failure.

Files: `evals/cve/nuisance/audit.py`

Tests: No test changes. The existing audit_once tests of test_nuisance_audit_once.py on incidents and on TYPES_ONLY must stay green unchanged, which shows the output is the same.

#### Fix 4.2: `evals/cve/nuisance/audit.py` `ProviderError` (duplication, glossary log)

Problem: ProviderError is the same one-field value as evals/cve/audit_attempts.ProviderErrorAttempt, with the same invariant stated in both docstrings: the text holds the error's type and status, never its message. audit.py already imports from audit_attempts. On a holdout run that invariant is what keeps provider text out of the output, and it is declared on two types.

Why it was kept: True: nuisance ProviderError(reason) and audit_attempts.ProviderErrorAttempt(description) are the same one-field value, for the same event (a transient provider error, the attempt thrown away), both built from describe_provider_error(failure.cause), and both docstrings state the same invariant (type and status, never the message). That invariant is what keeps provider text out of a holdout run's output, so it should sit on one type. The detection holdout policy already retries ProviderErrorAttempt within its attempts exactly as nuisance_audit retries ProviderError, so the shared docstring ('a later attempt may not meet, thrown away ungraded') also reads true here. The console line is unchanged: _failure prints f"provider error ({...})" from the same text. ProviderError appears nowhere else in src, evals or the living docs, only in nuisance/audit.py, its tests and two dated plans (2026-10-28, 2026-11-05), so the rename takes a glossary-log line.

Change: Delete the `ProviderError` dataclass from evals/cve/nuisance/audit.py and import ProviderErrorAttempt from evals.cve.audit_attempts. audit_once returns `ProviderErrorAttempt(describe_provider_error(failure.cause))`. Replace the type in the unions of audit_once, nuisance_audit, _cause_of and _failure, and read `outcome.description` in _failure. LaunchFailed and the rest of the union stay. Add one line to docs/glossary-log.md at its sorted place: `ProviderError` (the nuisance audit's outcome) to `ProviderErrorAttempt`, rename, dated the day of the change.

Files: `evals/cve/nuisance/audit.py`, `tests/unit/nuisance/test_nuisance_audit_once.py`, `tests/unit/nuisance/test_nuisance_retry_policy.py`, `tests/unit/nuisance/support/test_nuisance_retry_policy_given.py`, `docs/glossary-log.md`

Tests: Imports and type names follow. test_nuisance_retry_policy_given.py: PROVIDER_ERROR = ProviderErrorAttempt("ModelAPIError, status 500"). test_nuisance_retry_policy.py: the Attempt alias. test_nuisance_audit_once.py: the isinstance check and outcome.description in test_a_transient_provider_error_is_named_without_its_message. The test pinning 'provider error (ModelAPIError, status 500), attempt 1/3' stays and shows the console text is unchanged.

Risks: Internal type only: no written report, result file or record carries it. The retired-word guard reads its own list (retired_words.py), so the log line does not make it fire on ProviderErrorAttempt or ProviderErrorKind.

#### Fix 4.3: `evals/cve/nuisance/audit.py` `gate_run` (duplication, refactoring)

Problem: gate_run rewrites the loop of evals/cve/audit_attempts.graded_despite_missed_model_calls: up to INCOMPLETE_ATTEMPTS, union of the causes, one line per attempt, one final line, None when every attempt stays incomplete, None at once on a thrown-away attempt. Its docstring says so: 'the detection gate's policy on an incomplete attempt, with an alarm in place of a detection'. The only nuisance-specific knowledge is what makes an attempt incomplete (no counted alarm and a missed call). The shared loop cannot be reused today only because it takes a detection Target, and reads nothing from it but flaw_id. The function is also 21 body lines (inventory).

Why it was kept: The fact holds. gate_run (evals/cve/nuisance/audit.py:189) re-implements the loop of audit_attempts.graded_despite_missed_model_calls: INCOMPLETE_ATTEMPTS tries, union of causes, one line per attempt, one final line, None at the end, None at once on a thrown-away attempt. It is the same knowledge, not a similar shape: CONTRIBUTING.md states the rule in near-identical words for both gates (line 57 for detection, line 65 for nuisance: attempted again, up to three attempts, the run does not complete when every attempt stays incomplete), and gate_run's docstring calls it the detection gate's policy. The shared loop reads only target.flaw_id, and its only callers are detection/audit.py:65 and test_detection_audit_attempts.py (4 calls). The finder's direction is NOT adopted as written, because the output differs in two places. Retry line: nuisance ends 'no counted alarm, attempted again', shared ends 'not graded'. Final line: nuisance says '<pkg> run did not complete:', shared says '<label> run skipped:'. The rest of both lines is byte-identical. Adopting the shared words would change the gate console and need a CHANGELOG entry, so the fix carries the two phrases as a small value object and keeps every byte. Control flow compared branch by branch: DroppedRun maps to None (returned at once), a flagged or complete report to GateRun (returned), an incomplete one to IncompleteAttempt(report, incomplete_causes(report)) (causes unioned, line printed). The filter on _INCOMPLETE_CAUSES stays in the nuisance adapter. Side gain checked: audit_attempts no longer imports evals.cve.detection.targets. Its remaining imports do not load any detection module, and in a scratch copy with that import removed, audit_attempts, nuisance.audit, detection.audit, detection.holdout_audit, nuisance gate_session and the three entry points all import cleanly.

Change: In evals/cve/audit_attempts.py: delete `from evals.cve.detection.targets import Target`. Add `@dataclass(frozen=True) class MissedCallWording: attempt_note: str; run_note: str`. Change the signature to `graded_despite_missed_model_calls[T](label: str, attempt: Callable[[], Awaitable[AttemptOutcome[T]]], wording: MissedCallWording) -> T | None`, with `wording` required, so the shared module names no suite. The two prints become f"[yellow]{label}: attempt {number}/{INCOMPLETE_ATTEMPTS}: {describe_missed_call_causes(outcome.causes)}, {wording.attempt_note}[/yellow]" and f"[yellow]{label} {wording.run_note}:[/yellow] a model call missed at all {INCOMPLETE_ATTEMPTS} attempts ({describe_missed_call_causes(causes)})". evals/cve/detection/audit.py declares `DETECTION_GATE_WORDING = MissedCallWording("not graded", "run skipped")` and passes `target.flaw_id` and that wording. gate_run becomes, with `_GATE_WORDING = MissedCallWording("no counted alarm, attempted again", "run did not complete")`: an inner `async def attempt() -> AttemptOutcome[GateRun]`: `outcome = await audit()`; DroppedRun returns None; `report = outcome.report`; `flagged = bool(flagged_tools(report, counted_tools(server)))`; `if not flagged and is_incomplete(report): return IncompleteAttempt(report, incomplete_causes(report))`; `return GateRun(flagged=flagged, report=report)`. Then `return await graded_despite_missed_model_calls(server.server_package, attempt, _GATE_WORDING)`. Keep gate_run's docstring. In audit.py, import AttemptOutcome, IncompleteAttempt, MissedCallWording and graded_despite_missed_model_calls from audit_attempts, and drop INCOMPLETE_ATTEMPTS and describe_missed_call_causes, which nothing there reads any more. Avoid the word give-up for the fields: the glossary reserves it for a calibration agent's conclusion. No CHANGELOG entry: no output changes.

Files: `evals/cve/audit_attempts.py`, `evals/cve/detection/audit.py`, `evals/cve/nuisance/audit.py`, `tests/unit/detection/test_detection_audit_attempts.py`, `tests/unit/nuisance/test_nuisance_retry_policy.py`

Tests: First, on the current code, add to test_nuisance_retry_policy.py the assertions that pin the two gate-only phrases, and see them green: 'no counted alarm, attempted again' in test_a_gate_run_incomplete_without_an_alarm_is_attempted_again and 'run did not complete:' in test_a_gate_run_incomplete_at_every_attempt_does_not_complete (the captured console is 200 wide, so no wrap). They must stay green through the refactoring. test_detection_audit_attempts.py passes TARGET.flaw_id and `DETECTION_GATE_WORDING`, imported from evals/cve/detection/audit.py, at its 4 calls, and its pinned strings ('not graded', 'run skipped') stay. No fingerprinted module is touched: audit_attempts.py and detection/audit.py are not in the list, and counter.py and counting.py are only called.

Risks: Refactoring only: attempts, retries, results and console bytes stay the same, unlike the finder's direction, which changed two console phrases. Edits a shared module (evals/cve/audit_attempts.py), and detection/audit.py by its call and one constant. It is not imported by any kit (grep over evals/cve/kit, the dossiers and admission finds nothing).

#### Fix 4.4: `evals/cve/nuisance/audit.py` `gate_run` (other, refactoring)

Problem: audit.py holds the nuisance holdout run's retry policy and also the gate's opposite policy on an incomplete attempt (`GateRun`, `gate_run`). The gate policy is the only reason the module imports the counter (`flagged_tools`, `counted_tools`) and `INCOMPLETE_ATTEMPTS`, and the reason `gate_session_model` imports audit.py. The two policies differ by design (ADR 024 against the nuisance suite rule) and sit side by side, while the gate has its own package.

Why it was kept: True: audit.py carries the audit, the nuisance holdout run's retry policy and the gate's opposite policy on an incomplete attempt. gate_run and GateRun are the only reason it imports the counter (flagged_tools, counted_tools), and only the gate uses them. The detection side already keeps the two policies in separate modules (detection/audit.py for the gated session, detection/holdout_audit.py for the detection holdout run), and the nuisance gate has its own package. No cycle: the new module imports nuisance.audit, and nuisance.audit imports nothing from gate/. is_incomplete and incomplete_causes stay in audit.py because assembly.py and holdout_run_status.py read them too. The finder's list of importers misses tests/unit/nuisance/gate/test_nuisance_gate_session.py, and a missed importer would be caught only at import time since audit.py would no longer define the name.

Change: Create evals/cve/nuisance/gate/gate_audit.py holding `_GATE_WORDING`, `GateRun` and `gate_run` (in the shape fix 4.3 gives it), importing NuisanceAudit, DroppedRun, is_incomplete and incomplete_causes from evals.cve.nuisance.audit, flagged_tools from counter, counted_tools from counting, and AttemptOutcome, IncompleteAttempt, MissedCallWording and graded_despite_missed_model_calls from audit_attempts. Delete them from audit.py with its now unused imports (flagged_tools, counted_tools, AttemptOutcome, IncompleteAttempt, MissedCallWording, graded_despite_missed_model_calls). Repoint every importer: evals/cve/nuisance/gate/gate_session.py (GateRun, gate_run; audit_once and nuisance_audit stay on audit), evals/cve/nuisance/gate/gate_session_model.py, tests/unit/nuisance/test_nuisance_retry_policy.py (gate_run), tests/unit/nuisance/gate/test_nuisance_gate_session.py, tests/unit/nuisance/gate/support/nuisance_gate_sessions.py, tests/unit/nuisance/support/test_nuisance_solo_given.py. The gate_run tests stay in test_nuisance_retry_policy.py, which specifies the two policies side by side.

Files: `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/gate/gate_audit.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_session_model.py`, `tests/unit/nuisance/test_nuisance_retry_policy.py`, `tests/unit/nuisance/gate/test_nuisance_gate_session.py`, `tests/unit/nuisance/gate/support/nuisance_gate_sessions.py`, `tests/unit/nuisance/support/test_nuisance_solo_given.py`

Tests: Import lines only. The whole nuisance unit suite must stay green. counter.py and counting.py are imported from a new module but not changed, so counter_fingerprint and nuisance_fixture_fingerprint must read the same before and after. No kit imports nuisance.audit or the gate package.

Risks: A pure move: no behavior, message or field changes. Names are not re-exported from audit.py, so every importer listed must be repointed.

#### Fix 4.5: `tests/unit/nuisance/test_nuisance_assembly.py` `test_each_run_status_carries_its_server_health_and_missed_call_causes` (test-fragility, refactoring)

Problem: The assertion builds three NuisanceHoldoutRunStatus with 11 positional arguments, such as (False, False, True, 0, 0, 0, 3, 2, 0, 1, ['provider_refusal']). A reader cannot tell which integer is which health counter without opening the dataclass. The test's subject is the health and the causes, yet it also pins flagged, split_flagged, incomplete and both fail counts, so any new status field breaks these three lines.

Why it was kept: True: lines 104-108 of test_nuisance_assembly.py build three NuisanceHoldoutRunStatus with 11 positional arguments, so a reader cannot tell which integer is which counter, and any new status field breaks a test about health and causes. The fields the assertion would stop pinning are covered elsewhere: flagged and split_flagged at line 71, incomplete at line 76 of the same file, the raw fail counts through result.raw_fail_per_run at line 82, and declared_function_fail_per_run in test_each_run_status_counts_the_fails_on_the_tools_left_out_by_their_declared_function. This is not the precedent of a test pinning a public field name: the projection still names each field, and the literals line up with the ServerHealth(2, 1, 1, 4, 2) given just above.

Change: Replace the status assertion with two projections: `assert [(s.non_protocol_lines, s.lost_connection_responses, s.relaunches, s.unsent_calls, s.cut_responses) for s in result.statuses] == [(2, 1, 1, 4, 2), (0, 3, 2, 0, 1), (0, 0, 0, 0, 0)]` and `assert [s.missed_call_causes for s in result.statuses] == [[], ["provider_refusal"], ["unreadable_answer"]]`. Keep the three aggregate assertions. Drop the NuisanceHoldoutRunStatus import, whose only uses are these three lines.

Files: `tests/unit/nuisance/test_nuisance_assembly.py`

Tests: This test only. It must stay green, and no production code changes.

### 5. Containers, vet and benign call

Order and interactions: this section comes before the orchestrator of section 6. Fix 5.2 replaces `running_containers` and `remove_containers` of `NuisanceDeps` by `sweep: ContainerSweep` while `default_deps` is still in `holdout_run.py`. Fix 6.1 then moves `default_deps` with the `DOCKER_SWEEP` argument, so the two Docker functions are not among the imports it carries.

Verifier's notes: Inside the section. Six fixes stay: fix 5.2 (container sequence and ContainerSweep), fix 5.6 (committed_run_population), fix 5.3 (BenignCallCheck), fix 5.7 (benign_call.py), fix 5.4 and fix 5.5 (VetDeps), fix 5.1 (rename of reset_containers). Suggested order: fix 5.1 first (containers.py and backend_registry.py, independent), then fix 5.2, then fix 5.3, which retypes the same drop_failing_servers signature and the same deps classes, then fix 5.4 and fix 5.5 on VetDeps, fix 5.6 and fix 5.7 last, independent of the rest. No two conflict, but fix 5.2, fix 5.3, fix 5.4 and fix 5.5 all edit the VetDeps block of vet_command.py, so they are best done in one pass or in this order. Other sections on the same modules: - another section (fix 6.1, fix 5.6, fix 6.1, fix 6.1, fix 6.1, fix 6.1): rewrites the signature of run_nuisance and moves default_deps to holdout_run_command.py. Do fix 5.2 first or carry it over: the `with rebuilt_run_images(...)` block and the DOCKER_SWEEP argument move with them, and RunContainerDeps stays satisfied by NuisanceDeps. - another section: renames _REFUSAL to NUISANCE_HOLDOUT_RUN_REFUSED (the argument passed to rebuilt_run_images), moves NUISANCE_CONCURRENCY to commands.py (the file fix 5.6 edits, and vet_command's import), touches holdout_run_command.run's refusals around the block fix 5.6 replaces. - another section: fix 11.7 adds add_committed_input_arguments in commands.py and no read_committed, so committed_run_population keeps its three paths. a rejected finding would rename run_population and RunPopulation (the names in committed_run_population's signature), and fix 11.2 changes run_population's body only. - another section: fix 7.3 and fix 7.3 change the gate's rebuild (a behavior change). The gate's sequence comes closer to the run's but still has no refusal and removes inside its try, so it does not adopt rebuilt_run_images. gate_session_model.py is also touched by fix 5.3 (one field type). - another section: fix 10.6 renames `gaps` in unrecorded.py and in vet_command._print_unrecorded, which stays since a rejected finding is rejected. - another section: fix 13.6 rewrites _responder in backend_registry.py, near the field fix 5.1 renames, with no overlap (the responders pass no containers_removed_by_name). - another section: fix 1.3 edits _assemble_run in holdout_run.py, not the lines touched here.

#### Fix 5.1: `evals/cve/nuisance/containers.py` `RunImages.reset_containers` (ubiquitous-language, glossary log)

Problem: `reset_containers`, `backend_reset_containers`, "A reset container" and the test wording "resets the Doris cluster" use "reset" for removing a persistent backend container by name. In the nuisance suite, where a baseline reset is a governed event, a phrase like "the gate resets Doris" reads as a term of ADR 020.

Also covers: `evals/cve/nuisance/backend_registry.py` (ubiquitous-language): `reset_containers`, `backend_reset_containers` and `ServerImages.reset_containers` (containers.py:48/64/89) use "reset" for removing a persistent backend container at a command's start. The same package uses the word in its glossary sense: `server_reset`, `WHOLE_RESET`, `_reset_refusals` (gate_baseline.py, gate_recording.py). Test names carry the second sense too (`test_a_pulled_backend_is_reset_at_start_but_neither_rebuilt_nor_swept`, `test_a_built_backend_resets_no_container_by_name`).

Why it was kept: The glossary gives 'reset' one sense (deleting a baseline in the commit that changes a fixture, the scoring code, the model, the runs or the budget), absent from 'Words with several senses', and the same package uses it in that sense (server_reset, WHOLE_RESET, _reset_refusals). reset_containers names something else: persistent containers removed by name. The field is neither serialized nor read by the fingerprint, which reads only `served` of RegisteredBackend. Of the two names proposed, containers_removed_by_name is the accurate one: removed_at_start would be false, since vetting._second_pass also removes these containers before a second pass.

Change: Rename RegisteredBackend.reset_containers and RunImages.reset_containers to `containers_removed_by_name`, and backend_registry.backend_reset_containers to `backend_containers_removed_by_name`, with the import and call in containers.py. Reword the docstring of remove_backend_containers ('A container named by its backend's registry entry is removed whether it runs or not'). Rename the tests: test_the_removal_at_start_removes_the_doris_cluster_by_its_name, test_the_removal_at_start_removes_no_container_by_name_for_a_built_backend, test_a_pulled_backend_is_removed_at_start_but_neither_rebuilt_nor_swept, test_a_built_backend_removes_no_container_by_name, and the module docstring of test_nuisance_containers.py. plans/2026-11-10 and plans/2026-11-13 cite reset_containers, so add one line to docs/glossary-log.md, in sorted position: `reset_containers`, `backend_reset_containers` (a persistent backend's containers, removed by name when a nuisance command starts) | `containers_removed_by_name`, `backend_containers_removed_by_name` | rename | date of the change.

Files: `evals/cve/nuisance/backend_registry.py`, `evals/cve/nuisance/containers.py`, `tests/unit/nuisance/test_nuisance_containers.py`, `tests/unit/nuisance/test_nuisance_holdout_run_backends.py`, `tests/integration/committed/nuisance/test_nuisance_backend_registry.py`, `docs/glossary-log.md`

Tests: Test names and one field access change, no assertion. tests/integration/committed/project/test_glossary.py runs on the log line. nuisance_fixture_fingerprint must stay identical for the 65 admitted servers: backend_registry.py is not a hashed file (only each entry's `served` paths are), checked by the fingerprint check of Verification before and after.

Risks: The comment in evals/cve/backends/doris.py:175 ('the cluster is reset only when a command starts') keeps the word: doris.py is fingerprinted and served, so editing it would move the fixture fingerprint of the Doris server. docs/nuisance-suite-log.md:217 is a dated record and stays too. Both are left as they are.

#### Fix 5.2: `evals/cve/nuisance/containers.py` `ContainerHost` (duplication, refactoring)

Problem: `run_nuisance` and `vet_servers` repeat the same five-step sequence (refuse server containers, remove backend containers, rebuild, refuse again, try and sweep), and the vet's docstring says it follows the run's order so that it proves the run's launch: nothing enforces that. `ContainerHost` also restates the shared `ContainerSweep`: `NuisanceDeps` and `VetDeps` carry `running_containers` and `remove_containers` flat and pass themselves as the host, while the gate harness already holds a `ContainerSweep`.

Also covers: `evals/cve/nuisance/vet_command.py` (duplication): vet_servers repeats, line for line, the container protocol of holdout_run.run_nuisance (holdout_run.py:154-163): refuse_without_closed_networks, run_images, refuse_server_containers, remove_backend_containers, rebuild, refuse_server_containers again, then try/finally sweep_run_containers. Its docstring states the coupling: 'In the run's order, so a vet proves the launch a run makes'. Nothing enforces that order: a step added to one copy leaves the vet proving a launch the run does not make.

Also covers: `evals/cve/nuisance/vet_command.py` (duplication): The container hygiene (closed-network refusal, run_images, refuse, remove backends, rebuild, refuse again, try, sweep in finally) is written step for step in run_nuisance (holdout_run.py:153-164) and vet_servers (vet_command.py:153-162). The vet's guarantee rests on two copies staying in order by hand.

Also covers: `evals/cve/nuisance/containers.py` (duplication): The ContainerHost protocol restates ContainerSweep's two fields. NuisanceDeps (holdout_run.py:96-97) and VetDeps (vet_command.py:60-61) flatten them while NuisanceGateHarness and detection hold `sweep: ContainerSweep`. The test helper RemovalHost (tests/unit/support/nuisance_docker_hosts.py:48) is a third copy.

Also covers: `evals/cve/nuisance/containers.py` (duplication): The `ContainerHost` protocol declares the same two members as `run_images.ContainerSweep`, which detection, the nuisance gate (`harness.sweep`) and the fix-check command already carry. `NuisanceDeps` and `VetDeps` instead spread the pair into two fields each, and the tests add a third shape of it, `RemovalHost` in tests/unit/support/nuisance_docker_hosts.py.

Also covers: `evals/cve/nuisance/holdout_run.py` (duplication): NuisanceDeps and VetDeps carry running_containers and remove_containers as two flat fields, while the nuisance gate's harness, HoldoutDeps and the detection command use the shared ContainerSweep. The ContainerHost protocol in containers.py exists only so these flat deps objects and a ContainerSweep can both be passed. As a result drop_failing_servers(population.audited, deps.benign_call, deps) hands the whole deps object as a container host, and the test helpers add a third copy of the shape (RemovalHost in nuisance_docker_hosts.py).

Why it was kept: Both facts hold. (1) run_nuisance (holdout_run.py:154-163) and vet_servers (vet_command.py:153-162) write the same ordered sequence: closed-network refusal, run_images, refuse, remove backends, rebuild, refuse again, try, sweep in finally. The vet's docstring states the coupling ('In the run's order, so a vet proves the launch a run makes'), and CLAUDE.md documents the vet as having 'the run's container hygiene'. This is one piece of knowledge, not a look-alike. The gate has a different order (no refusal, its removal inside the try, its rebuild in _vetted), so it stays out. (2) ContainerHost restates the two fields of run_images.ContainerSweep. The gate harness, detection and the fix-check command already hold a ContainerSweep, and gate_session passes harness.sweep where ContainerHost is expected. Only NuisanceDeps and VetDeps flatten the pair, and tests/unit/support/nuisance_docker_hosts.RemovalHost is a third copy.

Change: In evals/cve/nuisance/containers.py: delete ContainerHost. Type remove_backend_containers and sweep_run_containers on `sweep: ContainerSweep` (imported from evals.cve.run_images). Add `class RunContainerDeps(Protocol)` with read-only properties `check_networks: Callable[[], None]`, `rebuild: Callable[[Sequence[str]], None]` and `sweep: ContainerSweep`. Add, right below `RunImages` and above `run_images` (the newspaper scan flags a function whose users all sit below it, and this one is the only user of the four functions it calls in this module), `@contextmanager def rebuilt_run_images(servers: Sequence[AdmittedServer], deps: RunContainerDeps, refusal: str) -> Generator[None]` whose body is: refuse_without_closed_networks(deps.check_networks), images = run_images(servers), _refuse_server_containers(deps.sweep, images, refusal), remove_backend_containers(deps.sweep, images), deps.rebuild(images.services), _refuse_server_containers(deps.sweep, images, refusal), then `try: yield finally: sweep_run_containers(deps.sweep, images)`. Its docstring carries the vet's guarantee and says a refusal raised before the yield sweeps nothing. refuse_server_containers becomes private (_refuse_server_containers), its only callers being this sequence. In holdout_run.py: replace the fields running_containers and remove_containers of NuisanceDeps by `sweep: ContainerSweep` at the same position (default_deps builds it positionally, with DOCKER_SWEEP), keep _refuse_dirty_tree before the block, and write `with rebuilt_run_images(population.audited, deps, NUISANCE_HOLDOUT_RUN_REFUSED): return await _run_surviving(population, deps, ctx, tree)` (the name fix 3.3 gives the title). In vet_command.py: same field change on VetDeps (DOCKER_SWEEP in default_vet_deps), and vet_servers becomes `with rebuilt_run_images(servers, deps, _REFUSAL): return await drop_failing_servers(servers, deps.benign_call, deps.sweep)`. In vetting.py: drop_failing_servers and _second_pass take `sweep: ContainerSweep`. _run_surviving passes deps.sweep. The gate's calls are unchanged since it already passes harness.sweep. Drop the imports ruff then flags (running_containers, remove_containers, refuse_without_closed_networks, run_images in holdout_run and vet_command). Behavior, order of Docker calls and refusal texts are identical.

Files: `evals/cve/nuisance/containers.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/vetting.py`, `tests/unit/support/nuisance_docker_hosts.py`, `tests/unit/support/nuisance_vets.py`, `tests/unit/support/nuisance_holdout_runs.py`, `tests/unit/nuisance/support/test_nuisance_vetting_given.py`, `tests/unit/nuisance/test_nuisance_vetting.py`, `tests/unit/nuisance/test_nuisance_containers.py`, `tests/unit/nuisance/test_nuisance_vet.py`, `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`

Tests: No test changes what it asserts. nuisance_docker_hosts: delete RemovalHost and host_of, add a `DockerHost.sweep` property returning ContainerSweep(self.running, self.remove), and deps_on passes sweep=host.sweep. nuisance_vets.deps_on passes sweep=host.sweep. nuisance_holdout_runs.deps_auditing passes sweep=docker.sweep, and deps_reaching_nothing builds ContainerSweep(running_containers, remove_containers) from its raising functions. ScriptedVet.host becomes `sweep = ContainerSweep(self._docker.running, self._remove)`, with its call sites in test_nuisance_vetting.py. test_nuisance_vet.py:99 replaces the two fields by sweep=containers.sweep. test_nuisance_holdout_run_sweep.py:21 replaces running_containers by sweep=<fake>.sweep: since the fake's remove no longer raises as deps_reaching_nothing's did, keep the fake in a local and add `assert containers.removed == []` so the test still proves nothing is removed on that refusal. The tests of the two refusals, of the sweep at the end and of the order (rebuilt, running_at_rebuild, removed) guard the sequence. Full check: uv run pytest -n auto, ruff, pyrefly. No fingerprinted module is touched, the fingerprint check of Verification stays identical.

Risks: A refactoring, as long as the try covers only the yield: a refusal must sweep nothing (test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running pins it). A sync context manager around an await keeps the finally on CancelledError, as the current try does. NuisanceDeps is built positionally in default_deps and deps_reaching_nothing, so the field position matters. The gate keeps its own sequence by design (ADR-level hygiene differs: no refusal).

#### Fix 5.3: `evals/cve/nuisance/vetting.py` `BenignCall` (ubiquitous-language, refactoring)

Problem: `type BenignCall` in vetting.py is a callable that launches a server and returns its failure reason, while `BenignCall` in admission.py is the recorded call (tool, arguments, expect, before), imported under that name by benign_call.py next door. One identifier holds two concepts in one package. The callable's signature is also spelled out three more times with its comment: VetDeps.benign_call (vet_command.py:62), NuisanceDeps.benign_call (holdout_run.py:85) and NuisanceGateHarness.benign_call (gate_session_model.py:30).

Also covers: `evals/cve/nuisance/vetting.py` (naming): `BenignCall` names two things in the suite: the admission record (admission.BenignCall, a tool and its arguments) and this callable that returns a failure reason. The callable's type is also written out in full in NuisanceDeps (holdout_run.py:85), VetDeps (vet_command.py:62) and NuisanceGateHarness (gate_session_model.py:30), each with its own comment on what None means.

Why it was kept: True collision: vetting.py:26 declares `type BenignCall` (a callable returning a failure reason) while admission.BenignCall is the recorded call, imported under that name by benign_call.py, fingerprint.py and admission_records.py, and it is a name of the admission's JSON schema shown in the dossiers. The glossary's benign call (nuisance) is the recorded call, so the alias is the one to rename. The callable's type is also spelled out in NuisanceDeps, VetDeps and NuisanceGateHarness, each with its comment.

Change: Delete the alias from vetting.py. In evals/cve/nuisance/benign_call.py add `type BenignCallCheck = Callable[[AdmittedServer], Awaitable[str | None]] # its failure reason, or None`, the wording of that module's docstring ('The benign call check'), importing Awaitable and Callable from collections.abc. Type vetting.drop_failing_servers, vetting._second_pass, NuisanceDeps.benign_call, VetDeps.benign_call and NuisanceGateHarness.benign_call with it, and drop their repeated comments and the imports ruff then flags. The field name `benign_call` stays. admission.BenignCall is untouched.

Files: `evals/cve/nuisance/benign_call.py`, `evals/cve/nuisance/vetting.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/gate/gate_session_model.py`

Tests: No test changes, pyrefly checks the types. fingerprint.py and the model-inputs golden read admission.BenignCall, which does not move.

#### Fix 5.4: `evals/cve/nuisance/vet_command.py` `VetDepsFactory` (premature-abstraction, refactoring)

Problem: VetDepsFactory is a Protocol with positional-only parameters, used only by the VetCommandDeps.vet_deps field. It says nothing `Callable[[int, int], VetDeps]` does not: default_vet_deps' extra `launcher` has a default, and the test harness's `_built` takes two positional arguments. The neighbouring RunCommandDeps.run_deps and GateCommandDeps.harness use a plain Callable for the same role.

Why it was kept: VetDepsFactory has one use, the VetCommandDeps.vet_deps field. A scratch pyrefly check confirms that `Callable[[int, int], Deps]` accepts both a function with an extra defaulted parameter (default_vet_deps' launcher) and a bound two-argument method (VetHarness._built). The neighbouring RunCommandDeps.run_deps uses a plain Callable for the same role. The only call with launcher= targets default_vet_deps directly, not the field.

Change: Delete VetDepsFactory and the `Protocol` import from vet_command.py, and declare `vet_deps: Callable[[int, int], VetDeps] = default_vet_deps`.

Files: `evals/cve/nuisance/vet_command.py`

Tests: No test changes. pyrefly covers the assignment.

#### Fix 5.5: `evals/cve/nuisance/vet_command.py` `VetDeps.ping_answers` (dead-code, refactoring)

Problem: `ping_answers` defaults to an empty dict, but both builders of VetDeps (default_vet_deps and tests/unit/support/nuisance_vets.deps_on) always pass it. The default could only produce a VetDeps whose answers nothing fills, so every server would silently print 'answers the ping: unknown'.

Why it was kept: VetDeps has two constructors, default_vet_deps and tests/unit/support/nuisance_vets.deps_on, and both pass ping_answers. Every other test goes through dataclasses.replace. The default is dead, and it could only produce a VetDeps printing 'unknown' for every server.

Change: Declare `ping_answers: dict[str, bool]` with no default on VetDeps and drop the `field` import. It stays the last field.

Files: `evals/cve/nuisance/vet_command.py`

Tests: No test changes.

#### Fix 5.6: `evals/cve/nuisance/vet_command.py` `vet` (function-length, refactoring)

Problem: vet has 26 body lines and mixes reading the committed inputs, validating --server, running with crash handling, and printing. Its first block (malformed_input_refused, committed_walk_inputs, committed_admission, the empty-admission exit, run_population over reached_servers and acceptance_target_servers) is a copy of the block in holdout_run_command.run (lines 96-103), so which servers a run audits is derived in two places that must agree for the vet to vet the run's population.

Also covers: `evals/cve/nuisance/vet_command.py` (duplication): `vet` and `holdout_run_command.run` each write the same block: read the walk inputs and the admission under `malformed_input_refused`, print `no server is admitted` and return 0 when empty, then compute `run_population(reached_servers(...), admission, acceptance_target_servers(...))`. The set of servers a vet proves and the set a run audits are the same rule held in two copies.

Also covers: `evals/cve/nuisance/vet_command.py` (duplication): `run_population(reached_servers(walk_inputs), admission, acceptance_target_servers(walk_inputs))` is written in vet_command.py:121 and holdout_run_command.py:101. Which servers a run audits is a rule, and the vet proves it only while both calls stay equal.

Also covers: `evals/cve/nuisance/holdout_run_command.py` (function-length): `run` has 26 body lines, and 9 of them (95-103) are the read of the run population: walk inputs, admission, the "no server is admitted" case and `run_population`, under `malformed_input_refused`. `vet_command.vet` (lines 114-123) carries the same block almost line for line. Which committed files make the audited population, and which errors count as malformed input, is thus written twice in the two commands whose contract is to audit the same servers (the vet proves the launch a run makes).

Why it was kept: vet (vet_command.py:115-123) and run (holdout_run_command.py:95-103) carry the same block: read the walk inputs and the admission under malformed_input_refused, return on an absent or empty admission, then run_population(reached_servers, admission, acceptance_target_servers). Which servers a run audits is a rule of the nuisance suite (Run conditions and statistic), and the vet only proves the run's launch while the two stay equal. The gate reads another population (nuisance_acceptance_servers), and walk and the dossiers need no run_population, so exactly two callers share it. commands.py can import holdout_servers: importing both shows no cycle, nothing under holdout_servers imports commands, and no kit module imports commands.

Change: Add to evals/cve/nuisance/commands.py, above malformed_input_refused (its first user in the module, which the newspaper scan needs above it): `def committed_run_population(census_path: Path, walk_record_path: Path, admission_path: Path) -> tuple[WalkInputs, RunPopulation] | None`, whose body is the current block under malformed_input_refused, returning None when the admission is absent or has no server, else (walk_inputs, population). vet and run call it with args.census, args.walk_record, args.admission, each keeps its `print("no server is admitted")` and `return 0` on None, then unpacks (`_, population` in vet, `walk_inputs, population` in run). The ValueError scope stays the same, run_population included. Drop from both commands the imports of acceptance_target_servers, reached_servers, run_population, committed_admission, committed_walk_inputs and malformed_input_refused (run keeps RunPopulation for _ReadyRun). fix 5.6's `_refuse_unready_servers` is not taken: a single-caller helper, and run falls to about 21 lines without it. vet falls to about 20.

Files: `evals/cve/nuisance/commands.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/holdout_run_command.py`

Tests: No test changes: tests/unit/nuisance/test_run_nuisance_vet.py and test_run_nuisance_holdout_run.py pin the empty admission, the malformed input and the order (conditions before the census, refusals before the settings) through the commands. run_population keeps its own tests. No fingerprinted module is touched.

Risks: The call stays after deps.conditions() in run, since a test pins that order. commands.py gains an import of holdout_servers, also reached by fix_check_command, with no effect on kits (no kit imports commands).

#### Fix 5.7: `evals/cve/nuisance/benign_call.py` `_chain_failure` (ubiquitous-language, refactoring)

Problem: _chain_failure plays a benign call's prerequisite calls and then the call. That is not a chain in the glossary's sense, and the nuisance suite counts real chains as alarms, so the word misleads in this suite. Its `tool` argument is always `call.tool`. It also re-implements _call_failure's try/except and its two message formats ('{label} failed', '{label} returned an error') for the final call.

Why it was kept: The glossary defines attack chain and chain step, and the nuisance suite counts chains as alarms, while _chain_failure plays a benign call's prerequisite calls: the glossary's own word for them is 'prerequisite calls'. The `tool` argument is redundant, since benign_calls keys the dict by call.tool. The try/except and the two message formats are written twice in the module, and these reasons are recorded in not_run. BenignCall subclasses ToolCall, and call_tool returns ToolResponse, so one helper covers both calls. A `T | str` return has a precedent (detection/measurement.py:82).

Change: In evals/cve/nuisance/benign_call.py: the loop of benign_call_failure becomes `for call in calls.values(): failure = await _failure_with_prerequisites(mcp_client, call)`. Replace _chain_failure by `_failure_with_prerequisites(mcp_client, call: BenignCall) -> str | None`, and _call_failure by `_answer(mcp_client, call: ToolCall, label: str) -> ToolResponse | str` returning the response or the failure text (`{label} failed: {exc}`, `{label} returned an error: {content}`). Prerequisites use the label `prerequisite call of {prior.tool!r} before {call.tool!r}` and return on a str. The final call uses `benign call of {call.tool!r}`, returns on a str, else returns _expectation_failure(call, answer.content). Import ToolResponse from mcp_auditor.domain.models. Every message stays byte-identical.

Files: `evals/cve/nuisance/benign_call.py`

Tests: No test changes: tests/unit/nuisance/test_nuisance_benign_call.py pins the prerequisite and benign call messages and the order of the calls. benign_call.py is not fingerprinted and no kit imports it (it already imports mcp_auditor).

Risks: The failure texts land in not_run and the vet's output, so they must stay byte-identical.

### 6. The nuisance holdout run's orchestrator

Order and interactions: fix 6.1 runs after sections 3 and 5, so `nuisance_overrides` is already gone and `NuisanceDeps` already holds `sweep`. Apply fix 6.2 with fix 6.1, since both rewrite the `runs=` line. Do fix 6.3 before fix 6.4, so the deleted test's script is not rewritten first.

Verifier's notes: Within the section: fix 6.1 carries seven findings as one change. Apply fix 6.2 with it, since both rewrite the `runs=` line of the orchestrator call. fix 6.5, fix 6.4 and fix 6.3 are independent test edits, all in test_nuisance_holdout_run.py. Do fix 6.3 before fix 6.4 so the deleted test's script is not rewritten first. fix 6.4 and fix 6.1 both edit tests/unit/support/nuisance_holdout_runs.py, in different functions. Other sections on the same modules, to order after fix 6.1, which reshapes holdout_run.py and moves default_deps into holdout_run_command.py: - another section is the closest. Its fix 3.6 and fix 3.6 also delete nuisance_overrides: this section does it, so they reduce to overrides.shape(None) in audit_once (fix 3.6). Its backend_image_ids findings (fix 3.4, fix 3.4, fix 3.4, fix 3.4) must edit default_deps at its new place in the command. Its _prices findings (fix 3.5, fix 3.5, fix 3.5) must read inputs.conditions and inputs.settings, not ctx. refuse_tracing, _DROP_PRECEDENCE, RunInterrupted, NUISANCE_CONCURRENCY and HOLDOUT_TEST_BUDGET stay in that section, and the moved default_deps needs the HOLDOUT_TEST_BUDGET import repointed if fix 3.8 lands. - another section (fix 1.3, fix 1.3) spreads ModelConditions in _assemble_run, which must read inputs.settings. - another section replaces the two container fields of NuisanceDeps by `sweep: ContainerSweep`, which changes default_deps (at its new place), deps_auditing, deps_reaching_nothing and deps_on, and may wrap the body of run_nuisance in a context manager. It also adds committed_run_population, which touches the `run` command just above _ReadyRun. - another section: a rejected finding would rename RunPopulation, hence the `population` field and its type in NuisanceHoldoutRunInputs. Its add_committed_input_arguments changes add_run_arguments next to the --runs line. - another section touches test_nuisance_solo_given.py (the GateRun import) next to fix 6.5, with no conflict. - another section touches test_nuisance_admission.py next to fix 6.3.

#### Fix 6.1: `evals/cve/nuisance/holdout_run.py` `run_nuisance` (argument-count, refactoring)

Problem: run_nuisance and its RunOrchestrator protocol take 8 arguments, and _RunContext repacks 7 of them just below, without the population, so _run_surviving takes 4 and _assemble_run 6. The defaults are dead: the only production caller (holdout_run_command._audit_admitted_servers) passes runs, concurrency and deps, and the test helper holdout_runs.run does too, so `deps or default_deps(...)` never fires. The detection side already made this move with HoldoutRunInputs and `run_holdout_targets(inputs, *, deps)`. The fake orchestrator in test_run_nuisance_holdout_run_given has to search its positional args with `next(arg for arg in args if isinstance(arg, RunProvenance))` because of this signature.

Also covers: `evals/cve/nuisance/holdout_run.py` (hexagonal-boundary): The orchestrator module also holds the live wiring: default_deps pulls build_auditor, SessionThrottles, rebuild_images, read_tree, the Docker calls and the clock into the module whose docstring says its I/O is injected. Detection keeps this in holdout_command_deps.py. nuisance_overrides is a line-for-line copy of RunOverrides.of_holdout. `overrides.tool_call_timeout or TOOL_CALL_TIMEOUT` is a dead fallback, since the overrides always come from conditions that passed require_ready and the assert guarantees a timeout.

Also covers: `evals/cve/nuisance/holdout_run.py` (argument-count): `run_nuisance` takes eight parameters, restated in the `RunOrchestrator` Protocol and regrouped at once into `_RunContext`. Its defaults `runs`, `concurrency` and `deps=None` are dead: the command and the tests pass all three, and the `default_deps(...)` fallback is never taken. The live wiring (`default_deps`, `SessionThrottles`, `build_auditor`, `datetime.now`, the Docker functions) sits in the orchestrator, whose docstring says its I/O is injected. `nuisance_overrides` copies `RunOverrides.of_holdout`, `audit_once` rebuilds `AuditShape` by hand in place of `overrides.shape(None)`, and `_refuse_tracing` is written in both the command and the orchestrator. The detection side has already moved to `HoldoutRunInputs`, `holdout_command_deps.default_deps` and a shared `refuse_tracing`.

Also covers: `evals/cve/nuisance/holdout_run.py` (dead-code): Both signatures default runs, concurrency and deps (:119-121, :143-145), and `deps = deps or default_deps(...)` (:151) is a fallback no caller reaches: the command and the test helper pass all three. It also forces the orchestrator to import the auditor's live wiring.

Also covers: `evals/cve/nuisance/holdout_run.py` (argument-count): The orchestrator takes five positional and three keyword arguments, restated in the RunOrchestrator protocol. Inside, _RunContext regroups seven of them, and the command has its own _ReadyRun holding four of the same (holdout_run_command.py:150). The detection side names this area HoldoutRunInputs.

Also covers: `evals/cve/nuisance/holdout_run.py` (naming): `ctx: _RunContext` is threaded through `_run_surviving`, `_run_all`, `_prices` and `_assemble_run`, with about 20 uses over 170 lines. The detection side no longer has this abbreviation (no `ctx` under evals/cve/detection).

Also covers: `evals/cve/nuisance/holdout_run_command.py` (argument-count): The command calls the orchestrator with 8 arguments through `RunOrchestrator`, whose `runs`, `concurrency` and `deps` defaults are dead: the only production caller passes all three. `deps or default_deps(...)` (holdout_run.py:151) is an unreachable fallback. The cost shows in the test support: `an_admitted_run_keeping_its_provenance` (given:43) has to find the provenance with `next(arg for arg in args if isinstance(arg, RunProvenance))`, because the signature has no named input. The orchestrator then regroups the same values in `_RunContext`. Detection already moved to `HoldoutRunInputs` and a required `deps`.

Why it was kept: Checked. run_nuisance (holdout_run.py:136) takes 8 parameters, RunOrchestrator restates them, and _RunContext regroups 7 of them. Its only production caller is holdout_run_command._audit_admitted_servers, and its only other caller is tests/unit/support/nuisance_holdout_runs.run. Both pass runs, concurrency and deps, so the three defaults and `deps or default_deps(...)` are dead. The fake in test_run_nuisance_holdout_run_given.py:43 searches its positional args for RunProvenance because the input has no name. Detection already made this move (HoldoutRunInputs, run_holdout_targets(inputs, *, deps), RunHoldoutTargets), and plans/2026-11-23_detection-suite-standards-pass.md lists the nuisance side as a follow-up (fixes 2.2 and 5.1). nuisance_overrides is a line-for-line copy of RunOverrides.of_holdout, assert included. The live wiring in the orchestrator is real: default_deps is the only reason holdout_run.py imports build_auditor, SessionThrottles, rebuild_images, read_tree, the Docker calls and datetime. This entry carries the seven findings on this one change. One direction is not followed: no new deps module. The nuisance suite's own pattern is the live builder in the command module, above its CommandDeps class (default_vet_deps in vet_command.py, default_fix_check_deps in fix_check_command.py). Detection's separate holdout_command_deps.py exists for an import isolation (no module run_detection imports reaches the holdout targets) that has no nuisance counterpart, since holdout_run_command.py already imports HOLDOUT_TARGETS. _ReadyRun also stays: it carries walk_inputs and exists before the provenance and the flags are read, exactly as detection keeps _ReadyHoldoutRun beside HoldoutRunInputs.

Change: In evals/cve/nuisance/holdout_run.py add, right after RunProvenance: @dataclass(frozen=True) class NuisanceHoldoutRunInputs: population: RunPopulation draw_order: Sequence[DrawEntry] conditions: HoldoutConditions settings: Settings provenance: RunProvenance runs: int concurrency: int @property def model_ids(self) -> list[str]: return list(dict.fromkeys([self.settings.resolve_model(), self.settings.resolve_judge_model()])) Delete _RunContext (the `ctx` abbreviation goes with it). Signatures: RunOrchestrator.__call__(self, inputs: NuisanceHoldoutRunInputs, /, *, deps: NuisanceDeps), run_nuisance(inputs, *, deps: NuisanceDeps), _run_surviving(inputs, deps, tree), _run_all(surviving, deps, inputs), whose `prices` line of fix 3.5 reads inputs.conditions and inputs.settings, and _assemble_run(inputs, deps, assembled, not_run, tree), which reads inputs.population.exits and .pending. Keep the order of run_nuisance's steps: tracing refusal, inputs.conditions.require_ready(inputs.model_ids), read_tree, and so on. Delete the runs, concurrency and deps defaults and the fallback. NUISANCE_RUNS stays in holdout_run.py as the flag default of the command. holdout_run.py drops its import of NUISANCE_CONCURRENCY, in commands.py since fix 3.7, which only the deleted defaults read. Move default_deps unchanged in name to evals/cve/nuisance/holdout_run_command.py, above RunCommandDeps (a class-level default, the shape of default_vet_deps), with its imports (bounded, check_closed_network_support, TYPES_ONLY, HOLDOUT_TEST_BUDGET, backend_image_ids and image_ids from evals.cve.images, SessionAuditor, build_auditor, nuisance images, audit_once, nuisance_audit, DroppedRun, NuisanceAudit, print_run_status, LaunchedBenignCall, rebuild_images, DOCKER_SWEEP, read_tree, SessionThrottles, datetime, UTC). Remove from holdout_run.py every import only it used, TOOL_CALL_TIMEOUT included, which moves with default_deps: its line `timeout = overrides.tool_call_timeout or TOOL_CALL_TIMEOUT` stays as it is, so that a timeout of 0 keeps its behavior. In _audit_admitted_servers build the inputs before the `with`, as run_detection_holdout does: NuisanceHoldoutRunInputs(population=ready.population, draw_order=draw_order(ready.walk_inputs.census), conditions=ready.conditions, settings=ready.settings, provenance=RunProvenance(deps.file_commit(args.census), deps.file_commit(args.walk_record), deps.file_commit(args.admission)), runs=args.runs, concurrency=args.concurrency), then asyncio.run(deps.orchestrate(inputs, deps=_tracked(run_deps, AuditProgress(bar)))). Rewrite the holdout_run.py module docstring: the heavy I/O is grouped in NuisanceDeps, faked by the unit tests and built by the command's default_deps.

Files: `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`, `tests/unit/support/nuisance_holdout_runs.py`, `tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py`

Tests: tests/unit/support/nuisance_holdout_runs.run builds NuisanceHoldoutRunInputs and calls run_nuisance(inputs, deps=deps), so its 60-odd callers do not change. In test_run_nuisance_holdout_run_given.py, an_admitted_run_keeping_its_provenance's orchestrator becomes `async def orchestrator(inputs: NuisanceHoldoutRunInputs, /, *, deps: NuisanceDeps)` and reads inputs.provenance, with no search through args. Its `*_, **__` fakes stay. Every behavior test stays green unchanged. No fingerprinted module is touched (counter.py, counting.py and confinement.py are not edited, and holdout_run.py only reads their functions), so nuisance_fixture_fingerprint, counter_fingerprint and the detection fingerprints are unchanged: the plan checks them before and after. Run the short loop, pyrefly, ruff, and test_code_standards for the newspaper order of default_deps above RunCommandDeps.

Risks: No flag, exit code, refusal message or result field moves. file_commit is now evaluated just before the `with partial_result_kept` block rather than inside it. It raises nothing that block catches, so the outcome is the same. NuisanceHoldoutRunInputs must be defined before RunOrchestrator and default_deps before RunCommandDeps. nuisance_overrides is deleted, not renamed, so it takes no glossary-log line, as its detection counterpart did.

#### Fix 6.2: `evals/cve/nuisance/holdout_run_command.py` `add_run_arguments` (dead-code, refactoring)

Problem: `--runs` defaults to None only for line 176 to replace None with `NUISANCE_RUNS`. No other reader needs the None, the help text is a literal f-string that does not depend on the default, and the detection command declares `default=HOLDOUT_RUNS` directly.

Why it was kept: Checked: args.runs is read only at holdout_run_command.py:176, where None becomes NUISANCE_RUNS. The help text is a literal f-string independent of the default, and argparse does not pass a non-string default through positive_int. run_detection_holdout passes args.runs directly with its default on the flag. The conditional has no other purpose.

Change: In add_run_arguments declare `default=NUISANCE_RUNS` on --runs, keeping the type and help unchanged, and pass runs=args.runs when building NuisanceHoldoutRunInputs.

Files: `evals/cve/nuisance/holdout_run_command.py`

Tests: No test changes. test_run_help_gives_the_default_number_of_runs keeps pinning the help text, and the effective default stays 2.

Risks: Touches the line fix 6.1 rewrites: apply them together. The flag, its help and its effective default do not change.

#### Fix 6.3: `tests/unit/nuisance/test_nuisance_holdout_run.py` `test_a_backend_server_records_its_backend_image_beside_its_service` (duplication, refactoring)

Problem: Two tests repeat a check another test already makes. This one is the single-image case of test_the_run_conditions_carry_one_id_per_image_of_a_two_image_backend (line 172), which runs the same path and asserts the same image_ids mapping with one more image. In test_nuisance_admission.py:56, test_a_networked_host_with_no_backend_is_refused repeats the mutation with_a_networked_host_and_no_backend that the _MUTATIONS table already checks, and only pins the rest of the message.

Why it was kept: Both redundancies are real. test_a_backend_server_records_its_backend_image_beside_its_service runs the same path as test_the_run_conditions_carry_one_id_per_image_of_a_two_image_backend, and _assemble_run has no branch on the image count. test_a_networked_host_with_no_backend_is_refused repeats the mutation already in the _MUTATIONS table and adds only the rest of the message. Nothing is lost if the table row carries the whole message, package prefix included, since the table already requires exactly one problem and SERVER_PACKAGE is available at module level.

Change: Delete test_a_backend_server_records_its_backend_image_beside_its_service from test_nuisance_holdout_run.py. In test_nuisance_admission.py delete test_a_networked_host_with_no_backend_is_refused and change the table row's fragment to f"{admissions.SERVER_PACKAGE}: has_network without a backend: a server with no backend runs with no network".

Files: `tests/unit/nuisance/test_nuisance_holdout_run.py`, `tests/unit/nuisance/admission/test_nuisance_admission.py`

Tests: Two fewer tests, with the same cases covered: the two-image test keeps the image_ids mapping, and the parametrized row pins the full message of the one problem.

Risks: The another section also touches test_nuisance_admission.py, on other tests.

#### Fix 6.4: `tests/unit/nuisance/test_nuisance_holdout_run.py` (given-then, refactoring)

Problem: `holdout_runs.scripted({package: [holdout_runs.an_audit(False) for _ in range(3)]})` is repeated 11 times in this file and 3 times in test_nuisance_holdout_run_sweep.py, once more in nuisance_docker_hosts.deps_on. The literal 3 is coupled to the hidden `runs=3` default of holdout_runs.run: a script of another length fails with an IndexError from pop(0) unrelated to the behavior under test. Beside this, test_a_backend_server_records_its_backend_image_beside_its_service is contained in the two-image test that follows it.

Why it was kept: True and slightly undercounted: three clean audits are spelled out at 17 sites (12 in test_nuisance_holdout_run.py, 3 in test_nuisance_holdout_run_sweep.py, 1 in nuisance_docker_hosts.deps_on, 1 in test_nuisance_holdout_run_interrupted_given.py), each coupled to the literal `runs: int = 3` of holdout_runs.run. A script of another length fails with an IndexError unrelated to the behavior under test. A named helper abstracts something real here: the runs of a server with nothing to report. The finder's auditing_clean(*servers) is reshaped: at least 5 sites mix a clean server with a scripted or empty one, so a helper returning the outcomes covers all of them and leaves scripted visible. The one-image test deletion it also proposes is carried by fix 6.3.

Change: In tests/unit/support/nuisance_holdout_runs.py add `DEFAULT_RUNS = 3`, use it as the default of run's `runs`, and add `def clean_audits() -> list[Outcome]: return [an_audit(False) for _ in range(DEFAULT_RUNS)]`. Replace the 16 sites left once fix 6.3 has deleted its test (17 today): `holdout_runs.scripted({"npm:first": holdout_runs.clean_audits()})`, and `"npm:kept": holdout_runs.clean_audits()` in the mixed scripts. Tests that script a specific outcome keep their own lists.

Files: `tests/unit/support/nuisance_holdout_runs.py`, `tests/unit/support/nuisance_docker_hosts.py`, `tests/unit/nuisance/test_nuisance_holdout_run.py`, `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`, `tests/unit/nuisance/support/test_nuisance_holdout_run_interrupted_given.py`

Tests: Same assertions, same outcomes. `[an_audit(False)] * 3` at one site becomes three distinct equal audits, which no test distinguishes. With fix 6.3 the file falls under 300 lines.

Risks: The name clean_audits is new and not a glossary term. gate_sessions.clean_runs stays, since it builds GateRun values, another type.

#### Fix 6.5: `tests/unit/nuisance/test_nuisance_holdout_run.py` `test_the_run_announces_each_finished_run_of_a_server_with_its_status` (test-fragility, refactoring)

Problem: Three test modules unpack the registry as a singleton: `(solo_package,) = SOLO_SERVERS` here, `(_SOLO_PACKAGE,) = SOLO_SERVERS` in test_nuisance_solo_given.py and `(SOLO_SERVER,) = SOLO_SERVERS` in test_nuisance_vetting_given.py. The two given unpackings run at import. solo.py documents the list as open to any server whose calls fail under contention, so adding a second entry, a legitimate fixture decision, raises ValueError and stops collection of those test modules although no behavior broke.

Why it was kept: True: `(x,) = SOLO_SERVERS` appears in test_nuisance_holdout_run.py:98 and, at import, in test_nuisance_solo_given.py:18 and test_nuisance_vetting_given.py:10. solo.py documents the list as open to any server whose calls fail under contention, so a second entry, a legitimate fixture decision, raises ValueError and stops the collection of the solo and vetting test modules with no behavior broken. None of these tests needs the registry to hold exactly one server: each plays one solo server beside non-solo ones. The fix is three one-line edits with no new helper.

Change: Write `solo_package = min(SOLO_SERVERS)` in test_nuisance_holdout_run.py, `_SOLO_PACKAGE = min(SOLO_SERVERS)` in test_nuisance_solo_given.py and `SOLO_SERVER = min(SOLO_SERVERS)` in test_nuisance_vetting_given.py. min keeps the choice deterministic, which next(iter(...)) on a frozenset of strings would not across hash seeds.

Files: `tests/unit/nuisance/test_nuisance_holdout_run.py`, `tests/unit/nuisance/support/test_nuisance_solo_given.py`, `tests/unit/nuisance/support/test_nuisance_vetting_given.py`

Tests: The three test modules pick the same server as today and assert the same behavior.

### 7. The gate session and command

Order and interactions: fixes 7.1 and 7.2 come first and empty `gate_session.py` of what is not the session. `gate_run` is already in `gate/gate_audit.py` (fix 4.4). Fixes 7.3, 7.5 and 7.6 are the behavior changes of this section, each in a commit of its own with a CHANGELOG line (see Decisions). `gate_servers.py` calls `standing_exit` from `admission_walk` until fix 11.3 makes it a property.

Verifier's notes: Order inside the section: (1) fix 7.1 and fix 7.2 first, since both empty gate_session.py of what is not the session and rewrite the imports of gate_command.py: after them `run_gate` is the first function of gate_session.py, and gate_command.py imports from gate_command_deps.py and gate_servers.py. (2) fix 7.3 (rebuild moved to `run_gate`) and fix 7.4 (`ServerRuns.runs` dropped) are independent edits of gate_session.py. (3) fix 7.5 touches the try of `gate()`, which fix 7.2 also rewrites around: same function, no conflict, do them in sequence. (4) fix 1.1 and fix 7.7 are independent. Two of the seven are real behavior fixes, each with a CHANGELOG line and its own commit: fix 7.3 (what a gate rebuilds) and fix 7.5 (the crash text of a fatal provider error, exit code unchanged). The other five are pure refactorings. `run_detection.main` has the same `ProviderFatal` leak through `traceback.print_exc()` (evals/run_detection.py:97), which fix 7.6 fixes. Other sections on the same modules: another section also lists `next_recording_step` (fix 1.1, fix 1.1), so fix 1.1 must be done only once, and fix 1.1 moves `_print_baselines` into gate_console.py. It also edits `_run_opened` (`exit_code`), `load_checked` and gate_session_recording.py, which fix 7.4 touches in `_recordings`. another section repoints `backend_image_ids` in `default_harness` and moves `NUISANCE_CONCURRENCY` (gate_command.py). another section fix 4.4 moves `GateRun` and `gate_run` to gate_audit.py (imports of gate_session, gate_session_model and the new gate_command_deps.py). another section edits gate_report.py and gate_console.py (`render_throttled`, the export import) and gate_command.py. another section edits the head of `gate()` (`add_committed_input_arguments`), moves `standing_exit` (import of the new gate_servers.py). another section renames the local `settled` in `_retested`. another section retypes `benign_call` in gate_session_model.py. Doing this section first, right after another section, keeps those later edits on their final modules.

#### Fix 7.1: `evals/cve/nuisance/gate/gate_session.py` `default_harness` (other, refactoring)

Problem: The module's docstring presents a session with git, Docker, the clock, the audit and the baseline directory injected, yet it also builds the real harness. About a dozen of its imports serve only `default_harness` (`build_auditor`, `SessionAuditor`, `RunOverrides`, `LaunchedBenignCall`, `rebuild_images`, `DOCKER_SWEEP`, `read_tree`, `check_closed_network_support`, `image_ids`, `bounded`, `functools`, `datetime`). Its only caller is the default of `GateCommandDeps.harness` in gate_command.py. It also sits between the selection helpers and `run_gate`, pushing the module's main function to line 116.

Also covers: `evals/cve/nuisance/gate/gate_session.py` (port-injection): The module docstring says git, Docker, the clock, the audit and the baseline directory are injected, yet the module also builds the live harness and so imports `SessionAuditor`, `build_auditor`, `bounded`, `check_closed_network_support`, `datetime`, `DOCKER_SWEEP`, `rebuild_images`, `read_tree` and the live audit functions. The orchestrator and its wiring are one module, while detection separates `session.py` from `command_deps.py`.

Why it was kept: The fact holds. The docstring of gate_session.py says git, Docker, the clock, the audit and the baseline directory are injected, while `default_harness` builds the live ones in the same module, with about fifteen imports that serve it alone. Its only reader is the default of `GateCommandDeps.harness`. This is not the rejected 'composition root is a missing port' pattern: nothing new is abstracted, the wiring only leaves the orchestrator, as detection does with `command_deps.py`. It takes a module of its own rather than joining gate_command.py (229 lines), as detection's `command_deps.py` does. The newspaper order does not decide this: the scan exempts a function that a dataclass default reads at import time, the shape of `default_vet_deps` and of `default_deps` after fix 6.1.

Change: New module `evals/cve/nuisance/gate/gate_command_deps.py` holding, unchanged, `default_harness` (from gate_session.py), `type GateSessionRunner` and `GateCommandDeps` (both from gate_command.py, where they live today), with the imports they use. gate_session.py loses `default_harness` and the imports only it uses (`functools`, `datetime`, `UTC`, `bounded`, `check_closed_network_support`, `image_ids`, `RunOverrides`, `SessionAuditor`, `build_auditor`, `audit_once`, `gate_run`, `nuisance_audit`, `NUISANCE_GATE_BASELINE_DIRECTORY`, `backend_image_ids`, `image_tag`, `LaunchedBenignCall`, `DOCKER_SWEEP`, `rebuild_images`, `read_tree`, `SessionThrottles`), and `run_gate` is its first function once `gate_servers` has left too. Repoint every importer of `GateCommandDeps`: gate_command.py, evals/run_nuisance.py, tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py. gate_command.py imports `GateCommandDeps` and `GateSessionRunner` from it. It keeps importing `gate_servers`, `not_admitted` and `outside_gate` from gate_session until fix 7.2 moves them, and then no longer imports gate_session. No behavior changes.

Files: `evals/cve/nuisance/gate/gate_command_deps.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/run_nuisance.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`

Tests: Only the import of the given changes. tests/unit/project/test_code_standards.py checks the newspaper order of the new module. No kit imports evals.cve.nuisance.gate (grep over evals/cve/kit and evals/cve/backends is empty), so no dossier closure moves, and no fingerprinted module is touched.

Risks: Other sections edit `default_harness`' imports (`backend_image_ids` from evals.cve.images, `gate_run` moved to gate_audit.py): whichever lands second repoints in gate_command_deps.py. No name is left re-exported by gate_session or gate_command.

#### Fix 7.2: `evals/cve/nuisance/gate/gate_command.py` `_run_gate` (missing-concept, refactoring)

Problem: The pair (admission, current) travels through gate, _print_empty_gate and _run_gate only to be re-derived into the same three lists: gate_servers is computed at line 101 and again at line 148, and outside_gate and not_admitted each take the pair. `admission is None` is branched on twice (lines 101-102 and 132). This pair is what pushes _run_gate to 4 arguments and gate to 21 lines.

Also covers: `evals/cve/nuisance/gate/gate_command.py` (missing-concept): The gate's partition of the admission is three separate functions (`gate_servers`, `outside_gate`, `not_admitted`) lodged in the session orchestrator, each taking `(admission, current)`. `gate` calls `gate_servers` and hands `admission` and `current` down to `_run_gate`, which calls it a second time, then the other two, and `_print_empty_gate` calls `outside_gate` again. The holdout side names the same concept: `holdout_servers.RunPopulation`.

Why it was kept: The fact holds. `gate` computes `gate_servers(admission, current)` and `_run_gate` recomputes it, `outside_gate` is called from `_print_empty_gate` and `_run_gate`, `admission is None` is branched on twice, and the pair (admission, current) is what brings `_run_gate` to 4 arguments and `gate` past 20 lines. The three functions are one partition of the admission, and only gate_command and test_nuisance_gate_selection.py use them. The name differs from both findings: 'selection rule' is a retired word in the glossary log, which rules out `GateSelection`, and `GateServers` says what the value holds, where `GatePopulation` would not.

Change: New module `evals/cve/nuisance/gate/gate_servers.py` with a frozen `GateServers(audited: list[AdmittedServer], outside_gate: list[ServerExit], not_admitted: list[str])` and a pure `gate_servers(admission: NuisanceAdmission | None, current: set[str]) -> GateServers`, carrying the existing docstring on a server that cannot launch. Body: `admitted = [] if admission is None else admission.servers`, `in_gate = [s for s in admitted if s.server_package in current]`, then `audited` where `standing_exit(s) is None`, `outside_gate` with the walrus on `standing_exit`, `not_admitted = sorted(current - {s.server_package for s in admitted})`. Delete the three functions from gate_session.py with the imports they alone use (`NuisanceAdmission`, `standing_exit`, `ServerExit`). `gate()` builds it once, calls `_print_empty_gate(servers.outside_gate)` when `servers.audited` is empty, and `_run_gate(args, servers, deps)`, which reads `servers.not_admitted` and `servers.outside_gate` for the report. The report's field names `not_admitted` and `outside_gate` do not change. A None admission gives no audited server and no exit, so the same 'no nuisance acceptance server is admitted' line prints.

Files: `evals/cve/nuisance/gate/gate_servers.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_command.py`, `tests/unit/nuisance/gate/test_nuisance_gate_selection.py`

Tests: test_nuisance_gate_selection.py keeps its three behaviors, ported to `gate_servers(...).audited`, `.outside_gate`, `.not_admitted`. Add one case: a None admission audits no server and names no exit. test_run_nuisance_gate.py passes unchanged and pins the printed lines.

Risks: `standing_exit` may move to exits.py (another section fix 11.3): only the import line of gate_servers.py follows. `not_admitted` under a None admission is `sorted(current)` but is never read, since the empty path returns first.

#### Fix 7.3: `evals/cve/nuisance/gate/gate_session.py` `_vetted` (duplication, behavior fix, CHANGELOG)

Problem: The gate writes its own rebuild list, `list(dict.fromkeys(server.service for server in servers))`, a copy of `containers.server_services`, and it has diverged from the mechanism. `run_nuisance` (holdout_run.py:158) and `vet_servers` (vet_command.py:157) rebuild `run_images(servers).services`, which adds the built backend services and, for a backend-less server with public names, the sentinel and stand-in. `run_gate` already holds that `RunImages` and uses it for removal and sweep, but not for the rebuild. Provisioners build an image only when it is absent (`responder._ensure_image`, `ckan._ensure_image`), so a stale backend image survives. `nuisance_fixture_fingerprint` hashes the backend's current Dockerfile and sources, so a gate or recording can carry the new fingerprint while auditing the old backend. It is latent: the gate set is empty today (4 current packages, none admitted).

Also covers: `evals/cve/nuisance/gate/gate_session.py` (duplication): The gate rebuilds only the server images (`server.service`), while the nuisance holdout run and the vet rebuild `images.services`, which adds the built backends and, for a backend-less server with public names, the sentinel and stand-in images. `run_gate` already holds `run_images(options.servers)`. A built backend's `_ensure_image` (n8n, the responders, Jenkins, GitLab) builds only when the tag is absent. Its Dockerfile is in `RegisteredBackend.served`, so a change moves `nuisance_fixture_fingerprint`: the gate reads fixture_changed, the maintainer resets the server, and the new baseline is recorded under the new fingerprint against the backend image built from the old Dockerfile.

Also covers: `evals/cve/nuisance/gate/gate_session.py` (duplication): _vetted re-derives the services to rebuild as `dict.fromkeys(server.service ...)` and omits what run_images(servers).services adds, the built backend services and the sentinel and stand-in images, while run_gate already holds `images`. Run and vet rebuild those. A gate server on a built backend would run an older image (provisioners build only an absent tag) under a fixture fingerprint that hashes the new Dockerfile, so its baseline compares a backend it did not run. No gate server is admitted today, so nothing is affected yet.

Why it was kept: The fact holds. `_vetted` (gate_session.py:163) rebuilds only `server.service`, while `run_nuisance` (holdout_run.py:158) and `vet_servers` (vet_command.py:157) rebuild `run_images(servers).services`, which adds the built backend services and, for a backend-less server with public names, the sentinel and stand-in. `run_gate` already holds that `RunImages`. A built backend builds only an absent tag (`responder._ensure_image` runs `docker image inspect` first, same shape in ckan, n8n, httpbin, gravitino), and `nuisance_fixture_fingerprint` hashes the backend's served Dockerfile (`_served`, `backend_content`). So a gate or a recording can carry the new fingerprint while auditing the old backend image. This is drift, not a decision: plans/2026-10-26_nuisance-backend-provisioning.md left the gate's inline list alone because 'no built backend exists' then. Built backends arrived later and only the run and the vet followed. The docstring of containers.py already describes one image set for 'a run, a vet and a gate, before any rebuild'. Latent today: no nuisance acceptance server is admitted.

Change: Real behavior fix, not a refactoring. In `run_gate`, inside the existing try, right after `remove_backend_containers(harness.sweep, images)`, call `harness.rebuild(images.services)`. Delete the rebuild line from `_vetted`, which then only vets. The order stays network check, open, removal, rebuild, benign calls, and `images` is computed from the same `options.servers` (already filtered by --server). What changes: a gate also rebuilds the built backend services, and the sentinel and stand-in for a backend-less server with public names. Add one sentence to the gate paragraph of CONTRIBUTING.md and to the gate line of the CLAUDE.md Commands list (it rebuilds the server and built backend images, and the sentinel and stand-in images when a backend-less server declares public names, so `never overlap it with a fix check or a calibration check on one machine`, the words of the `run` line), a line under Fixed in CHANGELOG.md, and the labeling-log entry of its own that Decisions requires, answering the four questions of ADR 016.

Files: `evals/cve/nuisance/gate/gate_session.py`, `tests/unit/nuisance/gate/test_nuisance_gate_benign_calls.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_benign_calls_given.py`, `CONTRIBUTING.md`, `CLAUDE.md`, `CHANGELOG.md`, `docs/labeling-log.md`

Tests: Test first in test_nuisance_gate_benign_calls.py: `test_the_gate_rebuilds_the_built_backend_service_with_the_server_service`, on `on_the_ckan_backend(FILESYSTEM)`, with a new given `watching_the_rebuild(harness, containers)` beside `watching_removals_at_each_benign_call` in test_nuisance_gate_benign_calls_given.py, which returns the harness, the services rebuilt and what `containers.removed` held at that moment. Assert the services equal `[server.service, *BACKENDS['ckan'].built_services]` and that the stale backend container was already removed. a_harness does not change. No fingerprint moves (`nuisance_fixture_fingerprint` is not touched), and no committed baseline exists.

Risks: Changes what a gate rebuilds. It has no effect today since the gate set is empty. Once a server with a heavy built backend (GitLab, Kubernetes) is admitted, a gate pays a compose build, cached unless the Dockerfile or a file it copies changed. The gate still does not refuse a running server container as the run and the vet do: that is outside this finding and is left as it is.

#### Fix 7.4: `evals/cve/nuisance/gate/gate_session_model.py` `ServerRuns` (missing-concept, refactoring)

Problem: `ServerRuns` holds two parallel lists built from the same outcomes in `_server_runs`: `runs: list[GateRun]` and `audits: list[GateAudit]`. Each `GateAudit` already carries `flagged` and `report`, and the only reads of `ServerRuns.runs` are `run.flagged` in `_candidate` and `_recordings`. Detection's equivalent differs because its `grades` hold data its audits do not.

Why it was kept: The fact holds. `_server_runs` builds `runs` and `audits` from the same outcomes, each `GateAudit` carries `flagged` and `report`, and the only reads of `ServerRuns.runs` are `run.flagged` in `_candidate` and `_recordings` (grep: `ServerRuns` appears in gate_session, gate_session_model and gate_session_recording only, never in tests). Both lists keep outcome order, so the redundant one can be dropped with no change.

Change: Drop `ServerRuns.runs`, leaving `ServerRuns(server, completed, audits)`. In `_server_runs`, keep the audits comprehension and return `ServerRuns(server, bool(audits) and len(audits) == len(outcomes), audits)`, with its comment on an empty candidate. `_candidate` and `_recordings` read `[audit.flagged for audit in server_runs.audits]`. `GateRun` stays imported where the harness and `_runs` type it.

Files: `evals/cve/nuisance/gate/gate_session_model.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_session_recording.py`

Tests: No test changes: test_nuisance_gate_session.py and test_nuisance_gate_recording.py pin the candidate, the completed flag and the recorded runs through `run_gate`.

#### Fix 7.5: `evals/cve/nuisance/gate/gate_command.py` `gate` (other, defect fix, CHANGELOG)

Problem: gate() re-raises Refused and turns every other Exception into traceback.print_exc() and exit 4. ProviderFatal is a plain Exception raised by nuisance audit_once, so it never reaches the handler in run_nuisance.main, which is dead for this subcommand. The traceback prints the chained cause with its message. Reproduced with fakes through run_nuisance.main and a run_gate raising ProviderFatal(PermissionError('the key sk-secret was revoked')): exit 4, and stderr shows 'PermissionError: the key sk-secret was revoked'. The `run` subcommand pins the opposite behavior in test_a_fatal_provider_error_exits_four_keeping_the_partial_result, whose assertion reads stdout.

Why it was kept: Real defect, checked. `audit_once` raises `ProviderFatal(failure.cause) from failure.cause` (nuisance/audit.py:99). Nothing between it and `gate()` catches it (`gate_run`, `gathered_then_alone`, `AuditProgress.tracked`, `run_gate` has only a finally). `gate()` re-raises only `Refused`, so `except Exception` calls `traceback.print_exc()`, which prints the chained cause with its message: a traceback of such a chain contains 'sk-secret' (run with a PermissionError cause). That breaks the contract of `describe_provider_error` ('never its message, which may quote the prompt'), and the `ProviderFatal` handler of `run_nuisance.main` is dead for this subcommand, while `run` pins the opposite in test_a_fatal_provider_error_exits_four_keeping_the_partial_result.

Change: In `gate()`, write `except (Refused, ProviderFatal): raise` before `except Exception`, importing `ProviderFatal` from evals.cve.provider_errors. `run_nuisance.main` then prints the existing 'Crashed: a fatal model provider error stopped the run.' panel with the error's type and status. The exit code stays 4 (`CRASHED_EXIT`). What changes: the text printed on this crash, and no provider message reaches stderr. Line under Fixed in CHANGELOG.md.

Files: `evals/cve/nuisance/gate/gate_command.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `CHANGELOG.md`

Tests: Test first in test_run_nuisance_gate.py: a `GateCommandDeps` whose `run_gate` runs `cause = PermissionError('the key sk-secret was revoked')` then `raise ProviderFatal(cause) from cause` (a small given beside `GreenRecording`). Without `from`, the traceback carries no secret and the test would stay green on today's code. Assert exit `CRASHED_EXIT`, 'PermissionError' in the output, and 'sk-secret' in neither stdout nor stderr. stderr must be read, since that is where the traceback goes and what makes the test red today.

Risks: Printed text of a crash changes (CHANGELOG), exit code unchanged. `run_detection.main` has the same `except Exception` with no `ProviderFatal` handler (evals/run_detection.py:97) and detection/audit.py:127 raises it: same leak on the detection gate, which fix 7.6 fixes.

#### Fix 7.6: `evals/run_detection.py` `main` (other, defect fix, CHANGELOG)

Problem: `main` has `except Exception: traceback.print_exc()` at line 97 and no `ProviderFatal` handler, while `evals/cve/detection/audit.py:127` raises `ProviderFatal(failure.cause) from failure.cause`. The traceback prints the chained cause with its message, which breaks the contract of `describe_provider_error` (never the message, which may quote the prompt). `evals/run_detection_holdout.py` and `evals/run_nuisance.py` already handle it. It is the defect of fix 7.5, on the detection gate.

Why it was kept: Reproduced in memory: `run_detection.main` with `ProviderFatal(cause) from cause` exits 4 and stderr shows the cause's message, with a `PermissionError` and with a real `anthropic.AuthenticationError` chain.

Change: In `main`, before `except Exception`, add `except ProviderFatal as fatal:` calling `display.print_refusal("Crashed: a fatal model provider error stopped the run.", [describe_provider_error(fatal.cause)])`, then `return CRASHED_EXIT`, the panel `evals/run_detection_holdout.py` prints. Import `ProviderFatal` and `describe_provider_error` from `evals.cve.provider_errors`. The exit code stays 4. Add a line under Fixed in CHANGELOG.md.

Files: `evals/run_detection.py`, `tests/unit/detection/test_run_detection.py`, `tests/unit/detection/support/test_run_detection_given.py`, `CHANGELOG.md`

Tests: Test first in test_run_detection.py, on `replace(cli.a_session_under_priced_models(monkeypatch), session=given.a_session_raising_a_fatal_provider_error)` and a `--no-baseline` run with its `--report` under `tmp_path`. The given runs `cause = PermissionError('the key sk-secret was revoked')` then `raise ProviderFatal(cause) from cause` (without `from`, the traceback carries no secret and the test would stay green on today's code). Assert exit `CRASHED_EXIT`, 'PermissionError' in the output, and 'sk-secret' in neither stdout nor stderr.

Risks: The text printed on this crash changes, the exit code does not. No fingerprinted module is touched.

#### Fix 7.7: `evals/cve/nuisance/gate/gate_console.py` `_gate_rows` (duplication, refactoring)

Problem: gate_console._gate_rows and gate_report._row each derive the same six cells of a server from a ServerComparison: the `server_letters(...) or "-"` pair, retest_fraction, server_detail, and the same `{line.server_package: line}` lookup (gate_console:49, gate_report:112). This forces gate_report to export server_letters and server_detail for the console alone. The line of a server outside the gate is also written three times (gate_command:138, gate_console:30, gate_report:81).

Also covers: `evals/cve/nuisance/gate/gate_report.py` (duplication): The line of a server outside the gate, `package: exit reason text`, is formatted in gate_report.py:81, gate_console.py:30 and gate_command.py:138, and the not-run line in gate_report.py:77 and gate_console.py:26. The console already imports its other shared lines from gate_report.

Why it was kept: The fact holds for one row and one exit line. `gate_console._gate_rows` and `gate_report._row` derive the same six cells of a server with the same `server_letters(...) or '-'`, `retest_fraction`, `server_detail` and the same `{line.server_package: line}` lookup, and gate_report exports `server_letters` and `server_detail` for the console alone (grep: no other importer, no test). The line of a server outside the gate is written three times with the same table lookup (gate_report:81, gate_console:30, gate_command:138). This is one concept, a server's row, rendered twice, so the precedent on two equal strings of different concepts does not apply. Output stays identical, since only the markdown escapes `|`, in the detail alone.

Change: In gate_report.py add public `gate_rows(report) -> list[GateRow]` (GateRow from evals.eval_display, which imports nothing from the nuisance suite) and `outside_gate_line(server: ServerExit) -> str`. `_servers_section` maps `gate_rows(report)` through a private `_markdown_row(row)` that joins subject, outcome, baseline, run, retests and `row.detail.replace('|', '\\|')`. `server_letters` and `server_detail` become private. gate_console.py calls `gate_table(gate_rows(report), 'Server')`, deletes `_gate_rows`, and drops the `retest_fraction` and `EXIT_REASON_TEXTS` imports. `_print_empty_gate` prints `f'- {outside_gate_line(server)}'`. The not-run line `f'{p}: {why}'` stays inline in its two renderers: a helper over one f-string with no lookup would abstract nothing.

Files: `evals/cve/nuisance/gate/gate_report.py`, `evals/cve/nuisance/gate/gate_console.py`, `evals/cve/nuisance/gate/gate_command.py`

Tests: No test changes expected: test_nuisance_gate_report.py and test_nuisance_gate_console.py pin the markdown rows and the console summary. test_code_standards.py checks the newspaper order of gate_report.py.

Risks: another section (render_throttled) and another section edit the same two modules, in other functions.

### 8. Gate tests and the retired sense of settle

Verifier's notes: Five confirmed fixes, all independent of each other. fix 8.4 and fix 8.6 both edit test_nuisance_gate_report.py (the test rename and the `then` calls) without conflict. fix 8.4 writes ServerCandidate directly, so it does not depend on the `package` parameter that fix 8.2 removes from a_candidate. No fix touches a fingerprinted module, a committed record, a dossier closure or a user-facing message. Overlaps with other sections of this plan: - another section: fix 8.1 renames the same `settled` local in holdout_servers._pending (apply once, `recorded` recommended). Its other findings on holdout_servers.py (fix 11.2, a rejected finding, fix 11.4, fix 8.2, fix 11.3) touch neighbouring lines. fix 11.6 renames the acceptance builders called inside test_run_nuisance_gate_given.py and test_run_nuisance_gate.py, the files of fix 8.5. - another section: fix 9.4 removes the same `runs` parameter of a_server_result and also repoints RUNS in test_nuisance_statistic.py (apply once). - another section: fix 7.5 adds a case to test_run_nuisance_gate.py, which should use the new `arguments` names if it lands after fix 8.5. fix 7.2 and fix 7.2 touch test_nuisance_gate_selection.py, and several of its findings touch gate_session.py. - another section: edits gate_session.py and test_nuisance_gate_recording.py (imports and recording helpers), a different part from the test rename here. - another section: fix 3.8 repoints the HOLDOUT_TEST_BUDGET import of nuisance_gate_baselines.py, a different line from the `commit` removal, and other findings touch gate_session.py. - another section and another section: touch gate_session.py and holdout_servers.py elsewhere. Order: the renames here are mechanical and can land after the structural sections. If a section moves gate_session._retested, the `retested` rename follows it to its new place.

#### Fix 8.1: `evals/cve/nuisance/gate/gate_session.py` `_with_retests` (ubiquitous-language, refactoring)

Problem: The nuisance gate keeps the retired word: `settled = apply_retests(...)` in gate_session.py:244-249 and in tests/unit/nuisance/gate/test_nuisance_gate.py:86-98. The retired-word scan only catches `settle(` and `_settled`, so these pass it. The detection side already writes `retested` (evals/cve/detection/session.py:212, tests/unit/detection/test_detection_gate.py:129). holdout_servers.py:55-60 also calls `settled` the servers the admission admitted or recorded an exit for, which is no maintainer ruling on a disagreement.

Also covers: `evals/cve/nuisance/gate/gate_session.py` (ubiquitous-language): The local variable `settled` holds the comparison after retests, which is the retired sense. Detection's `_retested` calls the same variable `retested`.

Also covers: `tests/unit/nuisance/gate/test_nuisance_gate.py` (ubiquitous-language): The test name and the local variable `settled` (five tests, lines 86 to 125) keep the retired sense of 'settle'. test_nuisance_gate_recording.py:123 does the same with test_a_confirmed_file_is_not_recorded_over_an_unsettled_comparison. In the glossary a settlement is the maintainer's ruling between two classifiers or admission agents, which has nothing to do with a retest. The same word remains at gate_session.py:244, outside this slice.

Also covers: `tests/unit/nuisance/gate/test_nuisance_gate.py` (ubiquitous-language): The gate tests keep the retired sense of settle: the test name test_settle_keeps_the_baseline_runs, the local `settled` in six tests of this file, and test_a_confirmed_file_is_not_recorded_over_an_unsettled_comparison (test_nuisance_gate_recording.py:123). The production loop has the same word (`settled`, gate_session.py:244-249). In the glossary, a settlement is the maintainer's ruling on a disagreement, which has nothing to do with a retest.

Also covers: `tests/unit/nuisance/gate/test_nuisance_gate.py` (ubiquitous-language): The test name and its `settled` locals (lines 86-125) keep the retired sense, as does the production loop gate_session._retested (gate_session.py:244-249), whose detection counterpart is already written `retested`.

Also covers: `evals/cve/nuisance/holdout_servers.py` (ubiquitous-language): The local `settled` holds the packages that are admitted or recorded out. No maintainer ruling is involved, and the admission code beside it (walk_record.py) uses the same word in its glossary sense.

Why it was kept: True. docs/glossary-log.md:143 retires `settle` in the gates (it became `apply_retests`, and "settle" names only a settlement). The retired sense remains in gate_session._retested (lines 244-249, 4 occurrences), in five tests of test_nuisance_gate.py (lines 81-125, the test name and 12 occurrences of the local) and in test_a_confirmed_file_is_not_recorded_over_an_unsettled_comparison (test_nuisance_gate_recording.py:123). The retired-word guard misses them. The detection counterpart already writes `retested` (evals/cve/detection/session.py:201-214) and names its test test_apply_retests_keeps_the_baseline_runs (tests/unit/detection/test_detection_gate.py:125). holdout_servers._pending:55-60 also calls `settled` the packages the admission admits or records an exit for, which involves no maintainer ruling. admission._is_settled and walk_record use the word in its glossary sense and stay.

Change: Rename the local `settled` to `retested` in gate_session._retested and in the five tests of test_nuisance_gate.py. Rename test_settle_keeps_the_baseline_runs to test_apply_retests_keeps_the_baseline_runs, the detection counterpart's name. Rename test_a_confirmed_file_is_not_recorded_over_an_unsettled_comparison to test_a_confirmed_file_is_not_recorded_over_an_undecided_comparison (its cases are a pending retest, an incomplete comparison and no comparison). In holdout_servers._pending, rename the local `settled` to `recorded` (the servers the admission records, admitted or out). The glossary keeps the verb `record` in its everyday sense. No public name changes.

Files: `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/holdout_servers.py`, `tests/unit/nuisance/gate/test_nuisance_gate.py`, `tests/unit/nuisance/gate/test_nuisance_gate_recording.py`

Tests: Two test functions are renamed and locals change, assertions unchanged. Run the short loop, ruff and pyrefly. No fingerprinted module is touched (gate_session.py and holdout_servers.py are not in the list of fingerprinted modules), and no import changes.

Risks: No public name changes. The local of `_pending` becomes `recorded`.

#### Fix 8.2: `tests/unit/nuisance/gate/support/test_nuisance_gate_given.py` `a_candidate` (dead-code, refactoring)

Problem: An AST scan of every call under tests/ finds three builder parameters no caller passes: `package` of a_candidate (26 calls), `commit` of nuisance_gate_baselines.an_unconfirmed_baseline (line 28, 24 calls) and `runs` of nuisance_report_runs.a_server_result (line 70, 52 calls).

Also covers: `tests/unit/nuisance/gate/support/test_nuisance_gate_given.py` (dead-code): An AST scan of the 8 calls to a_candidate shows the `package` parameter is never passed (only runs, completed and fixture are). It is the parameter that puts the builder over the 3-argument bar.

Also covers: `tests/unit/nuisance/gate/support/nuisance_gate_baselines.py` (dead-code): An AST scan of the 10 calls to an_unconfirmed_baseline shows `commit` is never passed, positionally (at most 2 positional arguments) or by keyword (only `package`).

Why it was kept: True, by an AST scan of every call under tests/ and evals/: no call passes `package` to the nuisance a_candidate, `commit` to the nuisance an_unconfirmed_baseline (keyword or third positional) or `runs` to a_server_result (52 calls), and no call splats arguments. `runs: int = 3` also restates the RUNS = 3 of the same module, which a_run uses, so the two can drift. Dropping `package` brings a_candidate back to 3 arguments.

Change: In test_nuisance_gate_given.a_candidate, remove `package` and build with server_package=nuisance_gate_baselines.SERVER_PACKAGE. In nuisance_gate_baselines.an_unconfirmed_baseline, remove `commit` and write commit=RECORDED_COMMIT. The unused `runs` of nuisance_report_runs.a_server_result is fix 9.4's.

Files: `tests/unit/nuisance/gate/support/test_nuisance_gate_given.py`, `tests/unit/nuisance/gate/support/nuisance_gate_baselines.py`

Tests: No test changes: no caller passes these parameters. Run the short loop and pyrefly.

Risks: fix 9.4 (another section) removes the same `runs` parameter and also repoints the RUNS of test_nuisance_statistic.py: the plan applies that part once.

#### Fix 8.3: `tests/unit/nuisance/gate/support/test_nuisance_gate_selection_given.py` `a_server_outside_the_census` (given-then, refactoring)

Problem: The whole given file is a one-line wrapper over holdout_runs.a_server, called once. Its name also misleads: gate_servers reads no census, it filters on the `current` set, and the test's own package is "npm:not-current".

Also covers: `tests/unit/nuisance/gate/support/test_nuisance_gate_selection_given.py` (given-then): This given file holds one function with one caller, and its body is `return holdout_runs.a_server(package)`. Whether the server is outside the census follows from the `CURRENT` set of the test, not from the builder.

Why it was kept: True. test_nuisance_gate_selection_given.py holds one function with one caller, whose body is `return holdout_runs.a_server(package)`, the one-liner wrapper CLAUDE.md says to inline. Its name also misleads: gate_servers reads no census and filters on the `current` set.

Change: Delete tests/unit/nuisance/gate/support/test_nuisance_gate_selection_given.py. In test_nuisance_gate_selection.py, replace the given import with `import tests.unit.support.nuisance_holdout_runs as holdout_runs` and write `other = holdout_runs.a_server("npm:not-current")`.

Files: `tests/unit/nuisance/gate/support/test_nuisance_gate_selection_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_selection.py`

Tests: The test keeps its assertions. The code standards scan only polices foreign imports of a given or then, so a test file with no given is fine.

#### Fix 8.4: `tests/unit/nuisance/gate/support/nuisance_gate_reports.py` `a_not_gated_server_with_an_alarm` (test-behavior-vs-implementation, refactoring)

Problem: The builder writes a ServerComparison by hand with outcome NOT_GATED, a baseline flagged once, the detail 'flagged in 1 of 6 baseline runs' and a candidate alarm. compare_server cannot produce this state: on a confirmed baseline with an alarm, a candidate alarm gives INCONCLUSIVE (gate.py, `unstable`). Running the real flow on the same inputs printed `inconclusive`. The two tests named test_a_not_gated_server_shows_its_detail_before_its_flagged_tools (report and console) therefore specify a row the gate never emits, and the detail string is a hand copy of _why_not_gated. a_held_server_beside_a_regression also writes its REGRESSION comparison and retests by hand.

Why it was kept: True for the unstable server. On a confirmed baseline with an alarm, compare_server returns INCONCLUSIVE when the candidate has an alarm (gate.py, `unstable`), and NOT_GATED with that detail only on a clean candidate. So a_not_gated_server_with_an_alarm specifies a row the gate never emits, with a hand copy of _why_not_gated. Run through the real flow, the row is `| inconclusive | .....A | A.. | - | flagged in 1 of 6 baseline runs; run 1: CVE-2025-0001_read |`. Only the outcome cell differs, and the console at width 200 still prints the asserted text. Rejected part: a_held_server_beside_a_regression writes a REGRESSION comparison the gate can produce (apply_retests on those retests gives the same outcome, retests and baseline runs), and a hand-built value object as the input of a pure renderer is an ordinary unit test.

Change: In nuisance_gate_reports.py, replace a_not_gated_server_with_an_alarm with an_inconclusive_server_with_an_alarm, which builds its comparison with compare_server(nuisance_gate_baselines.a_confirmed_baseline([False] * 5 + [True], package), ServerCandidate(server_package=package, fixture_fingerprint=nuisance_gate_baselines.FIXTURE, runs=runs, completed=True)). The module cannot import test_nuisance_gate_given (the one-pair rule), so it writes ServerCandidate itself. Move FLAGGED_IN_BASELINE up beside NOT_ADMITTED and OUTSIDE: it stays as the text the two tests expect, and no longer feeds the builder. Rename a_not_gated_report to an_inconclusive_report in test_nuisance_gate_console_given.py, and both tests to test_an_inconclusive_server_shows_its_detail_before_its_flagged_tools. Leave a_held_server_beside_a_regression as it is.

Files: `tests/unit/nuisance/gate/support/nuisance_gate_reports.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_console_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_report.py`, `tests/unit/nuisance/gate/test_nuisance_gate_console.py`

Tests: Two tests renamed, their assertions unchanged and checked against the real flow (markdown row and console output at width 200). A change to compare_server's detail text now reaches them. Production code is unchanged.

#### Fix 8.5: `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py` `a_gate_set_of_one_server` (ubiquitous-language, refactoring)

Problem: In the production command and CONTRIBUTING.md, the gate set is the set of gate servers (`gate_set` holds packages, and the refusal prints '(gate set: ...)'). In this given and its test file, a_gate_set_of_one_server and a_gate_set_beside_an_unrecorded_server return command-line arguments (--census, --walk-record, --admission, --report), and tests splat them as `*gate_set`. The helpers `_gate_arguments` and `gate_arguments` also differ by one underscore while taking different inputs (an admission versus a path) and producing different arguments.

Why it was kept: True. In gate_command.py and CONTRIBUTING.md the gate set is the set of gate servers (`gate_set` holds packages, and the refusal prints `gate set: ...`). In test_run_nuisance_gate.py, eight locals `gate_set` and the givens a_gate_set_of_one_server and a_gate_set_beside_an_unrecorded_server hold command-line arguments that the tests splat into argv. `_gate_arguments` and `gate_arguments` differ by one underscore while taking an admission and a path. The change stays within one test file and its given.

Change: Rename a_gate_set_of_one_server to arguments_for_one_gate_server, a_gate_set_beside_an_unrecorded_server to arguments_beside_an_unrecorded_server, the eight locals `gate_set` to `arguments` (no local of that name exists in the file), and `_gate_arguments` to `_arguments_with_a_report`. `gate_arguments` stays. The test name test_gate_on_a_server_outside_the_gate_set_exits_two uses the term in its true sense and stays.

Files: `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`

Tests: Names only, assertions unchanged. Run test_run_nuisance_gate.py, then the short loop.

#### Fix 8.6: `tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py` `row_of` (given-then, refactoring)

Problem: This given holds no setup. Its two functions, row_of and section, read the rendered markdown and are called only in the assertion phase of test_nuisance_gate_report.py, as in `assert given.section(markdown, "## Recording") == [...]`, so the Then phase of the spec reads 'given'.

Why it was kept: True. row_of and section hold no setup and are called only after the When, on the rendered markdown, so the assertions read `given.section(...)`. then modules already hold such read-off helpers (test_cve_planting_stand_ins_then.mounted_content). The scan accepts test_x_then.py as the pair of test_x.py. The helper is not the auditor's section_of (tests/unit/auditor/support/markdown_sections.py), which returns a body string where this one returns the lines up to the first blank.

Change: Rename tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py to test_nuisance_gate_report_then.py, import it as `then` in test_nuisance_gate_report.py, and call then.row_of and then.section at the 7 call sites. No logic changes.

Files: `tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_report_then.py`, `tests/unit/nuisance/gate/test_nuisance_gate_report.py`

Tests: Same assertions through the renamed module. test_code_standards.py checks the pair.

### 9. Report, markdown and statistic

Verifier's notes: Confirmed: fix 9.1 (carrying fix 9.1, fix 9.1 and fix 9.1), fix 9.2 (carrying fix 9.2, reshaped with no new module), fix 9.3, fix 9.4, fix 9.5, fix 9.1 and fix 9.7. Rejected: a rejected finding. Interactions inside the section: - fix 9.1 and fix 9.5 both edit nuisance/report.py on different lines. - fix 9.2 is independent of fix 9.1: report.py keeps calling nuisance_rate_controls, contrast and check_conclusion. - fix 9.4 and fix 9.7 both edit test_nuisance_statistic.py on different lines (the RUNS constant, a local in one test). fix 9.2 leaves that file alone. - The order is free. One commit per fix works. Other sections on the same modules: - another section (fix 2.2, fix 2.2, fix 2.2) deletes _throttled_lines from nuisance/markdown.py and render_throttled from gate_report.py. It holds the throttled part of fix 9.1, so it must reuse eval_display.throttled_lines and print_throttles, and nothing goes into holdout_report_lines.py. It edits the same import block and render_markdown list as fix 9.1: land one, then rebase the other. - another section also lists nuisance/markdown.py (fix 11.15 is anchored in admission_walk.py): check for overlap when ordering. - another section also touches gate_report.py and gate_console.py, relevant to another section rather than to this section. - docs/glossary.md is also edited by another section (fix 11.11) and another section (fix 12.8, fix 12.11), in different entries. - test_nuisance_counting_given.py is also edited by another section (fix 10.8), in another function. - another section lists nuisance_report_runs.py only because fix 8.2 uses the same builder name, in test_nuisance_gate_given.py: a different builder, so no conflict with fix 9.4. No fix of this section touches a fingerprinted module, a committed record, a report field name or a dossier's import closure.

#### Fix 9.1: `evals/cve/nuisance/markdown.py` `_run_cutoff_line, _conclusion_text, _controls_section, _health_facts, _incomplete_runs_lines, _span; report._two_sides, report._conclusion_line` (duplication, refactoring)

Problem: markdown.py keeps private copies of run_cutoff_line (:51), conclusion_text (:56), controls_section (:65), health_facts (:162), INCOMPLETE_RUNS and incomplete_runs_lines (:177-187) and span (:199). report.py keeps two_sides (:197) and rebuilds ConclusionLine field by field (:218) where ConclusionLine.of exists. The two rates are published side by side, so a wording change on one side alone breaks that.

Also covers: `evals/cve/nuisance/markdown.py` (duplication): The nuisance report and markdown keep private copies of `evals/cve/holdout_report_lines.py`, with identical output: `_run_cutoff_line`, `_conclusion_text`, `_controls_section`, `_span`, `_health_facts`, `_incomplete_runs_lines` with `_INCOMPLETE_RUNS`, and in report.py `_two_sides` and the hand-built `ConclusionLine`. `_throttled_lines` and `gate_report.render_throttled` copy `eval_display.throttled_lines`.

Also covers: `evals/cve/nuisance/markdown.py` (duplication): markdown.py still carries private copies of what holdout_report_lines.py exports: _run_cutoff_line (run_cutoff_line), _conclusion_text (conclusion_text), _controls_section (controls_section), _span (span), _INCOMPLETE_RUNS and the body of _incomplete_runs_lines (INCOMPLETE_RUNS, incomplete_runs_lines), and the five ifs of _health_facts (health_facts). The texts are identical today. The shared module's docstring says the two holdout rates are published side by side so these lines read the same, and only the detection side uses it.

Also covers: `evals/cve/nuisance/report.py` (duplication): _two_sides is a word-for-word copy of holdout_report_lines.two_sides, and _conclusion_line builds ConclusionLine field by field (lines 218-223) where ConclusionLine.of(conclusion) exists and the detection report uses it.

Why it was kept: True, and it is the follow-up the detection pass left open (plans/2026-11-23_detection-suite-standards-pass.md, Decisions, fix 3.2). markdown.py keeps private copies of run_cutoff_line, conclusion_text, controls_section, span, INCOMPLETE_RUNS, incomplete_runs_lines and the five ifs of health_facts. report.py copies two_sides and builds ConclusionLine field by field where ConclusionLine.of exists. Same knowledge: the holdout nuisance rate is published only beside the holdout detection rate (glossary), and the module docstring says these lines read the same. Output compared by running both versions on the same inputs: span, run_cutoff_line (with and without a note), conclusion_text (none, placed, inconclusive), the INCOMPLETE_RUNS label, health facts joined with ', ' and incomplete_runs_lines on a report with incidents are all equal. controls_section has the same body, sorted items included. ServerLine carries the five HealthCounts fields. No difference found. The throttled part of fix 9.1 is not carried here: the another section holds it (fix 2.2, fix 2.2, fix 2.2).

Change: In evals/cve/nuisance/markdown.py, import conclusion_text, controls_section, health_facts, incomplete_runs_lines, run_cutoff_line and span from evals.cve.holdout_report_lines, and drop the imports of ConclusionLine, IntervalModel and RunCutoffModel, which are no longer used. Delete _run_cutoff_line, _conclusion_text, _controls_section, _health_facts, _INCOMPLETE_RUNS and _span. Call `*controls_section(report.controls)` in render_markdown. In _health_section, write `if (facts := ", ".join(health_facts(line)))`. Keep a short _incomplete_runs_lines(report) that computes `touched` from report.servers and returns incomplete_runs_lines(report.incomplete_run_count, touched, report.incomplete_runs_by_cause), as detection/holdout_markdown.py does. In evals/cve/nuisance/report.py, import two_sides, write `pair = two_sides(split)`, delete _two_sides, end _conclusion_line with `return ConclusionLine.of(conclusion)` and drop the MethodLine import. _contrast_line and _conclusion_line stay as short wrappers over the nuisance statistic, as in detection/holdout_report.py. Refactoring: rendered markdown and written JSON are byte-identical.

Files: `evals/cve/nuisance/markdown.py`, `evals/cve/nuisance/report.py`

Tests: No test changes. tests/unit/nuisance/test_nuisance_report.py and test_nuisance_report_sections.py pin the rendered lines and must pass unchanged. No test imports MethodLine from nuisance.report (test_nuisance_report.py takes it from holdout_report_lines). Neither module is fingerprinted, so no fingerprint moves.

Risks: Edits the imports and render_markdown lines that another section also edits (_throttled_lines): one must rebase on the other. Keep throttled_lines out of holdout_report_lines.py (detection plan, fix 3.2).

#### Fix 9.2: `evals/cve/nuisance/statistic.py` `_GAMMA_1_1, _GAMMA_2_2, _MIN_SIDE, nuisance_rate_controls` (duplication, refactoring)

Problem: The pre-registered statistic is restated: the two Gamma priors and the minimum of 5 per side are private constants in both nuisance/statistic.py and holdout_statistic.py, and nuisance_rate_controls rewrites the four controls common to both rates (jeffreys, clopper_pearson, the two hierarchical intervals). The machinery nuisance imports (Side, side_of, Placement, Contrast, MethodPlacement, Reading, Conclusion, conclude, read_contrast) sits in holdout_statistic.py, a module typed on detection's HoldoutTargetResult, so the nuisance statistic and holdout_report_lines load detection's result types to reach it.

Also covers: `evals/cve/nuisance/statistic.py` (duplication): The minimum side size for the contrast and the conclusion is declared in both statistics (holdout_statistic.py:33 and statistic.py:35). The two rates are published side by side and read with the same methods, so the threshold is one piece of knowledge.

Why it was kept: Partly true, and the fix is reshaped. The restatement is real and is one piece of knowledge: the nuisance suite rule (Run conditions and statistic) says conclusions are checked 'as the detection suite rule checks its own' and the contrast is computed 'as the detection suite rule does', and the detection suite rule names the four controls, the two Gamma priors and the minimum of 5 per side. Today both statistics hold _MIN_SIDE, _GAMMA_1_1 and _GAMMA_2_2 and write the same four control entries. The proposed new module holdout_contrast.py is rejected: 11 files for a dependency that costs nothing. holdout_statistic.py already sits in evals/cve/, detection/holdout_results.py is a light dataclass module importing only holdout_conditions, and the nuisance package imports evals.cve.detection in about 15 other places (baseline, targets, draw_record). Sharing the constant and the four controls inside holdout_statistic.py removes the restatement. A prototype of rate_controls gave the same values and the same key order as nuisance_rate_controls on a sample under COARSE_GRID. hierarchical_interval reads its members through Counter, so a tuple and a list give the same result.

Change: In evals/cve/holdout_statistic.py: rename _MIN_SIDE to public MIN_SIDE, its comment reading 'Newcombe and the conclusion need at least this many members a side'. Add below detection_rate_controls `def rate_controls(reading: Reading, runs: int, grid: Grid) -> dict[str, Interval]`, returning in this order jeffreys, clopper_pearson, hierarchical_gamma_1_1 and hierarchical_gamma_2_2 from reading.share_sum, reading.members and reading.counted_runs. _GAMMA_1_1 and _GAMMA_2_2 stay private there. Widen Reading's docstring to 'One way of counting members, a side or a whole run: the sum of their shares, and the runs counted per member.' detection_rate_controls becomes `reading = Reading(_share_sum(results), tuple(r.detected_runs for r in results))` and returns `{**rate_controls(reading, runs, grid), "unchecked_as_misses_wilson": wilson(_unchecked_sum(results, runs), reading.members)}`. Delete the single-caller _hierarchical. In evals/cve/nuisance/statistic.py: delete _GAMMA_1_1, _GAMMA_2_2 and _MIN_SIDE, import MIN_SIDE and rate_controls, and write nuisance_rate_controls the same way with result.flagged_runs and the fifth key incomplete_as_flagged_wilson. Drop the imports of GammaPrior, hierarchical_interval, clopper_pearson and jeffreys there. Refactoring: interval values and the keys and order of `controls` stay identical.

Files: `evals/cve/holdout_statistic.py`, `evals/cve/nuisance/statistic.py`

Tests: No test changes. test_the_detection_rate_controls_are_the_five_intervals_on_the_detection_shares (tests/unit/cve/test_cve_holdout_statistic.py) and the nuisance_rate_controls test (tests/unit/nuisance/test_nuisance_statistic.py:119) pin all five intervals against direct calls and must pass unchanged. No test reads _MIN_SIDE or the _GAMMA constants. Neither module is in the list of fingerprinted modules, and no fingerprinted module imports them, so every fingerprint stays.

Risks: Touches holdout_statistic.py, shared with the detection holdout report (the detection area, done), by a small addition. The '5' in the markdown's 'fewer than 5 servers' line stays a literal, as on the detection side.

#### Fix 9.3: `tests/unit/nuisance/test_nuisance_report.py` `test_the_report_holds_no_proof_text` (test-behavior-vs-implementation, refactoring)

Problem: The field half of the guard barely guards. `set(model.model_fields).isdisjoint(PROOF_WORDS)` compares whole field names, so `response_text`, `payloads`, `verdicts` or `judge_evidence` all pass. The eleven models are also listed by hand, so a new nested line model added to NuisanceReport is not checked at all.

Why it was kept: True. `set(model.model_fields).isdisjoint(PROOF_WORDS)` compares whole field names, so response_text, payloads or judge_evidence pass, and the eleven models are listed by hand, so a new nested line model escapes. The test file presents this as the structural guarantee that a nuisance holdout run keeps no proof, which protects the holdout layer from being spent by its own report. Checked by running it: a walk of NuisanceReport.model_fields through typing.get_args finds exactly the eleven listed models, and comparing `_` tokens with a final s removed hits only lost_connection_responses and cut_responses on ServerLine and ServerRunLine, two counts that quote no response. The detection counterpart (test_the_report_holds_no_proof_text_fields) has another forbidden set and belongs to a finished group, so it is not changed here.

Change: In tests/unit/nuisance/support/test_nuisance_report_given.py, add `report_models() -> list[type[BaseModel]]`, which walks NuisanceReport.model_fields recursively through typing.get_args and collects each BaseModel subclass once. In tests/unit/nuisance/test_nuisance_report.py, add `COUNTS_NAMING_RESPONSES = {"lost_connection_responses", "cut_responses"}`. Replace the hand-kept list and the field assertion with a check that, for each model of given.report_models() and each field name outside that set, `{token.removesuffix("s") for token in name.split("_")}` is disjoint from PROOF_WORDS. Keep the markdown assertion. Drop the imports only this list used (MethodLine, ConclusionLine, RunCutoffModel, IntervalModel, ServerRunLine, SideLine, NotRunLine, ExitLine, ServerLine, NuisanceReport), after checking each against the rest of the file: CutoffModel at least stays used.

Files: `tests/unit/nuisance/test_nuisance_report.py`, `tests/unit/nuisance/support/test_nuisance_report_given.py`

Tests: The test stays green on the current report. To see it red first, add a temporary `response_text: str` field to ServerRunLine, run the test, then remove the field. No production code changes.

Risks: A future count field naming a proof word has to join the explicit allowance, which is the intended friction.

#### Fix 9.4: `tests/unit/nuisance/support/nuisance_report_runs.py` `a_server_result` (dead-code, refactoring)

Problem: The `runs: int = 3` parameter is passed by none of the 52 calls (AST scan of the tests). It restates the module's RUNS = 3 used by a_run, and test_nuisance_statistic.py declares a third RUNS = 3 that must match the builder for its intervals to hold.

Why it was kept: True. An AST scan of tests/ finds 52 calls of a_server_result, none passing `runs` or unpacking keywords. The default restates RUNS = 3 of the same module, and test_nuisance_statistic.py declares a third RUNS = 3 that must agree with it for its intervals to hold. The a_server_result of test_nuisance_gate_given.py (fix 8.2, another section) is a different builder.

Change: In tests/unit/nuisance/support/nuisance_report_runs.py, delete the `runs` parameter of a_server_result and use RUNS in its body (first_incomplete and range). In tests/unit/nuisance/test_nuisance_statistic.py, delete the local `RUNS = 3` and import RUNS from tests.unit.nuisance.support.nuisance_report_runs.

Files: `tests/unit/nuisance/support/nuisance_report_runs.py`, `tests/unit/nuisance/test_nuisance_statistic.py`

Tests: Same values. The tests of tests/unit/nuisance that use the builder pass unchanged.

#### Fix 9.5: `evals/cve/nuisance/report.py` `NuisanceReport.incomplete_runs_by_cause` (ubiquitous-language, refactoring)

Problem: The comment reads "a run missing steps of two causes counts twice", using the retired sense of step for a missed model call. The same field in detection/holdout_report.py already says "missing model calls".

Why it was kept: True, a false word in a comment. report.py:113 says 'missing steps' for missed model calls. The glossary log renames 'missed step' to missed model call, the glossary says 'A model call is not a step', and the same field in detection/holdout_report.py:53 already says 'missing model calls'.

Change: Write `# a run missing model calls of two causes counts twice` on NuisanceReport.incomplete_runs_by_cause.

Files: `evals/cve/nuisance/report.py`

Tests: None, comment only.

#### Fix 9.6: `evals/cve/nuisance/statistic.py` `split flaw (split_flaw)` (ubiquitous-language, glossary entry)

Problem: "Split flaw" is a domain term of the holdout nuisance rate, written in this docstring, in the tests and as the serialized keys `split_flaw` and `split_disclosure_date`, yet docs/glossary.md has no entry for it. Its definition (the server's first flaw of the draw order that still has a counted tool) exists only as a sentence of the nuisance suite rule, so a reader of the code or of a report cannot look the word up.

Why it was kept: True. split_flaw is a serialized key of the run result and the report, and 'split flaw' is written in statistic.py's docstring and in the tests. docs/glossary.md and docs/glossary-log.md have no entry for it. The nuisance suite rule defines the concept without the name ('its first flaw of the draw order that still has a counted tool'). The project standard wants a term of the code in the glossary, and the word has no other sense there. No rename, one line of docs.

Change: Add to the nuisance suite section of docs/glossary.md, after **holdout nuisance rate**: `- **split flaw**: the one flaw through which a server counts in the split by cutoff side: its first flaw of the draw order that still has a counted tool. The server takes this flaw's side and is flagged for the split only through this flaw's counted tools. A server with none leaves the split. Code: `split_flaw`, `split_disclosure_date` in a run result and its report. Defined by: nuisance suite rule (Run conditions and statistic).` A new term needs no glossary-log line.

Files: `docs/glossary.md`

Tests: Run tests/integration/committed/project/test_glossary.py (the retired-word scan). No code changes.

Risks: The another section (fix 11.11) and another section (fix 12.8, fix 12.11) also add to docs/glossary.md, in other entries.

#### Fix 9.7: `tests/unit/nuisance/test_nuisance_statistic.py` (ubiquitous-language, refactoring)

Problem: `verdict = check_conclusion(...)` (lines 88-93) holds a `Conclusion`, the name the retired `ConclusionVerdict` was replaced by. In tests/unit/nuisance/support/test_nuisance_counting_given.py:12, `verdict = RealSoftwareRecord(...)` holds an admission record about whether the tool's real software answers. Neither is a judge's PASS or FAIL, and the counter tests right beside them use `Verdict` in its real sense.

Why it was kept: True. In test_nuisance_statistic.py:88-93, `verdict` holds a Conclusion, and ConclusionVerdict is a retired name (tests/integration/committed/project/support/retired_words.py:421). In test_nuisance_counting_given.py:12, `verdict` holds a RealSoftwareRecord. The glossary keeps verdict for PASS or FAIL. Two locals, with no serialized name involved.

Change: In tests/unit/nuisance/test_nuisance_statistic.py, rename the local to `conclusion` in test_check_conclusion_is_inconclusive_when_counting_incomplete_runs_as_flagged_moves_the_gap. In tests/unit/nuisance/support/test_nuisance_counting_given.py, rename the local of a_silent_tool to `real_software`, which reads `"real_software": real_software` in the update.

Files: `tests/unit/nuisance/test_nuisance_statistic.py`, `tests/unit/nuisance/support/test_nuisance_counting_given.py`

Tests: Local renames only, the same tests pass.

Risks: The another section edits test_nuisance_counting_given.py in another function (fix 10.8).

### 10. The admission file and its load checks

Order and interactions: fix 10.1 is a pure move and comes first. Fixes 10.2 and 10.3 then edit the moved code in `admission_load.py`.

Verifier's notes: Order within the section: fix 10.1 first, as a pure move (admission_load.py), then fix 10.2 and fix 10.3 on the moved code, then fix 10.4 (the docstrings name admission_load). fix 10.5, fix 10.6, fix 10.7 and fix 10.8 are independent. fix 10.7 adds a property to admission.py and does not conflict with the move. a rejected finding is rejected, but its one sound part (the load test calling the_committed_admission()) is in fix 10.1. The trial of fix 10.1 on a scratch export of HEAD (since removed) kept every reference fingerprint and passed 766 tests. It covered the move and the admission_walk guard, not fix 10.2 to fix 10.5, a rejected finding, fix 10.7 or fix 10.8. Other sections on the same modules: - another section: fix 11.3, fix 11.14, fix 11.2, a rejected finding, fix 10.3 and fix 11.15 edit admission_walk.py. Do fix 10.1 first, since it only changes that file's import guard. fix 11.15 also edits the admission.py docstring, which fix 10.4 already writes with 'the nuisance walk'. a rejected finding renames names in test_nuisance_admission_loads.py and test_nuisance_walk_record_loads.py, whose import lines fix 10.1 changes. fix 11.5 and fix 11.6 touch tests/unit/support/nuisance_admissions.py, as do fix 10.1 and fix 10.2. - another section: fix 3.8 moves grammar_fingerprint and lists admission.py and nuisance_admissions.py. After fix 10.1 the import to repoint is in admission_load.py, so that fix must list admission_load.py instead of admission.py. - another section: `_print_unrecorded` stays, since the finding that would replace it is rejected, and fix 10.6 renames its local. - another section: fix 12.7 and fix 10.8 edit re_admission_dossier.py near the line fix 10.7 changes, with no conflict. - another section, another section and another section edit fix_check_command.py, where fix 10.7 changes one line of _field_mismatches. fix 13.7 edits the docstring just above it. - commands.py is touched by another section, another section and another section: fix 10.1 changes only its import of load_admission.

#### Fix 10.1: `evals/cve/nuisance/admission/admission.py` `load_admission` (file-length, refactoring)

Problem: admission.py (307 lines) holds two concepts: the pydantic schema of the admission file (lines 43-135), imported by about 35 modules of evals/, and the load validation (lines 138-307: load_admission, admission_problems and eleven private checks), whose only production caller is commands.committed_admission. Because the schema module imports the checks' dependencies at runtime (backend_registry, images, walk, admission_walk, detection.baseline), every module those checks need that also names AdmittedServer has to import it under TYPE_CHECKING to avoid a cycle: admission_walk, images and backend_registry do. No other fix brings the file under the bar.

Why it was kept: The fact holds. admission.py is 307 lines and holds two concepts: the pydantic schema (lines 43-135) and the load validation (lines 138-307). The 'barely over 300' precedent does not apply: no other fix brings it under the bar, since fix 10.2 and fix 10.3 add lines and fix 10.4 shortens the docstring by only a few. The detection pass made the same split (draw_record.py / draw_record_problems.py). The only production caller of load_admission is commands.committed_admission, and admission_problems is called by load_admission and tests/unit/support/nuisance_admissions.problems_of. I tried the split on a scratch export of HEAD. All evals.cve.nuisance modules outside fix_checks import alone in a fresh interpreter with no cycle. Importing the schema no longer loads backend_registry, walk or detection.baseline. The admission_walk guard can go. the fingerprint check of Verification prints the reference values exactly (grammar, 41 targets, counter, 65 servers). 766 tests of tests/unit/nuisance, test_kit_isolation, test_cve_dossier_closure and tests/integration/committed/nuisance/admission pass. admission.py is in no dossier closure (computed over the 65 servers' closure_roots) and in no standards debt list.

Change: Create evals/cve/nuisance/admission/admission_load.py holding load_admission, admission_problems and their private checks (_fingerprint_problems through _patched_version_problems), moved unchanged and in the same order, so every message and the order of problems stay identical. It imports AdmittedServer, FieldAgreement, NuisanceAdmission and ToolRecord from admission.py, plus record_problems, walk_problems, exit_problems, nuisance_walk, backend_registry, nuisance_images, detection_baseline, WalkInputs, counted_flaws and counted_tools. admission.py keeps ADMISSION_PATH and the models and drops the imports only the checks used (Mapping, Path, detection_baseline, backend_registry, nuisance_images, nuisance_walk, record_problems, exit_problems, walk_problems, WalkInputs, counted_flaws, counted_tools), so no moved name stays importable from it. In admission_walk.py, replace the TYPE_CHECKING guard by a plain import of AdmittedServer and NuisanceAdmission. counting.py, images.py and backend_registry.py keep theirs (counting.py is fingerprinted and stays byte-identical). Repoint every importer: evals/cve/nuisance/commands.py (load_admission), tests/unit/support/nuisance_admissions.py (admission_problems), tests/unit/support/committed_nuisance_admission.py, tests/unit/nuisance/admission/test_nuisance_admission.py and tests/integration/committed/nuisance/admission/test_nuisance_walk_record_loads.py (load_admission). In test_nuisance_admission_loads.py, test_the_committed_admission_loads becomes a call to the_committed_admission(), which does the same load, and the imports of CENSUS_PATH, load_census, load_walk_record, WALK_RECORD_PATH, ADMISSION_PATH and load_admission go (AdmittedServer stays).

Files: `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/admission_load.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/commands.py`, `tests/unit/support/nuisance_admissions.py`, `tests/unit/support/committed_nuisance_admission.py`, `tests/unit/nuisance/admission/test_nuisance_admission.py`, `tests/integration/committed/nuisance/admission/test_nuisance_admission_loads.py`, `tests/integration/committed/nuisance/admission/test_nuisance_walk_record_loads.py`

Tests: Import lines only, plus the one-line load test. Run the full check and the fingerprint check of Verification before and after: grammar, 41 detection fixtures, counter and 65 nuisance fixtures must be identical (they were on the trial). test_kit_isolation and test_cve_dossier_closure stay green, since admission.py is outside every closure.

Risks: counting.py must stay byte-identical: AdmittedServer, FlawRecord and ToolRecord do not move. A moved name must not stay imported in admission.py (implicit re-export escapes pyrefly). The tests/unit/support files belong to the shared test support area, but only their import lines change. The model schemas shipped by the dossiers (FlawRecord, AdmittedServer) do not change.

#### Fix 10.2: `evals/cve/nuisance/admission/admission.py` `admission_problems` (argument-count, refactoring)

Problem: admission_problems takes the admission plus three values that together are what it is checked against: walk_inputs, grammar_fingerprint and backends. The detection side named the same concept for the same kind of function: draw_problems(draw, references: DrawReferences). The two load validations now differ in shape for no reason.

Why it was kept: admission_problems takes four parameters, three of which together name what the admission is checked against. The detection side named that concept for the same kind of function: draw_problems(draw, references: DrawReferences) in draw_record_problems.py. There are exactly two call sites (load_admission and problems_of in tests/unit/support/nuisance_admissions.py), so the change is small and aligns the two suites' load validations. 'Reference' has no glossary sense that conflicts, and AdmissionReferences mirrors DrawReferences.

Change: In admission_load.py (after fix 10.1), add above admission_problems a frozen dataclass `AdmissionReferences` with the docstring 'What the admission's names and fingerprint are checked against.' and the fields walk_inputs: WalkInputs, grammar_fingerprint: str, backends: Mapping[str, backend_registry.RegisteredBackend]. The signature becomes admission_problems(admission: NuisanceAdmission, references: AdmissionReferences). load_admission builds it from walk_inputs, detection_baseline.grammar_fingerprint() and backend_registry.BACKENDS. The private checks keep their parameters. problems_of builds AdmissionReferences(census if census is not None else walk_inputs_of(), detection_baseline.grammar_fingerprint(), a_backend_registry()).

Files: `evals/cve/nuisance/admission/admission_load.py`, `tests/unit/support/nuisance_admissions.py`

Tests: problems_of changes, and its callers do not. The problem messages and their order are unchanged, pinned by test_nuisance_admission.py and the admission walk tests.

Risks: Apply after fix 10.1. If fix 3.8 moves grammar_fingerprint, only the import in admission_load.py and nuisance_admissions.py follows.

#### Fix 10.3: `evals/cve/nuisance/admission/admission.py` `_patched_version_problems` (function-length, refactoring)

Problem: The 26-line body carries two independent rules: the server's patched version must be one of its counted flaws' patched versions, and server_patched_surfaces must be set exactly on the flaws whose patched version differs from the server's. The early return and its comment concern only the first rule, since the second loop is empty when no flaw counts.

Why it was kept: The body is 26 lines and carries two independent rules: the server's version must be a counted flaw's, and server_patched_surfaces must be set exactly on the flaws whose version differs. The early return serves only the first rule, since the second loop is empty when no flaw counts. Splitting keeps the output identical: with no counted flaw both helpers return [], otherwise the version problem still comes before the per-flaw problems.

Change: In admission_load.py (after fix 10.1): `_patched_version_problems(server)` becomes `counted = counted_flaws(server)` then `return [*_version_of_no_counted_flaw(server, counted), *_server_patched_surfaces_problems(server, counted)]`. `_version_of_no_counted_flaw(server, counted)` holds the guard with its comment (`if not counted: return []`) and the version message. `_server_patched_surfaces_problems(server, counted)` holds the per-flaw loop unchanged. Newspaper order: both helpers right below their caller.

Files: `evals/cve/nuisance/admission/admission_load.py`

Tests: No test changes. The existing admission load tests pin the messages.

Risks: Do it after the pure move of fix 10.1, so the move stays reviewable as unchanged code.

#### Fix 10.4: `evals/cve/nuisance/admission/admission.py` (comments-docstrings, false docstring corrected)

Problem: The module docstring describes a state that no longer exists: "Every list is empty until the admission session" and "The file is absent until the session", while evals/nuisance_admission.json is committed with 65 servers. It also says "The fields defaulting to None are those nuisance suite rule v3 or v4 added", which is false for AdmittedServer.backend (default None, a server with no backend, read by _network_problems). The docstring of admission_records.py (line 4) points at `nuisance_admission.admission_problems`, a module that does not exist under that name.

Why it was kept: This is a real defect in living text. The docstring says every list is empty and the file absent until the admission session, while evals/nuisance_admission.json is committed with 65 servers. It says the fields defaulting to None are those nuisance suite rule v3 or v4 added, which is false for AdmittedServer.backend: it dates from nuisance suite rule v2 (nuisance suite log, 2026-10-26), None means a server with no backend, and 52 of the 65 servers have it None. `unrecorded` never reads it. The docstring of admission_records.py names `nuisance_admission.admission_problems`, a module that no longer exists under that name. The absent-file path of load_admission itself stays: commands.committed_admission turns it into 'no server admitted'.

Change: Rewrite the admission.py docstring: 'The admission file of the nuisance suite: the servers the maintainer admits, one file of its own (`evals/nuisance_admission.json`), distinct from the census. The schema is filled by the two blind admission agents and the maintainer who settles their disagreements, on the model of the draw record of `evals/cve/detection/draw_record.py`. `exits` records each server the nuisance walk lists and the admission leaves out, with its reason. `admission_load.py` holds the load validation. A field defaulting to `None` is one nuisance suite rule v3 or v4 added and not yet recorded, which `unrecorded.py` refuses at run, except `backend`, which is `None` on a server with no backend.' In the admission_records.py docstring, write `admission_load.admission_problems`.

Files: `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/admission_records.py`

Tests: None: module docstrings reach neither model_json_schema nor a fingerprint (neither file is fingerprinted or in a dossier closure).

Risks: This is a correction of false text, with no behavior change. fix 11.15 (another section) also edits this docstring to write 'the nuisance walk': the text above already does, so that fix has nothing left to do in admission.py.

#### Fix 10.5: `evals/cve/nuisance/admission/admission_records.py` `_duplicate_benign_calls` (naming, refactoring)

Problem: The name says the reverse of the check. The function deliberately tolerates duplicates (`if call not in calls[call.tool]` collapses identical calls across flaws) and reports a tool that has two or more DIFFERENT benign calls, as its message says ("different benign calls across the counted flaws"). The neighbouring check of the same shape of rule is correctly named _real_software_conflicts.

Why it was kept: The name says the reverse of the check. `if call not in calls[call.tool]` collapses identical calls, so duplicates are legal, and the function reports a tool with two or more different calls, as its message says. The neighbouring rule is already named _real_software_conflicts. It is private with one caller (record_problems), and no test or debt list names it.

Change: Rename `_duplicate_benign_calls` to `_conflicting_benign_calls` at its definition and in record_problems. The message does not change. plans/2026-11-03_rule-v3-v9-schema-and-vet.md cites the old name, so add a line to docs/glossary-log.md, in sorted position: `_duplicate_benign_calls` | `_conflicting_benign_calls` | rename | 2026-11-23.

Files: `evals/cve/nuisance/admission/admission_records.py`, `docs/glossary-log.md`

Tests: None. The existing test on differing benign calls pins the message.

#### Fix 10.6: `evals/cve/nuisance/admission/unrecorded.py` `refuse_unrecorded` (ubiquitous-language, refactoring)

Problem: unrecorded.py names its result `gaps` (lines 18, 19, 21, 26, 30, 31), a fourth, unlisted sense of a word the glossary already splits three ways, and the nearest one, coverage gap, is a report concept of the audit. The same sense spreads to vet_command._print_unrecorded, test_nuisance_unrecorded.py (`test_a_recorded_server_has_no_gap`, `test_no_refusal_without_a_gap`, the `gap` parameter) and test_nuisance_dossier_then.py.

Why it was kept: The glossary closes the senses of 'gap' (coverage gap, known gap, a gap a card check reports) and asks for the qualified form. Here `gaps` holds one line per server naming its unrecorded fields, a fourth sense, close to the coverage gap of an audit report. This is not the rejected mass rename pattern: the name does not keep a glossary sense, it is not serialized, and the change is limited to locals and three test names. No message contains the word.

Change: Rename the local to `unrecorded` in refuse_unrecorded and unrecorded_fields (unrecorded.py) and in vet_command._print_unrecorded (the module name is not bound there, so nothing is shadowed). In test_nuisance_unrecorded.py: test_a_recorded_server_has_no_gap becomes test_a_recorded_server_has_no_unrecorded_field, test_refusal_lists_the_gaps becomes test_refusal_lists_the_unrecorded_fields, test_no_refusal_without_a_gap becomes test_no_refusal_when_every_field_is_recorded, the local `gaps` becomes `unrecorded`, and the parametrized `gap` becomes `unrecorded_field`. In test_nuisance_dossier_then.py, `[gap]` becomes `[line]`.

Files: `evals/cve/nuisance/admission/unrecorded.py`, `evals/cve/nuisance/vet_command.py`, `tests/unit/nuisance/admission/test_nuisance_unrecorded.py`, `tests/unit/nuisance/admission/support/test_nuisance_dossier_then.py`

Tests: Test renames only, with the same assertions. test_run_nuisance_vet.py keeps pinning the vet's line.

Risks: `_print_unrecorded` stays, since the finding that would replace it is rejected.

#### Fix 10.7: `evals/cve/nuisance/admission/holdout_calibration_copies.py` `the source test of a holdout calibration copy` (missing-concept, refactoring)

Problem: Whether a fix check is a holdout calibration copy is spelled as the raw literal `source == "detection_holdout_calibration"` in four production modules: holdout_calibration_copies.py:36, unrecorded.py:73, re_admission_dossier.py:153, fix_check_command.py:208.

Why it was kept: The literal `source == "detection_holdout_calibration"` is written in four production modules (holdout_calibration_copies.py:36, unrecorded.py:73, re_admission_dossier.py:153, fix_check_command.py:208), and 'holdout calibration copy' is a glossary term. A property does not change the record: I checked that a subclass with this property has the same model_json_schema and the same model_fields as FixCheckRecord, so the dossier schemas, the golden of model inputs and test_fix_check_result_mirrors_the_admission_record_fields do not move. All four sites hold a FixCheckRecord, not the kit's FixCheckResult (_field_mismatches is typed with it). admission.py is not fingerprinted and is in no dossier closure.

Change: On FixCheckRecord in admission.py, add `@property def is_holdout_calibration_copy(self) -> bool: return self.source == "detection_holdout_calibration"`. Use it at the four sites: `if not check.is_holdout_calibration_copy or recorded is None` (holdout_calibration_copies.py), `check.is_holdout_calibration_copy and check.holdout_fingerprint is None` (unrecorded.py), `if flaw.fix_check.is_holdout_calibration_copy` (re_admission_dossier.py), `if record.is_holdout_calibration_copy` (fix_check_command.py). Leave `source == "fix_check"` in admission_records._fix_check_fingerprints, which names the other value of the closed Literal. Tests keep the literal: they build or filter on the serialized field.

Files: `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/holdout_calibration_copies.py`, `evals/cve/nuisance/admission/unrecorded.py`, `evals/cve/nuisance/admission/re_admission_dossier.py`, `evals/cve/nuisance/fix_check_command.py`

Tests: No test changes. Existing tests on stale copies, unrecorded fields, the re-admission dossier and fix_check_mismatches cover the four sites. The model-inputs golden must not move.

Risks: Use a plain @property, never computed_field, which would enter the JSON schema shipped by the dossiers and the dumped admission records.

#### Fix 10.8: `tests/unit/nuisance/support/test_nuisance_counting_given.py` `a_tool_whose_declared_function_is_effect` (naming, refactoring)

Problem: The builder's name asserts that the declared function is the effect, while its second positional argument can say the opposite: `a_tool_whose_declared_function_is_effect("probe", False)` at lines 65, 89 and 90 of test_nuisance_counting.py, and `("probe", None)` at line 75. `a_removed_tool_whose_declared_function_is_effect("query", False)` at line 107 has the same defect. This field decides what the fingerprinted counter counts, and these tests read as the reverse of their setup.

Why it was kept: The builder's name asserts the effect while its argument can say the opposite: `a_tool_whose_declared_function_is_effect("probe", False)` at lines 65, 89 and 90, `("probe", None)` at line 75, and `a_removed_tool_whose_declared_function_is_effect("query", False)` at line 107. These tests specify the rule the fingerprinted counter applies per tool, and they read as the reverse of their setup. Both builders are used only in test_nuisance_counting.py. The third builder, a_flaw_whose_declared_function_is_effect, always sets True, so its name is right and it stays.

Change: In test_nuisance_counting_given.py, rename to `a_tool_recording_declared_function(name, *, is_effect: bool | None)` and `a_removed_tool_recording_declared_function(name, *, is_effect: bool)`, with is_effect keyword-only, and update every call in test_nuisance_counting.py (`given.a_tool_recording_declared_function("probe", is_effect=False)`).

Files: `tests/unit/nuisance/support/test_nuisance_counting_given.py`, `tests/unit/nuisance/test_nuisance_counting.py`

Tests: Same tests and assertions, with the setup calls renamed. counting.py is not touched, and counter_fingerprint stays.

### 11. The nuisance walk and the commands

Order and interactions: fix 11.2 removes `MARK_REASONS`, so fix 11.3 only moves `standing_exit`, read as `server.standing_exit` in `addition_entries`, `run_population` and the new `gate_servers.py` of fix 7.2. Fix 11.15 rewrites message strings and comes last, so its pins change once.

Verifier's notes: Confirmed fixes of this section, in a workable order. 1. walk.py: fix 11.1, then fix 11.2 (`ServerMark` deleted), then fix 11.4 and fix 11.5. All touch `_mark`, `_walk` or `nuisance_population`, with no conflict. 2. fix 11.2 removes `MARK_REASONS`, so fix 11.3 only has `standing_exit` left to move, as a property of `AdmittedServer`. Do fix 11.2 first, or both in one step: after both, holdout_servers.py no longer imports admission_walk, and neither does gate_session.py. 3. admission_walk.py is touched by fix 11.2, fix 11.3 and fix 11.14, fix 11.4 and fix 11.15. Apply fix 11.15 (message strings) last, so its pins are updated once. 4. fix 11.7 carries fix 11.7, keeping the parser half only. fix 11.8 and fix 11.12 touch run_nuisance.py in different places from fix 11.7, and fix 11.2 changes only the type behind `_walk_line`. 5. tests/unit/support/nuisance_admissions.py is touched by fix 11.5 (docstring) and fix 11.6 (rename): same step. The rejection of a rejected finding keeps `nuisance_population`, `NuisanceServer`, `RunPopulation` and `run_population`, so the other sections can keep citing those names. Other sections on the same modules: - another section (fix 5.6, fix 5.6, fix 5.6, fix 5.6) wants a shared read of the run's servers in commands.py or holdout_servers.py, on the same blocks of vet and run. Do fix 11.7 and fix 11.4 first: that section then builds on the final `run_population` parameter and parser. - another section (fix 10.1) splits admission.py into schema and load checks. `standing_exit` stays with the schema, and commands.py must then import `load_admission` from the new module while `ADMISSION_PATH` stays in admission.py. fix 11.15 edits the admission.py docstring. Either order works, but the split moves `admission_walk` imports. - another section (fix 7.2) moves `gate_servers` and `outside_gate`, which read `standing_exit`. Whichever comes second must use `server.standing_exit`. That section and another section also edit gate_command.py, holdout_run_command.py and fix_check_command.py near the parsers (`NUISANCE_CONCURRENCY`). - another section edits test_run_nuisance_gate_given.py, also renamed by fix 11.6. - another section edits markdown.py, where fix 11.15 changes one docstring line. - another section edits test_run_nuisance_dossier.py and drives the `nuisance-dossier` parser, whose flags do not change. Fingerprints: no fix touches confinement.py, counter.py or counting.py, and nothing they import is renamed or moved. Check `nuisance_fixture_fingerprint` and `counter_fingerprint` around fix 11.3, the one fix on a module counting.py imports from.

#### Fix 11.1: `evals/cve/nuisance/admission/walk.py` `_met` (argument-count, refactoring)

Problem: _met takes 4 arguments because each caller computes the classifiers' reading of the criterion and passes it in. Those readings are the same knowledge written twice: _meets_draw_criteria uses any(criteria_met(c)[criterion]), while _may_count re-reads c.effect_in_tool_response and c.pinnable by hand. criteria_met maps EFFECT_IN_TOOL_RESPONSE and PINNABLE to exactly those fields (classification.py, _read_from_fields).

Why it was kept: True. `_met` takes 4 arguments and `_may_count` reads `c.effect_in_tool_response` and `c.pinnable` by hand while `_meets_draw_criteria` goes through `criteria_met`. `_read_from_fields` maps EFFECT_IN_TOOL_RESPONSE and PINNABLE to exactly those fields, and only MCP_SERVER is overridden by `criteria_met`. Checked on the committed census: 0 differences over 2,560 classifications. The cost is negligible (the whole listing builds in 0.035 s).

Change: In evals/cve/nuisance/admission/walk.py: `_met(flaw, walk_inputs, criterion)` returns the settlement's ruling when there is one, else `any(criteria_met(c)[criterion] for c in walk_inputs.classifications_by_flaw.get(flaw, []))`. `_meets_draw_criteria` becomes `all(_met(flaw, walk_inputs, criterion) for criterion in DRAW_ORDER_CRITERIA)`. `_may_count` becomes `_met(..., Criterion.EFFECT_IN_TOOL_RESPONSE) and _met(..., Criterion.PINNABLE) and _tools_reached(flaw, walk_inputs)`. `_tools_reached` takes two arguments and reads the classifications itself, keeping its comment and its rule that a False STDIO_TOOLS_CALL settlement does not override. Drop the now unused `Classification` import.

Files: `evals/cve/nuisance/admission/walk.py`

Tests: No test changes. tests/unit/nuisance/admission/test_nuisance_walk.py and tests/integration/committed/nuisance/admission/test_nuisance_walk_record_loads.py pin the behavior. The list of servers, marks and candidate flaws must be identical on the committed census and walk record.

Risks: Keep the STDIO_TOOLS_CALL exception out of `_met`: that criterion must not go through the shared reading, since `criteria_met` also requires the stdio transport and this suite counts a flaw whatever its transport.

#### Fix 11.2: `evals/cve/nuisance/admission/walk.py` `ServerMark` (duplication, printed tag, CHANGELOG)

Problem: ServerMark has two members that map one to one onto two ExitReason members through MARK_REASONS (admission_walk.py:22). The mark carries no information beyond the exit: holdout_servers.run_population and admission_walk._unlisted_exits only translate it back through that table, and every other reader only tests whether it is None. So the same two reasons exist under two enums, one of them spelled differently (EXCLUDED vs EXCLUDED_SERVER).

Why it was kept: True. `ServerMark` has two members mapped one to one onto two `ExitReason` members by `MARK_REASONS`. Its only readers test it against None, translate it through that table (`run_population`, `_unlisted_exits`), or print its value (`_walk_line`). `mark` is not serialized in any report, result or record. exits.py imports only pydantic, so walk.py gains no cycle, and walk.py is not shipped in a kit. This is one suite's same knowledge under two enums, not the rejected common table across two suites.

Change: Type `NuisanceServer.mark` as `ExitReason | None`. `_mark` returns `ExitReason.ACCEPTANCE_TARGET_SERVER` or `ExitReason.EXCLUDED_SERVER`, acceptance still first. Delete `ServerMark`, the `StrEnum` import of walk.py and `MARK_REASONS`. `run_population` builds `ServerExit(package, mark)`, and `_unlisted_exits` reads `EXIT_REASON_TEXTS[mark]`. Keep the field name `mark`, which CLAUDE.md and the docstrings use. Add a glossary-log row: `ServerMark` (the nuisance walk's mark on a server) -> `ExitReason` (`mark` holds the exit the nuisance walk derives), rename, 2026-11-23, since plans and log line 19 cite it. Add a CHANGELOG line for the printed tag.

Files: `evals/cve/nuisance/admission/walk.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/holdout_servers.py`, `tests/unit/nuisance/admission/test_nuisance_walk.py`, `tests/unit/nuisance/test_nuisance_holdout_servers.py`, `tests/unit/nuisance/support/test_nuisance_holdout_servers_given.py`, `docs/glossary-log.md`, `CHANGELOG.md`

Tests: Test first: the tests replace `ServerMark.EXCLUDED` with `ExitReason.EXCLUDED_SERVER` and `ServerMark.ACCEPTANCE_TARGET_SERVER` with `ExitReason.ACCEPTANCE_TARGET_SERVER`, and test_an_excluded_server_is_marked_excluded goes red (`excluded` is not `excluded_server`) until `_mark` returns the exit. Exits, audited servers and pending servers stay identical on the committed admission (test_nuisance_admission_loads.py).

Risks: One visible change: the `walk` line's tag reads `[excluded_server]` where it read `[excluded]`. No test or doc pins it, and no server of the committed walk carries a mark today (all 120 are unmarked), so the output on the committed inputs does not change. The retired-word pattern `ServerMark\.ACCEPTANCE\b` stays harmless.

#### Fix 11.3: `evals/cve/nuisance/admission/admission_walk.py` `standing_exit` (other, refactoring)

Problem: admission_walk.py is, per its docstring, the admission's load check against the nuisance walk. It also holds two pieces of exit knowledge used elsewhere: standing_exit (imported by holdout_servers.py and gate/gate_session.py) and MARK_REASONS (imported by holdout_servers.py). The gate session and the nuisance holdout run's population thus depend on a load-validation module to learn which exit a server's own record sets, while evals/cve/nuisance/exits.py exists for the exits of the rule.

Why it was kept: True for `standing_exit`: holdout_servers.py and gate/gate_session.py import the admission's load-check module only to learn which exit a server's own record sets. The fact depends only on two fields of `AdmittedServer`, so a property on the model is smaller than the finder's move to exits.py, which needs a TYPE_CHECKING import. A plain property is no pydantic field, so `model_dump`, the admission file and the fingerprints do not see it. The `MARK_REASONS` half is removed outright by fix 11.2.

Change: Add to `AdmittedServer` in admission.py `@property def standing_exit(self) -> ExitReason | None`, with the same two checks in the same order, importing `ExitReason` beside `RecordedExit`. Delete `standing_exit` from admission_walk.py. Callers read `server.standing_exit` in `addition_entries`, `run_population` and `gate_servers` (the function of gate/gate_servers.py, since fix 7.2). gate_servers.py and holdout_servers.py drop their import of admission_walk.

Files: `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/holdout_servers.py`, `evals/cve/nuisance/gate/gate_servers.py`

Tests: No test changes, none imports `standing_exit`. Check nuisance_fixture_fingerprint for the 65 admitted servers and counter_fingerprint before and after: counting.py imports `AdmittedServer` from this module, and the class keeps its fields.

Risks: admission.py is not fingerprinted but counting.py (fingerprinted) imports from it: nothing it imports is renamed or moved. The another section (fix 10.1) splits the load checks out of admission.py and keeps `AdmittedServer` there, so the property is compatible in either order.

#### Fix 11.4: `evals/cve/nuisance/holdout_servers.py` `run_population` (ubiquitous-language, refactoring)

Problem: The parameter and locals named `acceptance` (holdout_servers.py:30, admission_walk.py:30/44, walk.py:102/170) hold `acceptance_target_servers()`, the servers of current AND dropped acceptance targets. walk.py has a second set with a near name, `nuisance_acceptance_servers()`, the current-only subset, and the gap between the two decides an exit (`ExitReason.ACCEPTANCE_TARGET_SERVER`) against gate membership. A bare `acceptance: set[str]` does not say which one a caller must pass, and both have the same type.

Why it was kept: True. A bare `acceptance: set[str]` holds the servers of current and dropped acceptance targets, while `nuisance_acceptance_servers()` is the current-only subset of the same type. Passing the wrong one would silently put a dropped target's server in the nuisance holdout layer. Every caller passes the argument positionally (vet_command.py, holdout_run_command.py, the tests), so the rename stays within three modules.

Change: Rename the parameter of `run_population` to `acceptance_target_servers`, and the local and parameter of `walk_problems` and `_reach_problems` in admission_walk.py likewise (that module calls the function through `nuisance_walk.`, so nothing is shadowed). In walk.py, where the function is in scope, rename the local of `nuisance_population` and the parameter of `_mark` to `target_servers`.

Files: `evals/cve/nuisance/holdout_servers.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/admission/walk.py`

Tests: No test changes, callers are positional.

#### Fix 11.5: `evals/cve/nuisance/admission/walk.py` `acceptance_target_servers` (ubiquitous-language, refactoring)

Problem: Three moved or retired words around the nuisance walk. The docstring says "Every benchmark flaw's server", the test is named `test_a_benchmark_flaw_marks_its_server_acceptance` (test_nuisance_walk.py:158), although the CVE benchmark now names both suites and these are the flaws of acceptance targets. In `_walk` (walk.py:146), the local `holdout` holds the flaws the detection walk reached, in the function that sets them apart from the nuisance walk's queue.

Also covers: `evals/cve/nuisance/admission/walk.py` (ubiquitous-language): 'benchmark flaw' is in neither the glossary nor its log, and it misleads: read with the glossary's 'CVE benchmark', it says any census flaw, while the function covers only ACCEPTANCE_TARGET_FLAWS, the flaws of the current and dropped acceptance targets. The word also appears in test_a_benchmark_flaw_marks_its_server_acceptance and in the docstring of nuisance_admissions.a_census_with_an_acceptance_server.

Why it was kept: True. `benchmark flaw` is in neither the glossary nor its log, and read with `CVE benchmark` it says any census flaw, while `acceptance_target_servers` covers only ACCEPTANCE_TARGET_FLAWS. The local `holdout` of `_walk` holds the flaws the detection walk reached, and the glossary log says the word moved. Carries fix 11.5.

Change: Docstring of `acceptance_target_servers`: `The server of every current or dropped acceptance target.` Rename `test_a_benchmark_flaw_marks_its_server_acceptance` to `test_a_current_target_flaw_marks_its_server`, since its flaw is A_CURRENT_TARGET_FLAW and a neighbouring test covers the dropped target. In the docstring of the census builder of tests/unit/support/nuisance_admissions.py, write `the acceptance target flaw ACCEPTANCE_FLAW`. In `_walk`, rename the local `holdout` to `detection_walk_flaws`.

Files: `evals/cve/nuisance/admission/walk.py`, `tests/unit/nuisance/admission/test_nuisance_walk.py`, `tests/unit/support/nuisance_admissions.py`

Tests: One test renamed, no assertion changes.

Risks: nuisance_admissions.py sits under tests/unit/support but this is a one-phrase docstring edit tied to this fix, so it stays in this area.

#### Fix 11.6: `tests/unit/support/nuisance_admissions.py` `a_census_with_an_acceptance_server` (ubiquitous-language, refactoring)

Problem: The builders `a_census_with_an_acceptance_server` and `admitting_the_acceptance_server` (15 references across five test files) use the bare form the glossary forbids. The tests that call them are about the nuisance acceptance server, and test_nuisance_admission_walk.py:22 names it in full right above a bare call.

Why it was kept: True, a direct break of the glossary's word order: `acceptance server` is always qualified by its suite. Both builders build the admitted server of a current acceptance target (A_CURRENT_TARGET_FLAW), which is the glossary's nuisance acceptance server. The file is imported by cve tests too, but every call of these two builders is in tests/unit/nuisance, so the fix belongs to this area rather than G.

Change: Rename `a_census_with_an_acceptance_server` to `a_census_with_a_nuisance_acceptance_server` and `admitting_the_acceptance_server` to `admitting_the_nuisance_acceptance_server`, in tests/unit/support/nuisance_admissions.py and at their calls. ACCEPTANCE_FLAW and ACCEPTANCE_PACKAGE stay.

Files: `tests/unit/support/nuisance_admissions.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `tests/unit/nuisance/support/test_nuisance_vet_given.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`, `tests/unit/nuisance/admission/test_nuisance_admission_walk.py`

Tests: Mechanical rename of test builders, same assertions. `ruff format` reflows long calls.

Risks: The another section touches test_run_nuisance_gate_given.py too: apply after or rebase the rename on it.

#### Fix 11.7: `evals/run_nuisance.py` `_parser` (duplication, refactoring)

Problem: The three options --census, --walk-record and --admission, with their types and default paths, are declared six times: walk and nuisance-dossier in run_nuisance.py, then fix_check_command.py:83, vet_command.py:109, holdout_run_command.py:86 and gate_command.py:91. CONTRIBUTING.md states it as one contract: each nuisance command that takes --census also takes --walk-record with the same default.

Also covers: `evals/cve/nuisance/commands.py` (missing-concept): The three committed inputs travel together. The same three add_argument lines with their defaults are repeated in six parsers (run_nuisance.py:82 and :89, holdout_run_command.py:86, vet_command.py:109, gate_command.py:91, fix_check_command.py:83), and the same two-line read under malformed_input_refused in five commands (run_nuisance.py:130 and :181, holdout_run_command.py:95, vet_command.py:115, gate_command.py:97, fix_check_command.py:89).

Why it was kept: True. The same three options with their defaults are declared in six parsers (walk and nuisance-dossier in run_nuisance.py, fix_check_command.py:83, vet_command.py:109, holdout_run_command.py:86, gate_command.py:91), and CONTRIBUTING.md states them as one contract. commands.py already imports the modules that define CENSUS_PATH and ADMISSION_PATH, so it adds no module to any import closure. No test reads these constants through a command module. The read half of fix 11.7 is not kept: the with-blocks differ on purpose (walk computes the listing inside, run and vet compute the partition and return inside, the first-admission dossier reads no admission), and what sits inside the block decides which ValueError is a refusal rather than a crash. A helper over the argparse Namespace would also read untyped keys.

Change: Add `add_committed_input_arguments(parser: argparse.ArgumentParser) -> None` to evals/cve/nuisance/commands.py, declaring `--census`, `--walk-record` and `--admission` with `type=Path` and the defaults CENSUS_PATH, WALK_RECORD_PATH and ADMISSION_PATH. Call it from the six parsers and delete their three lines. Remove the imports each module no longer uses: CENSUS_PATH, ADMISSION_PATH and WALK_RECORD_PATH, and `Path` in fix_check_command.py and vet_command.py. run_nuisance.py, holdout_run_command.py and gate_command.py keep `Path` for their other options. Update the commands.py docstring only if it stops being true.

Files: `evals/cve/nuisance/commands.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/fix_check_command.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/holdout_run_command.py`, `evals/cve/nuisance/gate/gate_command.py`

Tests: No test changes: tests/unit/nuisance/test_run_nuisance.py, test_nuisance_vet.py, test_run_nuisance_gate.py and test_nuisance_fix_check_command.py drive the parsers with these flags. Run pyrefly and ruff for the removed imports.

Risks: Flags and defaults are unchanged. Only the place of `--admission` in the `nuisance-dossier --help` listing moves. A kept import of a removed constant would be an implicit re-export, so grep the five modules after the change.

#### Fix 11.8: `evals/cve/nuisance/admission/walk_record.py` `WalkInputs.settlements_by_flaw` (dead-code, refactoring)

Problem: Two branches handle a census with no draw, and neither can run. In production WalkInputs is built only by load_walk_record, whose _contradiction_problems raises through _draw on a draw-less census. settlements_by_flaw is read only by walk._settlement, and every walk path goes through reached_identifiers first. run_nuisance._walk (line 135) also writes `governing_steps(draw) if draw else {}`, after nuisance_population has already raised on that case. That fallback is not even coherent: an empty map makes _walk_line raise KeyError on the first non-addition server.

Why it was kept: True, real dead code. In production `WalkInputs` is built only by `load_walk_record`, whose `_contradiction_problems` raises through `_draw` on a draw-less census. The only test that strips the draw calls `reached_identifiers` directly. In run_nuisance `_walk`, the `if draw else {}` runs after `nuisance_population` has already raised, and the `{}` fallback would make `_walk_line` raise KeyError on a non-addition server.

Change: Rename `_draw` to public `followed_draw(census: Census) -> DrawRecord` in walk_record.py, same message, repointing `_contradiction_problems` and `reached_identifiers`. `settlements_by_flaw` reads `followed_draw(self.census).settlements`. run_nuisance `_walk` reads `governing = governing_steps(followed_draw(walk_inputs.census))` and drops the local `draw`.

Files: `evals/cve/nuisance/admission/walk_record.py`, `evals/run_nuisance.py`

Tests: No test changes: test_reached_identifiers_raises_without_a_draw keeps its message match, and the draw-less refusal stays the same ValueError inside `malformed_input_refused`.

#### Fix 11.9: `tests/unit/nuisance/admission/test_nuisance_walk.py` `test_settlements_override_the_classifiers_per_criterion` (test-behavior-vs-implementation, refactoring)

Problem: One test chains three independent arrange/act/assert sequences, and its third contradicts its name: a False STDIO_TOOLS_CALL settlement does NOT override the classifiers and the flaw stays in. That exception is the deliberate rule commented in walk._tools_reached (the settlement may hold for the transport alone), and the spec hides it under a name saying the opposite. A failure in the first sequence also masks the other two.

Why it was kept: True. test_settlements_override_the_classifiers_per_criterion chains three arrange/act/assert sequences, and its third pins the opposite of its name: a False STDIO_TOOLS_CALL settlement does not take the flaw out, the deliberate exception commented in `_tools_reached`. Splitting makes that rule readable in the spec.

Change: Split into `test_a_pinnable_settlement_brings_a_flaw_in`, `test_a_pinnable_settlement_takes_a_flaw_out` and `test_a_false_stdio_tools_call_settlement_leaves_a_flaw_reached_through_tools`, each with its own census and its one assertion. The first keeps the precondition that the flaw is out before the settlement.

Files: `tests/unit/nuisance/admission/test_nuisance_walk.py`

Tests: Same three behaviors in three tests, nothing else changes.

#### Fix 11.10: `tests/unit/nuisance/admission/support/test_nuisance_walk_record_given.py` `paired` (given-then, refactoring)

Problem: paired(census, record) only calls WalkInputs(census=census, record=record), under a name that hides the domain type across 16 calls of the test file. The two aliases in the same given, an_empty_record = walks.an_empty_record (line 42) and written = walks.written_record (line 71), are indirections with no setup of their own.

Why it was kept: True. `paired` only calls `WalkInputs(census=census, record=record)`, and `an_empty_record` and `written` are bare aliases of `walks.an_empty_record` and `walks.written_record`. The testing standard says to inline a one-liner wrapper. The neighbouring test_nuisance_walk.py already imports `nuisance_walks as walks` directly.

Change: Delete `paired` and the two aliases from test_nuisance_walk_record_given.py, whose `a_record_settling` and `a_record_identifying` call `walks.an_empty_record()`. The test file imports `tests.unit.support.nuisance_walks as walks` and `WalkInputs`, and writes `WalkInputs(census=..., record=...)`, `walks.an_empty_record(...)` and `walks.written_record(...)`.

Files: `tests/unit/nuisance/admission/support/test_nuisance_walk_record_given.py`, `tests/unit/nuisance/admission/test_nuisance_walk_record.py`

Tests: Same assertions. `ruff format` reflows the longer lines.

#### Fix 11.11: `evals/cve/nuisance/admission/walk.py` `_walk` (ubiquitous-language, glossary entry)

Problem: 'queue' is a working term of the nuisance walk with a precise meaning: the draw-order flaws past the detection walk that meet the draw-order criteria once their settlements apply. It is used in walk._walk, in the tests and their support (nuisance_queue_walks, QUEUE_FLAW, test names), in CONTRIBUTING.md ('The queue is settled in the walk record') and in the Commands list of CLAUDE.md. docs/glossary.md and docs/glossary-log.md list no such word, and no other sense of it exists there.

Why it was kept: True. `queue` has one precise meaning in walk.py, in the test support (`nuisance_queue_walks`, QUEUE_FLAW, test names), in CONTRIBUTING.md (`The queue is settled in the walk record`, `each queue flaw`) and in the Commands list of CLAUDE.md, while the glossary and its log list no such word. The only other use is an ordinary comment on a provider's queue in evals/run_probe.py, not a domain sense. The new text matches none of the 95 retired-word patterns.

Change: Add to the nuisance suite section of docs/glossary.md: `**queue**: the draw-order flaws the detection walk has not reached, which the nuisance walk goes through after it, in draw order, skipping a flaw that fails a draw-order criterion once its settlements apply. Not: addition, the logged decision that sizes how many of their servers may enter.` No glossary-log line, since the word is neither renamed nor moved.

Files: `docs/glossary.md`

Tests: tests/integration/committed/project/test_glossary.py stays green.

#### Fix 11.12: `evals/run_nuisance.py` (comments-docstrings, refactoring)

Problem: The 15-line module docstring restates, subcommand by subcommand, what each does and needs (Docker, LLM key, what it rebuilds). That is the content of the Commands list, CONTRIBUTING.md and the parser's own help strings, so a third copy must follow every change of a subcommand. The counterpart entry point run_detection_holdout.py keeps a short statement of why the module exists.

Why it was kept: True. Lines 3 to 14 of the run_nuisance.py docstring restate, per subcommand, what the Commands list, CONTRIBUTING.md and the parser's help strings already say, so a third copy must follow each change. Nothing reads `__doc__`: the parser has its own description.

Change: Reduce the module docstring to its first sentence: `Nuisance-specific commands, kept out of run_census, run_detection and run_detection_holdout.`

Files: `evals/run_nuisance.py`

Tests: None.

#### Fix 11.13: `tests/unit/nuisance/test_run_nuisance.py` `test_run_on_a_stale_admission_exits_three_naming_it` (dead-code, refactoring)

Problem: The test requests the monkeypatch fixture and never uses it, which suggests an environment setup that does not exist. The neighbouring test does call monkeypatch.setenv for tracing.

Why it was kept: True. test_run_on_a_stale_admission_exits_three_naming_it requests `monkeypatch` and never uses it.

Change: Remove the `monkeypatch` parameter from that test.

Files: `tests/unit/nuisance/test_run_nuisance.py`

Tests: Same test, one parameter fewer.

#### Fix 11.14: `evals/cve/nuisance/admission/admission_walk.py` `_reach_problems` (ubiquitous-language, refactoring)

Problem: In _reach_problems (line 52) and addition_entries (line 72), the variable `reach` holds a NuisanceServer, the nuisance walk's entry for a package, read as reach.reaching_flaw, reach.in_addition and reach.mark. The noun has a precise, different meaning in the glossary and in the data (`Place.reaches`, reach tokens), so `reach.mark` reads as a property of a primitive.

Why it was kept: True. In `_reach_problems` and `addition_entries` the local `reach` holds a `NuisanceServer`, a walk row, a sense the glossary does not give the noun (a flaw's primitive, a walk reaching a flaw, or the reached status). The rename is private, and walk.py's own `_Reach` is a reach of the nuisance walk and stays.

Change: Rename the local `reach` to `walked_server` in `_reach_problems` and `addition_entries`.

Files: `evals/cve/nuisance/admission/admission_walk.py`

Tests: None.

#### Fix 11.15: `evals/cve/nuisance/admission/admission_walk.py` `_reach_problems` (ubiquitous-language, refusal text, CHANGELOG)

Problem: The area writes bare "the walk" 26 times, including what a maintainer reads when an admission is refused (`not reached by the walk`, `recorded exit for a server the walk does not reach`, `which only the walk derives`) and the header of the `walk` subcommand (run_nuisance.py:137, `servers reached by the walk:`). These modules handle both walks: walk._walk joins the detection walk's flaws and the nuisance queue, and its error message does say "the detection walk", so the bare form is ambiguous exactly here.

Why it was kept: True. The glossary says the word walk is always qualified, and these modules handle both walks: `_walk` joins the detection walk's flaws and the queue. Bare `the walk` appears in 7 refusal or printed messages and in docstrings and comments of walk_record.py, admission_walk.py, admission.py, holdout_servers.py and markdown.py. `the walk record`, `walk.py`, the `walk` subcommand and `walk_inputs` are names and stay. CONTRIBUTING.md paraphrases the same refusals with the bare word: its line 63 means the nuisance walk, while its line 61 (`a flaw the walk left out`) means the detection walk, so the two lines must not be replaced blindly.

Change: Write `the nuisance walk` in the messages of admission_walk.py (`not reached by`, `is not the nuisance walk's`, the three `recorded exit` messages, `which only the nuisance walk derives`), in the header of run_nuisance `_walk` (`servers reached by the nuisance walk:`), and in the docstrings and comments of walk_record.py (lines 5, 47, 85), admission_walk.py, admission.py:6, holdout_servers.py:32 and markdown.py:96. In the Commands list of CLAUDE.md, write `which it checks against the nuisance walk` (line 47) and `from the nuisance walk's marks` (line 50). In CONTRIBUTING.md, write `the detection walk` on line 61 and `the nuisance walk` for the nine mentions of line 63, the sentence that opens `The walk reads` included. Update the four test pins. CHANGELOG line under Changed: the refusals of the nuisance admission and the `walk` header name the nuisance walk where they read "the walk".

Files: `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/admission/walk_record.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/holdout_servers.py`, `evals/cve/nuisance/markdown.py`, `evals/run_nuisance.py`, `tests/unit/nuisance/admission/test_nuisance_admission_walk.py`, `tests/unit/nuisance/admission/support/test_nuisance_admission_walk_given.py`, `tests/unit/nuisance/test_run_nuisance.py`, `CONTRIBUTING.md`, `CHANGELOG.md`, `CLAUDE.md`

Tests: Test first: the pins change at test_nuisance_admission_walk.py:19, :72, :134 and test_run_nuisance.py:32 and go red before the messages move, plus a docstring of the admission walk given. Only strings change, and the committed admission still loads.

Risks: User-facing text of refusals, hence the CHANGELOG line. Reflow the f-strings past 100 columns without changing their bytes beyond the added word. docs/evals.md's `the walk` is about the draw and stays out of this fix.

### 12. Admission and re-admission dossiers

Order and interactions: fix 12.1 precedes fix 12.2, which moves the table it creates. Fix 12.3 comes before fix 12.4. The docstring on `rule v3` of the unit test is fix 12.8's alone. Nothing here moves a test to `tests/integration/committed/`: the short unit loop keeps its committed-admission tests, as `plans/2026-11-22_faster-unit-short-loop.md` decided.

Verifier's notes: Order inside the section: (1) fix 12.1 then fix 12.2, in that order or as one commit, since the table `KIT_BACKEND_PARAGRAPHS` moves to `admission_docs.py`. Check byte identity with a `diff -r` of three written dossiers (first admission, first admission with `--backend doris`, re-admission) before and after. (2) The tests of tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py: fix 12.4, fix 12.5, fix 12.3, fix 12.6 and the renames of fix 12.7 and fix 12.8 touch the same file and its given, with no conflict. fix 12.3 removes one caller of `_copying` and fix 12.4 folds what remains into `a_server_copying(*flaw_ids)`, so apply fix 12.3 before fix 12.4. (3) fix 12.10 is independent and empties the committed `support/` package. Nothing in this section moves a test to tests/integration/committed: the moves proposed by fix 12.4, fix 12.4 and fix 12.4 contradict plans/2026-11-22_faster-unit-short-loop.md. docs/glossary.md is touched by fix 12.8 and fix 12.11, docs/glossary-log.md by fix 12.7 and fix 12.8. No fingerprinted module changes, and no module of a kit closure changes. Other sections: another section (fix 1.4) rewrites the same docstring 'rule v3' as fix 12.8, apply it once. another section touches re_admission_dossier.py (fix 10.7 adds `is_holdout_calibration_copy` in the very function fix 12.7 renames, textual overlap only, and the literal in `tests/unit/support/committed_nuisance_admission.py` may follow), test_nuisance_dossier_then.py (fix 10.6) and moves load_admission to admission_load.py (fix 10.1, which repoints committed_nuisance_admission.py). `admission.py` stays the home of `AdmittedServer` and `FlawRecord` that `admission_docs` imports. another section and another section touch admission.py and tests/unit/support/nuisance_admissions.py, which this section reads without changing. a finding deferred to another area is deferred to the census and planting area: when C moves the grammar text out of evals/run_census.py, it repoints `admission_docs.py` if fix 12.2 has landed.

#### Fix 12.1: `evals/cve/nuisance/admission/dossier.py` `_BACKENDS` (comments-docstrings, false comment corrected)

Problem: The comment justifies the set with a false reason: "so the dossier stays free of the auditor-coupled registry". `dossier.py` imports `admission.py`, which imports `backend_registry` at line 25, and `re_admission_docs`, which imports `BACKENDS`. Importing `evals.cve.nuisance.admission.dossier` does load the registry (checked in a fresh interpreter). The real reason is different: only Doris has a kit builder (`evals/cve/kit/backends.py`), so the accepted set is narrower than the registry. That fact is also spread over three places: `_BACKENDS`, `if backend == "doris"` in `write_dossier`, and `if backend == "doris"` in `_fixture_format`.

Why it was kept: The comment is false. In a fresh interpreter, importing `evals.cve.nuisance.admission.dossier` loads `evals.cve.nuisance.backend_registry` (through `admission.py` and `re_admission_docs`). The real reason for the narrower set is that only Doris has a builder in `evals/cve/kit/backends.py`. That fact is written three times: `_BACKENDS`, `backend == "doris"` in `write_dossier`, `backend == "doris"` in `_fixture_format`. A real defect of a comment, fixed without changing behavior.

Change: Replace `_BACKENDS` with `KIT_BACKEND_PARAGRAPHS: dict[str, str] = {"doris": _DORIS_BUILDER_PARAGRAPH}`, declared right after the paragraph, under the comment `# The backends whose builder the kit ships (evals/cve/kit/backends.py).` `_refuse_unknown_backend` reads its keys (`sorted(KIT_BACKEND_PARAGRAPHS)`, same message). `write_dossier` copies `evals.cve.kit.backends` on `backend is not None`, reached only after the refusal. The fixture format takes `KIT_BACKEND_PARAGRAPHS[backend] if backend is not None else ""`. With fix 12.2 the table lives in `admission_docs.py`, which is why it has a public name.

Files: `evals/cve/nuisance/admission/dossier.py`

Tests: No test changes. `test_an_unknown_backend_is_refused`, `test_a_backend_dossier_imports_closed` and `test_nuisance_dossier_with_an_unknown_backend_exits_three` pin the refusal and the copy. Verify with a `diff -r` of a dossier written with and without `--backend doris` before and after.

Risks: The refusal message and the written files stay byte-identical (`--backend` is documented).

#### Fix 12.2: `evals/cve/nuisance/admission/re_admission_docs.py` `admission_confinement_text` (naming, refactoring)

Problem: The first-admission dossier takes its `confinement.md` from a module named `re_admission_docs`, so the base flow depends on its extension by name, while `re_admission_dossier` depends on `dossier` in the opposite direction. Meanwhile `dossier.py` is 315 lines, about 210 of them the first admission's document templates, so assembly and text are mixed in the first-admission module while the re-admission side already separates them.

Why it was kept: Verified. `dossier.py` is 315 lines, about 210 of them first-admission templates, and fix 12.1 does not bring it under the bar, so the barely-over-300 precedent does not apply. The first admission takes its `confinement.md` from a module named `re_admission_docs`, while `re_admission_dossier` depends on `dossier`: the base flow names its extension. Re-admission already keeps text and assembly apart, so the split follows an existing shape. Neither module enters a kit closure: the kit roots are `evals.cve.kit.*`, and `dossier.py` and the docs modules are the assemblers.

Change: Create `evals/cve/nuisance/admission/admission_docs.py` (pure text renderers), moved unchanged apart from the names that now cross a module (`_ADMISSION_GRAMMAR_CLASSES` to `ADMISSION_GRAMMAR_CLASSES`, `_fixture_format` to `fixture_format`, `_readme` to `admission_readme`, `_IMAGE` of `re_admission_docs.py` to `IMAGE_PLACEHOLDER`): `ADMISSION_GRAMMAR_CLASSES` (with its comment), `_FIXTURE_FORMAT`, `_DORIS_BUILDER_PARAGRAPH`, `KIT_BACKEND_PARAGRAPHS`, `_README`, `fixture_format(backend)`, `admission_readme()`, `admission_confinement_text()`, `_ADMISSION_CONFINEMENT`, `_paired`, plus `confinement_options()` (the joined markdown list of options that `confinement_text` and `admission_confinement_text` each build today from `_paired(confinement_args())`) and `IMAGE_PLACEHOLDER = "<image>"`. `re_admission_docs.py` keeps `_NAME`, `confinement_text`, `re_admission_readme`, their templates and helpers, and imports `confinement_options` and `IMAGE_PLACEHOLDER` from it (dependency one way). `dossier.py` keeps `NUISANCE_SUITE_RULE`, `write_dossier` and the writing, calling these renderers. `admission_docs` imports `GRAMMAR_CLASS_DEFINITIONS` from `evals.run_census` until the census and planting area moves it (a finding deferred to another area).

Files: `evals/cve/nuisance/admission/admission_docs.py`, `evals/cve/nuisance/admission/dossier.py`, `evals/cve/nuisance/admission/re_admission_docs.py`, `tests/unit/nuisance/admission/test_nuisance_dossier.py`

Tests: `test_nuisance_dossier.py` imports `admission_confinement_text` from `admission_docs`. Verify byte identity with a `diff -r` of a first-admission dossier (without a backend and with `--backend doris`) and of a re-admission dossier, before and after. `tests/unit/cve/test_kit_isolation.py` and `test_cve_dossier_closure.py` stay green.

Risks: Kit closure unchanged (to be confirmed by the isolation tests). No fingerprinted module touched: `single_container_run_args` and `confinement_args` are only imported. `_paired` must not be confused with the unrelated `_paired` of `evals/judge/session.py`.

#### Fix 12.3: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` `test_a_copied_flaw_no_target_carries_is_refused` (duplication, refactoring)

Problem: The inner function `calibrated_on_an_unknown_target` is a line-for-line copy of `_copying` in the given (same `model_copy` of `source` to `detection_holdout_calibration`, same update of `flaw`), and it adds seven lines of setup to a test whose point is one refusal.

Why it was kept: True: the inner `calibrated_on_an_unknown_target` repeats `_copying`. A simpler setup than the proposed helper exists. `mutations.a_server_with_a_holdout_calibration_copy_at` already builds a server whose first flaw is a holdout calibration copy, and with an empty resolution any copied flaw is unknown. Run: `holdout_target_references(a_server_with_a_holdout_calibration_copy_at(None), {})` raises `Refused`.

Change: `test_a_copied_flaw_no_target_carries_is_refused` becomes `server = mutations.a_server_with_a_holdout_calibration_copy_at(None)`, then `with pytest.raises(Refused): holdout_target_references(server, {})`. Remove the inner function and the `FlawRecord` import. No new helper for this test.

Files: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`

Tests: Same refusal, with no read of the committed census.

#### Fix 12.4: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` `SHAPES` (test-placement, refactoring)

Problem: The core of this unit file writes real dossiers from servers picked with `next(...)` in the committed admission, then copies their committed fix-check modules, Dockerfiles, holdout fixtures and cards. Removing or editing an admitted server, a Dockerfile or a card turns these tests red, or raises StopIteration in a given, with no code change. Affected: `test_the_dossier_imports_nothing_from_the_auditor`, `test_every_admitted_server_has_a_clean_closure` (a sweep of the committed record), `test_a_fix_check_dossier_carries_its_record_rule_dockerfiles_and_fix_checks`, `test_a_backend_dossier_carries_its_backend_alone`, `test_a_holdout_copy_dossier_carries_its_holdout_reference_as_text`, `test_a_detection_holdout_server_with_its_own_fix_check_carries_its_reference_and_card`, `test_a_copy_on_a_drawn_target_and_its_sibling_resolve_to_one_target`, plus `test_a_detection_holdout_server_dossier_carries_the_holdout_reference_of_each_target` in test_nuisance_dossier.py and `test_a_re_admission_dossier_of_an_admitted_server_exits_zero` in test_run_nuisance_dossier.py. The committed test file for this area already exists and already imports this unit given.

Also covers: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` (test-placement): This unit file runs on the committed admission, census, walk record and holdout targets. test_every_admitted_server_has_a_clean_closure (line 77) sweeps all admitted servers and is the slowest test of the file (2.5 s). The SHAPES tests and the backend, fix-check and holdout calibration copy dossier tests take the first committed server of a shape with next(...). test_a_copy_on_a_drawn_target_and_its_sibling_resolve_to_one_target (line 226) needs a sibling in the committed cards. test_a_detection_holdout_server_dossier_carries_the_holdout_reference_of_each_target (test_nuisance_dossier.py:129) does the same. An edit of a record can turn them red. In the other direction, the committed test file imports the unit given of the same stem (`re_admission.the_copy_resolution`), a cross-level dependency the one-pair sweep cannot see because the stems match.

Also covers: `tests/unit/nuisance/test_run_nuisance_dossier.py` (test-placement): The three re-admission command tests call a_committed_server_with_fix_checks() and run on the default committed census and walk record. Two of them need nothing committed: the --backend refusal fires before any file is read and uses the server only as a name, and the missing-admission test only needs a readable census and walk record. The third, test_a_re_admission_dossier_of_an_admitted_server_exits_zero, really does write a dossier from the committed admission: a synthetic admission cannot replace it, since its service has no Dockerfile and filesystem-patched is refused as an acceptance service.

Why it was kept: Half true, and the fix is narrowed. The proposed move of the dossier-writing tests is refused. plans/2026-11-22_faster-unit-short-loop.md decided that a sweep of a committed registry which checks code stays in tests/unit, naming the import-boundary scans (no kit or dossier imports `mcp_auditor`, the clean closure of every admitted server), so that a broken import shows in the short loop. CLAUDE.md states the same rule. That plan moved two tests of this file and kept the others on purpose. The other writer tests follow the record they read (`record == server`, the services the server names): editing a record does not turn them red, and a break of `write_re_admission_dossier` does. Moved, the re-admission writer would have no test left in the short loop. A synthetic server cannot replace them, since the writer copies real Dockerfiles and fix-check modules. `test_a_re_admission_dossier_of_an_admitted_server_exits_zero` stays for the same reason. What holds: three tests depend on committed data they do not need. The two command refusals use the committed server only as a name or read the default census and walk record, and the sibling test depends on a sibling existing in the committed cards, raising StopIteration otherwise. All three were run on fictional inputs: the two refusals exit 3 and write nothing, and the sibling case resolves to its one drawn target.

Change: In tests/unit/nuisance/test_run_nuisance_dossier.py: `test_a_re_admission_dossier_with_a_backend_exits_three` passes the literal `npm:@acme/files`. `test_a_re_admission_dossier_without_an_admission_exits_three` passes that literal and `*walks.committed_census_arguments(tmp_path, censuses.written(tmp_path, admissions.a_census()))`. `a_committed_server_with_fix_checks` stays imported for the exit-zero test. In the unit re-admission test, `test_a_copy_on_a_drawn_target_and_its_sibling_resolve_to_one_target` takes `drawn = HOLDOUT_TARGETS[0].flaw_id`, `sibling = "CVE-2099-0002"`, `server = given.a_server_copying(drawn, sibling)` and calls the function with the resolution `{drawn: drawn, sibling: drawn}`. In its given, `a_server_copying(*flaw_ids)` replaces `a_server_copying_a_drawn_target_and_its_sibling` and absorbs `_copying`, and `a_drawn_target_and_its_sibling` is deleted. No test moves to tests/integration/committed.

Files: `tests/unit/nuisance/test_run_nuisance_dossier.py`, `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/unit/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`

Tests: Same test names and same assertions, on fictional inputs. Short loop on the two files, then the full short loop.

Risks: Do not move the writer or import-boundary tests: that would reverse a decision of plans/2026-11-22_faster-unit-short-loop.md and take the kit isolation of a re-admission dossier out of the short loop.

#### Fix 12.5: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` `test_a_holdout_copy_dossier_carries_its_holdout_reference_as_text` (duplication, refactoring)

Problem: The loop body retypes `it_carries_the_holdout_reference_of` from `holdout_reference_checks.py`: same fixture lookup, same `startswith` on the fixture text, same `def <builder>(` check, same absence of `.py` under `reference/`. The next test in the file calls the helper for the same assertions. Only the check of the Dockerfiles under `evals/docker/` is specific to this test.

Why it was kept: True. The loop retypes the fixture lookup, the `startswith`, the `def <builder>(` check and the `.py` absence of `it_carries_the_holdout_reference_of`. Run on the committed server with a holdout calibration copy, the helper passes, so it can replace them, and it also checks the card and `reference/docker`, which the loop does not. Only the Dockerfiles under `evals/docker/` are specific to this test.

Change: In the loop of `test_a_holdout_copy_dossier_carries_its_holdout_reference_as_text`, call `it_carries_the_holdout_reference_of(out, target)` and keep only the assertion on `out / "evals" / "docker"`. Drop the final `rglob` assertion (the helper makes it) and the `holdout_fixture_file` import.

Files: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`

Tests: Same test, slightly stronger (card and `reference/docker` now checked). Verified on the committed server.

#### Fix 12.6: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` `test_the_readme_says_a_per_launch_backend_is_stood_for_the_launch_alone` (test-fragility, refactoring)

Problem: The test asserts that a full sentence of the static `_README` template is in the rendered text. No input reaches that sentence and no branch selects it, so the only change that can turn the test red is a rewording of the sentence. The neighbouring README tests differ: they check values computed from the server, the registry or the kit's entry points.

Why it was kept: True that no input reaches the sentence: the test compares a literal to the same literal of the static template, so only a rewording or a deletion of that prose can turn it red. The finder's claim that the confinement test covers it is inexact (that test reads `confinement.md`, not the README), but the conclusion holds: a prose sentence of a static template needs no pin. Its neighbours differ, since they check computed values, entry points or the shared-backend pattern against the registry.

Change: Delete `test_the_readme_says_a_per_launch_backend_is_stood_for_the_launch_alone`.

Files: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`

Tests: One change-detector test fewer. The per-launch branch of `confinement.md` stays pinned by `test_the_confinement_of_a_server_on_a_per_launch_backend_points_at_its_launch`.

Risks: The sentence of the README is no longer pinned, which is the intent.

#### Fix 12.7: `evals/cve/nuisance/admission/re_admission_dossier.py` `holdout_target_references` (naming, glossary log)

Problem: `holdout_target_references` returns `list[Target]`, the drawn targets the server's holdout calibration copies resolve to. It holds no reference. The name collides with `write_holdout_target_references` and the module `holdout_target_reference`, where a reference is the written tree under `reference/`. A reader expects the first to feed the second, but `write_dossier` feeds it from `holdout_targets_among`. `_detection_holdout_targets` then concatenates both selections, and only the signature tells them apart.

Why it was kept: True. `holdout_target_references` returns `list[Target]`, the drawn targets the holdout calibration copies of a server resolve to, while `write_holdout_target_references` and the module `holdout_target_reference` use reference for the tree written under `reference/`. The two are not connected: `write_dossier` feeds the writer from `holdout_targets_among`. The name suggests a pipeline that does not exist. The candidate name passes the retired-word patterns (checked).

Change: Rename to `copied_holdout_targets(server, resolution)`: the definition and `_detection_holdout_targets` in re_admission_dossier.py, the unit test, its given and the committed test. The name is cited by two plans (2026-11-11_vocabulary-alignment, 2026-11-21_tests-review-since-new-tests-review), so add a line to docs/glossary-log.md, in sorted position: `holdout_target_references` (the function of `re_admission_dossier.py`, while `write_holdout_target_references` keeps its name) | `copied_holdout_targets` | rename | 2026-11-23.

Files: `evals/cve/nuisance/admission/re_admission_dossier.py`, `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/unit/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, `tests/integration/committed/nuisance/admission/test_nuisance_re_admission_dossier.py`, `docs/glossary-log.md`

Tests: Rename only. Short loop, committed tests, pyrefly.

Risks: Glossary log line required. Same function as another section fix 10.7 (the `is_holdout_calibration_copy` property), a textual overlap only.

#### Fix 12.8: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` (ubiquitous-language, glossary log)

Problem: Four departures in the slice. The module docstring writes "rule v3's fields". `test_the_fixture_format_names_every_fix_check_target_field` (test_nuisance_dossier.py:210) calls the fields of a `FixCheckFixture` "target" fields, while a fix check has no target. `a_committed_server_with_a_holdout_copy` and `test_a_holdout_copy_dossier_...` shorten the glossary's "holdout calibration copy". "Holdout reference", the term that `holdout_target_reference.py`, `write_holdout_target_references` and `it_carries_the_holdout_reference_of` are built on, is in neither the glossary nor its log.

Why it was kept: Verified against the glossary. "rule v3" alone is forbidden by the entry **rule vN**. A fix check has no target, so `..._fix_check_target_field` misuses a detection-suite word. "holdout copy" shortens **holdout calibration copy**. "holdout reference" names the module `holdout_target_reference`, the helper and a line of docs/nuisance-suite-log.md, and is in neither the glossary nor its log. The new names pass the retired-word patterns (checked, including the `holdout_calibration(?!_cop)` pattern).

Change: Docstring of the unit test: "nuisance suite rule v3's fields". Rename `test_the_fixture_format_names_every_fix_check_target_field` to `test_the_fixture_format_names_every_fix_check_fixture_field`, `a_committed_server_with_a_holdout_copy` to `a_committed_server_with_a_holdout_calibration_copy`, `test_a_holdout_copy_dossier_carries_its_holdout_reference_as_text` to `test_a_holdout_calibration_copy_dossier_carries_its_holdout_target_reference_as_text`. The given is cited by plans/2026-11-05_new-tests-review.md: add its line to docs/glossary-log.md. Write the term in full everywhere it is live: `holdout_reference_checks.py` becomes `holdout_target_reference_checks.py`, `it_carries_the_holdout_reference_of` becomes `it_carries_the_holdout_target_reference_of`, `test_a_detection_holdout_server_dossier_carries_the_holdout_reference_of_each_target` becomes `test_a_detection_holdout_server_dossier_carries_the_holdout_target_reference_of_each_target`, and the docstrings of `dossier.py` and `holdout_target_reference.py` write "holdout target reference". The dated line of docs/nuisance-suite-log.md stays. Add to docs/glossary-log.md: `holdout reference` | `holdout target reference` | rename | 2026-11-23. Add to docs/glossary.md, after **holdout calibration copy**: "**holdout target reference**: what the kit of an admission carries for each census flaw of its server that is a holdout target: the target's holdout fixture and builder as text, its Dockerfiles and its card. The admission agents may start from it, and nothing in it imports or runs. Code: `reference/` in the kit, `write_holdout_target_references`."

Files: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/unit/nuisance/admission/test_nuisance_dossier.py`, `tests/unit/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, `docs/glossary.md`, `docs/glossary-log.md`, `evals/cve/nuisance/admission/dossier.py`, `evals/cve/nuisance/admission/holdout_target_reference.py`, `tests/unit/nuisance/admission/support/holdout_reference_checks.py`

Tests: Test names and the ids of `SHAPES` change, not their assertions. The committed glossary and retired-word tests must stay green.

Risks: The docstring is also the object of fix 1.4 in the another section, with the same wording: apply it once.

#### Fix 12.9: `evals/cve/nuisance/admission/dossier.py` `_README` (duplication, refactoring)

Problem: The two `docker build` commands of the sentinel and stand-in images and the `mcp>=1.18.0,<2` requirement are typed in both this README and the calibration kit's (`calibration_dossier.py:196,205-206`), although the image tags already exist as `SENTINEL_IMAGE` and `STAND_IN_IMAGE` in `planting_base.py`, and `kit_dossier.py` is the module that ships those two Dockerfiles to every kit. The copies are held together only by `test_both_readmes_build_the_stand_in_image_beside_the_sentinel` and `test_both_readmes_state_the_mcp_specifier_of_the_project`, which make a nuisance test file write and read a detection kit.

Why it was kept: The shared-constant fix is refused, a narrow defect remains. The two READMEs do carry the same two `docker build` lines and the MCP bound, but the bound is already pinned to pyproject.toml by `test_both_readmes_state_the_mcp_specifier_of_the_project`, it is also written in CLAUDE.md, and holes in two prose templates through a new export of kit_dossier would save little for two stable lines. The real gap: `test_both_readmes_build_the_stand_in_image_beside_the_sentinel` compares the READMEs to a typed literal. A change of `STAND_IN_IMAGE` or `SENTINEL_IMAGE` in planting_base.py would leave both READMEs wrong and the test green, and despite its name the test never checks the sentinel line.

Change: In `test_both_readmes_build_the_stand_in_image_beside_the_sentinel`, build the two expected commands from the constants: `f"docker build -t {SENTINEL_IMAGE} -f docker/Dockerfile.sentinel docker"` and `f"docker build -t {STAND_IN_IMAGE} -f docker/Dockerfile.stand-in docker"`, imported from `evals.cve.planting_base`, and assert both in both READMEs. kit_dossier.py, calibration_dossier.py and the templates do not change.

Files: `tests/unit/nuisance/admission/test_nuisance_dossier.py`

Tests: The test stays green today (the constants equal the typed tags) and goes red on a change of either image tag.

Risks: planting_base.py is fingerprinted: it is only read by a test, not changed.

#### Fix 12.10: `tests/integration/committed/nuisance/admission/test_nuisance_re_admission_dossier.py` `test_no_committed_server_carries_a_shared_helper_of_the_fix_check_package` (test-behavior-vs-implementation, refactoring)

Problem: The test cannot fail. `the_fix_check_package_helpers` returns the modules with no `FIXTURES` attribute. `fix_check_modules` reads `getattr(module, "FIXTURES", ())` and keeps a module only when `any(fixture.flaw in flaws ...)`, so a module with no `FIXTURES` iterates an empty tuple and is never returned. `helpers.isdisjoint(fix_check_modules(server))` is therefore true by construction, for any admission and any package content.

Why it was kept: Verified by reading and by execution. `the_fix_check_package_helpers` returns the modules with no `FIXTURES` (4 of the 58 modules of the package). `fix_check_modules` reads `getattr(module, "FIXTURES", ())` and keeps a module only when one of its fixtures names a flaw of the server, so a module without `FIXTURES` can never be returned. The disjointness holds by construction for any admission. The test cannot go red.

Change: Delete `test_no_committed_server_carries_a_shared_helper_of_the_fix_check_package`, the `fix_check_modules` import and the `given` import of the committed test file. Delete `tests/integration/committed/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, whose only function is `the_fix_check_package_helpers`, and the `support/__init__.py` left alone beside it (no other module imports that package, grep checked). `test_every_copied_flaw_resolves_to_one_target_and_one_fixture` stays, with its import of the unit given, a cross-level import plans/2026-11-22_faster-unit-short-loop.md accepts for a helper both sides use.

Files: `tests/integration/committed/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/integration/committed/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, `tests/integration/committed/nuisance/admission/support/__init__.py`

Tests: One test that could not fail disappears. `uv run pytest tests/integration/committed -n auto` stays green.

#### Fix 12.11: `evals/cve/nuisance/admission/dossier.py` `write_dossier` (ubiquitous-language, glossary entry)

Problem: "Dossier" appears 145 times in the area and in the commands `nuisance-dossier` and `calibration-dossier`, but neither docs/glossary.md nor the log lists it. The glossary's term for this tree is **kit**, and the two are used for one thing: dossier.py's own README calls its output "A self-contained kit", and its docstring calls it the counterpart of `calibration_dossier.write_kit`. The word also has narrower senses (`advisory_dossier`, one advisory's file inside a kit).

Why it was kept: True: `dossier` names user-facing commands (`nuisance-dossier`, `calibration-dossier`, `classify-dossier`) and appears across the living docs, yet is in neither the glossary nor its log. It carries two senses: the kit of an agent, and the advisory file of one census flaw (`advisory_dossier`, `Dossier`). The glossary has a section made for this. The commands stay.

Change: Add to "Words with several senses" in docs/glossary.md, between **declared** and **eval**: "**dossier**: admission dossier or re-admission dossier (the kit of an admission agent, written by `nuisance-dossier`), calibration dossier (the kit of a calibration agent, written by `calibration-dossier`), or advisory dossier (the advisories of one census flaw as one JSON file, in a kit or in the classifiers' input of `classify-dossier`)." No code or flag changes.

Files: `docs/glossary.md`

Tests: `uv run pytest tests/integration/committed/project -n auto` (the wording passes the retired-word patterns, checked).

### 13. Fingerprint, backend registry and fix-check command

Order and interactions: fixes 13.1 to 13.3 edit the same test file and bring it back under 300 lines with no split. Fixes 13.7 to 13.9 edit `fix_check_command.py` and one sentence of `CONTRIBUTING.md`, written once. `is_holdout_calibration_copy` (fix 10.7) is already in place when fix 13.7 renames its function.

Verifier's notes: Inside the section. fix 13.1, fix 13.2 and fix 13.3 edit the same unit test file and its given: apply them together, the file falls from 309 lines to under 300 with no split. fix 13.1 and fix 13.4 both edit fingerprint.py on different lines. fix 13.7, fix 13.8 and fix 13.9 edit fix_check_command.py and its test: apply them in that order or as one change. fix 13.7 and fix 13.9 edit the same CONTRIBUTING.md sentence on the fix check (witness wording, then exit list), so write it once. fix 13.7 is carried by fix 13.7. a rejected finding is rejected, so host_stand_in_files stays in detection/baseline.py and only gains the directory parameter of fix 13.1. Glossary log: two lines (`provisioner_of`/`BackendProvisioner`, `_field_mismatches`). No confirmed fix touches a fingerprinted module. Check the 65 nuisance fixture fingerprints, the counter fingerprint and the detection fixture and grammar fingerprints before and after, notably for fix 13.1 and fix 13.6 of fingerprint-backends (served tuples verified equal). Other sections on the same modules. another section: fix 3.8 proposes the same planting-host move as the rejected a rejected finding and should get the same answer for that part (otherwise it must carry the new stand_ins_directory parameter of host_stand_in_files). fix 3.7, fix 3.7 and fix 3.7 move NUISANCE_CONCURRENCY and change the import block of fix_check_command.py. It and another section also edit audit.py, where fix 13.5 changes line 127 only. another section (fix 11.7, fix 11.7) edits the parser and the committed read of fix_check_command.py, just above the guard that fix 13.8 reduces. another section (fix 10.7) rewrites the source test inside the function that fix 13.7 renames: apply fix 13.7 first, then the property. another section (fix 5.1, fix 5.1) renames reset_containers in backend_registry.py and in tests/integration/committed/nuisance/test_nuisance_backend_registry.py, neighbors of fix 13.6 and fix 13.11 with no overlap. another section (fix 1.4) edits the docstring of test_nuisance_doris_backend.py. another section edits other passages of CONTRIBUTING.md.

#### Fix 13.1: `tests/unit/nuisance/support/test_nuisance_fingerprint_given.py` `serving_a_public_name` (test-fragility, refactoring)

Problem: The given declares the public name "example.com", and nuisance_fixture_fingerprint calls planting_host_parts(server.host) with its default directory. So test_the_fingerprint_moves_when_the_stand_in_image_of_a_public_name_changes reads the committed evals/stand_ins/example.com.json and its TLS leaf, key and authority. NuisanceFixtureSources injects the Docker directory, the backends and the confinement, but not the stand-ins directory, although planting_host_parts already takes one and the detection fingerprint passes it (test_detection_baseline.py uses a_stand_ins_directory).

Why it was kept: True. nuisance_fixture_fingerprint calls planting_host_parts(server.host) with its default directory (fingerprint.py:100), and given.serving_a_public_name declares "example.com", so test_the_fingerprint_moves_when_the_stand_in_image_of_a_public_name_changes reads the committed evals/stand_ins/example.com.json, its TLS leaf, key and authority. A removed or renamed capture turns a unit test red, which CLAUDE.md places under tests/integration/committed/. planting_host_parts already takes the directory, and the detection fingerprint passes it (test_detection_baseline.py:62 uses a_stand_ins_directory). NuisanceFixtureSources injects every other file input. The finder's direction misses one point: fingerprinted_files (fingerprint.py:130) calls host_stand_in_files(server.host), which is hard-wired to STAND_INS_DIRECTORY, so it would stop naming the files the fingerprint reads under a non-default source.

Change: In evals/cve/nuisance/fingerprint.py add a last field `stand_ins_directory: Path = public_stand_ins.STAND_INS_DIRECTORY` to NuisanceFixtureSources (last, so the positional `NuisanceFixtureSources(tmp_path, registry)` calls keep working; the `public_stand_ins` module is already imported there). Call `planting_host_parts(server.host, sources.stand_ins_directory)` and, in fingerprinted_files, `host_stand_in_files(server.host, sources.stand_ins_directory)`. In evals/cve/detection/baseline.py give host_stand_in_files a second parameter `stand_ins_directory: Path = STAND_INS_DIRECTORY`, passed to `_served_files`, the same signature shape as planting_host_parts. In the given, serving_a_public_name declares `fictional_stand_ins.HOST`. In the test, `sources = NuisanceFixtureSources(tmp_path, stand_ins_directory=a_stand_ins_directory(tmp_path))`.

Files: `evals/cve/nuisance/fingerprint.py`, `evals/cve/detection/baseline.py`, `tests/unit/nuisance/support/test_nuisance_fingerprint_given.py`, `tests/unit/nuisance/test_nuisance_fingerprint.py`

Tests: test_the_fingerprint_moves_when_the_stand_in_image_of_a_public_name_changes runs on the fictional stand-in directory. The committed guards through fingerprinted_files (test_nuisance_fixture_sources_then.py, test_detection_holdout_fixture_sources_then.py) use the defaults and do not change. Check before and after: nuisance_fixture_fingerprint for the 65 admitted servers and the detection fixture_fingerprint are identical, since the default directory is the one used today.

Risks: evals/cve/detection/baseline.py and fingerprint.py are not in the fingerprinted list and enter no hash. If the planting-host move of fix 3.8 (another section) were kept, it would carry the new parameter with it.

#### Fix 13.2: `tests/unit/nuisance/test_nuisance_fingerprint.py` `test_the_fingerprint_is_unchanged_by_an_exploit_or_a_settlement_change` (given-then, refactoring)

Problem: The test spends 17 of its 23 lines building a nested model_copy lambda and an AdmissionSettlement whose field values do not matter to the spec. test_the_fingerprint_is_unchanged_by_the_provenance_records (line 84) does the same with 8 lines of SeedRecord and StandInRecord literals. The behavior, that records outside the fingerprint do not move it, is buried.

Why it was kept: True. test_the_fingerprint_is_unchanged_by_an_exploit_or_a_settlement_change spends 17 of its lines on a nested model_copy lambda and an AdmissionSettlement whose values do not matter, and test_the_fingerprint_is_unchanged_by_the_provenance_records spends 8 on SeedRecord and StandInRecord literals. These givens abstract something real: the spec is that records outside the fingerprint do not move it. The file is at 309 lines, and this extraction with fix 13.3 brings it back under the bar with no split.

Change: In tests/unit/nuisance/support/test_nuisance_fingerprint_given.py add `with_provenance_records(server) -> AdmittedServer` (the seed and stand-in records through model_copy) and `with_a_moved_exploit_and_a_settlement(server) -> AdmittedServer` (mutations.with_the_first_flaw on the exploit calls, then the settlement). The two tests call them, and the test file drops its AdmissionSettlement, SeedRecord and StandInRecord imports.

Files: `tests/unit/nuisance/test_nuisance_fingerprint.py`, `tests/unit/nuisance/support/test_nuisance_fingerprint_given.py`

Tests: The two tests keep the same assertions on the same records, in about five lines each.

#### Fix 13.3: `tests/unit/nuisance/test_nuisance_fingerprint.py` `test_the_fingerprint_moves_when_a_backend_fixture_is_set` (test-fragility, refactoring)

Problem: This test and test_the_fingerprint_moves_when_a_backend_image_changes (lines 130 and 133) name the real provisioner "doris" with the default sources, so the fingerprint reads the real BACKENDS entry and hashes the real doris.py and closed_network.py. The same file already has FAKE_BACKEND and a fake registry for the served-files tests.

Why it was kept: True. test_the_fingerprint_moves_when_a_backend_fixture_is_set and test_the_fingerprint_moves_when_a_backend_image_changes name the real key "doris" with the default sources, so they read the real BACKENDS entry and hash the real doris.py and closed_network.py. They only need a registered key. The same file already has FAKE_BACKEND, and admissions.a_backend_registry() registers its "fake" key with served=() and the same image.

Change: In both tests use `sources = NuisanceFixtureSources(tmp_path, admissions.a_backend_registry())`. The first compares the server with `mutations.with_a_backend(server, FAKE_BACKEND)`. The second compares FAKE_BACKEND with `FAKE_BACKEND.model_copy(update={"images": ["fake/backend:2.0"]})`.

Files: `tests/unit/nuisance/test_nuisance_fingerprint.py`

Tests: The two tests stay red-capable on the backend part of the hash (`backend.model_dump()`). What a backend serves stays covered by test_the_fingerprint_moves_when_a_served_file_of_the_backend_changes.

#### Fix 13.4: `evals/cve/nuisance/fingerprint.py` `backend_content` (naming, refactoring)

Problem: backend_content is public but has no importer outside this module. Its name is also false at one of its two calls: line 115 applies it to _public_name_launch, which covers a server with no backend (the holder's and stand-in's Dockerfiles and the planting modules).

Why it was kept: True. backend_content has no importer outside fingerprint.py (grep over evals, tests and docs), and at line 115 it is applied to _public_name_launch, the holder's and stand-in's Dockerfiles and the planting modules of a server with no backend, so its name is false there. The finder's `_files_content` would differ by one letter from the `_file_content` it calls, so a clearer name is better.

Change: Rename to private `_contents_of(paths: Sequence[Path]) -> list[object]`, body unchanged, at its definition and its two calls (fingerprint.py:105 and 115). plans/2026-11-02_closed-eval-networks.md cites the old name, so add a line to docs/glossary-log.md, in sorted position: `backend_content` | `_contents_of` | rename | 2026-11-23.

Files: `evals/cve/nuisance/fingerprint.py`, `docs/glossary-log.md`

Tests: No test changes. The function name enters no hash, and fingerprint.py is not a hashed source: nuisance_fixture_fingerprint of the 65 servers is identical.

#### Fix 13.5: `evals/cve/nuisance/provisioners.py` `provisioner_of` (premature-abstraction, glossary log)

Problem: provisioner_of(lifecycle) returns a closure typed by the BackendProvisioner alias, but no provisioner is ever stored or passed: the registry stores the lifecycle, and all four call sites invoke the result at once as provisioner_of(x)(server) (audit.py:127, test_backend_lifecycle.py:40 and 189, test_backend_lifecycle_given.py:149). The alias has no other use.

Why it was kept: True. provisioner_of has four call sites, audit.py:127, test_backend_lifecycle.py:40 and 189, test_backend_lifecycle_given.py:149, and each invokes the result at once. No provisioner is stored or passed: RegisteredBackend stores the lifecycle (the 2026-11-05 plan moved it there). BackendProvisioner has no other use outside plans. The kit's counterpart, backend_launch(lifecycle, image, host, launch), is already one flat context manager, so the flat form is also the shape its parity test compares. launched_server_args is a pure match, so evaluating it on entry rather than at the factory call changes nothing.

Change: In evals/cve/nuisance/provisioners.py replace the factory with `@contextmanager def provisioned_launch(lifecycle: BackendLifecycle | PerLaunchBackend, server: AdmittedServer) -> Generator[Launch]`, whose body computes name and image and enters `launched_server_args(lifecycle)(name, image, server.host, server.launch)`. Delete BackendProvisioner and the Callable and AbstractContextManager imports. Update audit.py:127 to `with provisioned_launch(backends[server.backend.provisioner].lifecycle, server) as launch:`, the two calls of test_backend_lifecycle.py, test_backend_lifecycle_given.py:149, and the mention in the backend_registry docstring. Add a line to docs/glossary-log.md, in sorted position: `provisioner_of`, `BackendProvisioner` | `provisioned_launch` | rename | 2026-11-23, since plans cite both. The glossary term provisioner stays, and the kit docstring's 'whose provisioners' stays true.

Files: `evals/cve/nuisance/provisioners.py`, `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/backend_registry.py`, `tests/unit/cve/backends/test_backend_lifecycle.py`, `tests/unit/cve/backends/support/test_backend_lifecycle_given.py`, `docs/glossary-log.md`

Tests: Only the call form changes in the three test call sites. test_the_kit_backend_launch_is_the_provisioner_launch keeps pinning the parity for every registered backend. No fingerprint is involved: provisioners.py is neither hashed nor in a kit closure (the kit only names it in a docstring).

Risks: The test files sit in the backend fixtures area's directory but only their call form changes. audit.py is also edited by the another section and another section, on other lines.

#### Fix 13.6: `evals/cve/nuisance/backend_registry.py` `_responder` (argument-count, refactoring)

Problem: _responder takes 5 positional arguments, four of them strings or string-like and swappable, to save two lines on two registry entries (atlassian, googleapis). The third responder, facebook_ads, cannot use it because of its mounted files and spells out the same entry by hand, so the table mixes two forms for one kind of backend.

Why it was kept: True. _responder takes five positional arguments, four of them strings, for two entries (atlassian, googleapis), while facebook_ads, the third responder, spells out the same entry by hand. The helper saves no lines: each call takes 7 lines, the same as the explicit entry, and the table then has one form. I checked that the explicit served tuple equals the registered one for both keys (`(*_served(module, service), Path(responder.__file__))`, True for atlassian and googleapis), so the order and the hashed content do not move.

Change: Delete _responder. Write atlassian as `RegisteredBackend(atlassian.LIFECYCLE, ATLASSIAN_BRIDGE, (ATLASSIAN_RESPONDER_IMAGE,), ("atlassian-responder",), (*_served(atlassian.__file__, "atlassian-responder"), Path(responder.__file__)))` and googleapis the same way with its bridge, image and service. The `responder` import stays, used by these entries and facebook_ads.

Files: `evals/cve/nuisance/backend_registry.py`

Tests: No test changes. Check before and after: nuisance_fixture_fingerprint of the 65 admitted servers is identical, since `served` keeps its values and order. backend_registry.py itself is not hashed.

Risks: The another section renames reset_containers in this file (fix 5.1, fix 5.1). Neither of the two entries passes that field, so the edits do not overlap.

#### Fix 13.7: `evals/cve/nuisance/fix_check_command.py` `fix_check_mismatches` (dead-code, dead wrapper removed, glossary log)

Problem: `fix_check_mismatches` has no production caller: `grep` finds it only in tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py. The real path is `check_fixes` -> `_fix_check_problems` -> `_field_mismatches`, so the public function is a test-only wrapper around the private one. The explanation of the skipped fields sits on the wrapper's docstring, away from the `skip` set it explains. The comment beside that set says 'these two' above a set of three names.

Also covers: `evals/cve/nuisance/fix_check_command.py` (ubiquitous-language): The docstring says "The witness is a fresh random nonce each run ... so it never equals the recorded nonce". The field it compares is `FixCheckRecord.witness`, so the recorded value is a witness, and the sentence merges the two terms the glossary sets apart.

Why it was kept: True. fix_check_mismatches has no production caller (grep: only test_nuisance_fix_check_command.py), and the real path is check_fixes, _fix_check_problems, _field_mismatches. So the tests exercise a wrapper, the explanation of the skipped fields sits away from the `skip` set, and the comment 'these two' stands above a set of three names, which is false as written. The docstring also calls the recorded witness a 'nonce', which the glossary separates (witness, Not: nonce), the finding merged here. The test file is under tests/unit/nuisance/fix_checks/ but it is the test of fix_check_command.py, an E module.

Change: Delete the wrapper and rename `_field_mismatches` to public `fix_check_mismatches(result, record) -> dict[str, str]`, in the same position under _fix_check_problems, which calls it. Move the docstring onto it, with 'The witness is drawn fresh each run (check_fix plants RANDOM_NONCES), so it never equals the recorded witness and is not compared.' in place of the nonce sentence, and delete the inline 'these two' comment. In the tests, `== []` becomes `== {}`, and the two tests that read a field assert `list(mismatches) == ["patched_surfaces"]` and `["source"]`. Rename test_a_differing_witness_nonce_is_not_a_mismatch to test_a_differing_witness_is_not_a_mismatch and word its comment with witness. In CONTRIBUTING.md, 'the random `witness` nonce always excepted' becomes 'the random `witness` always excepted'. Add a line to docs/glossary-log.md: `_field_mismatches` (the nuisance fix-check comparison) | `fix_check_mismatches` | rename | 2026-11-23, since plans cite it. `RANDOM_NONCES` stays, the planting code's name.

Files: `evals/cve/nuisance/fix_check_command.py`, `tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py`, `CONTRIBUTING.md`, `docs/glossary-log.md`

Tests: The seven comparison tests now exercise the function production calls, with the same cases. No printed line changes: _fix_check_problems reads the same dict. Run the fix-check unit tests and tests/integration/committed (a doc changes).

Risks: fix 10.7 (another section) rewrites the `record.source == "detection_holdout_calibration"` line of this same function.

#### Fix 13.8: `evals/cve/nuisance/fix_check_command.py` `fix_check` (dead-code, dead branch removed)

Problem: The `or not deps.fixtures` branch handles an empty fixture registry, but `FIX_CHECK_FIXTURES` holds 62 committed fixtures. Only a test reaches the branch, by injecting `fixtures=()`. On that path the command prints 'no server is admitted' although the admission it just loaded holds servers, so the message is false.

Why it was kept: True. FIX_CHECK_FIXTURES holds 62 committed fixtures (computed), and the only path to `not deps.fixtures` is test_a_fix_check_with_no_fixture_says_no_server_is_admitted, which injects `fixtures=()` beside an admission holding servers. On that path the printed 'no server is admitted' is false. The two real empty cases, absent admission and no servers, stay tested by test_a_fix_check_with_no_admitted_server_says_so.

Change: Reduce the guard to `if admission is None or not admission.servers:`. Delete test_a_fix_check_with_no_fixture_says_no_server_is_admitted and the FixCheckCommandDeps import of the test file, which only that test uses (the given keeps its own import).

Files: `evals/cve/nuisance/fix_check_command.py`, `tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py`

Tests: One test deleted, the rest unchanged. Behavior on the committed data does not change.

Risks: Removal of a branch that committed data cannot reach: only an injected empty registry would now take the unknown-flaw path (exit 2) instead of printing a false message and exiting 0.

#### Fix 13.9: `evals/cve/nuisance/fix_check_command.py` `fix_check` (ubiquitous-language, documentation corrected)

Problem: An unknown `--flaw` returns `UNKNOWN_SERVER_EXIT`, a name that says server for a flaw selection. The exit is also undocumented: the fix-check line of CLAUDE.md lists 0, 1, 3 and 4 without 2, and CONTRIBUTING.md lists only 0, 1 and 3, missing both 2 and 4.

Why it was kept: True on both counts. An unknown `--flaw` returns UNKNOWN_SERVER_EXIT while the message says 'unknown flaw', and vet and gate use that constant for a real `--server` selection. The exit is undocumented: the fix-check line of CLAUDE.md lists 0, 1, 3 and 4 without 2, and the CONTRIBUTING.md passage lists only 0, 1 and 3, missing 2 and 4, while check_fixes returns CRASHED_EXIT. This is not the rejected precedent of a shared exit code named by convention: the constant is local to the command, and the shared one stays for vet and gate.

Change: Declare `UNKNOWN_FLAW_EXIT = 2` in fix_check_command.py, stop importing UNKNOWN_SERVER_EXIT there, and use it in fix_check and in test_a_fix_check_of_a_flaw_no_fixture_matches_exits_naming_it (imported from fix_check_command). In the CLAUDE.md fix-check line add `2 on a --flaw matching no fix-check fixture` to the exit list. In the CONTRIBUTING.md passage state `2` on a `--flaw` matching no fixture and `4` on a fix check that raises.

Files: `evals/cve/nuisance/fix_check_command.py`, `tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py`, `CLAUDE.md`, `CONTRIBUTING.md`

Tests: The test asserts the new name, with the value still 2. Run tests/integration/committed since docs change (retired-word and glossary guards read CLAUDE.md and CONTRIBUTING.md).

Risks: The exit code value does not change, so no CHANGELOG entry. The documentation correction touches CLAUDE.md, loaded at every session, on one line. The CONTRIBUTING sentence is the one fix 13.7 edits.

#### Fix 13.10: `tests/integration/test_nuisance_doris_backend.py` `_missing_prerequisite` (duplication, refactoring)

Problem: `_missing_prerequisite` and `_docker` rewrite the Docker availability check that `tests/integration/support/docker_prerequisites.missing_prerequisite` already provides through `DockerRuntime().available()`, including the same handling of a missing binary (`OSError` to 127). This file already imports `skip_or_require` from that module, and test_cve_layout_mount.py and test_cve_closed_networks.py use the shared check.

Why it was kept: True. _missing_prerequisite and _docker rewrite docker_prerequisites.missing_prerequisite. DockerRuntime().available() runs `docker version --format {{.Server.Version}}` and maps OSError to 127 (adapters/docker.py:25 and 82-90), so it answers no on the same two cases: no binary, and a daemon that does not answer. The file already imports skip_or_require from that module, and test_cve_layout_mount.py and test_cve_closed_networks.py use the shared check.

Change: Import `missing_prerequisite` beside `skip_or_require`, call it in `_prerequisites`, and delete `_missing_prerequisite`, `_docker` and `import subprocess`.

Files: `tests/integration/test_nuisance_doris_backend.py`

Tests: The test runs only behind NUISANCE_DORIS=1. Under the flag with Docker absent it still skips, or fails under CVE_PLANTING_REQUIRED=1. Only the skip text changes, to 'CVE planting needs Docker'.

Risks: fix 1.4 (another section) edits this file's docstring, on other lines.

#### Fix 13.11: `tests/integration/committed/nuisance/test_nuisance_fingerprint.py` `test_every_served_path_of_a_registered_backend_exists` (test-placement, refactoring)

Problem: The file's only test checks that each path in BACKENDS[key].served exists. It calls no fingerprint function and sits beside test_nuisance_backend_registry.py, which already holds the committed checks of the same registry. The name sends a reader looking for the fingerprint's committed checks to a file that has none.

Why it was kept: True. tests/integration/committed/nuisance/test_nuisance_fingerprint.py holds one test, on BACKENDS[key].served, and calls no fingerprint function. test_nuisance_backend_registry.py beside it holds the committed checks of the same registry and already imports pytest and BACKENDS. No doc or test refers to the committed file by name (the grep hits are the unit file of the same name).

Change: Move test_every_served_path_of_a_registered_backend_exists unchanged into tests/integration/committed/nuisance/test_nuisance_backend_registry.py and delete tests/integration/committed/nuisance/test_nuisance_fingerprint.py.

Files: `tests/integration/committed/nuisance/test_nuisance_fingerprint.py`, `tests/integration/committed/nuisance/test_nuisance_backend_registry.py`

Tests: Same test, same parametrization, one file fewer. Run tests/integration/committed.

Risks: The another section renames a test of the destination file (fix 5.1, fix 5.1), a textual neighbor only.

## Due diligence record

What the due-diligence pass concluded on the external facts this plan cites or defers, for the later passes to read. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it, so this section never asserts what nobody checked.

- OPEN (currency): `mcp>=1.18.0,<2`, valid (1.18.0 is published and not yanked, the lock installs 1.30.0) but PyPI's latest is 2.3.0, outside the bound. The plan keeps the specifier and only tests it.
- SETTLED: `docker build -t mcp-auditor-cve-sentinel:local -f docker/Dockerfile.sentinel docker` (verified against `SENTINEL_IMAGE` in `evals/cve/planting_base.py` and both kit READMEs)
- SETTLED: `docker build -t mcp-auditor-cve-stand-in:local -f docker/Dockerfile.stand-in docker` (verified against `STAND_IN_IMAGE` in `evals/cve/planting_base.py` and both kit READMEs)
- SETTLED: a `docker compose build` reuses its cache unless the Dockerfile or a file it copies changed (verified against docs.docker.com/build/cache/invalidation)
- SETTLED: a name imported into a module passes `pyrefly check` when imported from that module, as an implicit re-export (verified on pyrefly 1.5.0, strict preset)
- SETTLED: a plain `@property` stays out of `model_json_schema` and `model_dump`, while `computed_field` enters the serialization schema and the dump (verified on pydantic 2.14.1)
- SETTLED: a `finally` of a `@contextmanager` around an `await` runs on `CancelledError` (verified on the project's interpreter)
- SETTLED: `traceback.print_exc()` prints the message of a cause chained with `raise ... from` (verified on the project's interpreter)
- SETTLED: `anthropic.AuthenticationError` (verified on anthropic 1.17.0)

## Implementation steps

The steps carry out the fixes above in their order, one commit per step. A fix's text is its specification: each step names the plan lines to read and adds only what the fix text leaves to the order of the work.

**Before each step.** Read lines 1-107 of this plan (context, decisions, what stays unchanged, edge cases, verification), then the lines the step names. A note that weighs a rejected finding or says "another section" describes a neighbour, not work to do. Apply a step's fixes in the order listed.

**Run outputs stay closed.** Never open anything under `output/`, a `*.result.json`, a `*_judged_cases.jsonl` or a holdout report, by hand or through an agent. Scope every search to `evals tests docs`.

**The loop.** While a test is red, `uv run pytest <test files> -n 0`. Once green, `uv run pytest tests/unit -n auto --maxprocesses 6`, with `--lf` on a failure until it passes, then the full short loop again. Also `uv run ruff check .`, `uv run ruff format .`, `uv run pyrefly check`, the integration files the fix writes or that import a module it changes, and `uv run pytest tests/integration/committed -n auto` when it touches committed content.

**The closing check ends every step.** All of it passes, even right after a fix that ran part of it:

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyrefly check
sed -n '78,95p' plans/2026-11-23_nuisance-suite-standards-pass.md | PYTHONPATH=. uv run python -
```

The integration tests build images, so watch the disk. The last command prints exactly:

```
41 58afe8a1926bf5fbffa78146b6e7e35d5d5d27797332aea1c829a503cc3e33d1 689da547ef98cf466f67be55cdb28b319790d9e21b8ea6df2df85624c6dc420b
65 b6d3dc662faf2fb24b2b91ff0f7c7941d6927a7303cfab952f2cf5b41af54161 0444a788e1477df424ea3b29ab0dc2a2c1bacf55746975126c0ae46e667cfc5d
```

**The stale-import scan.** A moved name left imported passes `pyrefly` as an implicit re-export. Where a step lists `module:name` pairs, run this from the repository root with those pairs. It prints nothing and exits 0:

```bash
uv run python - module:name ... <<'PY'
import ast, pathlib, sys
pairs = {tuple(pair.split(":")) for pair in sys.argv[1:]}
hits = [
    f"{path}:{node.lineno}: from {node.module} import {alias.name}"
    for root in ("evals", "tests")
    for path in pathlib.Path(root).rglob("*.py")
    for node in ast.walk(ast.parse(path.read_text()))
    if isinstance(node, ast.ImportFrom)
    for alias in node.names
    if (node.module, alias.name) in pairs
]
for hit in hits:
    print(hit)
sys.exit(bool(hits))
PY
```

**The dossier comparison (section 12).** Before the step's first edit, on the clean tree, write the three dossiers to `before`, in a new directory of this step under your scratchpad, never one an earlier step wrote: the writer leaves in place a file it no longer writes, so a reused directory hides a removed file. After the step, write them to `after` beside it. `diff -r before after` prints nothing. The writing is deterministic (checked on these three):

```bash
write_dossiers() {
  uv run python -m evals.run_nuisance nuisance-dossier --server PyPI:awslabs-aws-api-mcp-server --out "$1/first"
  uv run python -m evals.run_nuisance nuisance-dossier --server PyPI:doris-mcp-server --backend doris --out "$1/first-doris"
  uv run python -m evals.run_nuisance nuisance-dossier --server PyPI:awslabs-aws-api-mcp-server --re-admission --out "$1/re-admission"
}
```

**A new glossary term.** Before a step that adds one is committed, a fresh Opus agent that has not seen this plan checks each new sentence against `docs/glossary.md` and `docs/nuisance-suite-rule.md` (style, one meaning per term, no clash with an existing sense). Hand it the sentences and those two files only.

### Step 1: The gate adopts the shared baseline and recording helpers

- **Fixes**: 1.1, 1.2. Their text at plan lines 110-171.
- **Files**: `tests/unit/nuisance/gate/test_nuisance_gate_recording.py`, `evals/cve/nuisance/gate/gate_baseline.py`, `evals/cve/nuisance/gate/gate.py`, `evals/cve/nuisance/gate/gate_recording.py`, `evals/cve/nuisance/gate/gate_session_recording.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_command.py`, `docs/labeling-log.md`
- **Do**:
  - Tests: in `test_nuisance_gate_recording.py`, import `leaves_gated_set` from `evals.cve.file_baselines`, keep its two tests, delete the two `decide_recordings` tests.
  - `gate_baseline.py`: `WHOLE_RESET`, `condition_mismatches` (sorted by package before the file-name mapping), `write_baseline` and `baseline_integrity` delegate to the shared helpers. Add `NUISANCE_GATE_BASELINE_STORE`.
  - `gate.py`, `gate_recording.py`, `gate_session_recording.py`, `gate_session.py`, `gate_command.py`: use the shared texts and functions as fix 1.1 lists, keeping `Text` around `next_recording_step`.
  - Fix 1.2: delete `gate.exit_code`, and `_run_opened` writes `NOT_COMPARABLE_EXIT if refused else gate.outcome.exit_code`.
  - `docs/labeling-log.md`: add the one entry Decisions describes (plan line 41), with the later fixes it covers, the four fingerprint values and the four questions of ADR 016.
- **Test**: No text, exit code or JSON key moves. `test_nuisance_gate.py`, `test_run_nuisance_gate.py` and the session tests keep pinning the texts, and session exit codes stay 0, 1 and 3.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.gate.gate_session_recording:load_checked`.

### Step 2: Model conditions and the gate's retired words

- **Fixes**: 1.3, 1.4. Their text at plan lines 110-115, 172-203.
- **Files**: `tests/integration/test_nuisance_doris_backend.py`, `evals/cve/nuisance/gate/gate_baseline.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/gate/gate_recording.py`
- **Do**:
  - `gate_conditions` and `_assemble_run` spread `ModelConditions.of(...).model_dump()` (`ctx.settings` in `_assemble_run` at this point).
  - Rewrite the four comments of fix 1.4, with "as a holdout run does by design" in the Doris test.
- **Test**: No test changes. `test_nuisance_gate_baseline.py` and the nuisance holdout run tests pin the conditions, and `tests/integration/committed/project` covers the retired words.
- **Verify**: The closing check.

### Step 3: The nuisance gate's judged-case exporter leaves the shared export

- **Fixes**: 2.1. Its text at plan lines 204-225.
- **Files**: `tests/unit/evals/test_export.py`, `tests/unit/evals/support/test_export_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_judged_cases_export.py`, `evals/export.py`, `evals/cve/nuisance/gate/gate_judged_cases_export.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/cve/nuisance/gate/gate_console.py`
- **Do**:
  - Tests first: create `test_nuisance_gate_judged_cases_export.py` with the moved test, assertions unchanged, built from `tests.unit.support.grammar_inputs` and `judged_case_exports`, with no given file. Delete its given from `test_export_given.py` and its imports from `test_export.py`.
  - Create `gate_judged_cases_export.py` holding the two functions verbatim. In `evals/export.py`, delete them and the `GateAudit` import, and rename `_chain_lines` to `chain_lines`. Repoint `gate_command.py` and `gate_console.py`, with no re-export.
- **Test**: The moved test keeps its assertions. The honeypot suite's JSONL stays byte-identical, and `test_nuisance_gate_console.py` keeps pinning the export path.
- **Verify**: The closing check. `PYTHONPATH=. uv run python -c "import sys, evals.run_honeypot_suite; assert not [m for m in sys.modules if m.startswith('evals.cve')]"` exits 0. Stale-import scan: `evals.export:export_nuisance_gate_judged_cases evals.export:nuisance_gate_export_path evals.export:_chain_lines`.

### Step 4: The throttle lines come from the shared display

- **Fixes**: 2.2. Its text at plan lines 204-207, 226-243.
- **Files**: `evals/cve/nuisance/markdown.py`, `evals/cve/nuisance/gate/gate_report.py`, `evals/cve/nuisance/gate/gate_console.py`
- **Do**:
  - Delete `_throttled_lines` from `markdown.py` and `render_throttled` from `gate_report.py`, both calling `throttled_lines` from `evals.eval_display`. `gate_console.py` calls `print_throttles`.
- **Test**: No test changes. `test_nuisance_report.py`, `test_nuisance_gate_report.py` and `test_nuisance_gate_console.py` pin the lines byte for byte.
- **Verify**: The closing check. `PYTHONPATH=. uv run python -c "import sys, evals.run_honeypot_suite; assert not [m for m in sys.modules if m.startswith('evals.cve')]"` exits 0.

### Step 5: Drop precedence, tracing refusal, backend image ids and overrides

- **Fixes**: 3.1, 3.3, 3.4, 3.6. Their text at plan lines 244-269, 290-327, 348-365.
- **Files**: `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`, `evals/cve/nuisance/images.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/images.py`
- **Do**:
  - Fix 3.1: add `DroppedRun.from_causes`, `_run_server` keeps its `if causes` guard, since the method raises on an empty set.
  - Fix 3.3: public `NUISANCE_HOLDOUT_RUN_REFUSED` and `refuse_tracing` in `holdout_run.py`, called from the command too. Both call sites stay.
  - Fix 3.4: delete the nuisance `backend_image_ids`, import it from `evals.cve.images` in `holdout_run.py` and `gate_session.py`, and make the comment in `evals/cve/images.py` true of both suites.
  - Fix 3.6: delete `nuisance_overrides`, use `RunOverrides.of_holdout` in the command and at the fallback, and write `auditor.overrides.shape(None)` inside the `try` of `audit_once`.
- **Test**: No test changes. The precedence, tracing and audit tests named by each fix stay green.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.images:backend_image_ids evals.cve.nuisance.holdout_run:nuisance_overrides`.

### Step 6: One RunInterrupted for both holdout runs

- **Fixes**: 3.2. Its text at plan lines 244-249, 270-289.
- **Files**: `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`, `tests/unit/nuisance/test_nuisance_holdout_run_interrupted.py`, `tests/unit/nuisance/test_run_nuisance_holdout_run.py`, `evals/cve/nuisance/results.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/run_files.py`
- **Do**:
  - Repoint the three test modules to `evals.cve.run_files`.
  - Delete `RunInterrupted` from `nuisance/results.py`, import it in `nuisance/holdout_run.py` from `evals.cve.run_files`, and in `evals/cve/run_files.py` narrow the `except` of `partial_result_kept` and delete the `nuisance_results` import.
- **Test**: Import lines only. `test_run_nuisance_holdout_run.py` proves that the partial result is still written and the cause re-raised.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.results:RunInterrupted`.

### Step 7: NUISANCE_CONCURRENCY moves to the shared commands

- **Fixes**: 3.7. Its text at plan lines 244-249, 366-383.
- **Files**: `tests/unit/nuisance/test_run_nuisance_vet.py`, `evals/cve/nuisance/commands.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/cve/nuisance/fix_check_command.py`
- **Do**:
  - Repoint `test_run_nuisance_vet.py`.
  - Move the constant to `commands.py`, extend its docstring as written, and repoint the five production modules with no re-export.
- **Test**: Every `--concurrency` default stays 6.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.holdout_run:NUISANCE_CONCURRENCY`.

### Step 8: HoldoutConditions prices an audit

- **Fixes**: 3.5. Its text at plan lines 244-249, 328-347.
- **Files**: `tests/unit/nuisance/test_nuisance_assembly.py`, `tests/unit/cve/test_cve_holdout_conditions.py`, `evals/cve/holdout_conditions.py`, `evals/cve/detection/holdout_assembly.py`, `evals/cve/detection/holdout_run.py`, `evals/cve/detection/measurement.py`, `evals/cve/nuisance/assembly.py`, `evals/cve/nuisance/holdout_run.py`
- **Do**:
  - Test first in `test_cve_holdout_conditions.py`: two models at different prices, `audit_prices(model, judge)` puts each on its own side. See it red.
  - Add `HoldoutConditions.audit_prices`, delete `holdout_prices`, and update `detection/holdout_run.py`, `detection/measurement.py`, `nuisance/assembly.py` and `nuisance/holdout_run.py` (price computed once in `_run_all`, from `ctx`).
  - `test_nuisance_assembly.py`: `_PRICES = AuditPrices(...)`, `one_run = _PRICES.cost(generator, judge)`.
- **Test**: The new test, and the detection cost tests unchanged. `total_cost` and `run_cost` keep their float values.
- **Verify**: The closing check. Stale-import scan: `evals.cve.detection.holdout_assembly:holdout_prices`.

### Step 9: HOLDOUT_TEST_BUDGET moves to the holdout conditions

- **Fixes**: 3.8. Its text at plan lines 244-249, 384-399.
- **Files**: `tests/unit/nuisance/test_nuisance_holdout_run.py`, `tests/unit/nuisance/gate/test_nuisance_gate_baseline.py`, `tests/unit/nuisance/gate/support/nuisance_gate_baselines.py`, `evals/cve/holdout_conditions.py`, `evals/cve/detection/holdout_run.py`, `evals/cve/detection/holdout_command_deps.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/gate/gate_baseline.py`
- **Do**:
  - Repoint the three test modules.
  - Move the constant to `evals/cve/holdout_conditions.py` with the extended comment, delete the comment in `nuisance/holdout_run.py`, and repoint the four production modules with no re-export.
- **Test**: Import lines only. The value 10 and the serialized `budget` keys do not move.
- **Verify**: The closing check. Stale-import scan: `evals.cve.detection.holdout_run:HOLDOUT_TEST_BUDGET`.

### Step 10: Audit incidents, provider error and the status test

- **Fixes**: 4.1, 4.2, 4.5. Their text at plan lines 400-433, 462-473.
- **Files**: `tests/unit/nuisance/test_nuisance_audit_once.py`, `tests/unit/nuisance/test_nuisance_retry_policy.py`, `tests/unit/nuisance/support/test_nuisance_retry_policy_given.py`, `tests/unit/nuisance/test_nuisance_assembly.py`, `evals/cve/nuisance/audit.py`, `docs/glossary-log.md`
- **Do**:
  - Tests: repoint the retry-policy given and tests and `test_nuisance_audit_once.py` to `ProviderErrorAttempt` and `outcome.description`. Rewrite the status assertion of fix 4.5 as two projections.
  - `audit.py`: `audit_once` calls `print_report_incidents` at the same place, and `ProviderError` goes for `ProviderErrorAttempt` in the four unions.
  - `docs/glossary-log.md`: the `ProviderError` line, at its sorted place.
- **Test**: The test pinning `provider error (ModelAPIError, status 500), attempt 1/3` stays, and the incident and `TYPES_ONLY` tests stay green unchanged.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.audit:ProviderError`.

### Step 11: gate_run on the shared attempt loop

- **Fixes**: 4.3. Its text at plan lines 400-405, 434-447.
- **Files**: `tests/unit/detection/test_detection_audit_attempts.py`, `tests/unit/nuisance/test_nuisance_retry_policy.py`, `evals/cve/audit_attempts.py`, `evals/cve/detection/audit.py`, `evals/cve/nuisance/audit.py`
- **Do**:
  - Tests first, on the current code: add the two gate-only phrases to `test_nuisance_retry_policy.py` and see them green.
  - `audit_attempts.py`: drop the `Target` import, add `MissedCallWording`, and `graded_despite_missed_model_calls` takes `label`, `attempt` and a required `wording`.
  - `detection/audit.py`: `DETECTION_GATE_WORDING`, and `test_detection_audit_attempts.py` passes it with `TARGET.flaw_id` at its 4 calls.
  - `gate_run` stays in `audit.py` for this step, on the loop with `_GATE_WORDING`.
- **Test**: The phrases `no counted alarm, attempted again`, `run did not complete:`, `not graded` and `run skipped` stay pinned. Attempts, results and console bytes do not change.
- **Verify**: The closing check.

### Step 12: gate_run moves to the gate package

- **Fixes**: 4.4. Its text at plan lines 400-405, 448-461.
- **Files**: `tests/unit/nuisance/test_nuisance_retry_policy.py`, `tests/unit/nuisance/gate/test_nuisance_gate_session.py`, `tests/unit/nuisance/gate/support/nuisance_gate_sessions.py`, `tests/unit/nuisance/support/test_nuisance_solo_given.py`, `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/gate/gate_audit.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_session_model.py`
- **Do**:
  - A pure move: create `gate/gate_audit.py` with `_GATE_WORDING`, `GateRun` and `gate_run`, delete them from `audit.py` with their now unused imports, and repoint every importer the fix lists.
- **Test**: Import lines only. The gate_run tests stay in `test_nuisance_retry_policy.py`.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.audit:GateRun evals.cve.nuisance.audit:gate_run`.

### Step 13: containers_removed_by_name

- **Fixes**: 5.1. Its text at plan lines 474-495.
- **Files**: `tests/unit/nuisance/test_nuisance_containers.py`, `tests/unit/nuisance/test_nuisance_holdout_run_backends.py`, `tests/integration/committed/nuisance/test_nuisance_backend_registry.py`, `evals/cve/nuisance/backend_registry.py`, `evals/cve/nuisance/containers.py`, `docs/glossary-log.md`
- **Do**:
  - Rename the field, the function and the tests as listed, reword the `remove_backend_containers` docstring, and add the `docs/glossary-log.md` line.
  - Leave `evals/cve/backends/doris.py:175` and `docs/nuisance-suite-log.md:217` as they are: the first is fingerprinted, the second a dated record.
- **Test**: Test names and one field access change, no assertion. `tests/integration/committed/project/test_glossary.py` runs on the log line.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.backend_registry:backend_reset_containers`.

### Step 14: The run and the vet share their container sequence

- **Fixes**: 5.2. Its text at plan lines 474-479, 496-519.
- **Files**: `tests/unit/support/nuisance_docker_hosts.py`, `tests/unit/support/nuisance_vets.py`, `tests/unit/support/nuisance_holdout_runs.py`, `tests/unit/nuisance/support/test_nuisance_vetting_given.py`, `tests/unit/nuisance/test_nuisance_vetting.py`, `tests/unit/nuisance/test_nuisance_containers.py`, `tests/unit/nuisance/test_nuisance_vet.py`, `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`, `evals/cve/nuisance/containers.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/vetting.py`
- **Do**:
  - Test support first: `DockerHost.sweep`, `deps_on`, `deps_auditing`, `deps_reaching_nothing` and `ScriptedVet` as the fix writes them. In `test_nuisance_holdout_run_sweep.py`, keep the fake in a local and add `assert containers.removed == []`.
  - `containers.py`: delete `ContainerHost`, add `RunContainerDeps` and `rebuilt_run_images` right below `RunImages`, with the `try` around the `yield` only, and make `_refuse_server_containers` private.
  - `NuisanceDeps` and `VetDeps` hold `sweep` at the position of the two fields it replaces. `holdout_run.py` and `vet_command.py` enter `rebuilt_run_images`, and `vetting.py` takes `sweep`. The gate keeps its own sequence.
- **Test**: No test changes what it asserts. The two refusals, the final sweep and the order (rebuilt, running at rebuild, removed) stay pinned, and `test_a_container_seen_only_after_the_rebuild_refuses_and_is_left_running` proves that a refusal sweeps nothing.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.containers:ContainerHost evals.cve.nuisance.containers:refuse_server_containers`.

### Step 15: Benign call check, vet deps and the committed run population

- **Fixes**: 5.3, 5.4, 5.5, 5.6, 5.7. Their text at plan lines 474-479, 520-591.
- **Files**: `evals/cve/nuisance/benign_call.py`, `evals/cve/nuisance/vetting.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/gate/gate_session_model.py`, `evals/cve/nuisance/commands.py`, `evals/cve/nuisance/holdout_run_command.py`
- **Do**:
  - Fix 5.3: `BenignCallCheck` in `benign_call.py` replaces the alias of `vetting.py`. `admission.BenignCall` is untouched.
  - Fixes 5.4 and 5.5: delete `VetDepsFactory`, and `ping_answers` has no default and stays the last field.
  - Fix 5.6: `committed_run_population` in `commands.py`, above `malformed_input_refused`. In `run`, the call stays after `deps.conditions()`.
  - Fix 5.7: `_failure_with_prerequisites` and `_answer` in `benign_call.py`, with every message byte-identical.
- **Test**: No test changes. `test_nuisance_benign_call.py`, `test_run_nuisance_vet.py` and `test_run_nuisance_holdout_run.py` pin the messages, the empty admission and the order of the refusals.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.vetting:BenignCall`.

### Step 16: NuisanceHoldoutRunInputs and default_deps in the command

- **Fixes**: 6.1, 6.2. Their text at plan lines 592-637.
- **Files**: `tests/unit/support/nuisance_holdout_runs.py`, `tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/holdout_run_command.py`
- **Do**:
  - Test support first: `nuisance_holdout_runs.run` builds `NuisanceHoldoutRunInputs` and calls `run_nuisance(inputs, deps=deps)`, and the provenance orchestrator of `test_run_nuisance_holdout_run_given.py` reads `inputs.provenance`.
  - `holdout_run.py`: add `NuisanceHoldoutRunInputs` right after `RunProvenance` and before `RunOrchestrator`, delete `_RunContext`, the defaults and the fallback, and rewrite the module docstring.
  - `holdout_run_command.py`: move `default_deps` unchanged above `RunCommandDeps`, keeping `overrides.tool_call_timeout or TOOL_CALL_TIMEOUT`. Build the inputs before the `with`, and declare `default=NUISANCE_RUNS` on `--runs`.
- **Test**: Every behavior test stays green unchanged, and the effective `--runs` default stays 2.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.holdout_run:default_deps`.

### Step 17: The nuisance holdout run's test support

- **Fixes**: 6.3, 6.4, 6.5. Their text at plan lines 592-597, 638-677.
- **Files**: `tests/unit/nuisance/test_nuisance_holdout_run.py`, `tests/unit/nuisance/admission/test_nuisance_admission.py`, `tests/unit/support/nuisance_holdout_runs.py`, `tests/unit/support/nuisance_docker_hosts.py`, `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`, `tests/unit/nuisance/support/test_nuisance_holdout_run_interrupted_given.py`, `tests/unit/nuisance/support/test_nuisance_solo_given.py`, `tests/unit/nuisance/support/test_nuisance_vetting_given.py`
- **Do**:
  - In this order: delete the two duplicate tests of fix 6.3 and update the table row, add `DEFAULT_RUNS` and `clean_audits` and replace the 16 sites left, then write the three `min(SOLO_SERVERS)` picks.
- **Test**: Test-only. Same assertions and outcomes, with two tests fewer, and `test_nuisance_holdout_run.py` falls under 300 lines.
- **Verify**: The closing check, then, with Docker and no LLM, `uv run python -m evals.run_nuisance vet --server PyPI:flyto-core`, which must exit 0: it plays the real container sequence of fix 5.2 and the moved `default_vet_deps` on a server with no backend. If it fails, run the same command on `bc79ec5` in a separate worktree to tell a regression from a failure that predates this plan.

### Step 18: Gate command deps and the gate's servers

- **Fixes**: 7.1, 7.2. Their text at plan lines 678-715.
- **Files**: `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_selection.py`, `evals/cve/nuisance/gate/gate_command_deps.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/gate/gate_servers.py`
- **Do**:
  - Test first in `test_nuisance_gate_selection.py`: port the three behaviors to `gate_servers(...).audited`, `.outside_gate` and `.not_admitted`, and add the case of a `None` admission.
  - Create `gate/gate_command_deps.py` with `default_harness` (from `gate_session.py`), and `GateSessionRunner` and `GateCommandDeps` (both from `gate_command.py`, where they live today), unchanged. Repoint `gate_command.py`, `evals/run_nuisance.py` and `test_run_nuisance_gate_given.py`.
  - Create `gate/gate_servers.py` with frozen `GateServers` and the pure `gate_servers(admission, current)`, still calling `standing_exit` from `admission_walk`. `gate()` builds it once and passes it to `_print_empty_gate` and `_run_gate`.
- **Test**: `test_run_nuisance_gate.py` passes unchanged and pins the printed lines. A `None` admission audits no server and names no exit.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.gate.gate_command:GateCommandDeps evals.cve.nuisance.gate.gate_command:GateSessionRunner evals.cve.nuisance.gate.gate_session:default_harness evals.cve.nuisance.gate.gate_session:gate_servers evals.cve.nuisance.gate.gate_session:not_admitted evals.cve.nuisance.gate.gate_session:outside_gate`.

### Step 19: The gate rebuilds its backend images

- **Fixes**: 7.3. Its text at plan lines 678-683, 716-733.
- **Files**: `tests/unit/nuisance/gate/test_nuisance_gate_benign_calls.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_benign_calls_given.py`, `evals/cve/nuisance/gate/gate_session.py`, `CONTRIBUTING.md`, `CLAUDE.md`, `CHANGELOG.md`, `docs/labeling-log.md`
- **Do**:
  - Test first in `test_nuisance_gate_benign_calls.py`: `test_the_gate_rebuilds_the_built_backend_service_with_the_server_service` on `on_the_ckan_backend(FILESYSTEM)`, with the given `watching_the_rebuild(harness, containers)`. See it red.
  - `run_gate`: inside the existing `try`, right after `remove_backend_containers(harness.sweep, images)`, call `harness.rebuild(images.services)`. Delete the rebuild from `_vetted`.
  - Docs: the sentence in the gate paragraph of `CONTRIBUTING.md` and on the gate line of the `CLAUDE.md` Commands list, which also says `never overlap it with a fix check or a calibration check on one machine`, a line under Fixed in `CHANGELOG.md`, and a `docs/labeling-log.md` entry of its own answering the four questions of ADR 016.
  - This commit holds this fix alone.
- **Test**: The services rebuilt equal `[server.service, *BACKENDS['ckan'].built_services]`, and the stale backend container is already removed at that moment.
- **Verify**: The closing check.

### Step 20: ServerRuns and the gate's rows

- **Fixes**: 7.4, 7.7. Their text at plan lines 678-683, 734-745, 774-789.
- **Files**: `evals/cve/nuisance/gate/gate_session_model.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/gate/gate_session_recording.py`, `evals/cve/nuisance/gate/gate_report.py`, `evals/cve/nuisance/gate/gate_console.py`, `evals/cve/nuisance/gate/gate_command.py`
- **Do**:
  - Fix 7.4: drop `ServerRuns.runs`, and `_candidate` and `_recordings` read `[audit.flagged for audit in server_runs.audits]`.
  - Fix 7.7: public `gate_rows` and `outside_gate_line` in `gate_report.py`, private `_markdown_row`, `server_letters` and `server_detail`. `gate_console.py` and `_print_empty_gate` use them.
- **Test**: No test changes. The session, recording, report and console tests pin the candidate, the recorded runs, the markdown rows and the summary.
- **Verify**: The closing check.

### Step 21: A fatal provider error during a gate prints the crash panel

- **Fixes**: 7.5. Its text at plan lines 678-683, 746-759.
- **Files**: `tests/unit/nuisance/gate/test_run_nuisance_gate.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `evals/cve/nuisance/gate/gate_command.py`, `CHANGELOG.md`
- **Do**:
  - Test first in `test_run_nuisance_gate.py`, with a small given beside `GreenRecording` whose `run_gate` raises `ProviderFatal(cause) from cause` on `PermissionError('the key sk-secret was revoked')`. See it red on stderr.
  - `gate()`: `except (Refused, ProviderFatal): raise` before `except Exception`.
  - A line under Fixed in `CHANGELOG.md`. This commit holds this fix alone.
- **Test**: Exit `CRASHED_EXIT`, `PermissionError` in the output, `sk-secret` in neither stdout nor stderr.
- **Verify**: The closing check.

### Step 22: A fatal provider error on the detection command prints the crash panel

- **Fixes**: 7.6. Its text at plan lines 678-683, 760-773.
- **Files**: `tests/unit/detection/test_run_detection.py`, `tests/unit/detection/support/test_run_detection_given.py`, `evals/run_detection.py`, `CHANGELOG.md`
- **Do**:
  - Test first in `test_run_detection.py`, on `replace(cli.a_session_under_priced_models(monkeypatch), session=given.a_session_raising_a_fatal_provider_error)` and a `--no-baseline` run with `--report` under `tmp_path`. The given raises with `from cause`. See it red.
  - `main`: `except ProviderFatal as fatal:` before `except Exception`, printing the panel of `run_detection_holdout` and returning `CRASHED_EXIT`.
  - A line under Fixed in `CHANGELOG.md`. This commit holds this fix alone.
- **Test**: Exit `CRASHED_EXIT`, `PermissionError` in the output, `sk-secret` in neither stdout nor stderr.
- **Verify**: The closing check.

### Step 23: The retired sense of settle and the gate's builders

- **Fixes**: 8.1, 8.2, 8.3. Their text at plan lines 790-849.
- **Files**: `tests/unit/nuisance/gate/test_nuisance_gate.py`, `tests/unit/nuisance/gate/test_nuisance_gate_recording.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_given.py`, `tests/unit/nuisance/gate/support/nuisance_gate_baselines.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_selection_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_selection.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/cve/nuisance/holdout_servers.py`
- **Do**:
  - Fix 8.1: `retested` in `_retested` and the five tests, `recorded` in `_pending`, and the two test renames.
  - Fix 8.2: remove `package` from `a_candidate` and `commit` from `an_unconfirmed_baseline`. The `runs` of `a_server_result` is fix 9.4's, so `nuisance_report_runs.py` is not touched here.
  - Fix 8.3: delete `test_nuisance_gate_selection_given.py`, and the test writes `holdout_runs.a_server("npm:not-current")`.
- **Test**: Test renames and locals only, assertions unchanged.
- **Verify**: The closing check.

### Step 24: Gate report and command test support

- **Fixes**: 8.4, 8.5, 8.6. Their text at plan lines 790-793, 850-885.
- **Files**: `tests/unit/nuisance/gate/support/nuisance_gate_reports.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_console_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_report.py`, `tests/unit/nuisance/gate/test_nuisance_gate_console.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_report_then.py`
- **Do**:
  - Fix 8.4: `an_inconclusive_server_with_an_alarm` builds through `compare_server`, with `ServerCandidate` written directly, and the report and both tests are renamed.
  - Fix 8.5: the renames to `arguments_for_one_gate_server`, `arguments_beside_an_unrecorded_server`, `arguments` and `_arguments_with_a_report`.
  - Fix 8.6: `git mv` the report given to `test_nuisance_gate_report_then.py`, import it as `then` at the 7 call sites.
- **Test**: Test-only. Same assertions, now reaching the real `compare_server` detail. `test_code_standards.py` checks the pair.
- **Verify**: The closing check.

### Step 25: The report, markdown and statistic use what both holdout runs share

- **Fixes**: 9.1, 9.2, 9.5. Their text at plan lines 886-925, 952-963.
- **Files**: `evals/cve/nuisance/markdown.py`, `evals/cve/nuisance/report.py`, `evals/cve/holdout_statistic.py`, `evals/cve/nuisance/statistic.py`
- **Do**:
  - Fix 9.1: `markdown.py` and `report.py` import the shared lines of `holdout_report_lines`. A short `_incomplete_runs_lines(report)` stays. `throttled_lines` stays in `eval_display`.
  - Fix 9.2: public `MIN_SIDE` and `rate_controls` in `holdout_statistic.py`, delete `_hierarchical`, and both suites call it, each adding its fifth key.
  - Fix 9.5: the comment on `incomplete_runs_by_cause`.
- **Test**: No test changes. The report and statistic tests pin the rendered lines and all five intervals, with keys and order identical.
- **Verify**: The closing check.

### Step 26: Report test support and the term split flaw

- **Fixes**: 9.3, 9.4, 9.6, 9.7. Their text at plan lines 886-889, 926-951, 964-991.
- **Files**: `tests/unit/nuisance/test_nuisance_report.py`, `tests/unit/nuisance/support/test_nuisance_report_given.py`, `tests/unit/nuisance/support/nuisance_report_runs.py`, `tests/unit/nuisance/test_nuisance_statistic.py`, `tests/unit/nuisance/support/test_nuisance_counting_given.py`, `docs/glossary.md`
- **Do**:
  - Fix 9.3: `report_models()` in the given and `COUNTS_NAMING_RESPONSES` in the test. See it red once with a temporary `response_text: str` on `ServerRunLine`, then remove that field.
  - Fixes 9.4 and 9.7: the `runs` parameter and the local `RUNS` go, and the two locals are renamed.
  - Fix 9.6: the **split flaw** entry in `docs/glossary.md`, after **holdout nuisance rate**, after the fresh-agent check of the new term.
- **Test**: Same values and assertions. `tests/integration/committed/project/test_glossary.py` stays green.
- **Verify**: The closing check.

### Step 27: The admission's load checks leave its schema

- **Fixes**: 10.1. Its text at plan lines 992-1011.
- **Files**: `tests/unit/support/nuisance_admissions.py`, `tests/unit/support/committed_nuisance_admission.py`, `tests/unit/nuisance/admission/test_nuisance_admission.py`, `tests/integration/committed/nuisance/admission/test_nuisance_admission_loads.py`, `tests/integration/committed/nuisance/admission/test_nuisance_walk_record_loads.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/admission_load.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/commands.py`
- **Do**:
  - A pure move: create `admission_load.py` with `load_admission`, `admission_problems` and their private checks, unchanged and in the same order. `admission.py` keeps `ADMISSION_PATH` and the models, and drops every import only the checks used.
  - `admission_walk.py` imports `AdmittedServer` and `NuisanceAdmission` plainly. `counting.py` stays byte-identical.
  - Repoint the importers the fix lists. `test_the_committed_admission_loads` calls `the_committed_admission()`.
- **Test**: Import lines and the one-line load test. `test_kit_isolation` and `test_cve_dossier_closure` stay green.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.admission.admission:load_admission evals.cve.nuisance.admission.admission:admission_problems`.

### Step 28: Admission references, version checks and record names

- **Fixes**: 10.2, 10.3, 10.4, 10.5, 10.8. Their text at plan lines 992-997, 1012-1065, 1094-1105.
- **Files**: `tests/unit/support/nuisance_admissions.py`, `tests/unit/nuisance/support/test_nuisance_counting_given.py`, `tests/unit/nuisance/test_nuisance_counting.py`, `evals/cve/nuisance/admission/admission_load.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/admission_records.py`, `docs/glossary-log.md`
- **Do**:
  - Fix 10.2: frozen `AdmissionReferences` above `admission_problems`, built in `load_admission` and in `problems_of`.
  - Fix 10.3: `_version_of_no_counted_flaw` and `_server_patched_surfaces_problems` right below their caller.
  - Fix 10.4: the two docstrings as written.
  - Fix 10.5: `_conflicting_benign_calls` and its `docs/glossary-log.md` line.
  - Fix 10.8: `a_tool_recording_declared_function` and `a_removed_tool_recording_declared_function`, with `is_effect` keyword-only, at every call.
- **Test**: Problem messages and their order stay pinned by `test_nuisance_admission.py` and the admission walk tests.
- **Verify**: The closing check.

### Step 29: Unrecorded fields and the holdout calibration copy

- **Fixes**: 10.6, 10.7. Their text at plan lines 992-997, 1066-1093.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_unrecorded.py`, `tests/unit/nuisance/admission/support/test_nuisance_dossier_then.py`, `evals/cve/nuisance/admission/unrecorded.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/holdout_calibration_copies.py`, `evals/cve/nuisance/admission/re_admission_dossier.py`, `evals/cve/nuisance/fix_check_command.py`
- **Do**:
  - Fix 10.6: the local `unrecorded`, the three test renames, `unrecorded_field`, and `[line]` in the then.
  - Fix 10.7: a plain `@property` `is_holdout_calibration_copy` on `FixCheckRecord`, never `computed_field`, used at the four sites. `source == "fix_check"` in `admission_records` stays.
- **Test**: Test renames, same assertions. The model-inputs golden does not move.
- **Verify**: The closing check.

### Step 30: The nuisance walk reads its criteria and marks with exits

- **Fixes**: 11.1, 11.2. Their text at plan lines 1106-1139.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_walk.py`, `tests/unit/nuisance/test_nuisance_holdout_servers.py`, `tests/unit/nuisance/support/test_nuisance_holdout_servers_given.py`, `evals/cve/nuisance/admission/walk.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/holdout_servers.py`, `docs/glossary-log.md`, `CHANGELOG.md`
- **Do**:
  - Tests first for fix 11.2: replace `ServerMark.EXCLUDED` and `ServerMark.ACCEPTANCE_TARGET_SERVER` by the `ExitReason` members. `test_an_excluded_server_is_marked_excluded` goes red.
  - Fix 11.1: `_met` reads `criteria_met`, and `_tools_reached` keeps the `STDIO_TOOLS_CALL` exception outside it.
  - Fix 11.2: `NuisanceServer.mark` is `ExitReason | None`, delete `ServerMark` and `MARK_REASONS`, add the `docs/glossary-log.md` row and the `CHANGELOG.md` line for the printed tag.
- **Test**: `_mark` returns the exit. Exits, audited and pending servers stay identical on the committed admission.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.admission.walk:ServerMark evals.cve.nuisance.admission.admission_walk:MARK_REASONS`.

### Step 31: standing_exit on the server and the walk's local names

- **Fixes**: 11.3, 11.4, 11.5, 11.9, 11.14. Their text at plan lines 1106-1111, 1140-1181, 1224-1235, 1284-1295.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_walk.py`, `tests/unit/support/nuisance_admissions.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/holdout_servers.py`, `evals/cve/nuisance/gate/gate_servers.py`, `evals/cve/nuisance/admission/walk.py`
- **Do**:
  - Fix 11.3: `AdmittedServer.standing_exit` property, read in `addition_entries`, `run_population` and `gate_servers`. `gate_servers.py` and `holdout_servers.py` drop their import of `admission_walk`.
  - Fixes 11.4, 11.5 and 11.14: the renames of parameters and locals as written.
  - Fix 11.9: split the settlement test into its three tests.
- **Test**: Same behaviors, the settlement test now in three, with one assertion each.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.admission.admission_walk:standing_exit`.

### Step 32: The walk's test builders

- **Fixes**: 11.6, 11.10, 11.13. Their text at plan lines 1106-1111, 1182-1195, 1236-1247, 1272-1283.
- **Files**: `tests/unit/support/nuisance_admissions.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `tests/unit/nuisance/support/test_nuisance_vet_given.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`, `tests/unit/nuisance/admission/test_nuisance_admission_walk.py`, `tests/unit/nuisance/admission/support/test_nuisance_walk_record_given.py`, `tests/unit/nuisance/admission/test_nuisance_walk_record.py`, `tests/unit/nuisance/test_run_nuisance.py`
- **Do**:
  - Fix 11.6: `a_census_with_a_nuisance_acceptance_server` and `admitting_the_nuisance_acceptance_server` at every call.
  - Fix 11.10: delete `paired` and the two aliases, and the test writes `WalkInputs(...)` and the `walks` builders.
  - Fix 11.13: remove the unused `monkeypatch` parameter.
- **Test**: Test-only. Same assertions, `ruff format` reflows the long calls.
- **Verify**: The closing check.

### Step 33: The committed inputs' arguments, the followed draw and the term queue

- **Fixes**: 11.7, 11.8, 11.11, 11.12. Their text at plan lines 1106-1111, 1196-1223, 1248-1271.
- **Files**: `evals/cve/nuisance/commands.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/fix_check_command.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/holdout_run_command.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/cve/nuisance/admission/walk_record.py`, `docs/glossary.md`
- **Do**:
  - Fix 11.7: `add_committed_input_arguments` in `commands.py`, called from the six parsers. Remove the imports each module no longer uses, and grep the five modules for a kept constant.
  - Fix 11.8: public `followed_draw`, read by `settlements_by_flaw` and `run_nuisance._walk`.
  - Fix 11.12: the module docstring reduced to its first sentence.
  - Fix 11.11: the **queue** entry in `docs/glossary.md`, after the fresh-agent check of the new term.
- **Test**: No test changes. The parser tests drive these flags, and `test_reached_identifiers_raises_without_a_draw` keeps its message.
- **Verify**: The closing check.

### Step 34: The refusals and docs name the nuisance walk

- **Fixes**: 11.15. Its text at plan lines 1106-1111, 1296-1309.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_admission_walk.py`, `tests/unit/nuisance/admission/support/test_nuisance_admission_walk_given.py`, `tests/unit/nuisance/test_run_nuisance.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/admission/walk_record.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/holdout_servers.py`, `evals/cve/nuisance/markdown.py`, `evals/run_nuisance.py`, `CONTRIBUTING.md`, `CHANGELOG.md`, `CLAUDE.md`
- **Do**:
  - Tests first: change the pins at `test_nuisance_admission_walk.py:19`, `:72`, `:134` and `test_run_nuisance.py:32`, plus the docstring of the admission walk given. See them red.
  - Write `the nuisance walk` in the messages, the `walk` header and the docstrings and comments the fix lists. `admission.py` already reads it since fix 10.4, so nothing is left to do there. Reflow f-strings past 100 columns with no byte changed beyond the added word.
  - `CLAUDE.md` (lines 47 and 50 at planning time, find them by their text), `CONTRIBUTING.md` (`the detection walk` on one line, `the nuisance walk` for the nine mentions of the next), and the Changed line of `CHANGELOG.md`.
- **Test**: Only strings change, and the committed admission still loads. `docs/evals.md` stays out of this fix.
- **Verify**: The closing check.

### Step 35: The first-admission texts leave the dossier writer

- **Fixes**: 12.1, 12.2. Their text at plan lines 1310-1343.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_dossier.py`, `evals/cve/nuisance/admission/dossier.py`, `evals/cve/nuisance/admission/admission_docs.py`, `evals/cve/nuisance/admission/re_admission_docs.py`
- **Do**:
  - Write the `before` dossiers first.
  - Fix 12.1: `KIT_BACKEND_PARAGRAPHS` replaces `_BACKENDS`, under its comment.
  - Fix 12.2: create `admission_docs.py`. Names that change on the move, since they cross a module: `_ADMISSION_GRAMMAR_CLASSES` to `ADMISSION_GRAMMAR_CLASSES`, `_fixture_format` to `fixture_format`, `_readme` to `admission_readme`, and `_IMAGE` of `re_admission_docs.py` to `IMAGE_PLACEHOLDER`.
  - `_paired` moves there too, and `confinement_options()` returns the joined markdown list that both callers build today from `_paired(confinement_args())`. `re_admission_docs.py` keeps `_NAME`, `confinement_text` and `re_admission_readme`, and imports `confinement_options` and `IMAGE_PLACEHOLDER` one way.
  - `dossier.py` drops the imports only the moved texts used. `test_nuisance_dossier.py` imports `admission_confinement_text` from `admission_docs`.
- **Test**: The refusal tests and `test_a_backend_dossier_imports_closed` stay green, as do `test_kit_isolation.py` and `test_cve_dossier_closure.py`.
- **Verify**: The closing check. The dossier comparison finds no difference. Stale-import scan: `evals.cve.nuisance.admission.re_admission_docs:admission_confinement_text`.

### Step 36: Re-admission dossier tests and copied_holdout_targets

- **Fixes**: 12.3, 12.4, 12.5, 12.6, 12.7, 12.9, 12.10. Their text at plan lines 1310-1315, 1344-1413, 1428-1453.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/unit/nuisance/test_run_nuisance_dossier.py`, `tests/unit/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, `tests/integration/committed/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/unit/nuisance/admission/test_nuisance_dossier.py`, `tests/integration/committed/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, `tests/integration/committed/nuisance/admission/support/__init__.py`, `evals/cve/nuisance/admission/re_admission_dossier.py`, `docs/glossary-log.md`
- **Do**:
  - Write the `before` dossiers first.
  - In this order: fix 12.3, fix 12.4 (`a_server_copying(*flaw_ids)` absorbs `_copying`, no test moves to `tests/integration/committed`), fix 12.5, fix 12.6.
  - Fix 12.7: rename to `copied_holdout_targets`, with its `docs/glossary-log.md` line. `write_holdout_target_references` keeps its name.
  - Fix 12.9: build the two expected commands from `SENTINEL_IMAGE` and `STAND_IN_IMAGE`.
  - Fix 12.10: delete the test, the committed given and the `support/__init__.py` left alone beside it.
- **Test**: Same assertions on fictional inputs where the fixes say so, with two tests fewer. Fix 12.5's test also checks the card and `reference/docker`.
- **Verify**: The closing check. The dossier comparison finds no difference. Stale-import scan: `evals.cve.nuisance.admission.re_admission_dossier:holdout_target_references`.

### Step 37: The holdout target reference and the term dossier

- **Fixes**: 12.8, 12.11. Their text at plan lines 1310-1315, 1414-1427, 1454-1465.
- **Files**: `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py`, `tests/unit/nuisance/admission/test_nuisance_dossier.py`, `tests/unit/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py`, `tests/unit/nuisance/admission/support/holdout_reference_checks.py`, `tests/unit/nuisance/admission/support/holdout_target_reference_checks.py`, `docs/glossary.md`, `docs/glossary-log.md`, `evals/cve/nuisance/admission/dossier.py`, `evals/cve/nuisance/admission/holdout_target_reference.py`
- **Do**:
  - Write the `before` dossiers first.
  - Fix 12.8: `git mv` `holdout_reference_checks.py` to `holdout_target_reference_checks.py`, then the test, given and helper renames, and the docstrings of `dossier.py` and `holdout_target_reference.py`. The dated line of `docs/nuisance-suite-log.md` stays.
  - `docs/glossary-log.md`: the line of the given and `holdout reference` to `holdout target reference`. `docs/glossary.md`: the **holdout target reference** entry after **holdout calibration copy**, and fix 12.11's **dossier** under "Words with several senses", between **declared** and **eval**, both after the fresh-agent check.
- **Test**: Test names and `SHAPES` ids change, not their assertions. The committed glossary and retired-word tests stay green.
- **Verify**: The closing check. The dossier comparison finds no difference.

### Step 38: Fingerprint sources and the tests around them

- **Fixes**: 13.1, 13.2, 13.3, 13.4, 13.10, 13.11. Their text at plan lines 1466-1521, 1594-1621.
- **Files**: `tests/unit/nuisance/support/test_nuisance_fingerprint_given.py`, `tests/unit/nuisance/test_nuisance_fingerprint.py`, `tests/integration/test_nuisance_doris_backend.py`, `tests/integration/committed/nuisance/test_nuisance_fingerprint.py`, `tests/integration/committed/nuisance/test_nuisance_backend_registry.py`, `evals/cve/nuisance/fingerprint.py`, `evals/cve/detection/baseline.py`, `docs/glossary-log.md`
- **Do**:
  - Tests first for fixes 13.1 to 13.3, one pass on the same file and its given: the fictional stand-in directory, `with_provenance_records`, `with_a_moved_exploit_and_a_settlement`, and the two backend tests on `a_backend_registry()`.
  - Fix 13.1: `stand_ins_directory` as the last field of `NuisanceFixtureSources`, and a second parameter of `host_stand_in_files`, defaulting to today's directory.
  - Fix 13.4: private `_contents_of`, with its `docs/glossary-log.md` line.
  - Fix 13.10: `missing_prerequisite` from the shared support in the Doris test.
  - Fix 13.11: move the served-path test into `test_nuisance_backend_registry.py`, delete the committed `test_nuisance_fingerprint.py`.
- **Test**: The test file falls under 300 lines with no split. The committed fingerprint guards use the defaults and do not change.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.fingerprint:backend_content`.

### Step 39: provisioned_launch and the registry's responders

- **Fixes**: 13.5, 13.6. Their text at plan lines 1466-1471, 1522-1549.
- **Files**: `tests/unit/cve/backends/test_backend_lifecycle.py`, `tests/unit/cve/backends/support/test_backend_lifecycle_given.py`, `evals/cve/nuisance/provisioners.py`, `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/backend_registry.py`, `docs/glossary-log.md`
- **Do**:
  - Tests: the two calls of `test_backend_lifecycle.py` and `test_backend_lifecycle_given.py:149` take the new call form.
  - Fix 13.5: `@contextmanager provisioned_launch(lifecycle, server)` replaces the factory, in `audit.py` and the `backend_registry` docstring, with its `docs/glossary-log.md` line.
  - Fix 13.6: delete `_responder`, and write the atlassian and googleapis entries directly, `served` keeping its values and order.
- **Test**: `test_the_kit_backend_launch_is_the_provisioner_launch` keeps pinning the parity for every registered backend.
- **Verify**: The closing check. Stale-import scan: `evals.cve.nuisance.provisioners:provisioner_of evals.cve.nuisance.provisioners:BackendProvisioner`.

### Step 40: The fix-check command's comparison, guard and exit

- **Fixes**: 13.7, 13.8, 13.9. Their text at plan lines 1466-1471, 1550-1593.
- **Files**: `tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py`, `evals/cve/nuisance/fix_check_command.py`, `CONTRIBUTING.md`, `docs/glossary-log.md`, `CLAUDE.md`
- **Do**:
  - Tests first in `test_nuisance_fix_check_command.py`: `== {}`, the two field reads, the witness rename, `UNKNOWN_FLAW_EXIT`, and the deletion of the no-fixture test.
  - Fix 13.7: delete the wrapper, public `fix_check_mismatches(result, record) -> dict[str, str]` at the place of `_field_mismatches`, and its `docs/glossary-log.md` line.
  - Fix 13.8: the guard is `if admission is None or not admission.servers:`.
  - Fix 13.9: `UNKNOWN_FLAW_EXIT = 2` in `fix_check_command.py`.
  - Docs: write the `CONTRIBUTING.md` sentence once, with `the random witness always excepted`, `2` on a `--flaw` matching no fixture and `4` on a fix check that raises. Add `2 on a --flaw matching no fix-check fixture` to the fix-check line of `CLAUDE.md`.
  - Last: reread the shared `docs/labeling-log.md` entry written at step 1 against the fixes that landed, and correct it if a fix was dropped or reshaped.
- **Test**: The seven comparison tests now run the function production calls, the exit value stays 2, and no printed line changes.
- **Verify**: The closing check.
