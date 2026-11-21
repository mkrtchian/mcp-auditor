# The holdout run renaming, in the code

## Context

Nuisance suite rule v7 (`ba93c1f`) and the glossary renamed the runs of the two holdout layers: "holdout run" now names a run of the holdout layer of either suite, "detection holdout run" and "nuisance holdout run" name one of the two, and "nuisance run" is a renamed word (`docs/glossary-log.md`, rows "holdout run", moved meaning, and "nuisance run", rename, both dated 2026-11-21). The living docs follow the new words. The code does not yet:

- "nuisance run" appears in the prose of `evals/**/*.py` (module and function docstrings, comments, printed messages), in `tests/**/*.py`, in 38 comment lines of `evals/docker/` (Dockerfiles and `compose.yml`), in two class names (`NuisanceRunStatus`, `NuisanceRunResult`), in three module paths (`evals/cve/nuisance/run.py`, `run_status.py`, `run_containers.py`), in eleven test file paths and in four test names.
- "holdout run" appears about 30 times in the detection code where it means the detection holdout run alone, the messages of `run_detection_holdout` included ("holdout run refused").
- `docs/glossary.md` lists, under `Code:`, "`holdout run` in the messages the command prints" for the detection holdout run and "`nuisance run` in the messages the command prints" for the nuisance holdout run: they record the lag, and go once the messages say the term.

Nothing guards the rename: "nuisance run" is not in `tests/unit/support/retired_words.py`, so it can come back. The maintainer chose a complete rename (decided in discussion, 2026-11-21): whatever the retired-word scan would read as "nuisance run" is renamed, identifiers, module paths, test files and test names included, rather than exempted.

This changes no behavior of the auditor or of an instrument beyond the text of the messages two eval commands print. No rule version, no baseline, no fixture fingerprint moves.

## Prerequisite

Implement after `plans/2026-11-21_readme-follow-ups.md` is implemented and committed, on a clean tree. Both touch the retired-word scan's inputs, and this plan's scan must run on the state that plan leaves.

## Approach

1. Record every fixture, image, grammar and counter fingerprint before any edit (see Verification). The rename touches comments, docstrings and strings of modules some fingerprints read. `fingerprint_source` (`evals/baseline.py`) drops comments and the module docstring but keeps function and class docstrings and every string literal, and `dockerfile_instructions` (`evals/cve/images.py`) drops whole-line comments of a Dockerfile. Checked before writing this plan: every hit in a fingerprinted module (the backend modules a nuisance fixture fingerprint reads through `backend_registry.RegisteredBackend.served`, `responder.py` among them, and `ckan.py` and `mcp_ssh_sshd.py`, which detection holdout fixtures also list in `backend_sources`) sits in its module docstring or a comment, and all 38 hits under `evals/docker/` are whole-line comments. The before/after comparison is the proof.
2. Test first: add the retired word and the old names to `tests/unit/support/retired_words.py`, run `uv run pytest tests/unit/project/test_glossary.py -n 0`, and see `test_living_files_use_no_retired_word` red with the list of hits. That list is the work list, plus the occurrences the scan cannot see: its pattern has a literal space, so "nuisance" at a line end and "run" on the next line escapes it. `rg -U -n -i --glob '!*.json' 'nuisance\s*\n[\s#"]*runs?\b' evals tests` lists them, four today: `evals/cve/backends/responder.py:4` (module docstring, fingerprinted, see step 1), `evals/cve/nuisance/audit.py:200` (`gate_run`'s docstring, "unlike the nuisance run's"), `evals/cve/nuisance/holdout_servers.py:4` (module docstring) and `evals/docker/Dockerfile.grok-faf:3` (a whole-line comment, "Doubles as the nuisance run image").
3. Rename until the scan is green, by the rules below.
4. Update the glossary's two `Code:` mentions.

## The retired words

In `tests/unit/support/retired_words.py`:

- A new `RetiredWord("nuisance-run", r"(?i:\bnuisance runs?\b)|\bNuisanceRun(?:Result|Status)\b", re.NOFLAG)`, beside the other `nuisance-…` entries. The scan reads a path and a test name with `_`, `/`, `.` and `-` as spaces, so this one pattern catches `evals/cve/nuisance/run.py`, `test_nuisance_run_backends.py` and `def test_a_nuisance_run_refuses_…`. It does not match `run_nuisance` (no word boundary after `_`) nor `NUISANCE_RUNS` (an underscore, not a space, in the content).
- The eleven old test stems added to `_OLD_TEST_STEMS`, keeping its order: `test_nuisance_run`, `test_nuisance_run_backends`, `test_nuisance_run_containers`, `test_nuisance_run_interrupted`, `test_nuisance_run_status`, `test_nuisance_run_sweep`, `test_run_nuisance_run`, `test_nuisance_run_backends_given`, `test_nuisance_run_given`, `test_nuisance_run_then`, `test_run_nuisance_run_given`. The "nuisance-run" pattern already catches them in a path; the `moved-test` pattern catches a reference to one in content (an import, a mention), where no underscore is read as a space.
- The three old module paths: `evals[./]cve[./]nuisance[./]run(?:_status|_containers)?\b`, added to the existing retired word that lists moved modules (the one whose pattern contains `evals[./]probe`), or as its own `RetiredWord` beside it if that entry's id does not fit. It catches an import or a path written in prose, and leaves `evals.cve.nuisance.holdout_run` alone.

## Renames

### Modules

| Old | New | Why |
|---|---|---|
| `evals/cve/nuisance/run.py` | `evals/cve/nuisance/holdout_run.py` | The orchestrator of the nuisance holdout run, like `evals/cve/detection/holdout_run.py`. |
| `evals/cve/nuisance/run_status.py` | `evals/cve/nuisance/holdout_run_status.py` | The status line the nuisance holdout run prints. |
| `evals/cve/nuisance/run_containers.py` | `evals/cve/nuisance/containers.py` | Shared by the run, the vet (`vet_command.py`, `vetting.py`) and the gate (`gate/gate_session.py`): the images of a nuisance command and their containers. Its docstring says so. |

Move with `git mv` so history follows. Update every import (`evals/run_nuisance.py`, `evals/cve/nuisance/vet_command.py`, `vetting.py`, `fix_check_command.py`, `gate/gate_command.py`, `gate/gate_session.py`, the moved modules themselves, and the tests). `NUISANCE_CONCURRENCY`, imported by the vet, the gate and the fix check, stays in `holdout_run.py`: moving it is out of scope. The orchestrator's module docstring also names two of the moved modules as bare words ("the container hygiene `run_containers`'", "the status line … `run_status`'s"), which no retired pattern catches: write `containers` and `holdout_run_status` there.

### Identifiers

- `NuisanceRunStatus` → `NuisanceHoldoutRunStatus` and `NuisanceRunResult` → `NuisanceHoldoutRunResult` (`evals/cve/nuisance/results.py`), with every use. Both serve the nuisance holdout run alone (the assembly, the statistic, the report, the run files). Their JSON field names do not change, so the committed run results under `evals/cve/holdout_runs/` still load.
- `HoldoutRunStatus` → `DetectionHoldoutRunStatus` and `HoldoutRunResult` → `DetectionHoldoutRunResult` (`evals/cve/detection/holdout_results.py`), with every use. Both serve the detection holdout run alone, and they leave the `detection` package (`evals/cve/run_files.py`, whose `write_result` takes either suite's result, and `tests/unit/support/holdout_runs.py`), where no package qualifies them and "holdout run" now names either suite's run (CLAUDE.md: a word whose meaning moved is written only in its current sense). Neither name sits in a fingerprinted module or in a committed JSON file.
- `_REFUSAL = "nuisance run refused"` keeps its name, its value changes (see Messages).
- Unchanged, since the scan does not read them as "nuisance run" and they name something else: `run_nuisance` (the orchestrator function, after the command module `evals/run_nuisance.py`), `NUISANCE_RUNS` (the number of runs), `NuisanceDeps`, `RunProvenance`, `RunImages`, `run_images`, `sweep_run_containers`, `RunCount`, `run_status_line`, `print_run_status`, and the detection identifiers that stay inside a module its `detection` package or file prefix already qualifies (`run_holdout_targets`, `HoldoutDeps`, `_ReadyHoldoutRun` in `evals/run_detection_holdout.py`, `evals/cve/detection/holdout_run.py`, `tests/unit/detection/test_detection_holdout_run*.py`).

### Test files

`git mv`, then update every import of the moved given and then modules, not only the moved test files': `test_nuisance_run_given` and `test_nuisance_run_backends_given` are imported by about twenty other test modules (among them `tests/unit/cve/test_cve_closed_network_refusal.py`, `tests/unit/nuisance/gate/support/nuisance_gate_sessions.py`, `tests/unit/nuisance/gate/test_nuisance_gate_*.py`, `tests/unit/nuisance/support/test_nuisance_{assembly,holdout_servers,solo,vet,vetting}_given.py`, `tests/unit/nuisance/test_nuisance_{audit_once,backend_registry_built,retry_policy,solo,vet}.py`, `tests/unit/nuisance/test_run_nuisance_vet.py`). `git grep -nE "test_(run_)?nuisance_run(_backends)?_(given|then)" -- tests` lists them, and the `moved-test` word flags any left.

| Old | New |
|---|---|
| `tests/unit/nuisance/test_nuisance_run.py` | `test_nuisance_holdout_run.py` |
| `tests/unit/nuisance/test_nuisance_run_backends.py` | `test_nuisance_holdout_run_backends.py` |
| `tests/unit/nuisance/test_nuisance_run_containers.py` | `test_nuisance_containers.py` (it tests `containers.py`) |
| `tests/unit/nuisance/test_nuisance_run_interrupted.py` | `test_nuisance_holdout_run_interrupted.py` |
| `tests/unit/nuisance/test_nuisance_run_status.py` | `test_nuisance_holdout_run_status.py` |
| `tests/unit/nuisance/test_nuisance_run_sweep.py` | `test_nuisance_holdout_run_sweep.py` |
| `tests/unit/nuisance/test_run_nuisance_run.py` | `test_run_nuisance_holdout_run.py` (like `tests/unit/detection/test_run_detection_holdout_run.py`) |
| `tests/unit/nuisance/support/test_nuisance_run_backends_given.py` | `test_nuisance_holdout_run_backends_given.py` |
| `tests/unit/nuisance/support/test_nuisance_run_given.py` | `test_nuisance_holdout_run_given.py` |
| `tests/unit/nuisance/support/test_nuisance_run_then.py` | `test_nuisance_holdout_run_then.py` |
| `tests/unit/nuisance/support/test_run_nuisance_run_given.py` | `test_run_nuisance_holdout_run_given.py` |
| `tests/unit/support/holdout_runs.py` | `detection_holdout_runs.py` (a detection holdout run on scripted audits, shared with `tests/unit/cve/`, so it stays in `tests/unit/support/`, where no `detection` directory qualifies its name) |

The last row is a detection helper: update its seven importers (`tests/unit/cve/test_cve_closed_network_refusal.py`, `tests/unit/detection/test_detection_holdout_run{,_containers,_interrupted,_pre_run}.py`, `tests/unit/detection/support/test_detection_holdout_run_interrupted_given.py`, `tests/unit/detection/support/test_run_detection_holdout_run_given.py`), listed by `git grep -n "support.holdout_runs\|support import holdout_runs" -- tests`. `evals/cve/holdout_runs/` keeps its name (see What stays unchanged).

### Test names

The four tests whose name reads "nuisance run" take "nuisance holdout run": `test_the_nuisance_run_launch_mounts_the_callers_known_hosts_read_only`, `test_a_nuisance_run_refuses_before_any_rebuild`, `test_a_missed_model_call_on_a_nuisance_run_prints_its_cause_without_the_provider_message`, `test_a_launch_failure_on_a_nuisance_run_carries_the_error_type_without_its_message`. The scan's red list is the authority if it names more.

The four tests whose name reads "holdout run" for the detection holdout run alone take "detection holdout run", by the Prose rule below (the scan does not list them, the generic term not being retired): `test_a_holdout_run_refuses_before_any_rebuild` (`tests/unit/cve/test_cve_closed_network_refusal.py`, beside the nuisance one renamed above), and `test_a_run_skipped_on_a_holdout_run_prints_the_error_type_without_its_message`, `test_a_missed_model_call_on_a_holdout_run_prints_its_cause_without_the_provider_message`, `test_a_server_taken_as_down_on_a_holdout_run_drops_the_run_as_a_launch_failure` (`tests/unit/detection/test_detection_audit_holdout.py`). `git grep -nE "def \w*holdout_run\w*" -- tests | grep -v detection_holdout_run` lists them.

## Messages

What the two commands print, and the tests that read it:

| Command | Old | New |
|---|---|---|
| `run_detection_holdout run` (`evals/run_detection_holdout.py`, `evals/cve/detection/holdout_run.py`) | `holdout run refused` | `detection holdout run refused` |
| same | `…; a holdout run keeps no trace` | `…; a detection holdout run keeps no trace` |
| same | `the git tree is dirty: a holdout run publishes from a clean tree` | `the git tree is dirty: a detection holdout run publishes from a clean tree` |
| `run_nuisance run` (`evals/run_nuisance.py`, `evals/cve/nuisance/holdout_run.py`) | `nuisance run refused` | `nuisance holdout run refused` |
| same | `…; a nuisance run keeps no trace` | `…; a nuisance holdout run keeps no trace` |
| same | `the git tree is dirty: a nuisance run publishes from a clean tree` | `the git tree is dirty: a nuisance holdout run publishes from a clean tree` |

Tests asserting the old nuisance text: `tests/unit/nuisance/admission/test_nuisance_unrecorded.py` (three lines, the title passed and read back), `tests/unit/nuisance/test_nuisance_run_sweep.py` (`match="nuisance run refused"`), `tests/unit/nuisance/test_run_nuisance.py` (`"nuisance run refused" in out`). Change their expected text with the message, in the same step. No test reads the detection messages today: add none (a test that pins a literal against its literal is the kind the project removes).

## Prose

Every comment, module docstring, function docstring and string in `evals/`, `tests/` and `evals/docker/` that the scan lists, plus the detection prose the scan cannot list (the generic "holdout run" is not retired). Rules:

- "nuisance run" meaning the run of the nuisance holdout layer (the `run` command, its orchestrator, its result, its report) → "nuisance holdout run". Examples: `evals/cve/nuisance/results.py` ("The result value objects of a nuisance run"), `report.py`, `audit.py:84`, `holdout_servers.py`, `vetting.py` ("The vet of a nuisance run"), `gate/gate_report.py` ("Unlike the nuisance run's report"), `gate/gate_baseline.py` ("the nuisance run's" conditions), `evals/cve/backends/n8n.py:20` ("This is the nuisance run's backend").
- "nuisance run(s)" meaning the repeated runs or launches of a server under any nuisance command → "runs", without the suite word. Examples: the backend modules' "reused across a server's concurrent nuisance runs" (`atlassian.py`, `ckan.py`, `facebook_ads.py`, `googleapis.py`, `gravitino.py`, `httpbin.py`, `jenkins.py`, `mcp_ssh_sshd.py`, `n8n.py`) → "reused across a server's concurrent runs"; `fix_checks/cve_2026_41041_gravitino.py` ("where every nuisance run reads") reads in context.
- "a holdout or nuisance run", "the holdout and nuisance runs" (`evals/cve/run_files.py`, `evals/cve/run_interruption.py`, `evals/cve/failure_text.py`) → "a holdout run", "holdout runs": the generic term now covers both.
- "holdout run" meaning the detection holdout run alone → "detection holdout run". That is every occurrence in `evals/cve/detection/` (`holdout_audit.py`, `holdout_card_readiness.py`, `holdout_pre_run_check.py`, `holdout_report.py`, `holdout_results.py`, `holdout_run.py`, `holdout_targets.py`, `layout_check.py`, `measurement.py`), `evals/run_detection_holdout.py`, `evals/cve/nuisance/holdout_run.py` (its docstring's "the run conditions of a holdout run" and the comment's "the holdout run's HOLDOUT_BUDGET"), `tests/unit/detection/` (the docstrings and comments listed by `git grep -ni "holdout run" -- tests/unit/detection`) and `tests/unit/support/detection_holdout_runs.py` (moved from `holdout_runs.py`, see Test files).
- "holdout run" stays where it means either suite (`evals/cve/holdout_conditions.py`: both commands read `evals/holdout_conditions.json`; `evals/README.md`; `tests/conftest.py:6`, "a later holdout run refuses on tracing", which both commands do) and where it quotes the detection suite rule, whose text keeps the word (detection suite rule v13 is unchanged): the section title "(A holdout run audits every target)" in `evals/cve/detection/baseline.py` and `evals/cve/nuisance/holdout_run.py` stays verbatim.
- In `evals/docker/`, a comment calling a server image the "nuisance run image" names the image every nuisance command launches (run, vet, gate, the fix check's patched arm): write "the image the nuisance suite audits", adapting the sentence ("Nuisance run image of android (rule v4): …" → "The image the nuisance suite audits for android (rule v4): …", "Doubles as the nuisance run image." → "Doubles as the image the nuisance suite audits."). "the nuisance run mounts no layout" → "the nuisance suite mounts no layout". "It is never built or started by a nuisance run: the run's graph.facebook.com stand-in is …" (`Dockerfile.facebook-ads-sentinel`) → "by a nuisance command: the stand-in those commands launch for graph.facebook.com is …". The two `compose.yml` comments read in context: the run command → "nuisance holdout run".
- A sentence the rules above do not settle is rewritten to say what it said with the new word, never left as is (the scan must end green with no allowlist entry), and listed in the step's summary for the maintainer to reread.

A function docstring or a string in a fingerprinted module moves its fingerprint (see Approach). If the before/after check shows a moved fingerprint, revert the edit that moved it and report it: a reset is out of scope. None is expected (Approach, step 1); a revert that leaves a scan hit stops the step for the maintainer rather than adding an allowlist entry.

## Glossary

In `docs/glossary.md`:
- **detection holdout run**: `Code: \`python -m evals.run_detection_holdout run\`, \`holdout run\` in the messages the command prints.` → `Code: \`python -m evals.run_detection_holdout run\`.`
- **nuisance holdout run**: `Code: \`python -m evals.run_nuisance run\`, \`nuisance run\` in the messages the command prints.` → `Code: \`python -m evals.run_nuisance run\`.`

No other glossary change: no term is added or moved. `docs/glossary-log.md` already carries both rows; nothing is added to it.

## What stays unchanged

- The rules, their logs, ADRs, plans, the glossary log, the published CHANGELOG sections: historical text, which the scan does not read.
- `evals/cve/holdout_runs/` (the directory name is the generic term, and its committed reports and results are records).
- `NUISANCE_RUNS`, its value and its log entry. The command names `run_detection_holdout run` and `run_nuisance run`.
- `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `docs/usage.md`, `docs/evals.md`: they already use the new words and name none of the renamed modules (checked with `git grep`).
- `CHANGELOG.md`: the messages are the eval commands', which the maintainer reads; the auditor's users see no change.
- Every fingerprint, baseline, admission record and golden file.

## Edge cases

- A commit of the rename that leaves an import on an old module path breaks collection: the moves and the import updates land in one step.
- `evals/cve/nuisance/__init__.py` and any `__all__` or re-export: check them for the old module names.
- `.pyc` caches of the old modules cannot let a stale import pass: Python never imports a `__pycache__` file whose source is gone, so a missed import fails without any cache cleanup.
- The `moved-test` and moved-module patterns would also fire on a living text that names an old path on purpose; there is none today.
- A string in a test given that builds a message the code prints (a fake refusal title) follows the code's new text.

## Test scenarios

No new behavior, so no new test beyond the retired words, which are the test-first red: the scan fails on the old words before the rename and passes after. The existing suites cover the moved modules and the renamed classes. The changed message assertions are the three nuisance tests listed under Messages.

## Verification

- Before any edit, in the scratchpad (never in the repository): a short script that computes, with the existing functions, `fixture_fingerprint` (`evals/cve/detection/baseline.py`) of every acceptance and holdout target, `grammar_fingerprint()`, `counter_fingerprint()` (`evals/cve/nuisance/counter.py`), `nuisance_fixture_fingerprint` (`evals/cve/nuisance/fingerprint.py`) of every admitted server of `evals/nuisance_admission.json`, and `dockerfile_fingerprint` (`evals/cve/images.py`) of every service of `evals/docker/compose.yml`, and writes them as sorted JSON. Run it again after the rename (with the new import paths if it imports a moved module) and `diff` the two files: they must be identical. No Docker, no network.
- `uv run pytest tests/unit/project/test_glossary.py -n 0`: red after the retired words land, green at the end, with no new allowlist entry in `tests/unit/support/retired_word_exemptions.py`.
- `git grep -niE "\bnuisance runs?\b" -- evals tests src .github ':!*.json'` returns nothing, and neither does the line-wrapped search `rg -U -n -i --glob '!*.json' 'nuisance\s*\n[\s#"]*runs?\b' evals tests`; `git grep -ni "holdout run" -- evals/cve/detection evals/run_detection_holdout.py evals/cve/nuisance/holdout_run.py tests/unit/detection` returns only "detection holdout run" and the rule's quoted section title (the line-wrapped one in `fixture_fingerprint`'s docstring, `evals/cve/detection/baseline.py:133`, is that title too).
- The short loop, then the closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.
- Neither step builds an image or runs Docker: a Dockerfile comment changes no image fingerprint, so no image goes stale.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, one line each, read by the implementation-phase fact check. It records what was concluded once, on 2026-11-22, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- SETTLED: Python never imports a `__pycache__` `.pyc` whose source file is gone, so a missed import of a moved module fails without any cache cleanup (verified against PEP 3147, peps.python.org/pep-3147: "Python will not import a pyc file from the cache directory unless the source file exists"; no sourceless legacy `.pyc` sits outside `__pycache__` under `evals/` or `tests/` today).
- SETTLED: `RetiredWord("nuisance-run", r"(?i:\bnuisance runs?\b)|\bNuisanceRun(?:Result|Status)\b", re.NOFLAG)` matches the old module and test paths in their spaced form and a "nuisance run" test name, and leaves `run_nuisance`, raw `NUISANCE_RUNS` and every new name alone (verified by running the pattern under the project's Python 3.13, `re.NOFLAG` being 3.11+).
- SETTLED: `evals[./]cve[./]nuisance[./]run(?:_status|_containers)?\b` matches the three old module paths and dotted imports and not `evals.cve.nuisance.holdout_run` (verified by running it under the project's Python 3.13).
- SETTLED: `rg -U -n -i --glob '!*.json' 'nuisance\s*\n[\s#"]*runs?\b' evals tests` finds line-wrapped occurrences (verified with ripgrep 14.1.1 on the current tree: the four sites the plan lists).

## Implementation steps

Commands (from `CLAUDE.md`): the short loop `uv run pytest tests/unit -n auto --maxprocesses 6` (with `-n 0` on the files being changed while red, `--lf` on failures), `uv run pyright <files>` in the loop, and the closing check of every step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`. No step builds an image or runs a Docker command, and none stages or commits for the maintainer.

**Fingerprint check, common to every step.** At the start of each step, before any edit, run the fingerprint script described under Verification and keep its output as `before.json` in the session's scratchpad directory (never in the repository). If a previous step left the script there, reuse it, else write it: it imports `fixture_fingerprint` and `grammar_fingerprint` (`evals/cve/detection/baseline.py`), `counter_fingerprint` (`evals/cve/nuisance/counter.py`), `nuisance_fixture_fingerprint` (`evals/cve/nuisance/fingerprint.py`) and `dockerfile_fingerprint` (`evals/cve/images.py`), none of which this plan moves, and enumerates `ACCEPTANCE_TARGETS` (`evals/cve/detection/targets.py`) with `HOLDOUT_TARGETS` (`evals/cve/detection/holdout_targets.py`) with the places their callers load (see `evals/cve/detection/holdout_run.py`, `fixture_fingerprints=`), the admitted servers of `evals/nuisance_admission.json` loaded the way `evals/run_nuisance.py` loads them, and the services of `evals/docker/compose.yml`, writing sorted JSON. At the end of the step, run it again into `after.json` and `diff` the two: they must be identical. A moved fingerprint means an edit touched a function or class docstring or a string of a fingerprinted module, or a non-comment Dockerfile line: revert that edit and report it. If the revert leaves a hit the step must clear, stop the step for the maintainer (no allowlist entry in `tests/unit/support/retired_word_exemptions.py`, ever).

### Step 1: Move the nuisance modules, rename the nuisance classes, move the nuisance test files

**Files**:
- `tests/unit/support/retired_words.py` (modify)
- Moved with `git mv`: `evals/cve/nuisance/run.py` → `holdout_run.py`, `run_status.py` → `holdout_run_status.py`, `run_containers.py` → `containers.py`, and the eleven test files of the plan's Test files table (every row but the last, `holdout_runs.py`, which is Step 4's)
- Importers updated (modify): `evals/run_nuisance.py`, `evals/cve/nuisance/{vet_command,vetting,fix_check_command,assembly,report,results}.py`, `evals/cve/nuisance/gate/{gate_command,gate_session}.py`, `evals/cve/run_files.py`, the moved modules themselves, and the test modules listed by `git grep -lE "nuisance(\.|/)run(_status|_containers)?\b|test_(run_)?nuisance_run|NuisanceRun(Status|Result)" -- evals tests` (about thirty, among them `tests/unit/cve/test_cve_closed_network_refusal.py`, `tests/unit/cve/backends/test_mcp_ssh_holdout_builder.py`, `tests/unit/nuisance/gate/support/nuisance_gate_sessions.py`, `tests/unit/nuisance/gate/test_nuisance_gate_*.py`, `tests/unit/nuisance/support/*_given.py`, `tests/unit/nuisance/support/nuisance_report_runs.py`, `tests/unit/nuisance/test_nuisance_{assembly,audit_once,backend_registry_built,retry_policy,solo,vet}.py`, `tests/unit/nuisance/test_run_nuisance_vet.py`)

The file count is high, but every edit past the retired words is mechanical (a path, an import, an identifier), done with `git mv` and a `git grep -l … | xargs sed -i` per old name, then read back with `git diff --stat` and the type checker. The moves, the imports and the class renames must land together: a split leaves an import on a missing module and breaks collection.

**Do**:
1. Run the fingerprint check's `before.json` (see above).
2. Test first, in `tests/unit/support/retired_words.py`: add the eleven old test stems to `_OLD_TEST_STEMS` in alphabetical position (`test_nuisance_run`, `test_nuisance_run_backends`, `test_nuisance_run_backends_given`, `test_nuisance_run_containers`, `test_nuisance_run_given`, `test_nuisance_run_interrupted`, `test_nuisance_run_status`, `test_nuisance_run_sweep`, `test_nuisance_run_then`, `test_run_nuisance_run`, `test_run_nuisance_run_given`), and the old module paths `evals[./]cve[./]nuisance[./]run(?:_status|_containers)?\b` to the retired word that already lists moved modules (the one whose pattern contains `evals[./]probe`), or as its own `RetiredWord` beside it if that entry's id does not fit. Do not add the "nuisance-run" word yet (Step 3 adds it, once the prose is renamed). Run `uv run pytest tests/unit/project/test_glossary.py -n 0` and see `test_living_files_use_no_retired_word` red on the old paths and stems.
3. `git mv` the three modules and the eleven test files (new names in the plan's Modules and Test files tables). Check `evals/cve/nuisance/__init__.py` for a re-export of the old names.
4. Update every import and every `evals.cve.nuisance.run…` path in strings (for instance a `monkeypatch.setattr` target, if any). `NUISANCE_CONCURRENCY` stays in `holdout_run.py`.
5. Rename `NuisanceRunStatus` → `NuisanceHoldoutRunStatus` and `NuisanceRunResult` → `NuisanceHoldoutRunResult` (`evals/cve/nuisance/results.py`) with every use. JSON field names unchanged.
6. In `holdout_run.py`'s module docstring, write `containers` and `holdout_run_status` where it names the two moved modules as bare words (`run_containers`, `run_status`).
7. In `containers.py`'s docstring, check that it says the module serves the run, the vet and the gate (adjust it only if it does not; use "nuisance holdout run" for the run if it names it).
8. Rename the four nuisance test names of the plan's Test names section ("nuisance run" → "nuisance holdout run"): `test_the_nuisance_run_launch_mounts_the_callers_known_hosts_read_only` (`tests/unit/cve/backends/test_mcp_ssh_holdout_builder.py`), `test_a_nuisance_run_refuses_before_any_rebuild` (`tests/unit/cve/test_cve_closed_network_refusal.py`), `test_a_launch_failure_on_a_nuisance_run_carries_the_error_type_without_its_message` and `test_a_missed_model_call_on_a_nuisance_run_prints_its_cause_without_the_provider_message` (`tests/unit/nuisance/test_nuisance_audit_once.py`). `git grep -nE "def \w*nuisance_run\w*" -- tests` must list none after.
9. Leave every other occurrence of "nuisance run" in prose for Steps 2 and 3, and every detection name for Step 4.

**Test**: no new behavior. The red retired-word scan of item 2 turns green, and the existing suites cover the moved modules and renamed classes (the moved test files keep their tests unchanged).

**Verify**:
- `uv run pytest tests/unit/project/test_glossary.py -n 0`: red after item 2, green at the end, with no new entry in `tests/unit/support/retired_word_exemptions.py`.
- `git grep -nE "nuisance(\.|/)run(_status|_containers)?\b|test_(run_)?nuisance_run|NuisanceRun(Status|Result)\b" -- evals tests src` returns nothing; `git log --follow --oneline -1 evals/cve/nuisance/holdout_run.py` shows the old history (the moves are renames, not delete and add).
- The fingerprint check: `before.json` and `after.json` identical.
- The short loop, then the closing check, all green.

### Step 2: Rename "nuisance run" in the Docker comments and the backend and fix-check modules

**Files** (modify, one comment or module docstring line each, mostly):
- The 36 files under `evals/docker/` (Dockerfiles and `compose.yml`) listed by `git grep -liE "\bnuisance runs?\b" -- evals/docker`, plus `evals/docker/Dockerfile.grok-faf` (line-wrapped hit, line 3)
- The 9 backend modules listed by `git grep -liE "\bnuisance runs?\b" -- evals/cve/backends` (`atlassian.py`, `ckan.py`, `facebook_ads.py`, `googleapis.py`, `gravitino.py`, `httpbin.py`, `jenkins.py`, `mcp_ssh_sshd.py`, `n8n.py`), plus `evals/cve/backends/responder.py` (line-wrapped hit, module docstring line 4)
- The 2 modules listed by `git grep -liE "\bnuisance runs?\b" -- evals/cve/nuisance/fix_checks`

These files are the bulk of the hits and all sit in fingerprinted inputs (the backend modules a nuisance fixture fingerprint reads, `ckan.py` and `mcp_ssh_sshd.py` also in detection holdout fixtures' `backend_sources`, the Dockerfiles): a step of their own keeps the fingerprint check focused on them. Each edit is a one-line comment rewrite by a fixed rule, so the file count does not reflect the reading load.

**Do**:
1. Run the fingerprint check's `before.json`.
2. Apply the plan's Prose rules to every hit in these files:
   - `evals/docker/`: a comment calling a server image the "nuisance run image" → "the image the nuisance suite audits", adapting the sentence ("Nuisance run image of android (rule v4): …" → "The image the nuisance suite audits for android (rule v4): …", "Doubles as the nuisance run image." → "Doubles as the image the nuisance suite audits."); "the nuisance run mounts no layout" → "the nuisance suite mounts no layout"; `Dockerfile.facebook-ads-sentinel`: "It is never built or started by a nuisance run: the run's graph.facebook.com stand-in is …" → "by a nuisance command: the stand-in those commands launch for graph.facebook.com is …"; the two `compose.yml` comments, read in context, where the run command is meant → "nuisance holdout run". Edit whole-line comments only: a hit on an instruction line stops the step for the maintainer.
   - Backend modules: "reused across a server's concurrent nuisance runs" → "reused across a server's concurrent runs"; `n8n.py:20` "This is the nuisance run's backend" → "nuisance holdout run's"; `responder.py:4`, read in context by the same rules.
   - Fix-check modules: `fix_checks/cve_2026_41041_gravitino.py` ("where every nuisance run reads") and the other hit, read in context: the repeated runs of any nuisance command → "runs" without the suite word, the `run` command → "nuisance holdout run".
   - A sentence these rules do not settle is rewritten with the new word, and listed in the step's summary for the maintainer to reread.
3. Run the fingerprint check's `after.json` and `diff`.

**Test**: no test changes. The retired word that would guard these lines lands in Step 3.

**Verify**:
- `git grep -niE "\bnuisance runs?\b" -- evals/docker evals/cve/backends evals/cve/nuisance/fix_checks` returns nothing, and `rg -U -n -i 'nuisance\s*\n[\s#"]*runs?\b' evals/docker evals/cve/backends evals/cve/nuisance/fix_checks` returns nothing.
- The fingerprint check: `before.json` and `after.json` identical (the proof that every edit stayed in a comment or a module docstring).
- The short loop, then the closing check, all green.

### Step 3: Rename the rest of "nuisance run", the nuisance messages, and retire the word

**Files**:
- `tests/unit/support/retired_words.py` (modify)
- `tests/unit/nuisance/admission/test_nuisance_unrecorded.py`, `tests/unit/nuisance/test_nuisance_holdout_run_sweep.py`, `tests/unit/nuisance/test_run_nuisance.py` (modify: the message assertions)
- `evals/cve/nuisance/holdout_run.py`, `evals/run_nuisance.py` (modify: the messages and prose)
- The remaining prose hits (modify), listed by the red scan of item 2: about twenty files, among them `evals/cve/nuisance/{results,report,audit,holdout_servers,vetting}.py`, `evals/cve/nuisance/gate/{gate_report,gate_baseline}.py`, `evals/cve/{run_files,run_interruption,failure_text}.py`, and the comments and docstrings under `tests/unit/nuisance/`
- `docs/glossary.md` (modify: the nuisance holdout run's `Code:` line)

**Do**:
1. Run the fingerprint check's `before.json`.
2. Test first: add `RetiredWord("nuisance-run", r"(?i:\bnuisance runs?\b)|\bNuisanceRun(?:Result|Status)\b", re.NOFLAG)` to `RETIRED_WORDS`, beside the other `nuisance-…` entries. Run `uv run pytest tests/unit/project/test_glossary.py -n 0`: `test_living_files_use_no_retired_word` red, and its list of hits is the work list. Add to it the line-wrapped sites the scan cannot see: `rg -U -n -i --glob '!*.json' 'nuisance\s*\n[\s#"]*runs?\b' evals tests` (`evals/cve/nuisance/audit.py:200`, `gate_run`'s docstring, "unlike the nuisance run's", and `evals/cve/nuisance/holdout_servers.py:4`, module docstring, once Step 2 has cleared the other two).
3. Messages, with their tests in the same edit: in `evals/cve/nuisance/holdout_run.py` and `evals/run_nuisance.py`, `"nuisance run refused"` → `"nuisance holdout run refused"` (`_REFUSAL` keeps its name), `…; a nuisance run keeps no trace` → `…; a nuisance holdout run keeps no trace`, `the git tree is dirty: a nuisance run publishes from a clean tree` → `the git tree is dirty: a nuisance holdout run publishes from a clean tree`. Change the expected text in `test_nuisance_unrecorded.py` (three lines, the title passed and read back), `test_nuisance_holdout_run_sweep.py` (`match="nuisance run refused"`) and `test_run_nuisance.py` (`"nuisance run refused" in out`), and any test given that builds a fake refusal title with the old text. Run those three files with `-n 0` and see them pass on the new text.
4. Prose, by the plan's Prose rules: "nuisance run" meaning the run of the nuisance holdout layer (the `run` command, its orchestrator, result, report) → "nuisance holdout run" (`results.py` "The result value objects of a nuisance run", `report.py`, `audit.py:84` and `:200`, `holdout_servers.py`, `vetting.py` "The vet of a nuisance run", `gate_report.py` "Unlike the nuisance run's report", `gate_baseline.py` "the nuisance run's" conditions); "nuisance run(s)" meaning the repeated runs of a server under any nuisance command → "runs"; "a holdout or nuisance run", "the holdout and nuisance runs" (`run_files.py`, `run_interruption.py`, `failure_text.py`) → "a holdout run", "holdout runs". Leave "holdout run" meaning the detection holdout run alone for Step 4. A sentence these rules do not settle is rewritten with the new word, and listed in the step's summary.
5. `docs/glossary.md`, entry **nuisance holdout run**: `Code: \`python -m evals.run_nuisance run\`, \`nuisance run\` in the messages the command prints.` → `Code: \`python -m evals.run_nuisance run\`.` No other glossary or glossary-log change.
6. Run the fingerprint check's `after.json` and `diff`.

**Test**: the retired-word scan red then green; the three message tests on the new text. No other new test.

**Verify**:
- `uv run pytest tests/unit/project/test_glossary.py -n 0`: red after item 2, green at the end, with no new entry in `tests/unit/support/retired_word_exemptions.py`.
- `git grep -niE "\bnuisance runs?\b" -- evals tests src .github ':!*.json'` returns nothing, and `rg -U -n -i --glob '!*.json' 'nuisance\s*\n[\s#"]*runs?\b' evals tests` returns nothing.
- The fingerprint check: `before.json` and `after.json` identical.
- The short loop, then the closing check, all green.

### Step 4: Name the detection holdout run in the code

**Files**:
- `evals/cve/detection/holdout_results.py` (modify: the class renames) and their uses: `evals/cve/detection/{holdout_assembly,holdout_report,holdout_run,holdout_target_line}.py`, `evals/cve/run_files.py`, `evals/run_detection_holdout.py`, `tests/unit/cve/test_cve_holdout_statistic.py`, `tests/unit/detection/support/{holdout_report_runs,test_detection_holdout_report_given,test_run_detection_holdout_run_given}.py`
- `tests/unit/support/holdout_runs.py` → `tests/unit/support/detection_holdout_runs.py` (`git mv`) and its seven importers: `tests/unit/cve/test_cve_closed_network_refusal.py`, `tests/unit/detection/test_detection_holdout_run{,_containers,_interrupted,_pre_run}.py`, `tests/unit/detection/support/test_detection_holdout_run_interrupted_given.py`, `tests/unit/detection/support/test_run_detection_holdout_run_given.py` (listed by `git grep -n "support.holdout_runs\|support import holdout_runs" -- tests`)
- Prose (modify): the files listed by `git grep -lni "holdout run" -- evals/cve/detection evals/run_detection_holdout.py evals/cve/nuisance/holdout_run.py tests/unit/detection tests/unit/support/detection_holdout_runs.py tests/unit/cve`
- `docs/glossary.md` (modify: the detection holdout run's `Code:` line)

The identifier renames and the helper move are mechanical (`git mv`, `sed` per name); the prose is about 35 lines over about 20 files under one rule. Nothing guards this step's words (the generic "holdout run" is not retired), so its verification is a scoped `git grep`.

**Do**:
1. Run the fingerprint check's `before.json`.
2. Rename `HoldoutRunStatus` → `DetectionHoldoutRunStatus` and `HoldoutRunResult` → `DetectionHoldoutRunResult` with every use (`git grep -lE "\bHoldoutRun(Status|Result)\b" -- evals tests`). JSON field names unchanged, so the committed results under `evals/cve/holdout_runs/` still load.
3. `git mv tests/unit/support/holdout_runs.py tests/unit/support/detection_holdout_runs.py` and update its seven importers.
4. Rename the four detection test names ("holdout run" → "detection holdout run"): `test_a_holdout_run_refuses_before_any_rebuild` (`tests/unit/cve/test_cve_closed_network_refusal.py`), `test_a_run_skipped_on_a_holdout_run_prints_the_error_type_without_its_message`, `test_a_missed_model_call_on_a_holdout_run_prints_its_cause_without_the_provider_message`, `test_a_server_taken_as_down_on_a_holdout_run_drops_the_run_as_a_launch_failure` (`tests/unit/detection/test_detection_audit_holdout.py`). `git grep -nE "def \w*holdout_run\w*" -- tests | grep -v detection_holdout_run` must list none after.
5. Messages of `run_detection_holdout run` (`evals/run_detection_holdout.py`, `evals/cve/detection/holdout_run.py`): `holdout run refused` → `detection holdout run refused`, `…; a holdout run keeps no trace` → `…; a detection holdout run keeps no trace`, `the git tree is dirty: a holdout run publishes from a clean tree` → `the git tree is dirty: a detection holdout run publishes from a clean tree`. No test reads them today: add none.
6. Prose: "holdout run" meaning the detection holdout run alone → "detection holdout run", in every hit of `evals/cve/detection/` (`holdout_audit.py`, `holdout_card_readiness.py`, `holdout_pre_run_check.py`, `holdout_report.py`, `holdout_results.py`, `holdout_run.py`, `holdout_targets.py`, `layout_check.py`, `measurement.py`), `evals/run_detection_holdout.py`, `evals/cve/nuisance/holdout_run.py` (its docstring's "the run conditions of a holdout run" and the comment's "the holdout run's HOLDOUT_BUDGET"), `tests/unit/detection/` and `tests/unit/support/detection_holdout_runs.py`. Keep "holdout run" where it means either suite (`evals/cve/holdout_conditions.py`, `evals/README.md`, `tests/conftest.py:6`, and what Step 3 wrote in `run_files.py`, `run_interruption.py`, `failure_text.py`) and in the detection suite rule's quoted section title "(A holdout run audits every target)" (`evals/cve/detection/baseline.py`, line-wrapped in `fixture_fingerprint`'s docstring, and `evals/cve/nuisance/holdout_run.py`), verbatim. Leave unchanged the detection identifiers the plan lists as qualified by their module (`run_holdout_targets`, `HoldoutDeps`, `_ReadyHoldoutRun`). A sentence the rule does not settle is rewritten with the new word, and listed in the step's summary.
7. `docs/glossary.md`, entry **detection holdout run**: `Code: \`python -m evals.run_detection_holdout run\`, \`holdout run\` in the messages the command prints.` → `Code: \`python -m evals.run_detection_holdout run\`.`
8. Run the fingerprint check's `after.json` and `diff`.

**Test**: no new test (the renamed classes, the moved helper and the renamed tests are covered by the existing suites; the detection messages get no literal-pinning test).

**Verify**:
- `git grep -ni "holdout run" -- evals/cve/detection evals/run_detection_holdout.py evals/cve/nuisance/holdout_run.py tests/unit/detection` returns only "detection holdout run" and the rule's quoted section title (including the line-wrapped one in `evals/cve/detection/baseline.py`'s `fixture_fingerprint` docstring).
- `git grep -nE "\bHoldoutRun(Status|Result)\b|support(\.| import )holdout_runs\b" -- evals tests` returns nothing.
- The plan's whole Verification list once more: `uv run pytest tests/unit/project/test_glossary.py -n 0` green with no new exemption; `git grep -niE "\bnuisance runs?\b" -- evals tests src .github ':!*.json'` and the line-wrapped `rg` empty.
- The fingerprint check: `before.json` and `after.json` identical.
- The short loop, then the closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green.
