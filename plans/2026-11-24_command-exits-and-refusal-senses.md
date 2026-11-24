# Command exits and the senses of "refusal"

## Context

A review of the eval commands after the standards passes on the detection and nuisance suites left six points, which the maintainer accepted after an independent check against the code. The glossary reserves the noun "refusal" for a provider refusal, while the instruments, the auditor and the living docs use it for a command that refuses to run or to record. Three entry points (`evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`) copy the same mapping of `Refused` to exit 3 and of `ProviderFatal` to a crash panel and exit 4. The honeypot suite does not recognize a fatal model provider error: it warns and prints a traceback for each run the error fails while the other runs go on, then exits 3 with "All runs failed." (or grades the runs completed before the error). `_run_graded` in `evals/run_detection.py` (34 body lines), `main` in the same file (32 body lines) and `tests/unit/detection/test_run_detection.py` (315 lines) are over the size guidelines. Two behaviors have no test: the `[excluded_server]` tag of the `walk` line, and the default number of runs a holdout run hands its orchestrator. Two living texts write "holdout fixture" where the glossary says detection fixture.

Each claim of the assessment that this plan relies on was checked against the code. Three corrections: the flag-rejection tests of `tests/unit/detection/test_run_detection.py` sit at lines 23-102 plus `test_a_concurrency_below_one_is_refused_by_the_parser` further down, not at lines 34-104. The classification of provider errors cannot move back to `evals/provider_errors.py`, a path the retired-word guard forbids (`moved-module-other` in `tests/integration/committed/project/support/retired_words.py`). And the living uses of the noun include, beyond the command sense, a planting sense (`planting_spec` refusing a fixture, in code comments and `CLAUDE.md`) and the audited server's refusal of an input (the judge criteria in `src/mcp_auditor/domain/category_guidance.py` and the labeling rubric).

## Approach

Ten changes, one commit each, in this order:

1. the glossary entry **refusal** amended into qualified senses, with the bare noun of the living Markdown qualified,
2. `print_refusal` renamed `print_titled_reasons`,
3. the classification of provider errors moved out of `evals/cve/` to `evals/model_provider_errors.py`,
4. `print_exit_panel`, the shared exit of a refusal or a fatal provider error, adopted by the three entry points of the CVE benchmark, which brings `run_detection.main` to 20 body lines,
5. the honeypot suite stops at the first fatal model provider error, with its full traceback,
6. `_run_graded` split,
7. the flag-rejection tests of `test_run_detection.py` moved to their own file,
8. a test of the `[excluded_server]` tag of the `walk` line,
9. tests of the default number of runs of both holdout runs,
10. "holdout fixture" written "detection fixture" in `CLAUDE.md` and one test docstring.

Change 5 is the only behavior change: it has lines in the `[Unreleased]` section of `CHANGELOG.md`, in `CONTRIBUTING.md` and a labeling-log entry. Change 1 corrects living text. Every other change is a refactoring that keeps every printed byte and exit code, or adds tests. Public content (code, docs, commit messages, the labeling-log entry) never names a change number of this plan.

## Decisions

- **"Refusal" keeps its word and gains qualified senses.** The glossary entry under "Words with several senses" is replaced by this text, which the maintainer validated on 2026-11-24: "- **refusal**: a provider refusal (the model provider declined to answer), a command refusal (a command stops with the reasons it prints, before its work or before it writes what it was asked to write: a recording refusal writes no baseline, a launch refusal launches no audited server), a planting refusal (the planting code refuses a fixture it cannot plant, a configuration error), or, in the judge criteria, the audited server's refusal of an input. Other acts take their own verb: a guard blocks a payload, a replay strikes a credit. Code: `ProviderRefusal` and `provider_refusal` for a provider refusal, `Refused`, `RECORDING_REFUSED` and `LaunchRefused` for a command refusal." The server sense is listed because the judge criteria and the labeling rubric use it and stay, since the judge criteria reach the judge. The entry adds senses and moves none, so `docs/glossary-log.md` takes no line for it.
- **The qualified form is written in the living Markdown, not in code.** The section's rule ("Write the qualified form") is applied in change 1 to every bare noun of the living Markdown whose sentence does not name the act refused (nine lines, listed in change 1). Code identifiers and comments keep the bare noun, as they do for the other words of the section (`budget`, `case`, `run`): renaming the about 138 lines of `evals/` and the few of `src/` is the full rename this plan leaves out. A guard on the bare noun cannot work, since many provider-sense identifiers carry no qualifier (`attempt.refusal`, `refusal_from_error`, `llm_refusals.py`).
- **A fresh agent checks the normative text.** Before the commit of change 1, a fresh Opus agent that has not seen this plan checks the amended entry and the nine rewritten lines against `docs/glossary.md` (style, one meaning per term, no clash with an existing sense). Hand it those texts and `docs/glossary.md` only. Its findings come back to the maintainer before the commit.
- **`print_refusal` becomes `print_titled_reasons`.** The function prints a red title and its reasons as bullets in a panel, for refusals ("Refused.", "Recording refused.", "Draw refused.") and for crashes ("Crashed: a fatal model provider error stopped the run.", "Crashed: a detection fixture of a holdout target is misconfigured."), so a name built on "refusal" is wrong for four of its 15 calls. A name built on "stop" would clash with the glossary's stopped tool and with the guard that stops a payload, and "exit" alone names a nuisance exit. The new name says what it prints and claims no term. It takes a line in `docs/glossary-log.md`, and a retired-word pattern `\bprint_refusal\b`.
- **The shared exit is `print_exit_panel(ending: Refused | ProviderFatal) -> int`, in `evals/eval_display.py`.** It prints `ending.title` and `ending.reasons` for a `Refused` and returns `NOT_COMPARABLE_EXIT` (3, "also the exit code of a refusal" in `evals/gate_outcome.py`), and for a `ProviderFatal` prints "Crashed: a fatal model provider error stopped the run." with `[describe_provider_error(ending.cause)]` and returns `CRASHED_EXIT` (4). It sits beside `print_titled_reasons` and `print_outcome`, the other ends of a command, rather than in a module of one function. Its name is a plain function name and coins no glossary term, and its parameter is `ending` rather than a name built on "stop", for the clash the paragraph above gives. The three copies it replaces are byte-identical in what they print (same title, same reasons, same panel, printed after `silenced_stdio_logging` has exited) and in their codes (3 and 4 under three names: `NOT_COMPARABLE_EXIT`, `REFUSED_EXIT` and the nuisance `REFUSED_EXIT`). Each caller keeps what differs: `run_detection` alone catches any other exception with a traceback and exit 4, while the holdout and nuisance commands let it propagate, which their tests pin (`pytest.raises(KeyError)`, `pytest.raises(ValueError)`). `run_census.py` and `draw_judge_cases.py`, which make no model call, keep their own handlers.
- **The classification moves to `evals/model_provider_errors.py`, whole.** `import evals.run_honeypot_suite` and `import evals.run_judge_eval` load no `evals.cve` module today (checked at the plan's base), and both must keep it so: the honeypot suite imports `classify` and `ProviderErrorKind` in change 5, and `evals/eval_display.py`, which both import, imports `ProviderFatal` and `describe_provider_error` for `print_exit_panel` in change 4. `evals/provider_errors.py`, the module's path before it moved into `evals/cve/`, is a retired path. "Model provider" is the glossary's qualified form of "provider". The whole module moves, `AuditFailed`, `classified` and `audit_failures_unwrapped` included: nothing in it is specific to the CVE benchmark, and a split would leave two modules on one subject. Its unit test and given move with it to `tests/unit/evals/`. The old path takes a line in `docs/glossary-log.md` and a retired-word pattern, and the two old test stems join the retired test stems. No module an eval fingerprint hashes imports it, and no kit closure can hold it, since it imports `mcp_auditor`.
- **The honeypot suite shows the whole error.** `describe_provider_error`'s rule (the error's type and status, never its message) protects the holdout layers, where reading a per-case trace spends a target. Nothing of the honeypot suite is protected that way, and the full error with its chain is what tells the maintainer what happened, so the honeypot suite prints the traceback, neither the crash panel nor `print_exit_panel`. The judge eval already exits 4 with the full traceback on any error `judge_one_case` does not catch, a fatal provider error included, and does not change.
- **A fatal error propagates from where a failure is caught today.** `_run_or_warn` (`evals/honeypot/runs.py`) and `_retest_or_fail` (`evals/honeypot/retest.py`) catch every `Exception` to turn it into a failed run or a failed retest: each becomes `except Exception as error:` and first re-raises it with a bare `raise` when `classify(error)` is `ProviderErrorKind.FATAL`, keeping its warning for any other error. The error itself leaves `asyncio.gather`, `asyncio.run` and `_evaluate`, and reaches the `except Exception` that `run_honeypot_suite.main` already has after its `except Refused`, which prints its traceback, chain included, and exits `CRASHED_EXIT` (4). It is not wrapped into `ProviderFatal`: the traceback would still show the error as its cause, under one more exception that adds nothing to read. The two-line check is written at each of the two sites rather than in a helper, as the CVE audits write theirs. For the exit code and stderr to be testable without `monkeypatch.setattr`, `main`'s try and its two handlers move unchanged into `exit_code_of(evaluate: Callable[[], int]) -> int`, below `main`, and `main` ends with `raise SystemExit(exit_code_of(lambda: _evaluate(args)))`: every printed byte and code of `main` stays. A run's error reaches `_run_or_warn` through `audit_honeypots` (`evals/honeypots.py`), which unwraps its task group with `raise failures.exceptions[0] from None`: that `from None` overwrites the leaf's own `__cause__`, where `classify` reads the status langchain_google_genai leaves on the google-genai error it raises from (`a_google_error_caused_by_status` in the moved given), so a fatal Google error whose status langchain_google_genai does not map to a `ModelError` subclass (402 at the pinned langchain-google-genai 4.4.2, whose 401, 403 and 404 map and are classified on the leaf itself) would read as no provider error and keep its warning, and its traceback would not show the error it was raised from. The unwrap becomes `leaf = failures.exceptions[0]` then `raise leaf from leaf.__cause__`, which keeps the cause, so that `classify` reads it and the traceback shows it, and still suppresses the group as context (the same concern as `_first_leaf`'s comment in the moved module). A retest calls `audit_honeypot` directly, with no task group, so `_retest_or_fail` needs no such fix.
- **The work in flight is cancelled, nothing is written.** The fatal error leaves `asyncio.gather` at once (in `run_all`, in `Retester.retest_flips`) and reaches the end of the coroutine `asyncio.run` runs with no `await` on the way, so no further call is sent. `asyncio.run` then cancels every task still pending (the other runs, the other retests, the audits in flight or waiting on the `bounded` semaphore) and waits for them, and a cancelled honeypot audit closes its server as the cancellation unwinds `connected()`, through the session owner. No report, no export and no baseline is written. This is how the detection gate already stops on a `ProviderFatal` under its plain `gather`, so the plan keeps `gather` and adds no task group.
- **`run_detection.py` stays above 300 lines.** After changes 4 and 6 it is about 320 lines, 56 of them the argument parser. Moving the parser alone would make a module of one function whose constants the command also reads (`_recorded_flags`). The guideline reads "rarely", and the plan leaves the file there.
- **Tests that read an exit constant the entry point no longer uses assert the literal code.** After change 4, `run_nuisance.py` no longer imports `REFUSED_EXIT` and `CRASHED_EXIT`, `run_detection_holdout.py` no longer uses its `REFUSED_EXIT`, and `evals/cve/nuisance/commands.py`'s `REFUSED_EXIT` has no reader left. Both unused constants are deleted, and the 19 test lines that read `run_nuisance.REFUSED_EXIT`, `run_nuisance.CRASHED_EXIT` or `run_detection_holdout.REFUSED_EXIT` assert `3` or `4`, the codes `CONTRIBUTING.md` documents. `run_detection_holdout.CRASHED_EXIT` stays, still used by its calibration check.
- **Left out**, as the brief decided: the stale pointer of `evals/cve/kit/fix_check.py:13`; the "opaquely" wording of the Doris kit paragraph; the full rename of "refusal" in code; the nuisance gate's lack of a refusal on a running container; the cell assertion of `test_an_inconclusive_server_shows_its_detail_before_its_flagged_tools`; the text of `src/mcp_auditor/domain/category_guidance.py`, which reaches the judge (63 times in `model_inputs_golden.json`); the kit text of `evals/cve/nuisance/admission/admission_docs.py` and the kit path `reference/holdout_fixtures/`, which change what the kits ship.

## What stays unchanged

- Every module an eval fingerprint hashes, the Dockerfiles and stand-in captures, `docs/adr/`, `plans/`, the two suite rules and their logs, the dated entries of `docs/labeling-log.md` and the released sections of `CHANGELOG.md`.
- The grammar, counter, detection fixture and nuisance fixture fingerprints, the honeypot ground truth fingerprint and the judge inputs fingerprint (values in Verification).
- The committed data: the census, the walk record, the admission, `evals/holdout_conditions.json`, the baselines and the golden files.
- What the kits ship: no change touches `evals/cve/kit/`, `evals/cve/backends/` or the dossier writers.
- Every printed text and exit code, apart from change 5: the panels of the three CVE entry points, the flag refusals of `run_detection`, its order of output (the "No cost reported" warning before the run, the recording panel after the summary).
- The handling of every error other than a fatal provider error, in every instrument: a transient provider error, a throttled audit and any other exception keep their failed run, failed retest, traceback or propagation.
- `tests/unit/project/support/code_standards_debt.py`: no entry is added.

## Edge cases

- `_selected_flaws` (change 4) and `_report` (change 6) are annotated with `_FlawSelection` and `_GradedRun`, which Python 3.13 evaluates at definition: each is defined after the dataclass it names, which still keeps it below its caller.
- `_selected_flaws` keeps `_reject_unknown_flaws`'s behavior on `--flaw` absent (no check) and its message and `sys.exit(2)` before the preflight, which `test_an_unknown_flaw_id_is_refused_before_the_preflight` pins.
- A honeypot run that meets a fatal error after other runs completed writes no report, prints the error's traceback and exits 4, where it graded the completed runs and exited 3. A gate on fewer runs than requested was not comparable and a recording refused it, so no green or red outcome and no recorded baseline is lost.
- Several runs meeting the error at once: the first to raise leaves the `gather`, which marks the later exceptions retrieved, and the others are cancelled. None prints a warning, since each raises instead of warning, and `main` prints the traceback of the first alone.
- With `audit_honeypots` keeping the leaf's cause, the traceback of a honeypot run's error shows the error the leaf was raised from, which `from None` hid. That is intended: on a fatal error it shows the provider's status and message, and on any other error the warned failed run's traceback shows the same chain, its warning line unchanged and no exit code reading it.
- A fatal error in a retest was a failed retest ("a retest of X failed", exit 3) and becomes the error's traceback and exit 4.
- `classify` reads an integer `status_code` or `code` on any error. An error of the honeypot harness carrying 401 to 404 there would now stop the suite. The CVE suites run under the same reading, and the harness raises no such error today.
- `print_exit_panel` takes a `Refused` built by `_refused_flags` without raising it, so the flag refusal of `run_detection` keeps its title (`RECORDING_REFUSED` with `--record-baseline`, else "Refused.") and its single reason.

## Verification

**Run outputs stay closed.** No step opens anything under `output/`, a `*.result.json`, a `*_judged_cases.jsonl` or a holdout report, by hand or through an agent. Every search is scoped to `evals tests docs src` plus `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `README.md` and `.github/`, since a plain `grep -r` from the root reads `output/`. Tests write their result files under `tmp_path` only.

**The loop.** While a test is red, `uv run pytest <test files> -n 0`. Once green, `uv run pytest tests/unit -n auto --maxprocesses 6`, with `--lf` on a failure until it passes, then the full short loop again. Also `uv run ruff check .`, `uv run ruff format .`, `uv run pyrefly check`, and `uv run pytest tests/integration/committed -n auto` for a change that touches committed content (changes 1, 2, 3, 5 and 10).

**The closing check ends every change**, even right after a step that ran part of it:

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyrefly check
sed -n '78,95p' plans/2026-11-23_nuisance-suite-standards-pass.md | PYTHONPATH=. uv run python -
PYTHONPATH=. uv run python -c "
from evals.baseline import fingerprint_ground_truth
from evals.honeypots import MERGED_GROUND_TRUTH
from evals.judge.fixture import inputs_fingerprint, load_fixture
from evals.run_judge_eval import FIXTURES_PATH
print(fingerprint_ground_truth(MERGED_GROUND_TRUTH), inputs_fingerprint(load_fixture(FIXTURES_PATH)))"
```

The integration tests build images, so watch the disk. The last two commands print exactly (checked at the plan's base):

```
41 58afe8a1926bf5fbffa78146b6e7e35d5d5d27797332aea1c829a503cc3e33d1 689da547ef98cf466f67be55cdb28b319790d9e21b8ea6df2df85624c6dc420b
65 b6d3dc662faf2fb24b2b91ff0f7c7941d6927a7303cfab952f2cf5b41af54161 0444a788e1477df424ea3b29ab0dc2a2c1bacf55746975126c0ae46e667cfc5d
072b33c72ecc3732df4df957ed3ff63662a6747ccb87ac29ed5332d1031cb025 638da4313024181cc88b5c54f9032ff6b1d158664046bea12ed40f2b2b7aac73
```

**The import boundary**, after changes 3, 4 and 5: both commands exit 0.

```bash
PYTHONPATH=. uv run python -c "import sys, evals.run_honeypot_suite; assert not [m for m in sys.modules if m.startswith('evals.cve')]"
PYTHONPATH=. uv run python -c "import sys, evals.run_judge_eval; assert not [m for m in sys.modules if m.startswith('evals.cve')]"
```

**No stale reference**, after change 2 and change 3 respectively: `git grep -n "print_refusal" -- evals tests src CLAUDE.md CONTRIBUTING.md` and `git grep -n -e "evals.cve.provider_errors" -e "evals/cve/provider_errors" -e "test_cve_provider_errors" -- evals tests src CLAUDE.md CONTRIBUTING.md` print only the retired-word patterns, and `git grep -n "provider_errors" -- evals/cve/kit evals/cve/backends evals/cve/nuisance/admission` prints nothing.

## Change 1: The senses of "refusal"

**Problem.** The glossary entry reads "provider refusal only", while the living docs write the noun for a command that refuses (`CONTRIBUTING.md`, `evals/census_method.md`, `docs/usage.md`, the `[Unreleased]` section of `CHANGELOG.md`) and for the planting code refusing a place (`CLAUDE.md`). The code uses the same senses in about 138 lines.

**Change.** Replace the **refusal** entry of `docs/glossary.md` with the text given in Decisions, once the maintainer has validated it. Qualify the nine bare nouns of the living Markdown, each with the text given here:

- `CONTRIBUTING.md`, the exit codes of the detection suite: "a gated target's run or retest did not complete, or a refusal)" becomes "a gated target's run or retest did not complete, or a command refusal)".
- `CONTRIBUTING.md`, the sentence on the vet: "(refusal on a running server container, built backend containers replaced," becomes "(a refusal to start while a server container is running, built backend containers replaced,".
- `CONTRIBUTING.md`, the honeypot recording paragraph: "Every refusal, and fewer completed runs than requested in any mode, exits `3`." becomes "Every command refusal, and fewer completed runs than requested in any mode, exits `3`."
- `evals/census_method.md`: "A refusal exits `3`, a malformed export or work file included." becomes "A command refusal exits `3`, a malformed export or work file included."
- `evals/fault_injection_method.md`: "An uncovered observation is a refusal, a cell outside the ground truth is PASS." becomes "An uncovered observation is a provider refusal, a cell outside the ground truth is PASS." (the `FixtureJudge` raises `ProviderRefusal` there).
- `docs/usage.md`, Exit codes: "The auditor prints the reason of the refusal or of the failed setup before it exits." becomes "The auditor prints the reason of the launch refusal or of the failed setup before it exits."
- `CLAUDE.md`, the `/work` landmine: "sets `PlantingHost.baked_work`, which drops the tmpfs and the refusal." becomes "sets `PlantingHost.baked_work`, which drops the tmpfs and lets `planting_spec` accept a file place resolving under `/work`."
- `CHANGELOG.md` `[Unreleased]`: "The refusals of a census whose draw record is malformed name" becomes "The command refusals of a census whose draw record is malformed name", and "The refusals of the nuisance admission and the header of" becomes "The command refusals of the nuisance admission and the header of".

The provider-sense uses of `evals/probe_method.md` name the provider in their sentence and stay. Then the fresh-agent check of Decisions.

**Files.** `docs/glossary.md`, `CONTRIBUTING.md`, `evals/census_method.md`, `evals/fault_injection_method.md`, `docs/usage.md`, `CLAUDE.md`, `CHANGELOG.md`.

**Tests.** No unit test. `uv run pytest tests/integration/committed -n auto` (the glossary, retired-word and README policy tests) and the closing check.

**Risks.** A rewritten line that breaks the README policy or the retired-word guard: the committed tests catch it. The wording is normative: it is implemented only as validated, and a change the fresh agent asks for goes back to the maintainer.

## Change 2: `print_refusal` renamed `print_titled_reasons`

**Problem.** `evals.eval_display.print_refusal` also prints the crash panels (`run_detection.py`, `run_detection_holdout.py` twice, `run_nuisance.py`), so its name says less than it does and uses the noun in a sense the glossary did not give it.

**Change.** Rename the function and its 19 uses in 9 files, with no other edit. Add to `docs/glossary-log.md`, in its alphabetical place (the table sorts ignoring backticks and case): "| `print_refusal` | `print_titled_reasons` (it prints a crash panel too) | rename | <date of the commit> |". Add `RetiredWord("print-refusal", r"\bprint_refusal\b", re.NOFLAG)` to `tests/integration/committed/project/support/retired_words.py`.

**Files.** `evals/eval_display.py`, `evals/run_honeypot_suite.py`, `evals/run_judge_eval.py`, `evals/judge/display.py`, `evals/draw_judge_cases.py`, `evals/run_census.py`, `evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`, `docs/glossary-log.md`, `tests/integration/committed/project/support/retired_words.py`.

**Tests.** No new test: no test names the function, and the panels its callers print are pinned through them (for example `test_a_fatal_provider_error_prints_the_crash_panel_without_its_message`). The committed tests run, the retired-word guard among them.

**Risks.** None beyond a missed use, which `pyrefly` and the stale-reference grep catch.

## Change 3: The classification of provider errors moves to `evals/model_provider_errors.py`

**Problem.** The honeypot suite needs `classify` and `ProviderErrorKind`, and `evals/eval_display.py`, which the honeypot suite and the judge eval import, needs `ProviderFatal` and `describe_provider_error` for `print_exit_panel`. They live in `evals/cve/provider_errors.py`, and importing it would load `evals.cve` into `evals.run_honeypot_suite` and `evals.run_judge_eval`.

**Change.** `git mv evals/cve/provider_errors.py evals/model_provider_errors.py`, with its content unchanged, and rewrite every importer (seven modules of `evals/` and thirteen test files besides the moved test, found with `git grep -n "evals.cve.provider_errors" -- evals tests`). Move `tests/unit/cve/test_cve_provider_errors.py` to `tests/unit/evals/test_model_provider_errors.py` and its given `tests/unit/cve/support/test_cve_provider_errors_given.py` to `tests/unit/evals/support/test_model_provider_errors_given.py`, repointing the test's given import. Add to `docs/glossary-log.md`: "| `evals/cve/provider_errors.py` | `evals/model_provider_errors.py` | rename | <date of the commit> |". In `retired_words.py`, add `evals[./]cve[./]provider_errors\b` to the `moved-module-other` pattern and `test_cve_provider_errors` and `test_cve_provider_errors_given` to `_OLD_TEST_STEMS`.

**Files.** `evals/model_provider_errors.py` (moved), `evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`, `evals/cve/launch_audit.py`, `evals/cve/detection/audit.py`, `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/gate/gate_command.py`, the test files the grep lists, the two moved test files, `docs/glossary-log.md`, `retired_words.py`.

**Tests.** The moved tests, unchanged apart from their imports. The import-boundary commands still exit 0 (nothing in the honeypot suite imports the module yet), and the stale-reference grep finds nothing.

**Risks.** A pattern added to the guard that also matches the new path: `evals[./]cve[./]provider_errors` cannot match `evals/model_provider_errors`, and the committed tests confirm it.

## Change 4: `print_exit_panel` shared by the three entry points of the CVE benchmark

**Problem.** `run_detection.py` (lines 95-103), `run_detection_holdout.py` (lines 69-77) and `run_nuisance.py` (lines 52-60) each map `Refused` to its panel and exit 3, and `ProviderFatal` to the crash panel and exit 4, in nine identical lines. `run_detection.main` is 32 body lines.

**Change.** Add `print_exit_panel` to `evals/eval_display.py` as given in Decisions, below `print_titled_reasons`. In each of the three entry points, replace the two `except` blocks with `except (Refused, ProviderFatal) as ending: return display.print_exit_panel(ending)`, keeping `run_detection`'s `except Exception` after it. In `run_detection.py`, turn `_flag_refusal` into `_refused_flags(args) -> Refused | None`, which builds the `Refused` with its title, and fold `_reject_unknown_flaws` and the two `_filter_by_flaw` calls into `_selected_flaws(ids) -> _FlawSelection`, defined after `_FlawSelection`. `main` then reads, in 20 body lines:

```python
    deps = DetectionCommandDeps() if deps is None else deps
    quiet_throttle_waits()
    args = _parse_args(argv)
    flaws = _selected_flaws(args.flaw)
    refused = _refused_flags(args)
    if refused is not None:
        return display.print_exit_panel(refused)

    # Says nothing of detection nor of the fixtures, so a crash in every mode.
    if not deps.preflight():
        return CRASHED_EXIT

    try:
        with silenced_stdio_logging():
            return asyncio.run(_run(args, flaws, deps))
    except (Refused, ProviderFatal) as ending:
        return display.print_exit_panel(ending)
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT
```

Delete `REFUSED_EXIT` from `run_detection_holdout.py` and from `evals/cve/nuisance/commands.py`, drop the imports that go unused (`describe_provider_error`, the nuisance `REFUSED_EXIT` and `CRASHED_EXIT` in `run_nuisance.py`), and make the 19 test lines that read a deleted or unimported constant assert `3` or `4` (`tests/unit/detection/test_run_detection_holdout.py`, `test_run_detection_holdout_run.py`, `tests/unit/nuisance/test_run_nuisance.py`, `test_run_nuisance_holdout_run.py`, `test_nuisance_vet.py`, `gate/test_run_nuisance_gate.py`, `fix_checks/test_nuisance_fix_check_command.py`).

**Files.** `evals/eval_display.py`, `evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/commands.py`, `tests/unit/evals/test_eval_display.py` and the seven test files above.

**Tests.** Two tests in `tests/unit/evals/test_eval_display.py`, written first: a `Refused("Recording refused.", ["the git tree has tracked modifications"])` prints its title and reason and gives 3, and a `ProviderFatal(ModelAuthenticationError("the key sk-secret was revoked"))` prints "Crashed: a fatal model provider error stopped the run." and "ModelAuthenticationError", not "sk-secret", and gives 4 (output read through `capsys`, whitespace normalized as `test_run_detection.py` does). The existing tests of the three entry points pin that their panels and codes do not move: the flag refusals, the fatal-error panel of `run_detection`, the holdout run's `test_a_fatal_provider_error_exits_four_keeping_the_partial_result`, the nuisance gate's and the nuisance holdout run's fatal-error tests, and the propagation tests (`pytest.raises(KeyError)`, `pytest.raises(ValueError)`).

**Risks.** A caller that loses its generic `except Exception`: only `run_detection` has one, and it keeps it. `ruff` flags any import left unused.

## Change 5: The honeypot suite stops at the first fatal model provider error

**Problem.** A fatal provider error (authentication, permission, model not found, a billing limit) is caught as any failure: each honeypot run it fails prints "Warning: run k/n failed:" and a traceback while the other runs go on, then the suite raises `Refused("All runs failed.")` and exits 3, or grades the runs completed before the error and exits 3 as incomplete. A retest becomes "a retest of X failed".

**Change.** As given in Decisions: the two-line fatal check in `_run_or_warn` and `_retest_or_fail`, each re-raising the error with a bare `raise`, `main`'s try and handlers moved into `exit_code_of`, and `audit_honeypots` keeping the leaf's cause. Update `_retest_or_fail`'s docstring, which says it returns the failure message whenever a retest raised. Living docs, in this commit:

- `CONTRIBUTING.md`, the honeypot recording paragraph: after "A refused or unreadable step, ... leaves the pass completed.", "A crash of the runner prints its traceback and exits `4`." becomes "A fatal model provider error (authentication, permission, model not found, a billing limit), in a run or a retest, stops the suite at the first such error: it prints the error's full traceback, its chain included, writes no report and exits `4`. Any other crash of the runner prints its traceback and exits `4`."
- `CHANGELOG.md`, `[Unreleased]`, under Fixed after the two lines on the nuisance gate and the detection command: "- A fatal model provider error (authentication, permission, model not found, a billing limit) during `python -m evals.run_honeypot_suite`, in a run or a retest, stops the suite at the first such error, prints its full traceback, its chain included, and exits with code 4: each run it failed printed a warning and a traceback while the other runs went on, and the suite then exited 3."
- `docs/labeling-log.md`: a new entry, "the honeypot suite stops at the first fatal model provider error", dated the day of the commit. State: the honeypot baseline confirmed, not reset, no label or fixture case moves. What changes: the printed outcome and the exit code above, the runs and retests in flight cancelled, no report written, and the classification it reads is the one the CVE benchmark uses, moved unchanged out of `evals/cve/` beforehand. Fingerprint: the ground truth fingerprint stays `072b33c72ecc3732df4df957ed3ff63662a6747ccb87ac29ed5332d1031cb025`. The four questions of ADR 016: (1) the change lands in the instrument, how the honeypot suite's runner ends on a fatal provider error, and no prompt, guard or default of the system under test, no label, fixture case or rule of the gate moves; (2) it was raised by a review of how the eval commands exit, not by a measured value; (3) a run that met a fatal error already left the honeypot gate not comparable (fewer completed runs than requested, or a failed retest) with its recording refused, so no green or red outcome and no baseline a recording would write changes; (4) it applies alike to every run and retest of the honeypot suite.

`.github/workflows/eval-command.yml` already reads a honeypot exit 4 as "honeypot suite crashed (see the log)", which now holds for this case too, and `evals.yml` fails on any non-zero code: no workflow changes. The maintainer accepted on 2026-11-24 that a revoked or invalid key now reads as crashed (exit 4) in CI, where it read as not comparable (exit 3).

**Files.** `evals/honeypot/runs.py`, `evals/honeypot/retest.py`, `evals/honeypots.py`, `evals/run_honeypot_suite.py`, `tests/unit/evals/test_run_honeypot_suite.py`, `tests/unit/evals/support/test_run_honeypot_suite_given.py`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/labeling-log.md`.

**Tests.** Written first and seen red, in `test_run_honeypot_suite.py`, the fakes in its given beside `FakeHoneypotAudit`: `an_audit_raising(error)`, and `a_suite_running(audit, runs) -> Callable[[], int]`, which runs `run_all(counted_audit(audit, SessionThrottles()), runs)` under `asyncio.run` and returns 0, standing for `_evaluate`. The `exit_code_of` tests are synchronous, since they call `asyncio.run`, and read the output through `capsys`.

- A run whose audit raises `ModelAuthenticationError("the API key was revoked")`: `exit_code_of(given.a_suite_running(given.an_audit_raising(error), runs=2))` is 4, stdout holds no "failed" warning, and stderr holds "ModelAuthenticationError: the API key was revoked".
- A run whose audit raises an error carrying its fatal status only on the error it is raised from (a plain error raised from one whose `code` is 403, built in the given as `a_google_error_caused_by_status` builds its own): `exit_code_of` is 4 and stderr holds both errors' messages. It is red until `audit_honeypots` keeps the leaf's cause, and `test_a_failing_honeypot_cancels_the_other_audits_of_its_run` (`tests/unit/evals/test_honeypots.py`) keeps pinning the unwrap.
- A run whose audit raises a transient provider error (`ModelAPIError("overloaded")`) is still a warned failed run: `run_all` returns `outcome.details == []` and stdout holds "Warning: run 1/1 failed:". It pins today's behavior and passes before the change.
- A retest whose audit raises the fatal error makes `retest_flips` raise that `ModelAuthenticationError`, with no warning announced, the `Retester` built as `test_a_retest_holding_a_throttled_model_call_is_a_failed_retest` builds it.

The import-boundary commands must still exit 0.

**Risks.** An error of the harness that carries a status 401 to 404 would now stop the suite (see Edge cases). A test that leaves a task pending: the fakes raise at once, and `asyncio.run` cancels whatever is left before `exit_code_of` returns.

## Change 6: `_run_graded` split

**Problem.** `_run_graded` in `evals/run_detection.py` is 34 body lines: it reads the conditions, runs the session, builds the report and publishes it.

**Change.** Add a frozen dataclass `_GradedRun` (`tree`, `conditions`, `measurement`, `pricing`, `throttles`, `session`), defined before its readers, and two functions below `_run_graded`: `_report(args, flaws, graded) -> DetectionReport`, which builds the results and the report as lines 220-235 do, and `_published(args, report, session) -> int`, which writes the report and the export, prints the summary and the recording, and prints the recording panel and returns 3, as lines 236-244 do. `_run_graded` keeps its reads in their order (the tree, the settings, the pricing and its warning, all before the session) and ends with `return _published(args, _report(args, flaws, graded), session)`, in about 11 lines.

**Files.** `evals/run_detection.py`.

**Tests.** No new test: `test_a_graded_run_reports_the_tree_it_ran_on_and_the_tokens_billed`, the cost tests, the measurement test, the recording tests of `test_run_detection_recording.py` and the container tests pin the report and the output.

**Risks.** Moving the pricing after the session would print "No cost reported" after the run: it stays before.

## Change 7: The flag-rejection tests in their own file

**Problem.** `tests/unit/detection/test_run_detection.py` is 315 lines.

**Change.** Move the tests that reject flags before any work into `tests/unit/detection/test_run_detection_flags.py`, unchanged: `test_incompatible_flags_are_refused_as_not_comparable`, `test_a_measurement_flag_outside_a_no_baseline_run_is_refused`, `test_chain_steps_without_chains_are_refused`, `test_a_measurement_flag_on_a_mode_that_runs_no_audit_is_refused_for_that_reason`, `test_a_negative_chain_count_is_refused_by_the_parser`, `test_an_unknown_flaw_id_is_refused_before_the_preflight` with its `_a_preflight_that_must_not_run`, and `test_a_concurrency_below_one_is_refused_by_the_parser`. They read the shared `run_detection_cli` support and need no given or then file. Drop the imports the old file no longer uses.

**Files.** `tests/unit/detection/test_run_detection.py`, `tests/unit/detection/test_run_detection_flags.py`.

**Tests.** The moved tests pass and the count of collected tests is unchanged. The old file ends near 230 lines.

**Risks.** None.

## Change 8: A test of the `[excluded_server]` tag

**Problem.** `_walk_line` (`evals/run_nuisance.py`) prints a server's exit tag, and `tests/unit/nuisance/test_run_nuisance.py` asserts only "(drawn)" and "(addition)": no test pins the tag, which changed in this release.

**Change.** Add a new given for `test_run_nuisance.py`, `tests/unit/nuisance/support/test_run_nuisance_given.py`, holding a builder `a_walk_reaching_an_excluded_server(tmp_path) -> list[str]` (its one user is `test_run_nuisance.py`, so it is that file's given rather than a builder of the shared `nuisance_queue_walks.py`, whose `QUEUE_FLAW` it imports), which returns the `walk` arguments of this census and record, checked to load at the plan's base: `censuses.with_a_cve_of(censuses.a_census(), QUEUE_FLAW, walks.AN_EXCLUDED_SERVER)`, with the second classifier naming another package (`walks.with_the_second_classifier_overriding`) and the figures recomputed (`censuses.recomputed`), then `census_draws.with_a_walk_skipping(..., admissions.FIRST_FLAW)`, a walk record (`walks.an_empty_record()`) with an `IdentitySettlement` of `QUEUE_FLAW` to `walks.AN_EXCLUDED_SERVER`, written with `walks.written_record`; and a missing admission. The excluded server's flaws are no draw-order candidates, so the nuisance walk reaches such a server only through a flaw whose classifiers disagree on its package, which an identity settles.

**Files.** `tests/unit/nuisance/test_run_nuisance.py`, `tests/unit/nuisance/support/test_run_nuisance_given.py` (new).

**Tests.** `test_walk_tags_an_excluded_server`: `run_nuisance.main(["walk", *arguments])` exits 0, and the printed line holding `walks.AN_EXCLUDED_SERVER` ends with the literal `  [excluded_server]`. It pins behavior that exists, so it is seen red once by changing the tag in `_walk_line` for a moment, the change undone before the commit.

**Risks.** None: a test only.

## Change 9: Tests of the default number of runs

**Problem.** `holdout_run_command.py` hands `runs=args.runs` to the nuisance orchestrator and `run_detection_holdout.py` to the detection one, and no test pins the default that reaches them. The help test of the nuisance holdout run interpolates `NUISANCE_RUNS`, so it follows any change of the constant.

**Change.** Add a given that captures the inputs each orchestrator receives and returns a run result: `an_admitted_run_capturing_its_inputs() -> tuple[NuisanceCommandDeps, list[NuisanceHoldoutRunInputs]]` in `tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py`, built as `an_admitted_run_keeping_its_provenance` is, and `a_drawn_run_capturing_its_inputs() -> tuple[HoldoutCommandDeps, list[HoldoutRunInputs]]` in `tests/unit/detection/support/test_run_detection_holdout_run_given.py`, through `holdout_command_deps.a_drawn_run_through`.

**Files.** `tests/unit/nuisance/test_run_nuisance_holdout_run.py` and its given, `tests/unit/detection/test_run_detection_holdout_run.py` and its given.

**Tests.** `test_run_hands_its_orchestrator_two_runs_by_default`: `run_nuisance.main(given.a_run_command(tmp_path), deps)` exits 0 and the captured `runs` are `[2]`. `test_run_hands_its_orchestrator_three_runs_by_default`: with `command_deps.a_ready_run(monkeypatch)` and `_run_flags(tmp_path, report)`, `run_detection_holdout.main` exits 0 and the captured `runs` are `[3]`. Both literal, neither reading `NUISANCE_RUNS` nor `HOLDOUT_RUNS`, and each seen red once by changing its default for a moment, the change undone before the commit.

**Risks.** None: tests only. A deliberate change of either default now also edits its test, as the rules' logs already require.

## Change 10: "Holdout fixture" written "detection fixture"

**Problem.** The `nuisance-dossier` line of the Commands list of `CLAUDE.md` and the docstring of `tests/integration/test_nuisance_doris_backend.py` write "holdout fixture", while the glossary (**holdout target reference**) writes "detection fixture".

**Change.** In `CLAUDE.md`, "for each census flaw of the server that is a holdout target its holdout fixture and builder as text" becomes "for each census flaw of the server that is a holdout target its detection fixture and builder as text". In the docstring, "and the holdout fixture's benign call answers without error" becomes "and the benign call of the holdout target's detection fixture answers without error". The kit text of `admission_docs.py` and the kit path `reference/holdout_fixtures/` stay.

**Files.** `CLAUDE.md`, `tests/integration/test_nuisance_doris_backend.py`.

**Tests.** `uv run pytest tests/integration/committed -n auto`. The Doris test runs only behind `NUISANCE_DORIS=1` and its code does not change.

**Risks.** None.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, at the plan's base, not what is true now. A maintainer who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: annotations such as `-> _FlawSelection` and `-> _GradedRun` are evaluated at definition (verified against `requires-python = ">=3.13"`, `.python-version` 3.13, the 3.13.16 interpreter, and the absence of `from __future__ import annotations` in `evals/run_detection.py`).
- SETTLED: `asyncio.gather` marks the exceptions of awaitables finishing after its outer future is done as retrieved, and `asyncio.run` cancels every pending task and waits for them with `gather(..., return_exceptions=True)` (verified against the installed CPython 3.13.16 `asyncio/tasks.py` and `asyncio/runners.py`).
- SETTLED: `raise leaf from leaf.__cause__` keeps the leaf's cause and suppresses the exception group as context (verified by running it under the 3.13.16 interpreter).
- SETTLED: langchain-google-genai 4.4.2 maps client statuses 400, 401, 403, 404 and 429 to `ModelError` subclasses and raises any other status as `ChatGoogleGenerativeAIError` from the google-genai `ClientError` carrying `code` (verified against the installed `langchain_google_genai/chat_models.py`, version pinned in `uv.lock`; corrected in Decisions).
- SETTLED: `langchain_core.exceptions.ModelAuthenticationError` classifies FATAL and `ModelAPIError("overloaded")` TRANSIENT, with no status, and `ProviderFatal` of the former prints `ModelAuthenticationError` only (verified by running `classify` at langchain-core 1.7.0).

## Implementation steps

Each step is one of the plan's changes and one commit, in the plan's order. Steps 1 and 5 stay alone in their commit (step 1 for the fresh-agent check of its wording, step 5 for its own CHANGELOG and labeling-log lines). Every step ends with the closing check of Verification: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyrefly check`, then the two fingerprint commands, whose output must match the three lines given there byte for byte. Every search is scoped to `evals tests docs src`, the top-level Markdown files and `.github/`, and nothing under `output/`, no `*.result.json`, no `*_judged_cases.jsonl` and no holdout report is opened. No commit message or public text names a change or step number.

### Step 1: The senses of "refusal" in the glossary and the living Markdown

- **Files**: `docs/glossary.md`, `CONTRIBUTING.md`, `evals/census_method.md`, `evals/fault_injection_method.md`, `docs/usage.md`, `CLAUDE.md`, `CHANGELOG.md`.
- **Do**:
  - Precondition: the maintainer has validated the entry text of Decisions ("Refusal keeps its word and gains qualified senses"). If that validation is not recorded, stop and report back before editing.
  - Replace the **refusal** bullet under "Words with several senses" of `docs/glossary.md` with that text, verbatim. No line in `docs/glossary-log.md`.
  - Apply the nine rewrites listed under Change 1, each exactly as written there (three in `CONTRIBUTING.md`, one each in `evals/census_method.md`, `evals/fault_injection_method.md`, `docs/usage.md`, `CLAUDE.md`, two in the `[Unreleased]` section of `CHANGELOG.md`). Locate each by `git grep -n` on its old text first, and change nothing else. `evals/probe_method.md` stays.
  - Do not commit: the caller hands the amended entry, the nine rewritten lines and `docs/glossary.md` to a fresh Opus agent that has not seen this plan, and the maintainer reads its findings before the commit.
- **Test**: no unit test. The committed tests (glossary, retired words, README policy) must stay green.
- **Verify**: `uv run pytest tests/integration/committed -n auto` green, then the closing check. `git diff --stat` lists only the seven files.

### Step 2: `print_refusal` renamed `print_titled_reasons`

- **Files**: `evals/eval_display.py`, `evals/run_honeypot_suite.py`, `evals/run_judge_eval.py`, `evals/judge/display.py`, `evals/draw_judge_cases.py`, `evals/run_census.py`, `evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`, `docs/glossary-log.md`, `tests/integration/committed/project/support/retired_words.py`.
- **Do**:
  - Add `RetiredWord("print-refusal", r"\bprint_refusal\b", re.NOFLAG)` to `retired_words.py` first, and run the committed tests to see the guard red on the current uses.
  - Rename the function and its 19 uses (`git grep -n "print_refusal" -- evals`), no other edit.
  - Add the row "| `print_refusal` | `print_titled_reasons` (it prints a crash panel too) | rename | <commit date> |" to `docs/glossary-log.md` in its alphabetical place (sorted ignoring backticks and case).
- **Test**: no new test. The entry points' existing panel tests and the retired-word guard cover it.
- **Verify**: `uv run pytest tests/integration/committed -n auto` green. `git grep -n "print_refusal" -- evals tests src CLAUDE.md CONTRIBUTING.md` prints only the retired-word pattern. Then the closing check.

### Step 3: Provider error classification moved to `evals/model_provider_errors.py`

- **Files**: `evals/cve/provider_errors.py` moved to `evals/model_provider_errors.py`; importers `evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`, `evals/cve/launch_audit.py`, `evals/cve/detection/audit.py`, `evals/cve/nuisance/audit.py`, `evals/cve/nuisance/gate/gate_command.py`; the thirteen test files `git grep -ln "evals.cve.provider_errors" -- tests` lists; `tests/unit/cve/test_cve_provider_errors.py` moved to `tests/unit/evals/test_model_provider_errors.py`; `tests/unit/cve/support/test_cve_provider_errors_given.py` moved to `tests/unit/evals/support/test_model_provider_errors_given.py`; `docs/glossary-log.md`; `retired_words.py`.
- **Do**:
  - Extend the guard first: add `evals[./]cve[./]provider_errors\b` to the `moved-module-other` pattern, and `test_cve_provider_errors` and `test_cve_provider_errors_given` to `_OLD_TEST_STEMS`.
  - `git mv` the module and the two test files, content unchanged apart from imports (the moved test imports its given from its new path).
  - Rewrite every import of `evals.cve.provider_errors` to `evals.model_provider_errors` (the code layout is a mechanical replacement; let `ruff format` and `ruff check --fix` reorder imports).
  - Add "| `evals/cve/provider_errors.py` | `evals/model_provider_errors.py` | rename | <commit date> |" to `docs/glossary-log.md` in its alphabetical place.
- **Test**: the moved tests, unchanged. The test count collected by `uv run pytest --collect-only -q | tail -1` is the same before and after.
- **Verify**: the stale-reference greps of Verification for this change print only the retired-word patterns, and `git grep -n "provider_errors" -- evals/cve/kit evals/cve/backends evals/cve/nuisance/admission` prints nothing. The two import-boundary commands exit 0. `uv run pytest tests/integration/committed -n auto` green, then the closing check (the fingerprint lines unchanged, which shows no fingerprinted module imports it).

### Step 4: `print_exit_panel` shared by the three CVE benchmark entry points

- **Files**: `tests/unit/evals/test_eval_display.py`, `evals/eval_display.py`, `evals/run_detection.py`, `evals/run_detection_holdout.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/commands.py`, and the tests reading the deleted constants: `tests/unit/detection/test_run_detection_holdout.py`, `tests/unit/detection/test_run_detection_holdout_run.py`, `tests/unit/nuisance/test_run_nuisance.py`, `tests/unit/nuisance/test_run_nuisance_holdout_run.py`, `tests/unit/nuisance/test_nuisance_vet.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`, `tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py`.
- **Do**:
  - Tests first in `tests/unit/evals/test_eval_display.py` (inline setup unless a given abstracts something): see them red.
  - Add `print_exit_panel(ending: Refused | ProviderFatal) -> int` to `evals/eval_display.py` right below `print_titled_reasons`: a `Refused` prints `ending.title` and `ending.reasons` through `print_titled_reasons` and returns `NOT_COMPARABLE_EXIT`; a `ProviderFatal` prints "Crashed: a fatal model provider error stopped the run." with `[describe_provider_error(ending.cause)]` and returns `CRASHED_EXIT`. Imports from `evals.eval_session`, `evals.gate_outcome` and `evals.model_provider_errors`, none from `evals.cve`.
  - In each entry point replace the `except Refused` and `except ProviderFatal` blocks with `except (Refused, ProviderFatal) as ending: return display.print_exit_panel(ending)`. Only `run_detection` keeps its `except Exception` with `traceback.print_exc()` and exit 4. The holdout and nuisance commands keep letting any other exception propagate.
  - In `run_detection.py`: `_flag_refusal` becomes `_refused_flags(args) -> Refused | None` (title `RECORDING_REFUSED` with `--record-baseline`, else "Refused.", the single reason), not raised; `_reject_unknown_flaws` and the two `_filter_by_flaw` calls fold into `_selected_flaws(ids) -> _FlawSelection`, defined after `_FlawSelection` (annotations are evaluated at definition), keeping its message and `sys.exit(2)` and no check when `--flaw` is absent. `main` reads exactly as the 20-line block of Change 4.
  - Delete `REFUSED_EXIT` from `evals/run_detection_holdout.py` and `evals/cve/nuisance/commands.py`, drop the imports left unused (`describe_provider_error`, the nuisance `REFUSED_EXIT` and `CRASHED_EXIT` in `run_nuisance.py`). `run_detection_holdout.CRASHED_EXIT` stays (its calibration check reads it).
  - Make the 19 test lines that read `run_nuisance.REFUSED_EXIT`, `run_nuisance.CRASHED_EXIT` or `run_detection_holdout.REFUSED_EXIT` assert the literal `3` or `4` (`git grep -n -e "run_nuisance.REFUSED_EXIT" -e "run_nuisance.CRASHED_EXIT" -e "run_detection_holdout.REFUSED_EXIT" -- tests`).
- **Test**:
  - `Refused("Recording refused.", ["the git tree has tracked modifications"])`: the output (through `capsys`, whitespace normalized as `test_run_detection.py` does) holds the title and the reason, the call returns 3.
  - `ProviderFatal(ModelAuthenticationError("the key sk-secret was revoked"))`: the output holds "Crashed: a fatal model provider error stopped the run." and "ModelAuthenticationError" and not "sk-secret", the call returns 4.
  - Existing tests that must stay green unchanged apart from the literal codes: the flag refusals of `run_detection`, its fatal-error panel test, `test_a_fatal_provider_error_exits_four_keeping_the_partial_result`, the nuisance gate's and holdout run's fatal-error tests, the `pytest.raises(KeyError)` and `pytest.raises(ValueError)` propagation tests.
- **Verify**: `uv run pytest tests/unit/evals/test_eval_display.py -n 0` red then green, then the short loop. The body of `run_detection.main` counts 20 lines. The two import-boundary commands exit 0. Then the closing check.

### Step 5: The honeypot suite stops at the first fatal model provider error

- **Files**: `tests/unit/evals/support/test_run_honeypot_suite_given.py`, `tests/unit/evals/test_run_honeypot_suite.py`, `evals/honeypot/runs.py`, `evals/honeypot/retest.py`, `evals/honeypots.py`, `evals/run_honeypot_suite.py`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/labeling-log.md`.
- **Do**:
  - Given first, beside `FakeHoneypotAudit`: `an_audit_raising(error)` and `a_suite_running(audit, runs) -> Callable[[], int]`, which runs `run_all(counted_audit(audit, SessionThrottles()), runs)` under `asyncio.run` and returns 0 (it stands for `_evaluate`). A builder of an error raised from one whose `code` is 403, built the way `a_google_error_caused_by_status` (in `tests/unit/evals/support/test_model_provider_errors_given.py`) builds its own.
  - Write the four tests below and see the first, second and fourth red.
  - `evals/run_honeypot_suite.py`: move `main`'s try and its two handlers unchanged into `exit_code_of(evaluate: Callable[[], int]) -> int`, below `main`. `main` ends with `raise SystemExit(exit_code_of(lambda: _evaluate(args)))`. Every printed byte and code of `main` stays.
  - `evals/honeypot/runs.py` `_run_or_warn` and `evals/honeypot/retest.py` `_retest_or_fail`: `except Exception as error:` whose first lines are `if classify(error) is ProviderErrorKind.FATAL: raise`, the warning kept for any other error. Written at both sites, no helper. Imports from `evals.model_provider_errors`. Update `_retest_or_fail`'s docstring (it no longer returns the failure message for every raised retest).
  - `evals/honeypots.py` `audit_honeypots`: `raise failures.exceptions[0] from None` becomes `leaf = failures.exceptions[0]` then `raise leaf from leaf.__cause__`.
  - Living docs, exactly as written under Change 5: the `CONTRIBUTING.md` sentence replacement in the honeypot recording paragraph, the `CHANGELOG.md` `[Unreleased]` Fixed line after the two lines on the nuisance gate and the detection command, and the new `docs/labeling-log.md` entry with its state, what changes, the fingerprint `072b33c72ecc3732df4df957ed3ff63662a6747ccb87ac29ed5332d1031cb025` and the four answers of ADR 016 (follow the format of the log's latest entry). No workflow changes.
- **Test** (the `exit_code_of` tests are synchronous and read output through `capsys`):
  - `exit_code_of(given.a_suite_running(given.an_audit_raising(ModelAuthenticationError("the API key was revoked")), runs=2))` is 4, stdout holds no "failed" warning, stderr holds "ModelAuthenticationError: the API key was revoked".
  - An audit raising a plain error from one whose `code` is 403: `exit_code_of` is 4 and stderr holds both messages (red until `audit_honeypots` keeps the cause).
  - An audit raising `ModelAPIError("overloaded")`: `run_all` returns `outcome.details == []` and stdout holds "Warning: run 1/1 failed:" (passes before the change, pins it).
  - A `Retester` built as `test_a_retest_holding_a_throttled_model_call_is_a_failed_retest` builds it, whose audit raises the fatal error: `retest_flips` raises that `ModelAuthenticationError`, with no warning announced.
  - `test_a_failing_honeypot_cancels_the_other_audits_of_its_run` (`tests/unit/evals/test_honeypots.py`) stays green.
- **Verify**: `uv run pytest tests/unit/evals/test_run_honeypot_suite.py tests/unit/evals/test_honeypots.py -n 0` red then green, then the short loop. The two import-boundary commands exit 0. `uv run pytest tests/integration/committed -n auto` green. Then the closing check (the ground truth fingerprint unchanged).

### Step 6: `_run_graded` split

- **Files**: `evals/run_detection.py`.
- **Do**: add a frozen dataclass `_GradedRun` (`tree`, `conditions`, `measurement`, `pricing`, `throttles`, `session`), defined before its readers. Below `_run_graded`, add `_report(args, flaws, graded) -> DetectionReport` (the results and the report, as the current report-building lines do) and `_published(args, report, session) -> int` (writes the report and export, prints the summary and the recording, prints the recording panel and returns 3 where it does today). `_run_graded` keeps its reads in order, the pricing and its "No cost reported" warning before the session, and ends with `return _published(args, _report(args, flaws, graded), session)`, about 11 body lines. No behavior change.
- **Test**: no new test. `test_a_graded_run_reports_the_tree_it_ran_on_and_the_tokens_billed`, the cost and measurement tests, `tests/unit/detection/test_run_detection_recording.py` and the container tests pin the report and output.
- **Verify**: `uv run pytest tests/unit/detection -n auto --maxprocesses 6` green, then the closing check. No function of `run_detection.py` exceeds 20 body lines apart from `_parse_args`.

### Step 7: The flag-rejection tests in their own file

- **Files**: `tests/unit/detection/test_run_detection.py`, `tests/unit/detection/test_run_detection_flags.py` (new).
- **Do**: move unchanged `test_incompatible_flags_are_refused_as_not_comparable`, `test_a_measurement_flag_outside_a_no_baseline_run_is_refused`, `test_chain_steps_without_chains_are_refused`, `test_a_measurement_flag_on_a_mode_that_runs_no_audit_is_refused_for_that_reason`, `test_a_negative_chain_count_is_refused_by_the_parser`, `test_an_unknown_flaw_id_is_refused_before_the_preflight` with `_a_preflight_that_must_not_run`, and `test_a_concurrency_below_one_is_refused_by_the_parser`. They read the shared `run_detection_cli` support, so no given or then file. Drop the imports the old file no longer uses.
- **Test**: the moved tests pass. The collected test count (`uv run pytest --collect-only -q | tail -1`) is the same before and after. `tests/unit/project/test_code_standards.py` stays green.
- **Verify**: `uv run pytest tests/unit/detection/test_run_detection.py tests/unit/detection/test_run_detection_flags.py -n 0` green, the old file near 230 lines, then the closing check.

### Step 8: A test of the `[excluded_server]` tag of the `walk` line

- **Files**: `tests/unit/nuisance/support/test_run_nuisance_given.py` (new), `tests/unit/nuisance/test_run_nuisance.py`.
- **Do**: in the new given, `a_walk_reaching_an_excluded_server(tmp_path) -> list[str]`, returning the `walk` arguments of this census and record: `censuses.with_a_cve_of(censuses.a_census(), QUEUE_FLAW, walks.AN_EXCLUDED_SERVER)` with the second classifier naming another package (`walks.with_the_second_classifier_overriding`) and the figures recomputed (`censuses.recomputed`), then `census_draws.with_a_walk_skipping(..., admissions.FIRST_FLAW)`; a walk record from `walks.an_empty_record()` with an `IdentitySettlement` of `QUEUE_FLAW` to `walks.AN_EXCLUDED_SERVER`, written with `walks.written_record`; and an admission path that does not exist. `QUEUE_FLAW` comes from `nuisance_queue_walks.py`. Read the existing walk tests of `test_run_nuisance.py` and those support modules for the exact signatures and argument flags.
- **Test**: `test_walk_tags_an_excluded_server`: `run_nuisance.main(["walk", *arguments])` returns 0, and the printed line holding `walks.AN_EXCLUDED_SERVER` ends with the literal `  [excluded_server]`. It pins existing behavior: see it red once by changing the tag in `_walk_line` (`evals/run_nuisance.py`) for a moment, then undo that change before the commit.
- **Verify**: `uv run pytest tests/unit/nuisance/test_run_nuisance.py -n 0` green, `git diff --stat` shows no change to `evals/`, then the closing check.

### Step 9: Tests of the default number of runs of both holdout runs

- **Files**: `tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py`, `tests/unit/nuisance/test_run_nuisance_holdout_run.py`, `tests/unit/detection/support/test_run_detection_holdout_run_given.py`, `tests/unit/detection/test_run_detection_holdout_run.py`.
- **Do**: add `an_admitted_run_capturing_its_inputs() -> tuple[NuisanceCommandDeps, list[NuisanceHoldoutRunInputs]]` to the nuisance given, built as `an_admitted_run_keeping_its_provenance` is, its orchestrator appending each input it receives and returning a run result; and `a_drawn_run_capturing_its_inputs() -> tuple[HoldoutCommandDeps, list[HoldoutRunInputs]]` to the detection given, through `holdout_command_deps.a_drawn_run_through`.
- **Test**:
  - `test_run_hands_its_orchestrator_two_runs_by_default`: `run_nuisance.main(given.a_run_command(tmp_path), deps)` returns 0 and the captured `runs` are `[2]`.
  - `test_run_hands_its_orchestrator_three_runs_by_default`: with `command_deps.a_ready_run(monkeypatch)` and `_run_flags(tmp_path, report)`, `run_detection_holdout.main` returns 0 and the captured `runs` are `[3]`.
  - Both assert literals, never `NUISANCE_RUNS` or `HOLDOUT_RUNS`. See each red once by changing its default (`NUISANCE_RUNS`, `HOLDOUT_RUNS`) for a moment, then undo that change before the commit.
- **Verify**: the two test files with `-n 0` green, `git diff --stat` shows no change to `evals/`, then the closing check.

### Step 10: "Holdout fixture" written "detection fixture"

- **Files**: `CLAUDE.md`, `tests/integration/test_nuisance_doris_backend.py`.
- **Do**: in the `nuisance-dossier` line of `CLAUDE.md`'s Commands list, "its holdout fixture and builder as text" becomes "its detection fixture and builder as text". In the docstring of `tests/integration/test_nuisance_doris_backend.py`, "and the holdout fixture's benign call answers without error" becomes "and the benign call of the holdout target's detection fixture answers without error". The kit text of `admission_docs.py` and the kit path `reference/holdout_fixtures/` stay.
- **Test**: no new test. The Doris test runs only behind `NUISANCE_DORIS=1` and its code does not change.
- **Verify**: `uv run pytest tests/integration/committed -n auto` green, `git diff` shows two one-line edits, then the closing check.
