# Pyrefly replaces pyright

## Context

The type check is `uv run pyright` in strict mode (`[tool.pyright]`, `typeCheckingMode = "strict"`). A full run takes 15 to 20 s and 1.4 GB of memory on the maintainer's laptop, and `--threads` does not help. In the loop, CLAUDE.md has the developer type-check only the changed files, which misses an error a changed signature causes in a caller, so every closing pass runs the full check again.

Pyrefly (Meta, stable since 1.0 in May 2026, MIT) checks the whole repository in about 2 s and 390 MB with a configuration close to pyright strict, measured on 2026-11-22 with pyrefly 1.5.0: the `strict` preset plus the unknown-type family (`unknown-attribute-access`, `unknown-attribute-type`, `unknown-from-error`, `unknown-variable-type`, `unknown-return-type`, `unknown-argument-type`), `implicit-any-parameter`, `implicit-any-type-argument`, `untyped-import`, `protected-access` and `untyped-function-decorator`. Pyrefly documents a pyright equivalent for each of these (https://pyrefly.org/en/docs/migrate/pyright/diagnostics/). That run reported 120 errors once the existing `# pyright: ignore` comments were honored, grouped below. Three of them (`src/mcp_auditor/domain/models.py:126` and `:256`, a `bad-return` and two `bad-argument-type` between `src.mcp_auditor.domain.models` and `mcp_auditor.domain.models`) came from the measurement's search path and disappear under the configuration below: with it, the same run reports 117 errors and 4 warnings (`unnecessary-type-conversion`), and 128 errors once only `# pyrefly: ignore` comments are honored, the dialect the configuration keeps. ty (Astral) was ruled out: it is still 0.0.x and has no equivalent of the unknown-type family yet.

The goal: pyright leaves the project, Pyrefly takes its place in the dependencies, the configuration, CI, the docs and the suppression comments, and the whole repository checks clean under a configuration that keeps what pyright strict checked, apart from the checks Pyrefly 1.5.0 has no counterpart for (listed in the Decisions).

## Decisions

- Pyright is removed in this change, not run beside Pyrefly for a transition period.
- The configuration starts from the `strict` preset and turns on, at error level, every kind listed above. It keeps `missing-override-decorator`, which the `strict` preset enables and pyright did not have: every overriding method gets `typing.override` (PEP 698).
- Pyrefly reads pydantic constructors in lax mode (a field typed `int` accepts what pydantic would coerce), so some constructor errors pyright reports go quiet. This loss is accepted: the models keep their runtime behavior, and no model is switched to pydantic strict.
- One suppression dialect. Every `# pyright: ignore[...]`, every file-level `# pyright: rule=false` comment and every `# type: ignore[...]` becomes a `# pyrefly: ignore[kind]` on the line that needs it, or disappears when Pyrefly does not need it. `enabled-ignores = ["pyrefly"]`, so a leftover comment of another dialect silences nothing, and `unused-ignore` is an error, so an unused ignore fails the check.
- No AST change to a fingerprinted source (see below). In such a file, an error is silenced with a `# pyrefly: ignore[kind]` comment only.
- Since a full run takes about 2 s, the loop type-checks the whole project, not the changed files.
- Pyright's lint-style rules are left to Ruff, whose `[tool.ruff.lint]` selection already covers unused imports (`F401`), unused variables (`F841`), duplicate imports (`F811`) and unused expressions (`B018`). Pyrefly 1.5.0 has `unused-import` and `unused-variable` kinds, at hint level, and they stay off. Pyright's unused private classes and functions (`reportUnusedClass`, `reportUnusedFunction`) have no counterpart in Ruff's selection or in Pyrefly. Nothing is added to the Ruff selection.
- Some pyright strict checks have no working counterpart in Pyrefly 1.5.0, and their loss is accepted: `reportUnnecessaryIsInstance` (the documented `redundant-type-check` kind is not accepted by the 1.5.0 configuration), `reportUnnecessaryContains`, the `x is None` form of `reportUnnecessaryComparison`, `reportTypeCommentUsage` and `reportInconsistentConstructor`, beside the unused private classes and functions above.

## Fingerprinted sources must not move

Several instruments hash Python sources through `evals/baseline.py:fingerprint_source`, which hashes the AST and leaves comments, formatting and the module docstring out. A change to the AST of one of these files moves a fingerprint, and a moved fingerprint resets a baseline, makes earlier holdout detection rates exploratory, or makes a holdout calibration copy stale. The fingerprinted sources are:

- the grammar: `evals/cve/detection/baseline.py:GRAMMAR_PATHS` (`grammar`, `proofs`, `units`, `report_units`). `evals/cve/proofs.py` carries four Pyrefly errors today (lines 89 to 92: `unknown-argument-type`, `implicit-any-type-argument`), plus an `unknown-variable-type` on lines 88 and 91 that their `# pyright: ignore` comments silence today.
- the planting code: `ENVIRONMENT_PATHS` in the same module. `evals/cve/planting_base.py:218` carries a `# type: ignore[operator]` that Pyrefly needs as `# pyrefly: ignore[not-callable]` (a comment change, AST unchanged).
- each target's `backend_sources`, and the Python sources `evals/cve/nuisance/fingerprint.py:nuisance_fixture_fingerprint` hashes for a nuisance fixture: the confinement source (`CONFINEMENT_SOURCE`), each backend's served `.py` modules (`backend_registry.BACKENDS[...].served`) and the planting modules of `_PUBLIC_NAME_SOURCES`. Fix-check modules are not fingerprinted.
- the counter: `evals/cve/nuisance/counter.py:_COUNTER_PATHS`.
- the honeypot servers, whose `fingerprint_source` the honeypot baseline records (`evals/eval_session.py`): `tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`. Each carries one `missing-override-decorator` error today, and `tests/chain_honeypot_server.py:189` an `unnecessary-type-conversion` warning. These files are also fixtures with planted flaws (CLAUDE.md Landmines): nothing in them changes but comments.

Before any code change, the implementer records every fingerprint with a throwaway script outside the repository (the scratchpad), and records them again at the end. The two lists must be identical:

- `grammar_fingerprint()` and `counter_fingerprint()`;
- `fixture_fingerprint(...)` of every acceptance target and every holdout target, called as `evals/run_detection.py` and `evals/run_nuisance.py` call it;
- `nuisance_fixture_fingerprint(...)` of every admitted server, called as `evals/run_nuisance.py` calls it;
- `fingerprint_source(path.read_text())` of the three honeypot servers.

The committed records also guard this: `tests/unit/nuisance/admission/test_nuisance_admission_loads.py::test_every_holdout_calibration_copy_is_recorded_at_its_targets_current_fingerprint` (or its new location under `tests/integration/committed/` once the short-loop plan has moved it) fails on a moved target fingerprint.

## Prerequisite

This plan runs after `plans/2026-11-22_faster-unit-short-loop.md` has landed: that plan moves test files this one edits and names `uv run pyright` in its verification. The error list below was taken before those moves. The implementer reruns Pyrefly at the start to get the current paths.

## Configuration

`pyproject.toml`:

- `[dependency-groups] dev`: remove `pyright>=1.1`, add `pyrefly>=1.5` and `types-PyYAML` (pyright bundles typeshed's third-party stubs, Pyrefly does not, and `yaml` is imported in seven places). `uv lock` updates `uv.lock`, and the locked versions are what CI runs.
- Remove `[tool.pyright]` and its comment.
- Add `[tool.pyrefly]`:
  - `project-includes = ["src", "evals", "tests"]`. Every tracked Python file sits under these three, and `output/` (gitignored, the census agents' scripts) lies outside them, so no `project-excludes` is needed.
  - `python-version = "3.13"`.
  - `preset = "strict"`.
  - `enabled-ignores = ["pyrefly"]`.
  - `min-severity = "warn"`, so a warning-level finding also makes `uv run pyrefly check` exit non-zero (checked with pyrefly 1.5.0: without it, a warning prints and the exit code stays 0).
  - `[tool.pyrefly.errors]`: `unknown-attribute-access`, `unknown-attribute-type`, `unknown-from-error`, `unknown-variable-type`, `unknown-return-type`, `unknown-argument-type`, `implicit-any-parameter`, `implicit-any-type-argument`, `untyped-import`, `protected-access`, `untyped-function-decorator`, `untyped-class-decorator`, `untyped-namedtuple`, `incompatible-comparison`, `unnecessary-comparison`, `unknown-base-class` and `unused-ignore` set to `"error"`. The five kinds after `untyped-function-decorator` report nothing on the repository today and keep pyright strict's untyped class decorator, untyped namedtuple and unnecessary comparison checks for the code to come. With `min-severity = "warn"`, any kind the preset leaves at warning level (today only `unnecessary-type-conversion` fires) fails the check too, so its exit code alone decides whether the check passes.
  - `search-path = ["src", "."]`, in that order. With a `src/` directory beside the config, Pyrefly's inferred import root is `src/` alone, so with no search path every `evals.*` and `tests.*` import is a `missing-import`. With `"."` alone, the files under `src/` are named `src.mcp_auditor...` while their imports resolve to `mcp_auditor...` through the editable install, and the two collide (the three `models.py` errors above). `src` first gives each file under it its `mcp_auditor` name, and `"."` resolves `evals` and `tests` (checked with pyrefly 1.5.0 on a scratch layout and on the repository).
  - The interpreter: Pyrefly must resolve the project's `.venv` under `uv run pyrefly check` with no path in the configuration (`uv run pyrefly dump-config` names the interpreter it uses). If it does not, set `python-interpreter-path = ".venv/bin/python"`.
- `.gitignore`: remove `.pyright/`.

## The errors to clear

The measured run grouped them as below. Each is fixed in the code where the file is not fingerprinted, else silenced with a `# pyrefly: ignore[kind]` comment carrying no prose beyond what the kind says, unless the reason is not obvious from the line.

- `bad-argument-type`, 50 of them on three lines: test helpers that forward `**changes: object` to `dataclasses.replace` (`tests/unit/support/acceptance_targets.py:15`, `tests/unit/detection/support/test_detection_baseline_given.py:128` and `:135`). Pyrefly checks each forwarded field against the synthesized `__replace__`. These helpers forward arbitrary field changes by design. Silence the three lines rather than mirror `Target`'s fields in a `TypedDict` that would drift from it.
- LangGraph's `StateGraph` (`src/mcp_auditor/graph/builder.py`, about ten `bad-specialization` and `bad-argument-type` on the state and input schemas and the node actions). Pyright's file-level `reportUnknownMemberType=false, reportArgumentType=false` hid them. They come from LangGraph's typing of its state bound. Silence them line by line and drop the file-level comment.
- The other file-level pyright comments (`src/mcp_auditor/audit.py`, `src/mcp_auditor/stream_handler.py`, `tests/unit/auditor/test_chat_model_factory.py`): drop them, and silence or fix line by line what Pyrefly then reports.
- `src/mcp_auditor/adapters/anthropic_structured_output.py`: an `unsupported-operation` on the `|` of two LangChain runnables (line 37) and a `missing-attribute` on `to_domain` read from `object` (line 99). Fix the second by narrowing the type if the code allows, else silence it. Silence the first.
- `implicit-any-empty-container`, 15 of them (`evals/cve/detection/route_check.py`, `evals/cve/nuisance/gate/gate_command.py`, test supports): annotate the container where the file is not fingerprinted.
- Invariance of generic containers (`evals/run_nuisance.py:169`, a `dict[str, Literal[...]]` passed as `dict[str, str]`; `tests/unit/cve/backends/support/test_gitlab_backend_given.py:36` and `test_kubernetes_backend_given.py:29`, tuple keys; `tests/unit/detection/test_detection_holdout_audit.py:143`): widen the parameter to `Mapping` or `Sequence`, or annotate the argument, whichever keeps the call site honest.
- `evals/cve/proofs.py:89` to `92` (fingerprinted): silence with comments only.
- `unknown-argument-type` elsewhere (`tests/unit/census/support/test_run_census_given.py:132`, `tests/unit/detection/test_detection_holdout_fixture_sources.py:12`): fix by annotating.
- `untyped-import` on `yaml`: gone with `types-PyYAML`.
- `missing-override-decorator`, 25 of them: add `@override` (from `typing`) in every file that is not fingerprinted. In the three honeypot servers, silence it with a comment.
- `unnecessary-type-conversion`, the four warnings: remove the redundant `bool()` or `str()` in `evals/cve/kit/client.py:118`, `src/mcp_auditor/adapters/mcp_client.py:113` and `src/mcp_auditor/domain/shown_response.py:20`. In `tests/chain_honeypot_server.py:189`, silence it with a comment.
- Errors that the existing `# pyright: ignore` and `# type: ignore` comments hide today and that reappear once only `# pyrefly: ignore` is honored (eleven of them: `evals/cve/planting_base.py:218`, `evals/cve/proofs.py:88` and `:91`, `anthropic_structured_output.py:37` and `:99`, the `FakeChatModel` passed as `BaseChatModel` on four lines of three test supports, `tests/unit/auditor/test_openrouter_models.py:106`, `tests/unit/evals/test_export.py:84`): handled through the conversion of their comments below.
- The 51 `# pyright: ignore[...]` and 19 `# type: ignore[...]` comments: each becomes the `# pyrefly: ignore[kind]` Pyrefly needs on that line, or is removed when Pyrefly reports nothing there. `unused-ignore` proves none is unused.

## What the destructive-payload guard relies on

ADR 013 records that `BlockedPayload` shares no attribute name with `ToolResponse`, so an unhandled blocked payload is a type error under strict pyright. The ADR is immutable and stays as written. The property has to hold under Pyrefly too: during the migration, the implementer writes a throwaway file under `tests/` (never committed) that reads `.content` on the `outcome` of the `SendAttempt` that `AuditedServer.attempt` returns (`ToolResponse | BlockedPayload | UnsentPayload`) without narrowing, checks that `uv run pyrefly check` reports a `missing-attribute` on it (pyrefly 1.5.0 does, checked on a scratch file), and deletes the file. The step report says it was done.

## Living docs and tooling

- `CLAUDE.md`:
  - Commands: `uv run pyright  # Type check (strict mode)` becomes `uv run pyrefly check             # Type check (strict, see [tool.pyrefly])`. The comment names no pyright, or the grep below fails on it.
  - Workflow: the sentence on type-checking only the changed files with `uv run pyright <files>`, and its caveat about callers, becomes: type-check the whole project with `uv run pyrefly check`, it takes about 2 s. The closing-pass sentence names `uv run pyrefly check`.
  - Coding standards: nothing names pyright there. Check the Landmines for any mention and update it.
- `CONTRIBUTING.md`: the command block and the "make sure `main` is green" line name `uv run pyrefly check`.
- `.github/workflows/ci.yml`: the "Type check" step runs `uv run pyrefly check`.
- `.claude/skills/standards/SKILL.md`, `.claude/skills/design-patrol/SKILL.md` and `.claude/skills/patrol/SKILL.md`: every `uv run pyright` becomes `uv run pyrefly check`, and "pyright" in prose becomes "the type check" or "Pyrefly".
- `tests/unit/auditor/support/graph_builders.py:77`: the comment says `CompiledStateGraph` is partially unknown "under strict pyright". Restate it for Pyrefly if it still holds, else remove the comment and what it justifies.
- `grep -rniw pyright` over the living text (`-w`, or `copyright` matches) (code, comments, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `docs/usage.md`, `docs/evals.md`, `evals/*.md`, the workflows, the skills) returns nothing. `docs/adr/`, `plans/` and the dated log entries keep their mentions.
- `CHANGELOG.md`: no entry. The type checker is contributor tooling, not a user-facing change.

## What stays unchanged

- Every fingerprint listed above, byte for byte.
- The honeypot servers, apart from comments.
- Runtime behavior: no change to any model's pydantic configuration, no change to what any function does. The code changes are annotations, `@override`, and parameter types widened to an abstract collection.
- Ruff's configuration.
- `docs/adr/` and `plans/`.

## Edge cases

- A line where Pyrefly reports two kinds: one comment lists both, `# pyrefly: ignore[kind-a, kind-b]`. Check the exact syntax in Pyrefly's suppression docs.
- A `# type: ignore` on an import that Pyrefly resolves cleanly (LangGraph ships types): remove it, `unused-ignore` would flag it otherwise.
- `@override` on a method of a `Protocol` implementation that does not inherit from the protocol: Pyrefly does not ask for it there. Add it only where it reports.
- A fix in a non-fingerprinted file that changes an import that a fingerprinted file re-exports: does not move the fingerprint, since only the listed files are hashed. The before-and-after comparison is the proof.

## Verification

- `uv run pyrefly check` exits 0 with no error and no warning, in about 2 s.
- The fingerprint lists before and after are identical.
- The ADR 013 throwaway file was rejected with `missing-attribute`.
- `grep -rniw pyright` over the living text returns nothing, `git grep -n "type: ignore" -- '*.py'` returns nothing (a leftover `# type: ignore` silences nothing under `enabled-ignores = ["pyrefly"]` but would mislead a reader), and `uv.lock` no longer holds pyright.
- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, all green.

## Due diligence record

What the due-diligence pass concluded on 2026-11-22 about the external facts this plan cites or defers, for the implementation-phase fact check and any later pass. It records what was concluded once, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `pyrefly>=1.5` (PyPI: 1.5.0 is the latest release, MIT; 1.0.0 released 2026-05-12, per the GitHub release and the pyrefly.org v1.0 post)
- SETTLED: `types-PyYAML` (PyPI: 6.0.12.20261113, targets `PyYAML==6.0.*`, the locked `pyyaml` is 6.0.3)
- SETTLED: `[tool.pyrefly]` with `project-includes`, `python-version = "3.13"`, `preset = "strict"`, `enabled-ignores = ["pyrefly"]`, `min-severity = "warn"`, `search-path = ["src", "."]` and a `[tool.pyrefly.errors]` table (pyrefly.org configuration docs, and every key accepted by pyrefly 1.5.0 on the repository and on a scratch `pyproject.toml`)
- SETTLED: `unknown-attribute-access`, `unknown-attribute-type`, `unknown-from-error`, `unknown-variable-type`, `unknown-return-type`, `unknown-argument-type`, `implicit-any-parameter`, `implicit-any-type-argument`, `untyped-import`, `protected-access`, `untyped-function-decorator`, `unused-ignore` (each accepted by pyrefly 1.5.0's config parser, which rejects an unknown kind; each mapped from a pyright rule on https://pyrefly.org/en/docs/migrate/pyright/diagnostics/)
- SETTLED: `min-severity = "warn"` turns a warning into a non-zero exit (pyrefly 1.5.0 on a scratch file: exit 0 without it, 1 with it)
- SETTLED: `# pyrefly: ignore[kind-a, kind-b]` (pyrefly 1.5.0 on a scratch file; `unused-ignore` reports each unused code of a multi-code comment separately)
- SETTLED: under `enabled-ignores = ["pyrefly"]`, a `# type: ignore[...]` silences nothing (pyrefly 1.5.0 on a scratch file)
- SETTLED: the repository under the plan's configuration reports 128 errors and 4 `unnecessary-type-conversion` warnings, in about 1.3 s wall and 384 MB (pyrefly 1.5.0, working tree of 2026-11-22, `.venv` interpreter)
- SETTLED: Pyrefly finds `.venv/bin/python` from the repository root with no `python-interpreter-path` (`pyrefly dump-config`, pyrefly 1.5.0)
- SETTLED: an unnarrowed `.content` on `SendAttempt.outcome` is a `missing-attribute` (pyrefly 1.5.0 on a scratch file importing `mcp_auditor.domain.audited_server`)
- SETTLED: `typing.override` (PEP 698, standard library since Python 3.12, the project requires 3.13)
- SETTLED: Pyrefly reads pydantic constructors in lax mode by default (https://pyrefly.org/en/docs/pydantic/)
- SETTLED: ty is at 0.0.107 on PyPI and its rule reference lists no unknown-type rule
- OPEN (deferred): the per-line `# pyrefly: ignore[kind]` kinds and the error paths, retaken by rerunning Pyrefly once `plans/2026-11-22_faster-unit-short-loop.md` has landed, since that plan moves files this one edits

## Implementation steps

The work is cut so that every commit stays green under the checks it documents: Pyrefly joins beside pyright first, the reports Pyrefly makes on lines no pyright or `type:` comment covers are cleared while `uv run pyright` still closes each step, and the last step switches dialect and tooling at once. Before Step 3, `uv run pyrefly check` is a measurement, not a gate: it may exit non-zero, and each step states what it must still report.

Facts checked while cutting the steps (pyrefly 1.5.0, ruff of the locked `.venv`, on scratch files): Ruff's `E501` measures a line without a trailing `# pyrefly: ignore[...]` pragma, so a suppression never makes a line too long. Pyrefly also honors a `# pyrefly: ignore[kind]` on its own line just above the flagged line, which keeps a long line readable.

Fingerprint record, used by every step. At the start of the step, before any edit, the implementer writes (or rewrites, if a previous session's copy is gone) a throwaway script in its scratchpad, never in the repository, that prints one sorted line per fingerprint listed in "Fingerprinted sources must not move": `grammar_fingerprint()` and `counter_fingerprint()`; `fixture_fingerprint(target, load_places(DETECTION_PLACES))` for every target of `ACCEPTANCE_TARGETS` (`evals/cve/detection/targets.py`) and `HOLDOUT_TARGETS` (`evals/cve/detection/holdout_targets.py`), as `evals/run_nuisance.py:current_copy_fingerprints` calls it; `nuisance_fixture_fingerprint(server)` for every admitted server of `evals/nuisance_admission.json`, loaded as `evals/cve/nuisance/commands.py` loads it (`load_admission` with the walk inputs); `fingerprint_source(path.read_text())` of the three honeypot servers. It saves the output, reruns the script after the last edit, and `diff`s the two outputs: they must be identical. The step report says so.

### Step 1: Pyrefly beside pyright, and the reports in `src/` and `evals/`

- **Files**: `pyproject.toml`, `uv.lock`; `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/adapters/throttling.py`, `src/mcp_auditor/adapters/log_redaction.py`, `src/mcp_auditor/adapters/mcp_client.py`, `src/mcp_auditor/domain/shown_response.py`, `src/mcp_auditor/graph/builder.py`, `evals/cve/detection/route_check.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/cve/kit/client.py`, `evals/run_nuisance.py`, `evals/cve/proofs.py` (comments only). The exact set is the one the rerun below names.
- **Do**:
  1. Check that `plans/2026-11-22_faster-unit-short-loop.md` has landed (its moves committed on `main`, a clean `git status` apart from this plan). If not, stop and report.
  2. Take the "before" fingerprint record.
  3. `pyproject.toml`: add `pyrefly>=1.5` and `types-PyYAML` to `[dependency-groups] dev`, keeping `pyright>=1.1` for now. Add `[tool.pyrefly]` exactly as the Configuration section says (`project-includes`, `python-version`, `preset`, `enabled-ignores`, `min-severity`, `search-path = ["src", "."]`, the `[tool.pyrefly.errors]` table). Leave `[tool.pyright]` in place. Run `uv lock` (and `uv sync`), then `uv run pyrefly dump-config` to confirm the `.venv` interpreter is used with no `python-interpreter-path`; add that key only if it is not.
  4. Run `uv run pyrefly check --output-format min-text` and keep the list. Under `src/` and `evals/`, clear every report on a line that carries no `# pyright: ignore` or `# type: ignore` comment, in a file that carries no file-level `# pyright:` comment other than `builder.py`:
     - `missing-override-decorator` (the four comparison methods of `Severity` in `models.py`, `throttling.py`, `log_redaction.py`): add `from typing import override` and `@override`.
     - `unnecessary-type-conversion` in `mcp_client.py`, `shown_response.py`, `evals/cve/kit/client.py`: remove the redundant `bool()` or `str()`.
     - `implicit-any-empty-container` in `route_check.py` and `gate_command.py`: annotate the container.
     - `evals/run_nuisance.py:169`, a `dict[str, Literal[...]]` passed as `dict[str, str]`: widen the callee's parameter to `Mapping[str, str]` if the callee only reads it, else annotate the argument.
     - `src/mcp_auditor/graph/builder.py` (`bad-specialization`, `bad-argument-type` on `StateGraph` and `add_node`): a `# pyrefly: ignore[kind]` on each flagged line. Keep the file-level pyright comment, Step 3 drops it.
     - `evals/cve/proofs.py:89`, `:90`, `:92` (fingerprinted): `# pyrefly: ignore[kind]` comments only, no other byte of the line changes. Lines 88 and 91 carry `# pyright: ignore` and wait for Step 3.
     - `untyped-import` on `yaml` (`src/mcp_auditor/config_file.py` and the test files): gone with `types-PyYAML`.
  5. Take the "after" fingerprint record and compare.
- **Test**: no new test, the changes are annotations, decorators, comments and one widened parameter. The existing suite proves no behavior moved.
- **Verify**:
  - `uv run pyrefly check --output-format min-text`: no report left under `src/` or `evals/` except on `evals/cve/planting_base.py:218`, `evals/cve/proofs.py:88` and `:91`, `src/mcp_auditor/adapters/anthropic_structured_output.py:37` and `:99` (lines a pyright or `type:` comment covers). No `unused-ignore`. Reports under `tests/` remain.
  - Fingerprint records identical.
  - `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all green.

### Step 2: the reports in `tests/`

- **Files**: the files under `tests/` that `uv run pyrefly check` names on lines with no `# pyright: ignore` or `# type: ignore` comment. Measured before the short-loop moves landed, about thirty, among them `tests/unit/support/acceptance_targets.py`, `tests/unit/detection/support/test_detection_baseline_given.py`, `tests/unit/detection/support/detection_sessions.py`, `tests/unit/detection/support/test_detection_replay_given.py`, `tests/unit/detection/support/test_detection_session_given.py`, `tests/unit/detection/test_detection_holdout_audit.py`, `tests/unit/auditor/support/test_checkpointing_given.py`, `tests/unit/auditor/support/test_graph_given.py`, `tests/unit/census/support/test_run_census_given.py`, `tests/unit/cve/backends/support/test_gitlab_backend_given.py`, `tests/unit/cve/backends/support/test_kubernetes_backend_given.py`, `tests/unit/cve/support/test_cve_planting_stand_ins_given.py`, `tests/unit/cve/support/test_kit_benign_probe_given.py`, `tests/unit/cve/test_cve_holdout_conditions.py`, `tests/integration/support/test_cve_planting_given.py`, `tests/integration/support/test_cve_planting_stand_ins_given.py`, `tests/integration/support/test_cve_planting_stand_ins_then.py`, `tests/integration/support/detection_read_server.py`, `tests/integration/committed/detection/test_detection_holdout_fixture_sources.py`, and the three honeypot servers. Each edit is one line located by the report, so read only the flagged range of each file.
- **Do**:
  1. Take the "before" fingerprint record.
  2. Clear each report as "The errors to clear" says:
     - `bad-argument-type` on the `dataclasses.replace(..., **changes)` lines of `acceptance_targets.py` and `test_detection_baseline_given.py`: one `# pyrefly: ignore[bad-argument-type]` per line.
     - `missing-override-decorator`: `@override` from `typing`, except in `tests/honeypot_server.py`, `tests/subtle_server.py` and `tests/chain_honeypot_server.py`, where it is a `# pyrefly: ignore[missing-override-decorator]` comment. In `tests/chain_honeypot_server.py:189`, `# pyrefly: ignore[unnecessary-type-conversion]`. Nothing else in the honeypot servers changes.
     - `implicit-any-empty-container`: annotate the container.
     - Invariance on tuple keys (`test_gitlab_backend_given.py:36`, `test_kubernetes_backend_given.py:29`) and `test_detection_holdout_audit.py:143`: widen the helper's parameter to `Mapping` or `Sequence`, or annotate the argument, whichever keeps the call site honest.
     - `unknown-argument-type` (`test_run_census_given.py:132`, `test_detection_holdout_fixture_sources.py`): annotate.
     - Any other kind: fix by annotation where the line allows it, else a `# pyrefly: ignore[kind]`.
  3. Take the "after" fingerprint record and compare (the honeypot servers changed by comments only, so their `fingerprint_source` must not move).
- **Test**: no new test. The existing suite, the honeypot servers' integration tests included, proves nothing moved.
- **Verify**:
  - `uv run pyrefly check --output-format min-text`: the only reports left are on lines a `# pyright: ignore` or `# type: ignore` comment covers (Step 1's five, plus the `FakeChatModel` lines of `tests/unit/auditor/support/test_graph_throttling_given.py`, `test_llm_adapter_given.py`, `test_llm_patience_given.py`, `tests/unit/auditor/test_openrouter_models.py:106` and `tests/unit/evals/test_export.py:84`, at their current paths). No `unused-ignore`.
  - Fingerprint records identical.
  - `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all green.

### Step 3: one dialect, pyright removed, living docs

- **Files**: every `.py` file carrying `# pyright:` or `# type: ignore` (`git grep -ln "pyright:\|type: ignore" -- '*.py'`, about thirty, among them `src/mcp_auditor/adapters/chat_model_factory.py`, `anthropic_structured_output.py`, `llm.py`, `graph/builder.py`, `audit.py`, `stream_handler.py`, `evals/cve/planting_base.py`, `evals/cve/proofs.py`, `tests/unit/auditor/test_chat_model_factory.py`); `tests/unit/auditor/support/graph_builders.py`; `pyproject.toml`, `uv.lock`, `.gitignore`, `.github/workflows/ci.yml`, `CLAUDE.md`, `CONTRIBUTING.md`, `.claude/skills/standards/SKILL.md`, `.claude/skills/design-patrol/SKILL.md`, `.claude/skills/patrol/SKILL.md`. The comment edits are mechanical, so a scripted removal followed by targeted re-additions keeps the context small.
- **Do**:
  1. Take the "before" fingerprint record.
  2. Remove every trailing `# pyright: ignore[...]` and `# type: ignore[...]` comment from the Python sources (a scripted removal of the comment only, the code before it untouched), and the file-level `# pyright: ...=false` comments of `builder.py`, `audit.py`, `stream_handler.py` and `test_chat_model_factory.py`.
  3. Run `uv run pyrefly check --output-format min-text`. For each report now:
     - `anthropic_structured_output.py:99` (`missing-attribute` on `to_domain` read from `object`): narrow the type if the code allows it, else `# pyrefly: ignore[missing-attribute]`. `:37` (`unsupported-operation` on the `|` of two runnables): `# pyrefly: ignore[unsupported-operation]`.
     - `evals/cve/planting_base.py:218`: `# pyrefly: ignore[not-callable]`. `evals/cve/proofs.py:88` and `:91`: `# pyrefly: ignore[unknown-variable-type]` (two kinds on one line in a single comment, `# pyrefly: ignore[kind-a, kind-b]`). Comments only in these fingerprinted files.
     - The `FakeChatModel` lines, `test_openrouter_models.py:106`, `test_export.py:84`, and whatever the removed file-level comments uncover in `audit.py`, `stream_handler.py`, `test_chat_model_factory.py`: fix by annotation where the line allows it, else `# pyrefly: ignore[kind]`.
     - A removed `# type: ignore` on an import Pyrefly resolves stays removed.
  4. `tests/unit/auditor/support/graph_builders.py:77`: simplify the construct the "under strict pyright" comment justifies and rerun Pyrefly. If Pyrefly then reports an error there, restore the construct and restate the comment for Pyrefly. Else keep the simplification and drop the comment.
  5. `pyproject.toml`: remove `pyright>=1.1` and `[tool.pyright]` with its comment, run `uv lock`. `.gitignore`: remove `.pyright/`. `.github/workflows/ci.yml`: the "Type check" step runs `uv run pyrefly check`.
  6. Living docs, as "Living docs and tooling" says: `CLAUDE.md` (the Commands line `uv run pyrefly check             # Type check (strict, see [tool.pyrefly])`, the Workflow sentences on the loop and the closing pass, any Landmine mention), `CONTRIBUTING.md` (command block, the "make sure `main` is green" line), the three skills. No `CHANGELOG.md` entry, no edit under `docs/adr/` or `plans/`.
  7. ADR 013 property: write a throwaway file under `tests/` that reads `.content` on the unnarrowed `outcome` of the `SendAttempt` returned by `AuditedServer.attempt`, check that `uv run pyrefly check` reports a `missing-attribute` on it, delete the file. The step report says it was done.
  8. Take the "after" fingerprint record and compare.
- **Test**: no new test. The ADR 013 check above is the one behavior of the type check itself that this change must preserve.
- **Verify**:
  - `uv run pyrefly check` exits 0 with no error and no warning, in about 2 s.
  - Fingerprint records identical.
  - `grep -rniw pyright` over `src/`, `evals/`, `tests/`, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `docs/usage.md`, `docs/evals.md`, `evals/*.md`, `.github/`, `.claude/skills/` returns nothing. `git grep -n "type: ignore" -- '*.py'` returns nothing. `grep -n pyright uv.lock` returns nothing.
  - `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`: all green.
