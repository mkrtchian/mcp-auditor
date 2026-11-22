# Enforce the strict code standards

## Context

`CLAUDE.md` sets coding and testing standards that nothing checks today. A deterministic inventory of the tree (977 tracked Python files, the 45 fingerprinted ones set aside) found that the hexagon already holds: no import of `adapters/` or of the composition root from `domain/` or `graph/`, no hidden I/O there. Three strict rules do not hold:

- **Newspaper order**: 394 top-level functions in 227 files are defined above every top-level definition that uses them, plus 15 in 12 fingerprinted files.
- **One given/then pair per test file**: 139 imports from test files, and 164 imports from given, then or support modules, reach another test file's given or then. Some givens re-export another given's names (`__all__`, `X as X`), which hides the foreign import.
- **Fakes, not mocks**: 82 `monkeypatch.setattr` calls in 36 files, and one `unittest.mock` use.

Ruff has no plugin system, so it can enforce only what its built-in rules express. Its `TID251` (banned-api), scoped per directory with a nested `ruff.toml`, covers the hexagon's import bans and `unittest.mock`. The three rules above need the whole module, the importing file's own name or a call shape that no built-in rule reads, so they are checked by a unit test that walks the AST of every tracked file with the standard library's `ast`. A web survey of the alternatives (flake8 and pylint plugins, Fixit, ast-grep, Semgrep, Opengrep, import-linter, Tach) found none that expresses the given/then rule declaratively, and every option that does needs Python checker code anyway: the test runs in `uv run pytest` with no new dependency, and parsing the tree takes about 0.7 s.

The soft rules (300-line files, 20-line functions, three arguments) are out of scope: they say "rarely", and a list of justified exceptions to them would only grow.

### Fingerprinted files stay untouched

Several eval fingerprints hash the AST of Python modules (comments, formatting and the module docstring are left out, everything else counts, the order of definitions included). Moving a function inside one of these modules moves a fingerprint: the grammar's (earlier holdout detection rates become exploratory, the nuisance eligibility applies again), the counter's (holdout nuisance rates stop comparing across it), every target's fixture fingerprint (the environment code), every nuisance server's (the confinement module), or a backend's. None of these files is modified by this plan, not even to reorder it. They are:

- the grammar: `evals/cve/grammar.py`, `proofs.py`, `units.py`, `report_units.py` (`GRAMMAR_PATHS` in `evals/cve/detection/baseline.py`);
- the environment code: the 13 files of `ENVIRONMENT_PATHS` in the same module;
- the counter: `evals/cve/nuisance/counter.py`, `counting.py` (`_COUNTER_PATHS`);
- the nuisance confinement: `evals/cve/nuisance/confinement.py` (`CONFINEMENT_SOURCE` in `evals/cve/nuisance/fingerprint.py`), and the planting modules a backend-less server with public names is fingerprinted on (`_PUBLIC_NAME_SOURCES`, same module, all inside `ENVIRONMENT_PATHS`);
- the backend sources: every `Target.backend_sources` of `ACCEPTANCE_TARGETS` and `HOLDOUT_TARGETS`, and every `.py` file of `BACKENDS[*].served` (`evals/cve/nuisance/backend_registry.py`);
- the honeypot sources: `tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py` (planted flaws, and their source is fingerprinted).

A violation in these files, or one that can only be cleared by modifying one of them, stays in the debt list for good, naming the file that blocks it. It is paid the day that file changes for a real reason and its fingerprint moves anyway.

## Approach

1. Ruff enforces the import bans: the hexagon's, and `unittest.mock` everywhere.
2. A code standards scanner (pure functions over `ast`) and a sweep test that runs it on every tracked file, with a debt list of the violations that exist today. The sweep is green from its first commit.
3. Every violation outside the fingerprinted files is cleared, rule by rule, the debt list shrinking with each step.
4. The last step makes every remaining entry name its blocker, checked against the set of fingerprinted files computed from the code, never written by hand.

At the end, the debt list holds only entries blocked by a fingerprinted file, plus the two `asyncio.sleep` patches blocked by third-party retry loops (the only exception category, decided in discussion).

## Decisions taken

- The newspaper rule covers top-level functions only. Classes (Pydantic models, value objects, exceptions) declared above their users read as the high-level part of a module, and Pydantic needs them first.
- `monkeypatch.setattr` is forbidden in every test, the composition-root commands' included. `monkeypatch.setenv` and `delenv` stay allowed: setting a process's environment is not a mock.
- The given/then rule covers every module under `tests/`, not only test files: only `test_x.py`, `test_x_given.py` and `test_x_then.py` may import `test_x_given` or `test_x_then`. A shared builder lives in a module named after what it builds, never in a given, and nothing is re-exported.
- The fake Docker for the tests that replace `subprocess.run` is a fake `docker` executable on `PATH`, in this plan.
- A debt entry has one of two kinds of blocker: a fingerprinted file, or a third-party package. The second kind covers only the two `asyncio.sleep` patches in `tests/unit/auditor/test_throttling.py`: the wait is in tenacity under `langchain_fireworks` (a hard-coded `wait_exponential(min=4)` in `langchain_core`'s `create_base_retry_decorator`, which `langchain_fireworks` calls) and in google-genai's retry loop. The Fireworks entry names `langchain-core`, the distribution that holds the blocking constant. The google-genai entry stays only if a per-request `http_options={"retry_options": {...}}` with tiny delays cannot replace the patch (step 10 tries it first).
- A debt entry is keyed by file, code standard and symbol, never by line number, so an unrelated edit never invalidates it. An entry that no longer matches a violation fails the sweep, so the list only shrinks.
- Command modules take `main(argv: Sequence[str] | None = None, deps: XCommandDeps | None = None) -> int`, `deps` being a frozen dataclass whose fields default to the production functions or factories (building it does no I/O). `None` stands for the production default because a call in a default argument trips Ruff's `B008` (checked: a frozen dataclass call is flagged too). The same holds for every value-object parameter this plan adds to a function: `sources: NuisanceFixtureSources | None = None`, `options: CheckOptions | None = None`, `bounds: SessionBounds | None = None`, `launcher: ServerLauncher | None = None`, the function building the default when it gets `None`. A dataclass field takes a `field(default_factory=...)` instead.
- What the commands read from committed files: a path that is a command-line option is redirected through `argv` to a `tmp_path` file; a committed file read with no option is read through a reader field of the deps (for example `conditions: Callable[[], HoldoutConditions] = committed_conditions`). A pure function (`build_report`, `unready_cards`) is never injected.
- The orchestrators (`run_gated`, `run_holdout_targets`, `run_nuisance`, `run_gate`) are injected and replaced by fakes in the command tests, typed by a `Protocol` mirroring their signature (strict typing), not `Callable[..., ...]`. They have their own tests.
- The "result is written before the report" tests inject the report write (`write_report`, an I/O), on both the detection and the nuisance side. Provoking a rendering failure through an input `build_report` happens to reject would tie the test to an accident of the renderer.
- Aliases that would no longer match their module are renamed (`admission_given.` pointing at `nuisance_admissions` becomes `admissions.`, and so on): a misleading alias goes against naming over comments.
- The two `_SENTINEL_PROBE_BUDGET` patches (`tests/integration/test_cve_planting.py`) stay as debt blocked by `evals/cve/planting_docker.py`: dropping them would cost about 24 s of Docker integration time.
- No dependency declaration or version changes in this plan: `pyproject.toml`'s dependency lists and `uv.lock` stay as they are. The `.env` guard below relies on `PYTHON_DOTENV_DISABLED`, which python-dotenv honours from 1.2.0, and the lock resolves 1.2.4. That `src/mcp_auditor/config.py` imports python-dotenv without declaring it is a separate fix, outside this plan.
- The commits that touch `src/mcp_auditor/` (steps C and D3) change the system under test's code with no behavior change: their message answers the four questions of ADR 016 (`CLAUDE.md`, When an eval number comes back red), saying that no prompt, guard or default moves.

## Step A: Ruff import bans

`pyproject.toml`:

- `[tool.ruff]` gains `src = [".", "src"]`. A nested `ruff.toml` resolves the default `src` relative to its own directory, so without it `mcp_auditor` stops being first-party under `domain/` and `graph/` and `I001` fails on every import block there (checked on a copy of the tree with Ruff 0.17.2).
- `[tool.ruff.lint] select` gains `"TID251"`.
- `[tool.ruff.lint.flake8-tidy-imports.banned-api]` bans `"unittest.mock"` with the message `"use a fake (CLAUDE.md, Testing standards)"`.

`src/mcp_auditor/domain/ruff.toml` and `src/mcp_auditor/graph/ruff.toml`, identical (both sit at the same depth):

```toml
extend = "../../../pyproject.toml"

[lint.flake8-tidy-imports.banned-api]
"mcp_auditor.adapters".msg = "the hexagon never imports adapters (CLAUDE.md, Hexagonal boundary)"
"mcp_auditor.audit".msg = "the hexagon never imports the composition root"
# ... one entry per top-level module of src/mcp_auditor/ outside the hexagon
"os.environ".msg = "inject the environment through a Port"
"os.getenv".msg = "inject the environment through a Port"
"subprocess".msg = "no process in the hexagon"
"time".msg = "inject a clock"
"datetime.datetime.now".msg = "inject a clock"
"datetime.datetime.utcnow".msg = "inject a clock"
"datetime.date.today".msg = "inject a clock"
"random".msg = "inject a source of randomness"
"secrets".msg = "inject a source of randomness"
"uuid.uuid4".msg = "inject a source of randomness"
"os.system".msg = "no process in the hexagon"
"os.urandom".msg = "inject a source of randomness"
"asyncio.create_subprocess_exec".msg = "no process in the hexagon"
"asyncio.create_subprocess_shell".msg = "no process in the hexagon"
"socket".msg = "no network in the hexagon"
"httpx".msg = "no network in the hexagon"
"shutil".msg = "no filesystem in the hexagon"
"tempfile".msg = "no filesystem in the hexagon"
```

A nested `banned-api` table replaces the root's instead of merging with it (checked), so the root's `unittest.mock` ban does not reach `domain/` and `graph/`. That is harmless, since no test lives there. The composition-root modules to list are, today: `audit`, `checkpointing`, `cli`, `config`, `config_file`, `console`, `progress`, `report_files`, `server_execution`, `stream_handler`, `studio`. The sweep test of step B checks that the list covers every top-level module of `src/mcp_auditor/` other than `__init__`, `domain` and `graph`, so a new module cannot slip past it.

`tests/unit/cve/backends/support/test_atlassian_backend_given.py:45` replaces `mock.patch.dict(os.environ, environment, clear=True)` with `monkeypatch.setenv`/`delenv` (the given takes the `monkeypatch` of its caller). It is the only `unittest.mock` use.

The hexagon has no violation today (its imports are dataclasses, typing, json, re, operator, enum, collections, pathlib, pydantic and langgraph), so `uv run ruff check .` stays green.

## Step B: the scanner and the sweep, green with today's debt

### Scanner: `tests/unit/project/support/code_standards_scan.py`

Pure functions, the same layout as `tests/unit/support/retired_word_scan.py`. It lives in `tests/unit/project/support/`, not `tests/unit/support/`, because only the `project` area uses it (`CLAUDE.md`: a helper shared across areas goes to `tests/unit/support/`, the others to their area's `support/`):

```python
class CodeStandard(StrEnum):
    NEWSPAPER_ORDER = "newspaper-order"
    FOREIGN_GIVEN_THEN = "foreign-given-then"
    MONKEYPATCH_SETATTR = "monkeypatch-setattr"

@dataclass(frozen=True)
class Violation:
    path: str      # relative to the repository root, POSIX separators
    standard: CodeStandard
    symbol: str
    line: int      # reported, never compared

@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str

def violations(source: SourceFile) -> list[Violation]
def newspaper_violations(source: SourceFile, module: ast.Module) -> list[Violation]
def foreign_given_then_imports(source: SourceFile, module: ast.Module) -> list[Violation]
def monkeypatch_setattrs(source: SourceFile, module: ast.Module) -> list[Violation]
```

The enum is `CodeStandard`, not `Rule`: the glossary gives the bare word "rule" to the detection suite rule and the nuisance suite rule, and asks for the qualified form of a word with several senses (`docs/glossary.md`, Words with several senses).

- **Newspaper order** (`symbol`: the function's name): a top-level `FunctionDef` or `AsyncFunctionDef` is a violation when at least one other top-level definition (function or class) uses it, every such user is defined below it, and no eager code uses it. A definition uses a name when one of its deferred parts loads it (`ast.Name` with `Load` context): a function's body, a class's method bodies. Eager code is everything Python runs at import time: module-level statements, decorators, argument defaults and annotations, return annotations, class bases and keywords, and the statements of a class body outside its methods. A function whose body binds the name locally (an argument, or a `Store` context) does not count as a user, so a local variable that shadows a helper is never mistaken for a call. Nested functions and methods are not checked.
- **Foreign given/then** (`symbol`: the imported module's last component): a module whose last component matches `test_\w+_(given|then)` may be imported only by `test_<stem>.py`, `test_<stem>_given.py` or `test_<stem>_then.py`, where `<stem>` is that name minus its `_given`/`_then` suffix. Applies to every file under `tests/`. Both forms are read: `import a.b.test_x_given as given` and `from a.b import test_x_given`, along with `from a.b.test_x_given import name`.
- **monkeypatch setattr** (`symbol`: `<enclosing top-level function or class>:<ast.unparse of the first argument>`, the second argument appended after a `.` when it is a string constant): a call whose function is the attribute `setattr` of the name `monkeypatch`. No other spelling exists in the tree today (no `MonkeyPatch.context()`, no other receiver).

### Debt list: `tests/unit/project/support/code_standards_debt.py`

```python
@dataclass(frozen=True)
class FingerprintedFile:
    path: str

@dataclass(frozen=True)
class ThirdParty:
    distribution: str
    reason: str

@dataclass(frozen=True)
class Debt:
    path: str
    standard: CodeStandard
    symbol: str
    blocked_by: FingerprintedFile | ThirdParty | None  # None: not blocked, cleared before the lock

DEBTS: tuple[Debt, ...] = (...)
```

The initial list is generated once from the scanner's output by an ad hoc script that is not committed, sorted by path, code standard and symbol. The entries in a fingerprinted file get `FingerprintedFile` of that same file, the two throttling entries get `ThirdParty`, and the rest get `None`.

### Sweep: `tests/unit/project/test_code_standards.py`

- `test_the_tree_carries_no_violation_outside_the_debt_list`: every `*.py` file git knows of is scanned (`git ls-files --cached --others --exclude-standard '*.py'`, the inventory's tracked set plus the files not yet staged, so a module created during a step is swept before it is committed, and a path deleted from the working tree but still in the index, which `--cached` still lists, is skipped by checking that the file exists), and every violation not in `DEBTS` (matched on path, code standard and symbol) is reported as `path:line: standard symbol`.
- `test_every_debt_still_matches_a_violation`: a debt entry that matches nothing fails, with a message that tells you to delete it.
- `test_the_hexagon_bans_every_module_of_the_composition_root`: reads both nested `ruff.toml` files with `tomllib` and checks that their `banned-api` lists `mcp_auditor.<name>` for every top-level module or package of `src/mcp_auditor/` other than `__init__`, `domain` and `graph`.

The sweep checks code, so it is a unit test (`CLAUDE.md`: "A test that sweeps a registry to check code stays a unit test").

### Scanner unit tests: `tests/unit/project/test_code_standards_scan.py` (+ `support/test_code_standards_scan_given.py`)

Written before the scanner and run red first (`CLAUDE.md`, Workflow: test-first). Each code standard is tested on small source strings: a helper above its only caller fires; one below it does not; one used by a decorator, a default, a class body or module-level code does not; a class above its users does not; a later function with a local of the same name is not a user; a method is never checked. A test importing its own given or then passes, one importing another test's given fires in both import forms, and so does a given importing another given; a shared support module importing a given fires. `monkeypatch.setattr(module, "name", value)` fires with the expected symbol, while `monkeypatch.setenv` does not.

## Step C: newspaper order

An ad hoc script (not committed) moves each violating function right below the end of its first user, repeating until the scanner finds nothing outside the fingerprinted files. The moved block is the function's lines from its first decorator (or its `def`) to its `end_lineno`, plus the comment lines directly above it with no blank line between. `uv run ruff format .` restores the blank lines afterwards. The fingerprinted files are skipped.

Check, file by file: the multiset of `ast.dump` of the module's top-level statements is the same before and after. That proves only the order changed. The ad hoc script asserts it before it writes a file. The 394 entries leave the debt list, and the 15 fingerprinted ones stay.

## Step D: no `monkeypatch.setattr`

### D1. Detection commands (`evals/run_detection.py`, `evals/run_detection_holdout.py`)

New `evals/cve/run_images.py` value object, beside `ContainerSweep`, shared with the nuisance fix check:

```python
@dataclass(frozen=True)
class RunDocker:
    check_networks: Callable[[], None] = check_closed_network_support  # raises ClosedNetworkUnsupported
    images: ImageStore = field(default_factory=ComposeImageStore)
    sweep: ContainerSweep = DOCKER_SWEEP
```

New `evals/cve/detection/command_deps.py`, which must not import `holdout_targets`:

```python
@dataclass(frozen=True)
class DetectionCommandDeps:
    preflight: Callable[[], bool] = preflight_ok
    sweep: ContainerSweep = DOCKER_SWEEP
    read_tree: Callable[[], TreeState] = read_tree
    audit_target: AuditTargetFactory = audit_target
    session: RunSession = run_gated
    calibration_check: CalibrationCheckFactory = default_calibration_check_deps
    survey_one: SurveyOne = survey_one
```

with `AuditTargetFactory`, `RunSession`, `CalibrationCheckFactory` (`(concurrency, ci) -> CalibrationCheckDeps`) and `SurveyOne` as `Protocol`s in the same module. New `evals/cve/detection/holdout_command_deps.py`, a separate module because `holdout_targets` must stay out of every module `run_detection` imports (a unit test already pins that):

```python
@dataclass(frozen=True)
class HoldoutCommandDeps:
    drawn: Sequence[Target] = HOLDOUT_TARGETS
    docker: RunDocker = field(default_factory=RunDocker)
    calibration_check: CalibrationCheckFactory = default_calibration_check_deps
    conditions: Callable[[], HoldoutConditions] = committed_conditions
    holdout_deps: HoldoutDepsFactory = default_deps
    run_targets: RunHoldoutTargets = run_holdout_targets
    last_commit: Callable[[Path], str] = last_commit
    write_report: ReportWriter = write_report
```

`RunHoldoutTargets` and `HoldoutDepsFactory` are `Protocol`s in `evals/cve/detection/holdout_run.py` mirroring `run_holdout_targets` and `default_deps(places, overrides, concurrency)`. `write_report` has to be importable without `run_detection_holdout`: `evals/cve/nuisance/commands.py:write_report(path, report: BaseModel, markdown)` moves to `evals/cve/run_files.py`, beside `write_result`, and `run_detection_holdout._write_report`, its byte-for-byte twin, is deleted for it. `run_nuisance.py` and `gate/gate_command.py` import it from there. `ReportWriter` is `Callable[[Path, BaseModel, str], None]` in `run_files.py`. `committed_conditions() -> HoldoutConditions` is new in `evals/cve/holdout_conditions.py` (it calls `load_conditions(CONDITIONS_PATH)`), shared with the nuisance commands. `last_commit` is injected because git refuses a census under `tmp_path`: without it, `test_run_refuses_an_acceptance_target_for_its_tools_filter` exits 3 because git refused, not because of the tools filter, so it passes for the wrong reason. The test also asserts the refusal's reason text.

- `run_detection.main(argv, deps) -> int`, and `__main__` becomes `sys.exit(main())`. argparse and `_reject_unknown_flaws` keep raising `SystemExit(2)`. `_run` and `_run_graded` (4 arguments today) take value objects: `_FlawSelection(graded, tracked)` and `_CommandRun(places, deps)`.
- `evals/cve/detection/no_llm_modes.py` is deleted. The calibration check calls `run_calibration_check(graded, places, deps.calibration_check(args.concurrency, args.ci))` (the ADR 031 comment moves along), and the survey calls `survey_all(graded, bounded(lambda target: deps.survey_one(target, places), args.concurrency))`. The real `survey_all` then runs in the tests. `tests/unit/detection/test_detection_holdout_targets.py` scans `command_deps.py` in place of `no_llm_modes.py`.
- `run_detection_holdout.main(argv, deps)` dispatches `args.command(args, deps)`. `IMAGE_STORE` goes away. `_check_calibrations(targets, places, concurrency, sweep)` becomes `_check_calibrations(targets, checks, sweep)`, with `load_places` moved inside.
- Test doubles: the existing `FakeContainerSweep`, `FakeImageStore`, `deps_reaching_nothing` (`tests/unit/support/detection_holdout_runs.py`) and `deps_with` (the calibration-check exit given). No new fake class is needed. The drawn test target of the run command is `replace(an_acceptance_target(...), flaw_id="CVE-2026-0001")` in a census written by `a_census_drawing(["CVE-2026-0001"])`: `load_census` refuses an acceptance flaw ID, which is no draw-order candidate, as a draw. `cards_reporting` goes away: the unready case writes a census with no draw.
- Files: `tests/unit/detection/support/run_detection_cli.py`, `support/test_run_detection_given.py`, `support/test_run_detection_recording_given.py`, `support/test_run_detection_holdout_run_given.py`, `test_run_detection.py`, `test_run_detection_recording.py`, `test_run_detection_holdout.py`, `test_run_detection_holdout_run.py`. The autouse sweep fixtures go: each test builds its deps.

### D2. Nuisance commands (`evals/run_nuisance.py` and the command modules)

```python
# evals/run_nuisance.py
@dataclass(frozen=True)
class NuisanceCommandDeps:
    run: RunCommandDeps = field(default_factory=RunCommandDeps)
    fix_check: FixCheckCommandDeps = field(default_factory=FixCheckCommandDeps)
    gate: GateCommandDeps = field(default_factory=GateCommandDeps)
    vet: VetCommandDeps = field(default_factory=VetCommandDeps)
```

Each `add_*_arguments(parser, deps)` binds its handler with `functools.partial`, so `args.command(args)` stays as it is. Each subcommand's deps type lives in its own command module, which the aggregate imports, never the reverse.

- **run**: `_run` and its helpers (`run_nuisance.py:221-317`, `current_copy_fingerprints` included) move to a new `evals/cve/nuisance/run_command.py`. That also brings `run_nuisance.py` under 300 lines. `RunCommandDeps(conditions, settings, run_deps, orchestrate: RunOrchestrator, file_commit, write_report)`, where `RunOrchestrator` is a `Protocol` in `evals/cve/nuisance/holdout_run.py`. `committed_walk_inputs` needs no seam: the injected `conditions` is read first, so a raising `conditions` already proves the order.
- **fix-check**: `FixCheckDeps` gains the `RunDocker` fields it needs (`check_networks`, `sweep`), and `FixCheckCommandDeps(fixtures=FIX_CHECK_FIXTURES, fix_check_deps=default_fix_check_deps)`. `_selected_fixtures(fixtures, flaw)` is extracted to keep `fix_check` under 20 lines.
- **gate**: `GateCommandDeps(conditions, settings, harness, run_gate)`. The pure `gate_conditions` stays a direct call, fed by the injected readers. No `console` field: the gate's output is printed by `gate_command` and `gate_console` through the shared `eval_display.console`, so the gate tests capture it with `captured_console` like every other display test (D3, Console), and a field would capture only `gate_command`'s half.
- **vet**: `VetCommandDeps(conditions, vet_deps)`. `default_vet_deps(tool_call_timeout, concurrency, launcher: ServerLauncher | None = None)`.
- **benign call** (`evals/cve/nuisance/vetting.py`): a callable value object replaces `benign_call` and the three `functools.partial` around it (`vet_command.py`, `holdout_run.py`, `gate/gate_session.py`):

  ```python
  @dataclass(frozen=True)
  class ServerLauncher:
      environment: Callable[[AdmittedServer], AbstractContextManager[Launch]] = nuisance_environment
      connect: Connect = connect

  @dataclass(frozen=True)
  class LaunchedBenignCall:
      timeout: int
      on_ping: Callable[[AdmittedServer, bool], None] | None = None
      launcher: ServerLauncher = field(default_factory=ServerLauncher)
      async def __call__(self, server: AdmittedServer) -> str | None: ...
  ```

  `Connect` is the existing alias of `evals/cve/launch_audit.py` (`Callable[..., AbstractAsyncContextManager[MCPClientPort]]`), which `vetting.py` already imports from. No new connector type is written, and the test fakes (`flaky.connect`, `FakeLaunches.connect`, which takes no `tool_call_timeout`) fit it. `environments.connect` is fingerprinted: it is referenced, never modified.
- **fingerprint** (`evals/cve/nuisance/fingerprint.py`, not fingerprinted itself): one value object replaces the two optional parameters and clears the four patches of the confinement (`CONFINEMENT_SOURCE`, and `planting_base.confinement_args`/`resolver_args` in `test_nuisance_fingerprint.py`):

  ```python
  @dataclass(frozen=True)
  class SuiteConfinement:
      source: Path = CONFINEMENT_SOURCE
      options: Callable[[], list[str]] = planting_base.confinement_args
      resolver: Callable[[], list[str]] = planting_base.resolver_args

  @dataclass(frozen=True)
  class NuisanceFixtureSources:
      docker_directory: Path = DOCKER_DIRECTORY
      backends: Mapping[str, RegisteredBackend] = field(default_factory=lambda: BACKENDS)
      confinement: SuiteConfinement = field(default_factory=SuiteConfinement)

  def nuisance_fixture_fingerprint(server: AdmittedServer, sources: NuisanceFixtureSources | None = None) -> str
  def fingerprinted_files(server: AdmittedServer, sources: NuisanceFixtureSources | None = None) -> list[Path]
  ```

  `_PUBLIC_NAME_SOURCES` becomes public (`PUBLIC_NAME_SOURCES`) for the fingerprinted-set helper of step F. The hash must stay byte-identical: the step records the fingerprint of every admitted server before the change and asserts it after. The production callers pass nothing.
- **re-admission dossier**: computing is split from writing. `re_admission_plan(walk_inputs, admission, server_package) -> ReAdmittedDossier` and `write_re_admission_dossier(plan, out)` (not `ReAdmissionPlan`: the retired-word scan's `readmission` pattern is case-insensitive and flags any identifier spelling `ReAdmission`), which also fixes today's 4-argument signature. The test patching `closure_roots` (`test_nuisance_re_admission_dossier.py:256`) is deleted: `tests/unit/cve/test_cve_dossier_closure.py` already covers the refusal of `mcp_auditor`, and computing the plan before writing makes "before writing" a fact of the types.
- Files: the 14 test files and givens that patch these modules (`tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py`, `test_run_nuisance_holdout_run.py`, `fix_checks/support/test_nuisance_fix_check_command_given.py`, `fix_checks/test_nuisance_fix_check_command.py`, `gate/support/test_run_nuisance_gate_given.py`, `gate/test_run_nuisance_gate.py`, `support/test_nuisance_vet_given.py`, `test_run_nuisance_vet.py`, `test_nuisance_vet.py`, `support/test_nuisance_vetting_given.py`, `test_nuisance_vetting.py`, `support/test_nuisance_fingerprint_given.py`, `test_nuisance_fingerprint.py`, `admission/test_nuisance_re_admission_dossier.py` and its given), plus `tests/integration/committed/nuisance/admission/test_nuisance_admission_loads.py`, which imports from `run_command`.

### D3. The other collaborators

- **Session bounds** (`src/mcp_auditor/adapters/mcp_client.py`): `SessionBounds(initialize, ping, teardown)`, whose defaults are today's constants (`_INITIALIZE_TIMEOUT`, `PING_TIMEOUT_SECONDS` from `domain/server_watch.py`, `TEARDOWN_TIMEOUT_SECONDS`), replaces `initialize_timeout` on `StdioMCPClient.connect` as `bounds: SessionBounds | None = None`. `tool_call_timeout` stays a keyword, because the fingerprinted `environments.connect` passes it. The three callers of `initialize_timeout` move to `bounds=SessionBounds(initialize=0.5)`. The relaunch test passes `bounds=SessionBounds(teardown=0.2)`. The replay test injects a `connect` through the existing `replay_with_causes` parameter, with a given `connect_pinging_within(seconds)` that mirrors `environments.connect` with `bounds=SessionBounds(ping=seconds)`. The kit's own client is untouched.
- **Calibration check** (`evals/cve/detection/calibration_check.py`): `CheckOptions(report_detail, on_ping, connect: Connect)` (`Connect` from `evals/cve/launch_audit.py`), so `check_target(target, places, options: CheckOptions | None = None)` goes from 4 parameters to 3, and `passes_calibration_check(target, places, connect=connect)`. The callers that pass `report_detail=TYPES_ONLY` move to `options=CheckOptions(report_detail=TYPES_ONLY)`: `evals/cve/detection/holdout_run.py` (`default_deps`) and `tests/integration/test_detection_calibration_check.py` (two calls). Test double: the existing `FakeLaunches.connect`.
- **Benign probe** (`evals/cve/kit/benign_probe.py`): `probe_launch(record, image, lifecycles=lifecycle_of)` and `main(argv=None, probe=probe)`.
- **Backend lifecycle lookup** (`evals/cve/kit/backend_launch.py`): `lifecycle_of(key, import_module=importlib.import_module)`.
- **Checkpoint path** (`tests/integration/test_audit_server_failures.py:75`): a test-only change. `monkeypatch.setenv("HOME", str(tmp_path))`, and `tmp_path/.mcp-auditor/checkpoints.db` is created as a directory, which gives the expected `sqlite3.OperationalError`.
- **`.env` guard** (`tests/conftest.py:19`): `monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")`, which python-dotenv honours since 1.2.0. The variable also reaches the subprocesses the tests start, which today still read `.env`. That closes a gap. No dependency changes: the lock resolves python-dotenv 1.2.4.
- **Console** (`tests/unit/evals/support/test_eval_display_given.py:22`): every display module imports the single `eval_display.console`, which resolves `sys.stdout` at write time, and reads `COLUMNS` at write time only when `COLUMNS` was unset when the console was built (rich freezes the width when it is set then: checked with rich's installed version). `a_captured_console(capsys, monkeypatch, width=200)` sets `COLUMNS`, asserts `eval_display.console.width == width` so a shell that exports `COLUMNS` fails loudly instead of wrapping silently, and returns an object whose `getvalue()` accumulates `capsys.readouterr().out`. The 15 files that call it (about 75 calls, wrappers in givens included) gain a `capsys` parameter, mechanically. Check that no assertion of the form `not in` starts passing because of a stray `print`.
- **Command line**: `parse_args(argv=None)` and `main(argv=None)` in `evals/run_honeypot_suite.py`, `evals/run_judge_eval.py` and `evals/draw_judge_cases.py`. The tests pass their flags.
- **Stays as debt**, each blocked by its fingerprinted file:
  - `tests/unit/cve/backends/support/doris_launch.py:45-48`, blocked by `evals/cve/detection/holdout_environments.py`: `doris_db_env` calls its Doris helpers and `time.sleep` directly.
  - `tests/unit/cve/backends/support/test_doris_seed_given.py:70-71`, blocked by `evals/cve/backends/doris.py`: a 180 s `time.monotonic` loop with no injected clock. The `subprocess.run` patch in the same given rides along.
  - `tests/integration/test_cve_planting.py:140,150,203`, blocked by `evals/cve/planting_docker.py`: the probe budget and the probe timeout are its constants.
  - `tests/unit/cve/test_cve_planting_host_files.py:140`, blocked by `evals/cve/planting_docker.py`: `write_host_file` calls `tempfile.mkstemp` with no directory, and `TMPDIR` cannot replace it, because `gettempdir()` caches its first answer.
  - `tests/unit/auditor/test_throttling.py:57,67`: `ThirdParty("langchain-core", ...)` for the Fireworks test. For the google test, `ThirdParty("google-genai", ...)` only if passing `http_options={"retry_options": {"attempts": 3, "initial_delay": 0.001, "max_delay": 0.001, "jitter": 0.001}}` to `ainvoke` does not clear the patch while the test still counts the throttled response once.

### D4. Fake `docker` executable

The tests that replace `subprocess.run` to simulate Docker (`tests/fakes/scripted_docker.py:38`, `tests/unit/support/recorded_subprocess.py:16`, `tests/unit/cve/backends/support/test_node_sandbox_engine_given.py:51`) reach production modules that are nearly all fingerprinted (`closed_network`, every shared backend's `remove`, `mcp_ssh_sshd`, gitlab, kubernetes, `node_sandbox_engine`), so no in-process seam exists. Each of them runs `subprocess.run(["docker", ...])`, which looks `docker` up on `PATH` at call time, as the failing shim of `tests/unit/support/docker_shim.py` already relies on.

New `tests/fakes/docker_executable.py`, `ScriptedDockerExecutable(answers)`:

- `installed(monkeypatch, tmp_path)` writes an executable `docker` whose shebang is `#!{sys.executable} -IS` (one combined flag: a Linux shebang passes a single argument), plus a JSON file of answers keyed by argv prefix, and prepends its directory to `PATH` with `monkeypatch.setenv`.
- The script appends `{argv, stdin}` to a JSONL log and answers with the longest matching prefix (stdout, stderr, exit code), or with success and no output when no prefix matches, as `ScriptedDocker` does today.
- It keeps the reading API of `ScriptedDocker`: `commands`, `inputs`, `started()`, `created_networks()`, `removed()`. `recorded_commands` becomes the same fake with no answers.
- The node sandbox engine's socket moves into the script: it binds a unix socket in the mounted directory and gives it mode 0666, as the real engine's entrypoint does.

`scripted_docker.py` and `recorded_subprocess.py` are replaced or deleted. `test_doris_seed_given.py:70` stays as debt, with its clock patch. Each call costs about 13 ms (`python -IS` start-up), so about 0.2 s for a gitlab or kubernetes test.

## Step E: one given/then pair per test file

The shared code of a given moves to a module named after what it builds, in the `support/` directory of the area that holds all its users, or in `tests/unit/support/` when users span areas. Moves keep history (`git mv`) when a whole given becomes a shared module. No given is left as a re-export. Each `support/` directory has its `__init__.py`. New modules do not start with `test_`, so pytest does not collect them.

**Ownership rule:** the area that owns the source module sets the destination, and the other areas' imports follow it.

### E1. Outside `tests/unit/nuisance`

| Source | Destination |
|---|---|
| `auditor/support/test_console_given.py` (no `test_console.py`) | `git mv` to `test_console_display_given.py`. The displays go to new `auditor/support/audit_displays.py`. The two findings builders go to new `test_console_findings_given.py`, which pairs the existing then. The private case builders go to `report_builders.py` as `a_passing_case`/`a_failing_case`. The console's `a_fail_result` is dropped for `report_builders.a_fail_result`: only `arguments` differs, and the console renders arguments for dry-run payloads only. |
| `auditor` `test_shown_response_given`/`_then` | new `auditor/support/cut_responses.py` (`NEEDLE`, `a_long_text`, `HEAD_LENGTH`, `TAIL_LENGTH`, `shows_cut`). The emptied then is deleted. |
| `auditor` `test_chain_nodes_given` | `a_fail_judge_result`, `a_single_step_case` and `a_blocked_single_step_case` go to the existing `chain_states.py` |
| `auditor` `test_rendering_then` | `summary_of` to new `auditor/support/markdown_sections.py` |
| `auditor` `test_llm_throttling_given` | `git mv` to `tests/unit/support/provider_errors.py` |
| `census` `test_census_given` | new `tests/unit/support/censuses.py`, with `a_classification` (from the figures given), `OUTSIDE_THE_GRAMMAR`, `a_judgment`, `no_proof` (from grouping) and `recomputed` (made public) |
| `census` `test_census_figures_given` | `a_classification` to `censuses.py`. The rest goes to new `census/support/classifier_pairs.py`, where its `a_census` is renamed `census_parts`. Given deleted. |
| `census` `test_census_identity_given`, `test_census_sources_given` (six shared names) | new `census/support/advisory_sources.py`. Identity given deleted. |
| `cve` `test_cve_grammar_given` | `git mv` to `tests/unit/support/grammar_inputs.py`, imported `as grammar`. The three own-only items move too. |
| `cve` `test_cve_launch_audit_given` | `git mv` to `tests/unit/support/launch_audit_fakes.py` |
| `cve/backends` `test_backend_lifecycle_given` | `every_responder` to new `tests/unit/support/registered_responders.py`: `tests/integration/committed/nuisance/test_nuisance_backend_registry_built.py` uses it too, so its users span the `cve` and `nuisance` areas (`CLAUDE.md`: a helper shared across areas goes to `tests/unit/support/`) |
| `detection` `test_detection_oracle_given` | new `detection/support/detection_reports.py` |
| `detection` `test_detection_draw_record_given` | new `tests/unit/support/census_draws.py` |
| `detection` `test_detection_holdout_pre_run_check_given` | `ScriptedChecks` to new `detection/support/scripted_checks.py` |
| `detection` `test_run_detection_holdout_run_given` | `PROOF_FIELDS`, `result_keys` to new `tests/unit/support/holdout_result_keys.py`. `cards_reporting` goes away in D1. |
| `detection` `test_detection_calibration_check_exit_given` | `git mv` to `detection/support/calibration_check_deps.py` |
| `detection` golden givens (`test_detection_layout_check_golden_given.py`, `test_detection_route_check_golden_given.py`) | Not renamed: they are golden-master generators run as `python -m`, with the command in their docstring. Their golden-reading tests move to new `test_detection_layout_check_golden.py` (10 tests) and `test_detection_route_check_golden.py` (4 tests), as `test_cve_grammar_golden.py` already does. No golden is regenerated: no golden JSON holds a module path. |
| `evals` `test_judge_fixture_given` | new `evals/support/judge_cases.py` (`_A_DRAW` made public) |
| `evals` `test_honeypot_retest_given` | new `evals/support/fictional_honeypots.py` |
| `evals` `test_eval_display_given` | `a_captured_console` to new `tests/unit/support/captured_console.py` |
| integration `test_cve_planting_given`/`_then` | new `integration/support/recording_planting.py` and `integration/support/target_commands.py` |
| integration `test_cve_planting_stand_ins_given` (325 lines) | split into `integration/support/stand_in_fetches.py` and `integration/support/stand_in_capture.py` (`git mv`). Given deleted. |
| integration `test_mcp_client_given` | `PAGINATED_SERVER_PATH` to the existing `support_servers.py` |

`.github/workflows/detection-calibration-check.yml` filters its triggers on `tests/integration/support/test_cve_planting_*.py`. Its two `paths` lists gain `recording_planting.py` and `target_commands.py`, plus `docker_prerequisites.py`, which is already missing. Otherwise the job silently stops running when they change.

### E2. `tests/unit/nuisance`

| Source | Destination |
|---|---|
| `test_nuisance_admission_given` (every name is shared) | `git mv` to `tests/unit/support/nuisance_admissions.py`, plus `a_recorded_exit` |
| `tests/unit/support/test_nuisance_admission_edits_given.py` (no test of its own) | merged into the existing `tests/unit/support/admission_mutations.py`, with `with_every_new_field_unrecorded`, `recording` and `a_server_with_a_holdout_calibration_copy_at`. Deleted. |
| `test_nuisance_holdout_run_given` | `git mv` to `tests/unit/support/nuisance_holdout_runs.py`, minus `InterruptingAudit`, which moves to new `test_nuisance_holdout_run_interrupted_given.py` |
| `test_nuisance_holdout_run_backends_given` | new `tests/unit/support/nuisance_docker_hosts.py`. Deleted. |
| `test_nuisance_walk_given` | the shared names go to new `tests/unit/support/nuisance_walks.py`. The given keeps four names. |
| `tests/unit/support/test_nuisance_committed_admission_given.py` | `git mv` to `tests/unit/support/committed_nuisance_admission.py`, plus the lookups of servers in the committed admission (`a_committed_server_with_fix_checks`, `a_detection_holdout_server_with_its_own_fix_check`, `its_holdout_targets`) |
| `test_nuisance_vet_given` (shared part) | new `tests/unit/support/nuisance_vets.py` |
| `test_nuisance_vetting_given` (shared part) | new `nuisance/support/flaky_launches.py`. Its `__all__` re-export goes. |
| `test_run_nuisance_given` | new `nuisance/support/nuisance_queue_walks.py`. Deleted. |
| `test_nuisance_statistic_given` (`a_server_result`) | the existing `nuisance/support/nuisance_report_runs.py` |
| `test_nuisance_gate_baseline_given` | `git mv` to `nuisance/gate/support/nuisance_gate_baselines.py`, plus `a_comparison`. The `X as X` re-exports of `test_nuisance_gate_given` and `test_nuisance_gate_recording_given` go. |
| `test_nuisance_gate_report_given` (shared part) | new `nuisance/gate/support/nuisance_gate_reports.py` |
| `test_nuisance_dossier_then` (`it_carries_the_holdout_reference_of`) | new `nuisance/admission/support/holdout_reference_checks.py` |
| `test_nuisance_unrecorded_given.a_server_with_every_field_unrecorded` | inlined at its single foreign call site |

The `__all__` re-export of `test_nuisance_assembly_given` goes too. Import order to keep acyclic: `nuisance_walks` ← `nuisance_admissions` ← `admission_mutations`, and `nuisance_admissions` ← `nuisance_holdout_runs` ← `nuisance_docker_hosts` ← `nuisance_vets`. `nuisance_admissions` never imports `admission_mutations`. Names that exist in two modules with different values (`a_server`, `deps_on`, `SERVER_PACKAGE`, `conditions`, `RECORDED_AT`, `Outcome`) are always read through a module alias, never imported by name.

### E3. The remaining foreign imports

After E1 and E2, the sweep lists what is left of the foreign given/then imports, from test files (the 139) and from given, then or support modules (the 164). For example `tests/unit/cve/support/test_cve_planting_stand_ins_given.py`, which the tables above do not move, is still imported by `tests/unit/support/audited_launch_builders.py`, `tests/unit/detection/support/test_detection_baseline_given.py` and two nuisance files. Each one is cleared by the same principle: the shared name moves to a builder module, or the import is replaced by the builder module that E1 or E2 created. No re-export.

## Step F: the lock

- `Debt.blocked_by` becomes required (`FingerprintedFile | ThirdParty`), and `None` disappears from the type.
- New `tests/unit/project/support/fingerprinted_sources.py` (only the `project` area uses it), `fingerprinted_sources() -> frozenset[str]`: the union, as repository-relative paths, of `GRAMMAR_PATHS`, `ENVIRONMENT_PATHS`, the counter's `_COUNTER_PATHS` (a private name, read as is: `counter.py` cannot change), `CONFINEMENT_SOURCE`, `PUBLIC_NAME_SOURCES`, every `backend_sources` of `ACCEPTANCE_TARGETS` and `HOLDOUT_TARGETS`, every `.py` file of `BACKENDS[*].served`, and the `server` of every honeypot in `evals.honeypots.HONEYPOTS`. It is computed from the code, so it follows the fingerprints.
- `test_every_debt_is_blocked_by_a_fingerprinted_file_or_a_third_party`: a `FingerprintedFile` must be in `fingerprinted_sources()`, and a `ThirdParty` must name an installed distribution (`importlib.metadata.distribution`) and carry a non-empty reason.

## What stays unchanged

- The 45 fingerprinted files listed above, byte for byte. Every fingerprint therefore stays identical: the grammar's, the counter's, every detection and nuisance fixture fingerprint, and the honeypot source fingerprints. No baseline reset, no holdout calibration copy to redo.
- Behavior: no change a user or an instrument can observe. Exit codes, command lines and reports stay identical. `main` returning an `int` keeps the same process exit code through `sys.exit(main())`.
- The goldens: none is regenerated (`CLAUDE.md` forbids it in a refactoring).
- The soft rules (file and function length, argument count) are not enforced, except where a step's refactoring brings a function under them.
- `plans/` and `docs/adr/`.

## Edge cases

- A function used only by eager code (a decorator, a default, a class body, a module-level call) is never a newspaper violation, since Python forces it first.
- A function with no user at all (a public entry point, a pytest fixture used through a parameter name) is never a violation.
- An `if TYPE_CHECKING:` block is module-level code: a name loaded there counts as eager.
- A given whose own test does not exist: any import of it is foreign, whoever imports it (that is how the misnamed givens surface).
- A debt entry for a function that the reordering of step C moves: the key carries no line number, so the entry survives as long as the violation does.
- The ad hoc reordering script meets a module where moving a block would change the multiset of top-level statements (for example a comment glued to two definitions): it refuses to write the file, and the file is reordered by hand.

## Test scenarios

- Scanner unit tests: the cases listed in step B, each on a source string, asserting the list of `(standard, symbol)` returned.
- The sweep: green at the end of every step. At the end of step F, `DEBTS` holds only the 15 fingerprinted newspaper entries, the D3 debt entries and the third-party entries, each with its blocker.
- A deliberate check in step B: add a helper above its caller in a scratch copy of a module and confirm the sweep fails with `path:line: newspaper-order name`. The same for a foreign given import and a `monkeypatch.setattr`. Then revert.
- Step C: the AST multiset check on every reordered file, then the full suite.
- Step D2: the fingerprint of every admitted server is identical before and after (`nuisance_fixture_fingerprint` over `evals/nuisance_admission.json`).
- Step D4: the backend and node-sandbox tests pass on the fake executable, and the Docker-free unit loop still hits the failing shim for any unscripted call.

## Verification

Inside a step, the short loop of `CLAUDE.md` (Workflow): the test files being changed with `-n 0` while red, then `uv run pytest tests/unit -n auto --maxprocesses 6`, the integration files the step touches, and `uv run pytest tests/integration/committed -n auto` when it changes committed content (`pyproject.toml` and `uv.lock` in steps A and D3, the workflow filter in step E, the living docs).

At the end of every step, and again in the closing pass (`CLAUDE.md`, Workflow: every pass that closes a step runs the full check):

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyrefly check
```

The full run includes the integration tests, which need Docker for the planting tests of steps D1, D3, D4 and E.

## Living docs

- `CONTRIBUTING.md`: a short paragraph on the code standards check. It covers what Ruff bans and where (`domain/ruff.toml`, `graph/ruff.toml`), saying that the ban list catches the common I/O APIs only and review covers the rest (a builtin `open()` or a `Path.read_text` in the hexagon is not caught), what the sweep checks, and the debt list: an entry is added only for a violation blocked by a fingerprinted file or a third-party package, it names that blocker, and it is paid when the blocker changes for its own reason.
- `CLAUDE.md`, Testing standards: one sentence pointing at `tests/unit/project/test_code_standards.py` as the check of the newspaper, given/then and no-`monkeypatch.setattr` rules. Commands: none added (the check runs in the existing pytest commands).
- `CHANGELOG.md`: nothing (no user-facing change, no dependency change).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, read by the later passes. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: Ruff has no third-party plugin system (verified against the Ruff FAQ, docs.astral.sh/ruff/faq).
- SETTLED: `TID251` with `[lint.flake8-tidy-imports.banned-api]` in a nested `ruff.toml` carrying `extend = "../../../pyproject.toml"` flags `import subprocess`, `import time`, `from mcp_auditor.adapters import ...`, `os.environ[...]` and `datetime.now()`, and its table replaces the root's (`unittest.mock` no longer flagged under it) (verified with the installed Ruff 0.17.2 on a scratch tree, and the banned-api rule page).
- SETTLED: `src = [".", "src"]` under `[tool.ruff]` (verified with Ruff 0.17.2 on a scratch tree, and the Ruff settings page for the default of `src`).
- SETTLED: `B008` flags a frozen dataclass call in an argument default (verified with Ruff 0.17.2 on a scratch tree).
- SETTLED: `PYTHON_DOTENV_DISABLED` honoured from python-dotenv 1.2.0 (verified against the python-dotenv CHANGELOG, 1.2.0 of 2025-10-26, and the installed 1.2.4 source), lock at 1.2.4 (verified in `uv.lock`).
- SETTLED: rich resolves `sys.stdout` at write time and freezes the width only when `COLUMNS` is set at construction (verified in the installed rich 15.0.0 source, `Console.__init__`, `Console.file`, `Console.size`).
- SETTLED: a `#!{sys.executable} -IS` shebang runs with isolated and no-site flags and forwards the argv (verified by running such a script on this Linux host).
- SETTLED: `tempfile.gettempdir()` caches its first answer in `tempfile.tempdir` (verified in the installed CPython 3.13 source).
- SETTLED: `git ls-files --cached --others --exclude-standard '*.py'` lists a file deleted from the working tree but still in the index (verified on a scratch repository), so the sweep checks existence itself.
- SETTLED: the Fireworks retry wait is `wait_exponential(multiplier=1, min=4, max=10)` in `langchain_core.language_models.llms.create_base_retry_decorator`, which `langchain_fireworks` calls, and tenacity's async sleep looks up `asyncio.sleep` at call time (verified in the installed langchain-fireworks 1.7.1, langchain-core and tenacity 9.1.4 sources).
- OPEN (unverified): google-genai's retry loop "where nothing can be injected": langchain-google-genai 4.4.2 merges a per-request `http_options` over its derived retry options, and google-genai 2.32.0 reads `initial_delay`, `max_delay` and `jitter` from them, so a short wait looks injectable at the call; whether that keeps the test on the production path is not settled. Resolved as an instruction: step 10 tries it, and the google-genai entry stays only if it fails.

## Implementation steps

The work is cut so that the sweep exists from the first commit and checks every later one: the bans and the sweep first, the newspaper order next in one scripted pass over the tree (before any hand edit, so the later steps write into files already in order), then the `monkeypatch.setattr` seams (D1 to D4), then the given/then moves (E1 to E3), the lock last. Each step is one commit.

Rules every step follows:

- **Debt list.** A step deletes from `DEBTS` the entries of the violations it clears (`test_every_debt_still_matches_a_violation` names them). No step adds an entry, with one exception: when a step moves a file (`git mv`) or a block of code that still carries a violation a later step clears, its entry follows it, re-keyed to the new path or symbol with the same code standard and the same blocker. Code a step writes follows the three code standards, or the sweep fails.
- **Fingerprinted files.** No step modifies a file of `fingerprinted_sources()` (created in Step 1). Every step checks it before closing: `git diff --name-only HEAD | uv run python -c "import sys; from tests.unit.project.support.fingerprinted_sources import fingerprinted_sources; hit = sorted(set(sys.stdin.read().split()) & fingerprinted_sources()); print(hit); sys.exit(bool(hit))"` prints `[]` and exits 0.
- **Fingerprint record** (Steps 2 to 10, the steps that change production code under `evals/` or `src/`). Before any edit, the implementer writes (or rewrites, if a previous session's copy is gone) a throwaway script in its scratchpad, never in the repository, that prints one sorted line per fingerprint: `grammar_fingerprint()` and `counter_fingerprint()`; `fixture_fingerprint(target, load_places(DETECTION_PLACES))` for every target of `ACCEPTANCE_TARGETS` and `HOLDOUT_TARGETS`, as `current_copy_fingerprints` calls it (`evals/run_nuisance.py`, `evals/cve/nuisance/run_command.py` from Step 7); `nuisance_fixture_fingerprint(server)` for every admitted server of `evals/nuisance_admission.json`, loaded as `evals/cve/nuisance/commands.py` loads it; `fingerprint_source(path.read_text())` of the three honeypot servers. It saves the output, reruns the script after the last edit and `diff`s the two outputs: they must be identical, and the step report says so.
- **Verification.** In the loop, the `CLAUDE.md` short loop: the test files being changed with `uv run pytest <files> -n 0` while red, then `uv run pytest tests/unit -n auto --maxprocesses 6` (with `--lf` until green, then the full short loop again), the integration files the step touches, and `uv run pytest tests/integration/committed -n auto` when the step changes committed content. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .` and `uv run pyrefly check`, all green, plus the fingerprinted-files check above.
- **Commit messages.** Steps 2 and 9 touch `src/mcp_auditor/`: their commit message answers the four questions of ADR 016 and says that no prompt, guard or default moves.

### Step 1: Ruff import bans, the scanner, the sweep and the debt list

- **Files**: `tests/unit/project/support/test_code_standards_scan_given.py`, `tests/unit/project/test_code_standards_scan.py`, `tests/unit/project/support/code_standards_scan.py`, `tests/unit/project/support/fingerprinted_sources.py`, `tests/unit/project/support/code_standards_debt.py`, `tests/unit/project/test_code_standards.py` (all new); `pyproject.toml`; `src/mcp_auditor/domain/ruff.toml`, `src/mcp_auditor/graph/ruff.toml` (new); `tests/unit/cve/backends/support/test_atlassian_backend_given.py` (and its test file if the given's callers must pass `monkeypatch`); `CONTRIBUTING.md`, `CLAUDE.md`.
- **Do**:
  1. Scanner tests first, red: `test_code_standards_scan.py` and its given, with the cases of "Scanner unit tests" (Step B). Each test feeds a small source string as a `SourceFile` (path chosen to exercise the given/then rule) and asserts the list of `(standard, symbol)`.
  2. `code_standards_scan.py` as Step B specifies (`CodeStandard`, `Violation`, `SourceFile`, `violations`, `newspaper_violations`, `foreign_given_then_imports`, `monkeypatch_setattrs`), pure, laid out like `tests/unit/support/retired_word_scan.py`.
  3. `fingerprinted_sources() -> frozenset[str]` in `fingerprinted_sources.py`, exactly as Step F defines it, brought forward so every step can run the fingerprinted-files check and so the debt list is tagged from the start. It reads `_PUBLIC_NAME_SOURCES` under its private name until Step 5 makes it public.
  4. `code_standards_debt.py` with `FingerprintedFile`, `ThirdParty`, `Debt` (`blocked_by: FingerprintedFile | ThirdParty | None`) and `DEBTS`. Generate `DEBTS` once with a scratchpad script (not committed) from the scanner's output over the swept file set, deduplicated on (path, code standard, symbol) and sorted by them. Blockers: an entry in a file of `fingerprinted_sources()` gets `FingerprintedFile` of that file; the entries Step D3 lists under "Stays as debt" get their named blocker now (`tests/unit/cve/backends/support/doris_launch.py` by `evals/cve/detection/holdout_environments.py`; `tests/unit/cve/backends/support/test_doris_seed_given.py`, its clock and `subprocess.run` patches, by `evals/cve/backends/doris.py`; `tests/integration/test_cve_planting.py` and `tests/unit/cve/test_cve_planting_host_files.py` by `evals/cve/planting_docker.py`); the two `asyncio.sleep` entries of `tests/unit/auditor/test_throttling.py` get `ThirdParty("langchain-core", ...)` (Fireworks) and `ThirdParty("google-genai", ...)` with the reasons of "Decisions taken"; every other entry gets `None`.
  5. `test_code_standards.py`: the three sweep tests of Step B, plus `test_every_debt_is_blocked_by_a_fingerprinted_file_or_a_third_party` as Step F words it (a `FingerprintedFile` is in `fingerprinted_sources()`, a `ThirdParty` names a distribution `importlib.metadata.distribution` finds and carries a non-empty reason), which accepts `None` until Step 19.
  6. Step A: `pyproject.toml` (`src = [".", "src"]`, `TID251`, the `unittest.mock` ban) and the two nested `ruff.toml` files, the composition-root list taken from `ls src/mcp_auditor` (today `audit`, `checkpointing`, `cli`, `config`, `config_file`, `console`, `progress`, `report_files`, `server_execution`, `stream_handler`, `studio`). In the atlassian given, `mock.patch.dict(os.environ, environment, clear=True)` becomes `monkeypatch.delenv` of every variable present and `monkeypatch.setenv` of `environment` (the given takes its caller's `monkeypatch`).
  7. Living docs: the `CONTRIBUTING.md` paragraph and the `CLAUDE.md` sentence of "Living docs", in their final form (an entry is added only for a violation blocked by a fingerprinted file or a third-party package).
- **Test**: the scanner cases of Step B (helper above its only caller fires, below does not, used by a decorator, a default, a class body or module-level code does not, a class above its users does not, a later function with a local of the same name is not a user, a method is never checked; own given or then passes, another test's given fires in both import forms, a given importing another given fires, a shared support module importing a given fires; `monkeypatch.setattr(module, "name", value)` fires with the expected symbol, `monkeypatch.setenv` does not). The sweep green on today's tree. The deliberate check of "Test scenarios": a helper above its caller, a foreign given import and a `monkeypatch.setattr` added to a scratch copy inside the tree each make the sweep fail with `path:line: <standard> <symbol>`, then reverted.
- **Verify**: `uv run pytest tests/unit/project -n 0` green; `uv run ruff check .` green with the new bans (no hexagon violation, no `unittest.mock` left); `uv run pytest tests/integration/committed -n auto` (pyproject, docs); the closing checks.

### Step 2: newspaper order

- **Files**: the non-fingerprinted Python files the scanner names under `newspaper-order` (about 227 files under `src/`, `evals/` and `tests/`, edited by script, not read one by one); `tests/unit/project/support/code_standards_debt.py`.
- **Do**:
  1. Take the "before" fingerprint record.
  2. Write the reordering script of Step C in the scratchpad (not committed): per file, move each violating function, from its first decorator (or its `def`) to its `end_lineno`, plus the comment lines glued above it, right below the end of its first user, repeating until the scanner finds no newspaper violation in the file. Skip every file of `fingerprinted_sources()`. Before writing a file, assert that the multiset of `ast.dump` of its top-level statements is unchanged; on a refusal, reorder that file by hand and assert the same.
  3. `uv run ruff format .`, then rerun the scanner.
  4. Delete every `newspaper-order` entry with no blocker from `DEBTS` (394). The 15 `FingerprintedFile` entries stay.
  5. Take the "after" fingerprint record and compare.
- **Test**: no new test. The AST multiset check on every reordered file, then the full suite, which proves no behavior moved. The goldens are not regenerated.
- **Verify**: the sweep reports no `newspaper-order` violation outside the 15 fingerprinted entries; fingerprint records identical; the closing checks. Commit message with the ADR 016 answers (`src/mcp_auditor/` is touched).

### Step 3: the `run_detection` command takes its deps

- **Files**: `tests/unit/detection/support/run_detection_cli.py`, `tests/unit/detection/support/test_run_detection_given.py`, `tests/unit/detection/support/test_run_detection_recording_given.py`, `tests/unit/detection/test_run_detection.py`, `tests/unit/detection/test_run_detection_recording.py`, `tests/unit/detection/test_detection_holdout_targets.py`; `evals/cve/detection/command_deps.py` (new), `evals/run_detection.py`, `evals/cve/detection/no_llm_modes.py` (deleted); the debt list.
- **Do** (Step D1, its `run_detection` half):
  1. Take the "before" fingerprint record.
  2. Tests first: the givens build a `DetectionCommandDeps` from fakes (`FakeContainerSweep`, a preflight lambda, a fixed `TreeState`, the existing audit target and session fakes, `deps_with` for the calibration check, a fake `survey_one`) and call `main(flags, deps)`, asserting the returned exit code (argparse errors and `_reject_unknown_flaws` still raise `SystemExit(2)`). The `sys.argv` patch and the autouse sweep fixtures go. `test_detection_holdout_targets.py` scans `cve/detection/command_deps.py` in place of `no_llm_modes.py`.
  3. `command_deps.py`: `DetectionCommandDeps` and the `Protocol`s `AuditTargetFactory`, `RunSession`, `CalibrationCheckFactory` (`(concurrency, ci) -> CalibrationCheckDeps`), `SurveyOne`, with no import of `holdout_targets`.
  4. `run_detection.main(argv: Sequence[str] | None = None, deps: DetectionCommandDeps | None = None) -> int`, `__main__` as `sys.exit(main())`. `_run` and `_run_graded` take `_FlawSelection(graded, tracked)` and `_CommandRun(places, deps)`. Delete `no_llm_modes.py`: the calibration check and the survey are called inline as D1 says (the ADR 031 comment moves along), the real `survey_all` running in the tests.
  5. Delete the cleared debt entries. Take the "after" record.
- **Test**: every scenario the existing tests cover keeps its assertion (preflight refusal does not start the session, dirty tree refusal on recording, unknown flaw ID exits 2, calibration-check and survey modes dispatch, recording paths), now through injected deps. A survey test checks that the real `survey_all` drives the injected `survey_one` for each graded target.
- **Verify**: no `monkeypatch-setattr` entry left for the five detection files above; the test pinning `holdout_targets` out of `run_detection`'s imports green; fingerprint records identical; the closing checks.

### Step 4: the `run_detection_holdout` command takes its deps

- **Files**: `tests/unit/detection/support/test_run_detection_holdout_run_given.py`, `tests/unit/detection/test_run_detection_holdout.py`, `tests/unit/detection/test_run_detection_holdout_run.py`; `evals/cve/run_images.py` (`RunDocker`), `evals/cve/detection/holdout_command_deps.py` (new), `evals/cve/detection/holdout_run.py` (`RunHoldoutTargets`, `HoldoutDepsFactory`), `evals/cve/run_files.py` (`write_report`, `ReportWriter`), `evals/cve/holdout_conditions.py` (`committed_conditions`), `evals/run_detection_holdout.py`, `evals/cve/nuisance/commands.py` (its `write_report` removed), `evals/run_nuisance.py` and `evals/cve/nuisance/gate/gate_command.py` (import only); the debt list.
- **Do** (Step D1, its `run_detection_holdout` half):
  1. Take the "before" fingerprint record.
  2. Tests first: the givens build a `HoldoutCommandDeps` (`drawn`, a `RunDocker` of `FakeImageStore`, `FakeContainerSweep` and a network check lambda, `deps_with`, a conditions reader, `deps_reaching_nothing`, a fake `RunHoldoutTargets`, a `last_commit` lambda, a `write_report`) and call `main(argv, deps)`. The drawn test target is `replace(an_acceptance_target(...), flaw_id="CVE-2026-0001")` in a census from `a_census_drawing(["CVE-2026-0001"])`. `cards_reporting` goes: the unready case writes a census with no draw. Any test of `commands.write_report` moves to `run_files.write_report`.
  3. `RunDocker` in `run_images.py`, `committed_conditions()` in `holdout_conditions.py`, `write_report` and `ReportWriter` moved into `run_files.py` (delete `run_detection_holdout._write_report` and `commands.write_report`, update `run_nuisance.py` and `gate_command.py`), the two `Protocol`s in `holdout_run.py`, `holdout_command_deps.py` as D1 specifies (separate module, `holdout_targets` stays out of everything `run_detection` imports).
  4. `run_detection_holdout.main(argv, deps)` dispatches `args.command(args, deps)`. `IMAGE_STORE` goes. `_check_calibrations(targets, checks, sweep)` with `load_places` inside.
  5. Delete the cleared debt entries. Take the "after" record.
- **Test**: `test_run_refuses_an_acceptance_target_for_its_tools_filter` exits 3 and asserts the refusal's reason text (with `last_commit` injected, git is never asked about `tmp_path`); the result is written before the report (an injected `write_report` that raises leaves `<report>.result.json` on disk); an unready card refuses before any Docker or LLM work (a census with no draw, the run orchestrator unreached); a stale image is refused through `FakeImageStore`; a daemon without closed networks exits 3; nothing drawn exits 0.
- **Verify**: no `monkeypatch-setattr` entry left for the three files above; fingerprint records identical; the closing checks.

### Step 5: nuisance fingerprint sources and the re-admission plan

- **Files**: `tests/unit/nuisance/support/test_nuisance_fingerprint_given.py`, `tests/unit/nuisance/test_nuisance_fingerprint.py`, `tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py` and its given; `evals/cve/nuisance/fingerprint.py`, `evals/cve/nuisance/admission/re_admission_dossier.py`, `evals/run_nuisance.py` (`_re_admission_dossier`); `tests/unit/project/support/fingerprinted_sources.py`; the debt list.
- **Do** (Step D2, its fingerprint and re-admission dossier items):
  1. Take the "before" fingerprint record (it covers `nuisance_fixture_fingerprint` of every admitted server).
  2. Tests first: the fingerprint tests pass a `NuisanceFixtureSources` whose `SuiteConfinement` carries a copied source file, or `options`/`resolver` lambdas, in place of the four patches. The re-admission tests build the plan with `re_admission_plan(...)` and write it with `write_re_admission_dossier(plan, out)`. Delete the test that patched `closure_roots`.
  3. `SuiteConfinement`, `NuisanceFixtureSources`, and the `sources: NuisanceFixtureSources | None = None` parameter on `nuisance_fixture_fingerprint` and `fingerprinted_files`, the hash byte-identical. `_PUBLIC_NAME_SOURCES` becomes `PUBLIC_NAME_SOURCES`, and `fingerprinted_sources.py` reads the public name.
  4. `re_admission_plan(walk_inputs, admission, server_package) -> ReAdmittedDossier` and `write_re_admission_dossier(plan, out)`. `run_nuisance._re_admission_dossier` calls both.
  5. Delete the cleared debt entries. Take the "after" record.
- **Test**: the fingerprint moves when the confinement source, the confinement options or the resolver option change (each through `sources`), and stays put otherwise; the re-admission dossier tests keep their assertions on what the dossier holds.
- **Verify**: the "after" fingerprint record identical, every admitted server included; the closing checks.

### Step 6: nuisance benign call and the vet command

- **Files**: `tests/unit/nuisance/support/test_nuisance_vetting_given.py`, `tests/unit/nuisance/test_nuisance_vetting.py`, `tests/unit/nuisance/support/test_nuisance_vet_given.py`, `tests/unit/nuisance/test_nuisance_vet.py`, `tests/unit/nuisance/test_run_nuisance_vet.py`; `evals/cve/nuisance/vetting.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/holdout_run.py`, `evals/cve/nuisance/gate/gate_session.py`, `evals/run_nuisance.py`; the debt list.
- **Do** (Step D2, its benign call and vet items):
  1. Take the "before" fingerprint record.
  2. Tests first: the vetting given builds a `LaunchedBenignCall(timeout, launcher=ServerLauncher(flaky.environment, flaky.connect))` in place of its two patches. The vet given passes a `VetCommandDeps(conditions, vet_deps)` in place of patching `load_conditions` and `default_vet_deps`, through `run_nuisance.main(argv, NuisanceCommandDeps(vet=...))`.
  3. `ServerLauncher` and `LaunchedBenignCall` in `vetting.py` (`Connect` from `evals/cve/launch_audit.py`), replacing `benign_call` and the three `functools.partial` in `vet_command.py`, `holdout_run.py` and `gate/gate_session.py`. `default_vet_deps(tool_call_timeout, concurrency, launcher: ServerLauncher | None = None)`. `VetCommandDeps` in `vet_command.py`.
  4. `NuisanceCommandDeps` in `run_nuisance.py` with its `vet` field only (the `run`, `fix_check` and `gate` fields join in Steps 7 and 8), `main(argv, deps: NuisanceCommandDeps | None = None)`, and `add_vet_arguments(parser, deps)` binding its handler with `functools.partial`, so `args.command(args)` stays.
  5. Delete the cleared debt entries. Take the "after" record.
- **Test**: the existing vetting scenarios (first pass fails, second pass on a fresh launch passes or fails, `on_ping` recorded) and vet command scenarios (exit codes 0, 1, 2, 3, the `--server` selection, the timeout default taken from the conditions) keep their assertions through the injected launcher and deps.
- **Verify**: no `monkeypatch-setattr` entry left in the two givens; fingerprint records identical; the closing checks.

### Step 7: the nuisance run command moves to `run_command.py`

- **Files**: `tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py`, `tests/unit/nuisance/test_run_nuisance_holdout_run.py`, `tests/integration/committed/nuisance/admission/test_nuisance_admission_loads.py`; `evals/cve/nuisance/run_command.py` (new), `evals/run_nuisance.py`, `evals/cve/nuisance/holdout_run.py` (`RunOrchestrator`); the debt list.
- **Do** (Step D2, its run item):
  1. Take the "before" fingerprint record.
  2. Tests first: the given builds `RunCommandDeps(conditions, settings, run_deps, orchestrate, file_commit, write_report)` from fakes and calls `main(argv, NuisanceCommandDeps(run=...))`. The "unreached" patches become deps whose fields raise if called. The "result before report" test injects a raising `write_report` in place of patching `build_report`. The committed admission test imports `current_copy_fingerprints` from `run_command`.
  3. Move `_run` and its helpers, `current_copy_fingerprints` included, from `run_nuisance.py` to `run_command.py` with `RunCommandDeps` (no import of `run_nuisance` from it). `RunOrchestrator` `Protocol` in `holdout_run.py`. `NuisanceCommandDeps` gains `run`, `add_run_arguments(parser, deps)` binds it.
  4. Delete the cleared debt entries. Take the "after" record.
- **Test**: the existing run command scenarios keep their assertions: tracing refused, existing report paths refused, stale holdout calibration copies refused before any Docker or LLM work (the injected `conditions` raising first proves the order), nothing admitted exits 0, the result written before the report, the commits recorded.
- **Verify**: `evals/run_nuisance.py` under 300 lines; `uv run pytest tests/integration/committed -n auto`; fingerprint records identical; the closing checks.

### Step 8: the nuisance fix-check and gate commands take their deps

- **Files**: `tests/unit/nuisance/fix_checks/support/test_nuisance_fix_check_command_given.py`, `tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py`, `tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py`, `tests/unit/nuisance/gate/test_run_nuisance_gate.py`; `evals/cve/nuisance/fix_check_command.py`, `evals/cve/nuisance/gate/gate_command.py`, `evals/run_nuisance.py`; the debt list.
- **Do** (Step D2, its fix-check and gate items):
  1. Take the "before" fingerprint record.
  2. Tests first: the fix-check given passes `FixCheckCommandDeps(fixtures=(fixture,), fix_check_deps=...)` whose `FixCheckDeps` carries the network check and the `FakeContainerSweep`. The gate given passes `GateCommandDeps(conditions, settings, harness, run_gate)`; the gate output stays captured with the shared console (not a deps field).
  3. `FixCheckDeps` gains `check_networks` and `sweep` (the `RunDocker` fields of Step 4), `FixCheckCommandDeps`, `_selected_fixtures(fixtures, flaw)` to keep `fix_check` under 20 lines. `GateCommandDeps`, with `gate_conditions` called directly on what the injected readers return. `NuisanceCommandDeps` gains `fix_check` and `gate`, bound through `add_fix_check_arguments` and `add_gate_arguments` with `functools.partial`.
  4. Delete the cleared debt entries. Take the "after" record.
- **Test**: the existing scenarios keep their assertions: no fixture selected exits 0, an unknown `--flaw`, a daemon without closed networks exits 3, a mismatch exits 1, the sweep runs at the end even on a raise; the gate's exits 0, 1, 3, recording paths and refusals.
- **Verify**: no `monkeypatch-setattr` entry left under `tests/unit/nuisance/` (Steps 5 to 8 clear them all); fingerprint records identical; the closing checks.

### Step 9: session bounds and calibration check options

- **Files**: `src/mcp_auditor/adapters/mcp_client.py`, `src/mcp_auditor/adapters/session_owner.py` (if `initialize_timeout` passes through it); `tests/integration/test_mcp_client_transport.py`, `tests/integration/test_mcp_client_cancellation.py`, `tests/integration/support/test_mcp_client_cancellation_given.py`, `tests/integration/test_mcp_client_relaunch.py`, `tests/integration/test_detection_replay.py` (and its given for `connect_pinging_within`); `evals/cve/detection/calibration_check.py`, `evals/cve/detection/holdout_run.py`, `tests/integration/test_detection_calibration_check.py`, `tests/unit/detection/support/test_detection_calibration_check_given.py`; the debt list.
- **Do** (Step D3, its session bounds and calibration check items):
  1. Take the "before" fingerprint record.
  2. Tests first: the relaunch test passes `bounds=SessionBounds(teardown=0.2)`, the three `initialize_timeout` callers pass `bounds=SessionBounds(initialize=0.5)`, the replay test injects `connect_pinging_within(1)` through `replay_with_causes`, the unit calibration check given passes `CheckOptions(connect=fake.connect)`, and a unit test pins `SessionBounds()` to the three current constants (`_INITIALIZE_TIMEOUT`, `PING_TIMEOUT_SECONDS`, `TEARDOWN_TIMEOUT_SECONDS`), so no audit's timeouts can move by accident.
  3. `SessionBounds(initialize, ping, teardown)` in `mcp_client.py` with today's constants as defaults, `bounds: SessionBounds | None = None` on `StdioMCPClient.connect` in place of `initialize_timeout`, `tool_call_timeout` unchanged. The kit's own client (`evals/cve/kit/client.py`) is untouched.
  4. `CheckOptions(report_detail, on_ping, connect)` in `calibration_check.py`, `check_target(target, places, options: CheckOptions | None = None)`, `passes_calibration_check(target, places, connect=connect)`. `default_deps` in `evals/cve/detection/holdout_run.py` and the two integration calls pass `options=CheckOptions(report_detail=TYPES_ONLY)`.
  5. Delete the cleared debt entries. Take the "after" record.
- **Test**: the relaunch, cancellation, transport and replay integration tests keep their assertions with the bounds injected; the calibration check unit tests keep theirs with the injected connect.
- **Verify**: `uv run pytest tests/integration/test_mcp_client_relaunch.py tests/integration/test_mcp_client_transport.py tests/integration/test_mcp_client_cancellation.py tests/integration/test_detection_replay.py tests/integration/test_detection_calibration_check.py -n auto` green; fingerprint records identical; the closing checks. Commit message with the ADR 016 answers.

### Step 10: benign probe, lifecycle lookup, checkpoint path, `.env` guard and command lines

- **Files**: `evals/cve/kit/benign_probe.py`, `evals/cve/kit/backend_launch.py`, `tests/unit/cve/support/test_kit_benign_probe_given.py`, `tests/unit/cve/backends/test_backend_lifecycle.py`; `tests/integration/test_audit_server_failures.py`; `tests/conftest.py`; `tests/unit/auditor/test_throttling.py` and its given; `evals/run_honeypot_suite.py`, `evals/run_judge_eval.py`, `evals/draw_judge_cases.py`, `tests/unit/evals/test_run_honeypot_suite.py`, `tests/unit/evals/test_run_judge_eval.py`, `tests/unit/evals/test_draw_judge_cases.py`; the debt list.
- **Do** (Step D3, the remaining items but the console):
  1. Take the "before" fingerprint record.
  2. Tests first, each replacing its patch: the probe given passes `lifecycles=` to `probe_launch` and `probe=` to `main`; the lifecycle test passes `import_module=` to `lifecycle_of`; the checkpoint test sets `HOME` to `tmp_path` and creates `tmp_path/.mcp-auditor/checkpoints.db` as a directory; the three eval command tests pass their flags to `main(argv)`.
  3. `probe_launch(record, image, lifecycles=lifecycle_of)`, `main(argv=None, probe=probe)`, `lifecycle_of(key, import_module=importlib.import_module)`; `parse_args(argv=None)` and `main(argv=None)` in the three eval commands.
  4. `tests/conftest.py`: `monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")` in place of the `load_dotenv` patch. No change to `pyproject.toml` or `uv.lock`.
  5. The google throttling test: try passing `http_options={"retry_options": {"attempts": 3, "initial_delay": 0.001, "max_delay": 0.001, "jitter": 0.001}}` to `ainvoke` in place of the `asyncio.sleep` patch. If the test still counts the throttled response once and runs fast, delete its `ThirdParty("google-genai", ...)` entry. Otherwise keep the patch and the entry. The Fireworks test keeps its patch and its `ThirdParty("langchain-core", ...)` entry.
  6. Delete the cleared debt entries. Take the "after" record.
- **Test**: the existing scenarios keep their assertions; the checkpoint test still gets `sqlite3.OperationalError`; a test run with a `.env` in the repository root reads none of its values (the guard's existing test, if any, keeps passing).
- **Verify**: `uv run pytest tests/integration/test_audit_server_failures.py -n 0`; `uv run pytest tests/integration/committed -n auto` (pyproject, lock); fingerprint records identical; the closing checks.

### Step 11: the captured console

- **Files**: `tests/unit/support/captured_console.py` (new), `tests/unit/evals/support/test_eval_display_given.py`, and the 16 files that call `a_captured_console` today (`grep -rln a_captured_console tests`), edited mechanically; the debt list.
- **Do** (Step D3, its console item, together with the E1 row that moves `a_captured_console`, since every caller is touched here anyway):
  1. `captured_console.py`: `a_captured_console(capsys, monkeypatch, width=200)` sets `COLUMNS`, asserts `eval_display.console.width == width` and that the captured text carries no ANSI escape sequence (rich decides its colour system when the console is built, so a run with `-s` in a terminal fails loudly instead of breaking string assertions), and returns an object whose `getvalue()` accumulates `capsys.readouterr().out`. Remove it from the eval display given (and the given itself if nothing else is left in it).
  2. Every caller imports it from `tests.unit.support.captured_console` and gains a `capsys` parameter, wrappers in givens included.
  3. Check that every display module imports the single `eval_display.console`, and that no `not in` assertion starts passing because a stray `print` now lands in the captured output.
  4. Delete the cleared debt entries (the `setattr` and the foreign imports of `test_eval_display_given`).
- **Test**: the display tests keep their assertions on the captured text.
- **Verify**: `COLUMNS=80 uv run pytest tests/unit/evals -n 0` fails loudly on the width assertion (then unset); the closing checks.

### Step 12: the fake `docker` executable

- **Files**: `tests/fakes/docker_executable.py` (new), `tests/fakes/scripted_docker.py` and `tests/unit/support/recorded_subprocess.py` (deleted), `tests/fakes/__init__.py`, `tests/unit/cve/backends/support/test_node_sandbox_engine_given.py`, and their users: `tests/unit/cve/backends/support/test_gitlab_backend_given.py`, `test_gitlab_backend_then.py`, `test_kubernetes_backend_given.py`, `test_kubernetes_backend_then.py`, `tests/unit/cve/backends/test_backend_lifecycle.py`, `test_ckan_holdout_builder.py`, `test_mcp_ssh_holdout_builder.py`, `tests/unit/cve/test_cve_closed_network.py`, `tests/unit/cve/test_cve_run_images.py`; the debt list.
- **Do** (Step D4):
  1. `ScriptedDockerExecutable(answers)` with `installed(monkeypatch, tmp_path)` and the reading API of `ScriptedDocker` (`commands`, `inputs`, `started()`, `created_networks()`, `removed()`), as D4 specifies: a `#!{sys.executable} -IS` script, a JSON answers file keyed by argv prefix (longest prefix wins, success with no output otherwise), a JSONL log of `{argv, stdin}`, `PATH` prepended with `monkeypatch.setenv`. The node sandbox engine's socket binding (mode 0666 in the mounted directory) moves into the script.
  2. Move every user to it (`recorded_commands` becomes the fake with no answers), then delete `scripted_docker.py` and `recorded_subprocess.py`.
  3. `test_doris_seed_given.py` stays as it is (blocked debt).
  4. Delete the cleared debt entries.
- **Test**: the backend, closed network, run image and node sandbox tests keep their assertions on the fake executable; an unscripted call in the Docker-free unit loop still reaches the failing shim of `tests/unit/support/docker_shim.py` when the fake is not installed.
- **Verify**: `uv run pytest tests/unit/cve -n auto --maxprocesses 6`; the closing checks.

### Step 13: given/then moves, auditor and evals areas

- **Files**: the sources and destinations of the E1 rows for `auditor` (`test_console_given`, `test_shown_response_given`/`_then`, `test_chain_nodes_given`, `test_rendering_then`, `test_llm_throttling_given`) and `evals` (`test_judge_fixture_given`, `test_honeypot_retest_given`), with their importers (`grep -rln <module> tests`), edited mechanically; the debt list.
- **Do** (Step E1, these rows, following the ownership rule, `git mv` where a whole given becomes a shared module, no re-export, no new module starting with `test_`, each `support/` with its `__init__.py`): apply each row as its table says (`audit_displays.py`, `test_console_display_given.py`, `test_console_findings_given.py`, `report_builders.py`, `cut_responses.py`, `chain_states.py`, `markdown_sections.py`, `tests/unit/support/provider_errors.py`, `evals/support/judge_cases.py`, `evals/support/fictional_honeypots.py`). Rename an alias that no longer matches its module. Delete the cleared debt entries (and re-key the entries a `git mv` carries, per the rules above).
- **Test**: no new test; the moved tests keep their assertions.
- **Verify**: the sweep lists no foreign import of the moved modules; the closing checks.

### Step 14: given/then moves, census and detection areas

- **Files**: the sources and destinations of the E1 rows for `census` (`test_census_given`, `test_census_figures_given`, `test_census_identity_given`, `test_census_sources_given`) and `detection` (`test_detection_oracle_given`, `test_detection_draw_record_given`, `test_detection_holdout_pre_run_check_given`, `test_run_detection_holdout_run_given`, `test_detection_calibration_check_exit_given`, the two golden givens), with their importers; the debt list.
- **Do** (Step E1, these rows, same conventions as Step 13): `tests/unit/support/censuses.py`, `census/support/classifier_pairs.py` (`a_census` renamed `census_parts`), `census/support/advisory_sources.py`, `detection/support/detection_reports.py`, `tests/unit/support/census_draws.py`, `detection/support/scripted_checks.py`, `tests/unit/support/holdout_result_keys.py`, `detection/support/calibration_check_deps.py` (`git mv`), and the golden-reading tests moved to new `test_detection_layout_check_golden.py` (10 tests) and `test_detection_route_check_golden.py` (4 tests), the golden givens left in place and no golden regenerated. Delete the cleared debt entries.
- **Test**: no new test; the moved tests keep their assertions, the golden-reading test count unchanged.
- **Verify**: the sweep lists no foreign import of the moved modules; `git status` shows no golden JSON modified; the closing checks.

### Step 15: given/then moves, cve and integration areas

- **Files**: the sources and destinations of the E1 rows for `cve` (`test_cve_grammar_given`, `test_cve_launch_audit_given`, `cve/backends` `test_backend_lifecycle_given`) and the integration rows (`test_cve_planting_given`/`_then`, `test_cve_planting_stand_ins_given`, `test_mcp_client_given`), with their importers; `.github/workflows/detection-calibration-check.yml`; the debt list.
- **Do** (Step E1, these rows, same conventions as Step 13): `tests/unit/support/grammar_inputs.py` (`git mv`, imported `as grammar`), `tests/unit/support/launch_audit_fakes.py` (`git mv`), `tests/unit/support/registered_responders.py`, `integration/support/recording_planting.py`, `integration/support/target_commands.py`, `integration/support/stand_in_fetches.py` and `integration/support/stand_in_capture.py` (`git mv` of the 325-line given, then split), `PAGINATED_SERVER_PATH` into `support_servers.py`. The workflow's two `paths` lists gain `recording_planting.py`, `target_commands.py` and `docker_prerequisites.py` (and the stand-in modules if the filter covered the old given). Delete the cleared debt entries.
- **Test**: no new test; the moved tests keep their assertions.
- **Verify**: `uv run pytest tests/integration/committed -n auto` (workflow); the planting integration tests (`uv run pytest tests/integration/test_cve_planting.py tests/integration/test_cve_planting_stand_ins.py -n auto`, Docker); the closing checks.

### Step 16: given/then moves, nuisance walks and admissions

- **Files**: `test_nuisance_walk_given` (shared names to new `tests/unit/support/nuisance_walks.py`), `test_nuisance_admission_given` (`git mv` to `tests/unit/support/nuisance_admissions.py`, plus `a_recorded_exit`), `tests/unit/support/test_nuisance_admission_edits_given.py` (merged into `admission_mutations.py`, deleted), `tests/unit/support/test_nuisance_committed_admission_given.py` (`git mv` to `committed_nuisance_admission.py`, plus the three committed-admission lookups), with their importers (about 70 files, edited by script); the debt list.
- **Do** (Step E2, these rows, same conventions as Step 13): move in the order that keeps imports acyclic (`nuisance_walks` first, then `nuisance_admissions`, then `admission_mutations`; `nuisance_admissions` never imports `admission_mutations`). Aliases follow their module (`admission_given.` becomes `admissions.`). Names that exist in two modules with different values (`a_server`, `deps_on`, `SERVER_PACKAGE`, `conditions`, `RECORDED_AT`, `Outcome`) are read through a module alias, never imported by name. Delete the cleared debt entries.
- **Test**: no new test.
- **Verify**: `uv run pytest tests/integration/committed -n auto` (importers there); the closing checks.

### Step 17: given/then moves, nuisance holdout runs, vets and queue walks

- **Files**: `test_nuisance_holdout_run_given` (`git mv` to `tests/unit/support/nuisance_holdout_runs.py`, `InterruptingAudit` to new `test_nuisance_holdout_run_interrupted_given.py`), `test_nuisance_holdout_run_backends_given` (to new `tests/unit/support/nuisance_docker_hosts.py`, deleted), `test_nuisance_vet_given` (shared part to new `tests/unit/support/nuisance_vets.py`), `test_nuisance_vetting_given` (shared part to new `nuisance/support/flaky_launches.py`, its `__all__` gone), `test_run_nuisance_given` (to new `nuisance/support/nuisance_queue_walks.py`, deleted), with their importers; the debt list.
- **Do** (Step E2, these rows, same conventions as Step 16), keeping the order `nuisance_admissions` ← `nuisance_holdout_runs` ← `nuisance_docker_hosts` ← `nuisance_vets`. Delete the cleared debt entries.
- **Test**: no new test.
- **Verify**: the closing checks.

### Step 18: the remaining foreign imports outside `tests/unit/nuisance`

- **Files**: the importers the sweep still lists under `foreign-given-then` outside `tests/unit/nuisance` and `tests/integration/committed/nuisance`, and the builder modules their shared names move to. Measured while cutting the steps, the givens still imported from another file there are, among others, `test_judge_baseline_given`, `test_llm_adapter_given`, `test_eval_gate_given`, `test_eval_baseline_given`, `test_detection_gate_given`, `test_models_given`, `test_llm_refusals_given`, `test_cve_strike_given`, `test_eval_session_given`, `test_honeypot_fault_injection_given`, `test_judge_outcomes_given`, `test_probe_analysis_given`, `test_kit_fix_check_given`, the backend givens of ckan, kubernetes and searxng, and `tests/unit/cve/support/test_cve_planting_stand_ins_given.py` (imported by `audited_launch_builders.py`, `test_detection_baseline_given.py` and two nuisance files). The sweep's list is the authority.
- **Do** (Step E3, outside nuisance): for each remaining import, move the shared name to a builder module named after what it builds (ownership rule, area `support/` or `tests/unit/support/` when users span areas), or replace the import by a builder module Steps 11 to 17 created. No re-export. A nuisance importer of a module moved here follows the move. Delete the cleared debt entries.
- **Test**: no new test.
- **Verify**: the sweep lists no `foreign-given-then` violation outside the nuisance directories; the closing checks.

### Step 19: the last nuisance moves and the lock

- **Files**: `test_nuisance_statistic_given` (`a_server_result` to `nuisance/support/nuisance_report_runs.py`), `test_nuisance_gate_baseline_given` (`git mv` to `nuisance/gate/support/nuisance_gate_baselines.py`, plus `a_comparison`, the `X as X` re-exports of `test_nuisance_gate_given` and `test_nuisance_gate_recording_given` gone), `test_nuisance_gate_report_given` (shared part to new `nuisance/gate/support/nuisance_gate_reports.py`), `test_nuisance_dossier_then` (`it_carries_the_holdout_reference_of` to new `nuisance/admission/support/holdout_reference_checks.py`), `test_nuisance_unrecorded_given` (inlined at its one foreign call site), the `__all__` of `test_nuisance_assembly_given`, and the importers the sweep still lists in the nuisance directories (among them `test_nuisance_admission_records_given`, `test_nuisance_dossier_given`, `test_nuisance_gate_given`, `test_nuisance_admission_walk_given`, `test_nuisance_re_admission_dossier_given`, `test_nuisance_holdout_calibration_copies_given`); `tests/unit/project/support/code_standards_debt.py`, `tests/unit/project/test_code_standards.py`; `CONTRIBUTING.md` if its paragraph needs adjusting.
- **Do** (the E2 rows left, Step E3 for the nuisance directories, then Step F):
  1. Apply the rows and clear the remaining nuisance imports, same conventions as Step 16. Delete the cleared debt entries.
  2. Check that no `None` blocker is left in `DEBTS`, then make `blocked_by: FingerprintedFile | ThirdParty` required (`None` leaves the type) and drop the `None` acceptance from `test_every_debt_is_blocked_by_a_fingerprinted_file_or_a_third_party`.
- **Test**: the lock test rejects a `FingerprintedFile` outside `fingerprinted_sources()` and a `ThirdParty` naming no installed distribution or carrying an empty reason (checked once by hand on a scratch entry, then reverted).
- **Verify**: `DEBTS` holds only the 15 fingerprinted `newspaper-order` entries, the D3 "Stays as debt" entries (Doris launch and seed, planting probe budget and timeout, planting host files) and the two `ThirdParty` throttling entries, each with its blocker; the sweep reports no violation and no stale entry; `uv run pytest tests/integration/committed -n auto`; the closing checks.
