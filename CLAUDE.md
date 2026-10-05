# mcp-auditor

## Commands

```bash
uv run pytest -n auto            # Unit + integration tests
uv run pytest tests/unit         # Unit tests only
uv run pytest tests/integration -n auto  # Integration tests only, the fault injection on the gate included (one test needs Docker and network access, it skips without Docker)
uv run ruff check .              # Lint
uv run ruff format .             # Format
uv run pyright                   # Type check (strict mode)
uv run python -m evals.run_evals       # E2E evals (honeypot servers, needs an LLM key: OPENAI_API_KEY by default)
uv run python -m evals.run_evals --record-baseline  # Record evals/baselines/honeypot_e2e.json from a clean tree: run it twice at the same commit (exploratory, then confirmed), then commit it by hand
uv run python -m evals.run_evals --ungated          # Floors only (recall one detection per run, precision and coverage 0.50), any conditions, no baseline comparison (never in CI)
uv run python -m evals.run_evals --concurrency N    # Honeypot audits in flight at once, runs and replays alike, default 9, 1 for the old sequence (recorded in the report, never in the baseline)
uv run python -m evals.run_judge_eval  # Judge isolation eval (needs an LLM key: OPENAI_API_KEY by default)
uv run python -m evals.run_judge_eval --record-baseline  # Record evals/baselines/judge_isolation.json from a clean tree: run it twice at the same commit (exploratory, then confirmed), then commit it by hand
uv run python -m evals.run_judge_eval --ungated          # Floors only (recall one detection per run, precision 0.50), any conditions, no baseline read (never in CI)
uv run python -m evals.run_judge_eval --runs N           # Judge each case N times, default 3 (the baseline's conditions)
uv run python -m evals.run_judge_eval --concurrency N    # Judge calls in flight at once, runs and replays alike, default 30
uv run python -m evals.draw_judge_cases --honeypot-export PATH --honeypot-export PATH --cve-export PATH  # Draw the unlabeled judge cases into evals/fixtures/judge_cases_drawn.json from clean source runs at one commit (no LLM), then commit it by hand
uv run python -m evals.draw_judge_cases --honeypot-export PATH --honeypot-export PATH --cve-export PATH --complement  # Once every drawn case is labeled and FAIL cases are 40 % or more of the pass or fail ones: one more case per PASS cell, same exports

docker compose -f evals/docker/compose.yml build      # Build the pinned vulnerable-server images (one-time, prerequisite for the CVE benchmark)
uv run python -m evals.run_cve_benchmark --calibrate  # CVE benchmark: confirm each fixture is live and its benign call is clean (Docker, no LLM)
uv run python -m evals.run_cve_benchmark              # CVE acceptance gate (Docker + an LLM key): compares each target to evals/baselines/cve/, exit 0 green, 1 red, 3 not comparable, 4 crash (the preflight included, --calibrate too)
uv run python -m evals.run_cve_benchmark --record-baseline  # Record one file per target in evals/baselines/cve/ from a clean tree: run it twice at one commit on the local images (exploratory, then confirmed), then commit evals/baselines/cve/ by hand
uv run python -m evals.run_cve_benchmark --ungated          # CVE graded run with no comparison to the baseline, exit 0
uv run python -m evals.run_cve_benchmark --concurrency N    # Audits (or calibrations) in flight at once, default 6, 1 for the old sequence (combines with any graded mode and --calibrate)
uv run python -m evals.capture_probe_corpus           # Capture evals/fixtures/probe_corpus.json once, reference settings only (Docker, the CVE images, GOOGLE_API_KEY), then commit it by hand
uv run python -m evals.run_probe                      # Model probe: replay the corpus against the reference and every candidate, report statistics and defects (needs GOOGLE_API_KEY and OPENAI_API_KEY, see evals/probe_method.md)
uv run python -m evals.run_probe --candidates "gpt-6-luna none" "gpt-6-luna low" --schema TestCaseBatch  # Subset run: debugging only, no statistics, needs the keys of the named candidates only
```

## Coding standards

- Code in the style of **Kent Beck**, **Martin Fowler**, **Robert C. Martin**, **Eric Evans** — the XP, software craftsmanship, and DDD tradition.
- Prompts are **domain logic**, not infra. They live in the `graph/*prompts.py` modules (`graph/prompts.py`, `graph/chain_prompts.py`) as pure functions `(data) -> str`. Never put prompt construction in adapters.
- Graph nodes are built via **factory functions** (`make_node(dependency)`) for dependency injection. The injected dependency is normally a Port, a `Protocol` class in `domain/`. The one exception is the server under audit: the nodes that reach it take the concrete `AuditedServer` domain service, which owns the destructive-payload guard, so no object able to call `call_tool` lives inside the hexagon (ADR 013). Tests inject a `FakeMCPClient` underneath it.
- **Hexagonal boundary**: `domain/` and `graph/` are inside the hexagon. `adapters/` is outside. `domain/` and `graph/` never import from `adapters/`. Top-level modules (`cli.py`, `console.py`, `config.py`, ...) are the composition root and presentation layer, outside the hexagon — they may import from anywhere.
- **Prefer pure functions.** Same inputs → same output, no side effects. Maximise the amount of code that is purely transformational (prompts, rendering, models, routing). When a function truly needs a side effect, inject the dependency via a Port — never hide I/O, env vars, or clock access behind direct calls.
- All code, comments, docstrings, and identifiers in **English**.
- **Newspaper rule** (Clean Code): read a module top-to-bottom like an article. Public/high-level functions first, private/low-level helpers right below their callers.
- Functions should rarely exceed **20 lines**, files should rarely exceed **300 lines**. When they do, split.
- **Functions should take few arguments** (aim for ≤ 3). When parameters accumulate, a concept is missing — extract a Value Object, dataclass, or Protocol that names the grouping. The fix is not a generic `params` dict but a domain-relevant name.
- **Naming over comments.** Code should read without them. Reserve comments for non-obvious logic, hacks, or workarounds. Same rule applies to docstrings — don't restate the class or function name in prose. Use **domain-relevant, readable names** — no abbreviations except in very short scopes (e.g. comprehensions).

## Testing standards

- Test **behavior**, not implementation. Tests assert on observable outcomes, never on internal structure or call sequences.
- Unit tests are exhaustive on `domain/` and `graph/` (the hexagon interior), using fakes. But **maintainability beats coverage** — delete a fragile test rather than keep it. A test that breaks on every refactor without catching bugs is a liability.
- Fakes (`FakeLLM`, `FakeMCPClient`), not mocks. Fakes are real implementations with deterministic, configurable behavior.
- Three test levels (see `docs/adr/003-testing-philosophy.md`): unit (fakes, in-process), integration (real MCP server, no LLM), evals (`evals/`, real LLM against honeypot ground truth). **Never test LLM quality with fakes** — that's what evals are for.
- **Given/When/Then pattern**: test files stay ultra-readable by extracting setup into `given.py` and assertions into `then.py`, one pair per test file (e.g. `test_audit.py` + `test_audit_given.py` + `test_audit_then.py`). The test file reads like a spec. Only extract into given/then when the function **actually abstracts something** — if it's just a one-liner wrapper, inline it instead.

```python
# test_audit.py
import tests.unit.test_audit_given as given
import tests.unit.test_audit_then as then

async def test_detects_missing_input_validation():
    tool = given.a_tool_with_weak_validation()
    fake_llm = given.a_fake_llm_returning(category="input_validation")
    state = given.an_audit_state(tools=[tool])
    graph = build_graph(fake_llm, AuditedServer(FakeMCPClient([tool])))  # trivial — inline

    results = await graph.ainvoke(state)

    then.verdicts_failure_for(results, tool="get_user", category="input_validation")
```

### When an eval number comes back red

Governed by ADR 016, amended by ADR 020 for the honeypot suite (`docs/adr/016-eval-gate-governance.md`, `docs/adr/020-honeypot-baseline-changes.md`). The short form:

- **Fix the system, not the instrument.** A prompt, a guard table or a default may be changed after reading eval output, and it may ship. Its written justification has to hold once every mention of the measurement is deleted. A justification that needs "and the oracle credits that" is fitting the product to the benchmark. The number that change then produces is exploratory: it is recorded and confirms nothing.
- **An instrument change and a system change do not license each other.** An instrument change does not borrow its justification from a system change shipped with it. A system change written to make the revision look earned licenses nothing.
- **Never re-record a baseline while the gate is red.** That compares the candidate to itself, and it is the one move forbidden outright.
- **A reset is not a re-recording.** A change to a fixture, the scoring code, the model, runs or budget deletes the baseline in its own commit and records it again twice. Under a red gate it names the cells that fired it, and each must come out stable and correct in the confirmed baseline, or the change is reverted. Runs and budget change only from a green gate. A label revision re-scores the stored runs and needs no reset. One such change per commit. See `docs/adr/020-honeypot-baseline-changes.md`.
- **A deliberate regression is declared, never waved through.** A change to the system under test that costs gated cells names them in `evals/declared_flips.json`, in the commit that makes the change and before the evals run on it (see `CONTRIBUTING.md`). An entry is active only at the commit whose parent is its `base`. Never declare a cell after seeing it flip on a run of an undeclared change: revert instead.
- **Every instrument change has a labeling log entry**, labels, fixtures or scoring code, whatever the state of the gate.
- **The ground truth is revised by rubric, never cell by cell.** Write the rubric clause down before computing its effect on the metrics, apply it to every affected cell including the ones it does not help, and record it in `docs/labeling-log.md`, created with the first revision.
- **Honeypots are fixtures.** Only deliberately planted flaws count. A branch whose intent cannot be recovered is annotated as unspecified and its cell leaves the ground truth, instead of carrying a guessed label.
- **A delta smaller than the instrument's resolution is inconclusive**, a third verdict beside pass and fail, and it is never reported as a win.
- **Write down where the change lands, and why.** The four questions of ADR 016 are answered in the labeling log entry for a ground truth revision, and in the commit message for a change to the system under test.

## Workflow

- **Test-first**: write tests before implementation, run them to confirm they fail, then write the code to make them pass — a test that was never red might pass for the wrong reason.
- **Run unit tests frequently** — after each meaningful change, not just at the end.
- **Refactor continuously.** After green tests, look for simplification opportunities before moving on.
- **Update the living docs as part of the change, not after.** When an implementation adds or changes a command, prerequisite, env var, CLI flag, or user-facing behavior, update the living docs in the same work: `README.md`, this `CLAUDE.md` (the Commands list especially), `CONTRIBUTING.md`, and the `[Unreleased]` section of `CHANGELOG.md` for user-facing changes. These are the only Markdown that tracks the current state. Do **not** touch `plans/` or `docs/adr/` for this — they are immutable historical artifacts (a decision change is a new ADR, not an edit). A feature isn't done until the living docs match it.

## Landmines

- Integration tests require the honeypot server (`tests/honeypot_server.py`) to be spawned as a subprocess — the test fixtures handle this, but the server must be a valid MCP stdio server (reads stdin, writes stdout).
- The honeypot servers (`tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`) contain **deliberately planted vulnerabilities**. They are the ground truth of `evals/ground_truth.py`. Fixing an apparent bug there degrades the eval suite silently, no unit test will fail.
- The MCP SDK uses **two nested async context managers** (`stdio_client` + `ClientSession`). The adapter wraps both into a single `async with`. Don't try to manage them separately.
- `with_structured_output` returns a single `BaseModel`, not a list — that's why `TestCaseBatch` exists as a wrapper.
- The confined container's home is a tmpfs created with the invoking `uid` and `gid` (`--tmpfs /home/audit:exec,uid=…,gid=…`). Drop those two options and the tmpfs is root-owned, so `npx` fails with `EACCES` on its npm cache under `--user`. Same for `--memory-swap`: without it Docker grants as much swap again, the memory bound never bites and `oom_killed` reads `false` in the very case it is recorded for.
- The throttle count reads the `httpx`/`httpx2` log format, and Google's model is given an `httpx` transport for it. Do not drop `client_args={"transport": ...}` from `_make_google_model`: without it `google-genai` switches to `aiohttp` and Google's 429s silently stop counting.
- The server's stderr goes through a pipe (`adapters/stderr_capture.py`): the MCP SDK hands the `errlog` file descriptor to the child process, so a Python wrapper on the file never sees a byte. What keeps a raw server line off the terminal while a value is relayed with `--env` is `adapters/log_redaction.py`: the `mcp.client.stdio` logger raised to `CRITICAL`, and a redacting filter on the root logger and on the SDK's `client` logger (a filter sees only records created on its own logger). All three apply only while a value is relayed, so an audit without `--env` keeps the SDK's diagnostics. An SDK upgrade can add a log call that quotes server data: `tests/integration/test_relayed_environment.py` is the guard, and a new call site needs a case there.
- The **unconfined** thread id must keep its pre-0.3.0 hash: `compute_thread_id` hashes the command alone under `unconfined` and appends the regime only under the two container regimes. A unit test pins the literal hash. Hashing the regime for all three would make every audit interrupted before 0.3.0 unresumable, silently.

## Pointers

- `docs/adr/` — Architecture Decision Records. Explain *why*, not *how*. **Immutable once accepted** — to change a decision, write a new ADR that supersedes the previous one. What goes in one, and what does not:
  - **What an ADR records**: a decision, the reason that decided it, the alternatives it beat, and the consequences the reader has to live with, such as what a published number does not mean and what is not built yet. A figure that a run re-measures goes to the README beside its provenance, where the repo publishes it at all. A dated figure that justified the decision may stay, and so may a derivation from the frozen design.
  - **Where the rest lives**: how a number is computed, in the docstring of the module that computes it. What the report says, in the report. What is checked by hand, in a test or in a living method note beside the eval it checks, which goes next to that code and not here. The ADR points at them and does not restate them. A path or a symbol named in an ADR is as of its date, so a pointer that has to survive a refactoring names the symbol rather than the file.
  - **One reason per decision**, the one that would flip it if false. A limit the reader has to live with is stated as a fact in one sentence, under Consequences. A limit that is itself the reason for a decision stays with the reason, and is not stated twice. A sentence that carries neither the decision, its reason, a beaten alternative nor a consequence is cut.
  - **Length**: about 800 words, the size of the ADRs already here. Past 1,500 words, the mechanics have leaked in.
- `plans/` — **Spec-driven development**: before implementing a non-trivial feature, write a plan as a markdown file in `plans/` for review. The user reviews and approves the plan before any code is written. Naming convention: `YYYY-MM-DD_short_description.md` (e.g. `2026-03-15_llm_adapter.md`). **Immutable once implemented** — plans are not living documentation. They serve as historical context for what was done. Never update a past plan, write a new one for new changes.