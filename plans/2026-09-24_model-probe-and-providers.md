# Model selection groundwork: providers, reasoning settings, batch completeness and the admission probe

## Context

ADR 019 (Draft, `docs/adr/019-default-model-selection.md`) supersedes ADR 005 and sets how the default model is chosen: two challengers, `gpt-6-luna` and GLM-5.3-Flash on Fireworks, measured against Gemini 3.1 Flash-Lite at thinking level `minimal`. A challenger is admitted if it clears bars written before it runs, and the definitions and values of those bars are committed with a probe that measures them, before its first run. This plan builds what the procedure needs and nothing past it. It does not change the default model and does not move ADR 019 out of Draft.

The challenger settings are three, not the four ADR 019 lists: Luna at effort `none`, Luna at effort `low`, and GLM with the schema enforced by Fireworks (reasoning then off). The fourth, GLM with reasoning at `low` and unconstrained JSON, is dropped: in unconstrained mode Fireworks sends no schema, no prompt states the output keys, and giving them to the model would mean adding the schema to the domain prompts for one candidate. That candidate would fail on what the harness leaves out, not on what the model does. ADR 019's challenger paragraph was edited to match on 2026-09-24, while it is still Draft, in its own commit before this plan's implementation.

Five things are missing today:

- **The providers.** `adapters/llm.py` knows `google` and `anthropic` only. ADR 019 adds `openai` and `fireworks` whatever the outcome.
- **The reasoning setting.** Nothing in `config.py` or `adapters/llm.py` sets Gemini's thinking level, so the reference runs at whatever the API defaults to. Luna's effort has no setting at all.
- **Token accounting for cost.** `TokenUsage` holds input and output tokens only. The cost bar needs cached input tokens (priced five to ten times lower) and reasoning tokens (to check that a setting reached the API).
- **A completeness check on the generator's batch.** The generator node takes `batch.cases` as it comes. A batch shorter than the budget, or one that leaves out a category, goes unnoticed: the audit covers less and says nothing. On the last recorded run (`output/judged_cases.jsonl`, 3 runs x 8 tools, budget 10) every batch was complete, so this is not a known defect of the reference. It is a silent failure mode that a model change can open, and a security audit must not lose coverage without saying so.
- **The probe.** Nothing measures parse failures per schema, refusals, latency per call and cost on a frozen corpus, identically for every candidate.

The baseline conditions (`evals/baseline.py`) record the provider and the model names, not the reasoning setting, so two settings of one model would be indistinguishable to the gate.

## Approach

Four kinds of change, committed separately because ADR 016 keeps system and instrument changes apart:

0. **System under test: the LangChain upgrade, alone and first.** `langchain-openai` and `langchain-fireworks` need `langchain-core>=1.6.4`, against 1.2.19 locked today, and `langgraph`, `langchain-google-genai` and `langchain-anthropic` depend on it. The upgrade therefore changes the reference itself, so it lands in its own commit before any provider work, with nothing else in it, and is verified on its own (see "The dependency upgrade" below).
1. **System under test.** The two providers, the reasoning setting resolved per provider in `config.py`, the token accounting, and the batch completeness check with one retry and a reported gap. Setting Gemini's thinking level to `minimal` explicitly is a change to the system under test whose justification holds without any measurement: the reference of ADR 019 is defined at that level, and a default left to the API can move without a code change.
2. **Instrument: baseline conditions.** `BaselineConditions` records the resolved reasoning setting, and the CI-conditions check covers it.
3. **Instrument: the probe.** A capture command records every structured call of a reference run on the three honeypots plus generator prompts built from the tool definitions of the CVE fixtures, and freezes them in a committed corpus. A probe command replays the corpus against each candidate, round-robin, and prints an admission verdict per candidate. A method note beside it carries the definitions and the bar values, and is committed before the first probe run.

Decisions taken in discussion, recorded here so the implementation does not reopen them:

- **The setting lives in `Settings`.** One field, `reasoning`, read from `MCP_AUDITOR_REASONING` like the existing fields, with a per-provider default resolved in `config.py` when unset (the `_default_model` pattern). The environment variable serves the judge eval and the e2e eval of a challenger. The probe builds its `Settings` in code.
- **The structured output method is fixed per provider, in the adapter**, not a setting: each provider has one method this plan uses, so a setting would have no second value to take. `google` keeps `json_schema` and `anthropic` keeps `function_calling` (their LangChain defaults today). `fireworks` uses `json_schema`, enforced at decoding. `openai` uses `json_schema` **non-strict**: OpenAI's strict mode only accepts closed objects, and `AuditPayload.arguments` is an open `dict[str, Any]` by design (its keys depend on the audited tool), so a strict schema is rejected by the API before the model runs. Non-strict sends the schema without enforcing it, and a malformed output counts as a parse failure in the probe.
- **One model for both roles.** The generator and the judge share the provider and the reasoning setting. `MCP_AUDITOR_JUDGE_MODEL` stays a user override of the model name only.
- **The provider-default reasoning applies to the provider-default model only.** An explicit `MCP_AUDITOR_REASONING` applies to whatever model runs. With no explicit value, a model that is not the provider's default (an `MCP_AUDITOR_MODEL` or `MCP_AUDITOR_JUDGE_MODEL` override) gets no reasoning parameter, so the API decides. This keeps `.env.example`'s documented judge override (`gemini-3.1-pro-preview`, which does not accept `minimal`) working, and an OpenAI model that does not reason is not sent an effort.
- **Refusals: zero, counted mechanically.** A generator call counts as a refusal when its output does not parse within the adapter's attempts, when the batch holds fewer cases than the budget, or when it covers fewer distinct categories than `min(budget, number of categories)`. The rule is blind by construction and needs no reading of payloads. A watered-down payload that keeps its category is not detected, and the method note says so.
- **Bars.** Zero parse failures after the adapter's attempts, on every schema. Zero refusals. Median latency per call, per role (generation calls and judge calls), at most 3 times the reference's median measured in the same probe run. Cost of the whole corpus at most equal to the reference's. The provider does not train on API data at the tier used (a documented fact per provider, recorded in the method note, not computed). The reference is exempt from every bar (ADR 019): a bar it fails is recorded and triggers nothing.
- **Inputs of the generator beyond the honeypots.** Tool definitions captured once from the CVE fixture images through Docker and committed. Reading a tool definition is not reading a trace (ADR 015). No target is reserved as holdout yet, so none is excluded.
- **Judge prompts.** 60 judge prompts drawn with a fixed seed from the judge calls of the capture run, uniformly, never by verdict. The corpus stores prompts only: no label, no verdict, no justification.
- **Incomplete batch in the product.** The generator node retries the generation once. If the batch is still incomplete, the audit continues with it and the tool report records the gap, shown in the console, the Markdown and the JSON report.

## Files to modify

### The dependency upgrade (first commit, alone)

`pyproject.toml` and `uv.lock`: raise `langchain-core` to the version `langchain-openai` 1.6.6 needs (`>=1.6.4`), and with it every dependency the resolver requires to move (`langgraph`, `langchain-google-genai`, `langchain-anthropic`, and any other that pins an older core). The implementer first runs `uv lock --upgrade-package langchain-core` together with a dry resolution that includes `langchain-openai` and `langchain-fireworks`, reads the lock diff, and lists every package that moved and why. The two new packages are not added in this commit, only what they will need, so the commit isolates the effect of the upgrade on the reference.

What is re-checked in the upgraded packages, because the plan relies on it:

- `langchain-google-genai`: `output_tokens` still includes `thoughts_token_count`, `input_token_details.cache_read` is still filled, `thinking_level` still accepts `minimal`, and `with_structured_output` still defaults to `json_schema`. If the resolver cannot keep 4.x or changes any of these, the implementer stops and reports.
- `langchain-anthropic`: `with_structured_output` still defaults to `function_calling`.
- `langgraph`: the checkpoint tests and the `--resume` path still pass (`tests/unit/test_checkpointing.py`), and the deserialization warning on unregistered types has not become an error.

Verification of this commit, before any other work starts:

- The whole suite: `uv run pytest` (unit and integration), `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.
- The judge isolation eval (`uv run python -m evals.run_judge_eval`) and one e2e run (`uv run python -m evals.run_evals --ungated`, default 3 runs, budget 10), both on the reference and both needing `GOOGLE_API_KEY`. They are run by the operator, since they cost LLM calls. Their numbers are exploratory under ADR 016: the check is that nothing crashes, every run completes, every structured call parses, and the floors hold. The metrics are recorded beside the last exploratory measurement of 2026-09-24 (R 0.79, P 0.75, C 0.93, 36 cells), and a delta smaller than the instrument's resolution is inconclusive, not a regression.

The commit message answers the four questions of ADR 016: it lands in the system under test, and its justification holds with every measurement deleted (the new providers require it). It lists the packages that moved.

### System under test

#### `src/mcp_auditor/config.py`

Add one field and its resolution, following `_default_model`:

```python
class Settings(BaseSettings):
    ...
    reasoning: str = ""

    def resolve_reasoning(self, model: str) -> str | None: ...
```

Per-provider table, module-level, beside `_default_model`:

| provider | default model | default reasoning (for the default model) | accepted reasoning |
|---|---|---|---|
| `google` | `gemini-3.1-flash-lite` (unchanged) | `minimal` | `minimal`, `low`, `medium`, `high` |
| `anthropic` | `claude-haiku-4-5-20251001` (unchanged) | none | none: any non-empty value raises |
| `openai` | `gpt-6-luna` | `low` | `none`, `low`, `medium`, `high`, `xhigh`, `max` |
| `fireworks` | `accounts/fireworks/models/glm-5p3-flash` | none | `low`, `medium`, `high` |

`resolve_reasoning(model)` returns the explicit value if set (validated against the provider's accepted values, `ValueError` naming them otherwise), else the provider default when `model` is the provider's default model, else `None` (no parameter sent). The adapter calls it with the main model and with the judge model, so a judge override gets `None` unless `MCP_AUDITOR_REASONING` is set. `.env.example`'s judge example keeps working. The unknown-provider error message lists the four providers.

`fireworks` has no default reasoning: the adapter enforces the schema on Fireworks, and Fireworks documents that an enforced schema disables reasoning, so a default would be a parameter that does nothing. An explicit `MCP_AUDITOR_REASONING` is still passed through. The accepted values `low`, `medium`, `high` are the ones Fireworks documents as examples, not a list it states as complete for `glm-5p3-flash`, and a value it rejects surfaces as an API error.

`openai` and `fireworks` model ids are to be confirmed by the due diligence pass (pinned snapshot preferred over an alias where the provider offers one). The Gemini default stays the alias `gemini-3.1-flash-lite` unless a dated identifier exists for the GA model, in which case the due diligence pass records it and this plan's implementer uses it. Verified on 2026-09-24: OpenAI lists `gpt-6-luna` with no dated snapshot, Fireworks lists `accounts/fireworks/models/glm-5p3-flash`, and Google lists `gemini-3.1-flash-lite` as stable with no dated identifier, so the three ids in the table stand.

#### `src/mcp_auditor/adapters/llm.py`

`_create_for_provider(provider, model)` becomes `_create_for_provider(settings, model)` (the model varies between main and judge, the rest comes from settings, with `reasoning = settings.resolve_reasoning(model)`). It builds the chat model through a public `make_chat_model(settings, model) -> BaseChatModel`, which dispatches to the per-provider `_make_<provider>_model` factories, so the tests check the construction on a public function's output rather than on private helpers (the unit tests import no private symbol today). One factory per provider, each short, passing the reasoning parameter only when it is not `None`:

- `google`: `ChatGoogleGenerativeAI(model=..., thinking_level=reasoning, max_retries=3)`.
- `anthropic`: unchanged construction.
- `openai`: `ChatOpenAI(model=..., reasoning_effort=reasoning, use_responses_api=True, max_retries=3)`. `use_responses_api=True` routes Luna to the Responses API, which `langchain-openai` 1.6.6 does not do on its own for `gpt-6-luna` (absent from `_RESPONSES_API_ONLY_PREFIXES`; the closed issue langchain-ai/langchain#40346 reports the same gap for `gpt-6-astra` with function tools), and OpenAI's page for Luna says Chat Completions supports function calling only at effort `none`.
- `fireworks`: `ChatFireworks(model=..., reasoning_effort=reasoning, max_retries=3)`. `reasoning_effort` is a constructor field of `ChatFireworks` in `langchain-fireworks` 1.6.2 and on master (forwarded as the request's `reasoning_effort`), so no `model_kwargs` is needed.

Structured output per provider, fixed in the adapter (no setting):

- `google`, `anthropic`, `fireworks`: `with_structured_output(output_schema, method=..., include_raw=True)` with `json_schema`, `function_calling` and `json_schema` respectively, the Pydantic class passed as today.
- `openai`: non-strict JSON schema. `langchain-openai` makes the schema strict whenever it is given a Pydantic class (`strict=False` is ignored then), so the adapter passes `output_schema.model_json_schema()` as a dict with `method="json_schema", strict=False`, receives a dict, and validates it with `output_schema.model_validate`. A `ValidationError` counts as an unparsed attempt, like a `None` parsed result today, so the adapter's retry and its final `ValueError` behave as for the other providers. Due diligence confirms against the pinned `langchain-openai` that a dict schema with `strict=False` is sent non-strict and accepts the open `arguments` object, and whether the `$defs` references Pydantic emits need inlining. Partly verified: `langchain-core`'s `convert_to_openai_function` accepts a JSON-schema dict with a `title` and no `description` (`AuditPayload` has no docstring, so its schema carries none), and with `strict=False` it sets `strict: false` without adding `additionalProperties: false`. OpenAI's structured outputs accept `$defs` with `$ref`. Not settled from source: how `langchain-openai` 1.6.6 turns that dict into the Responses API `text.format`, and whether it keeps or inlines `$defs`. The implementer checks both in the installed package before relying on them.

`LLM.__init__` takes the provider's structured-output choice as one small value (method, and whether the schema goes as a dict and is validated in the adapter), built by the provider factory. The existing tests in `tests/unit/test_llm_adapter.py` construct `LLM(model, max_parse_attempts=3)` and are updated for the new parameter. `_to_token_usage` reads `input_token_details.cache_read` and `output_token_details.reasoning` when present (both are optional in LangChain's `UsageMetadata`), defaulting to 0. The `_UsageMetadata` TypedDict gains the two optional nested keys.

`langchain-fireworks` (`_usage_to_metadata`) fills `input_token_details.cache_read` but not `output_token_details.reasoning`, so Fireworks reasoning tokens read 0 in `TokenUsage`. The only Fireworks candidate runs with the schema enforced, which disables reasoning, so the probe does not check reasoning tokens for it (`reasoning_expected=None`) and the method note says so. Whether Fireworks' `completion_tokens` includes reasoning tokens matters only for a later GLM reasoning candidate (see "Out of scope, recorded for the choice").

A missing API key must fail when the chat model is built, not at the first call, so the CLI prints "could not initialize LLM" (`cli._hired_analysts` catches `KeyError` and `ValueError`) and the probe stops before spending a call. `ChatFireworks` already raises `ValueError` from its validator when `FIREWORKS_API_KEY` is missing. `ChatOpenAI` 1.6.6 may defer the error to the first call (the source could not be settled), so the OpenAI factory checks that `OPENAI_API_KEY` is set and non-empty before building the model, and raises `ValueError` naming the variable otherwise. The check is explicit rather than relying on the library, whose behavior on this point is not documented.

New dependencies in `pyproject.toml`: `langchain-openai` and `langchain-fireworks`, at versions verified by due diligence to support the calls above. Verified on 2026-09-24: the latest releases are `langchain-openai` 1.6.6 and `langchain-fireworks` 1.6.2 (the one checked for `reasoning_effort`). They require `langchain-core>=1.6.4` and `>=1.6.0`, against 1.2.19 in `uv.lock`, so the lock moves `langchain-core` as well. `uv.lock` updated and committed.

#### `src/mcp_auditor/domain/models.py`

```python
class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0   # subset of input_tokens
    reasoning_tokens: int = 0      # subset of output_tokens

    def add(self, other: "TokenUsage") -> "TokenUsage": ...  # sums all four


class CoverageGap(BaseModel):
    requested_cases: int
    received_cases: int
    missing_categories: list[AuditCategory]


class ToolReport(BaseModel):
    ...
    coverage_gap: CoverageGap | None = None
```

The comments on the two new `TokenUsage` fields state the non-obvious fact, that they are subsets and not additions.

#### `src/mcp_auditor/domain/coverage.py` (new)

`models.py` is at 286 lines, and the check would take it past 300, so the function gets its own domain module beside `payload_safety.py`. `CoverageGap` stays in `models.py` because `ToolReport` refers to it.

```python
def find_coverage_gap(
    batch: TestCaseBatch, budget: int, categories: list[AuditCategory]
) -> CoverageGap | None: ...
```

`find_coverage_gap` is pure. It returns `None` when the batch holds at least `budget` cases and at least `min(budget, len(categories))` distinct categories. Otherwise it returns the gap. `missing_categories` lists the requested categories absent from the batch only when the batch covers fewer than `min(budget, len(categories))` distinct ones, and it is empty otherwise (with a budget of 3, a batch covering three categories misses none, even though two of the five are absent). More cases than the budget is not a gap.

#### `src/mcp_auditor/graph/nodes.py` and `src/mcp_auditor/graph/state.py`

`make_generate_test_cases`: after the first call, `find_coverage_gap`. On a gap, one more call with the same prompt. The node keeps the retried batch, and its gap (possibly `None`), and returns both usages. The node returns `coverage_gap` in its update.

`coverage_gap: CoverageGap | None` is added to `AuditToolState` and to `GraphState` so it reaches `build_tool_report` through both the audit subgraph and the dry-run subgraph. `prepare_tool` resets it to `None` for each tool. `build_tool_report` copies it into `ToolReport`. Every read uses `state.get("coverage_gap")`, so a checkpoint written before this change resumes.

The chain planner's `ChainPlanBatch` is out of this check: a chain budget has no category distribution to verify.

#### `src/mcp_auditor/domain/rendering.py` and `src/mcp_auditor/console.py`

- Markdown: `_render_tool_section` adds one line right under the tool heading when the report carries a gap, naming requested and received cases and the missing categories.
- JSON: nothing to write, `coverage_gap` serializes with the model.
- Console: the summary prints one warning line per tool with a gap, through `print_warning`, after the summary panel in rich mode and after the one-line summary in CI mode (`print_summary` returns early in CI mode today, so the warnings must be printed on both paths).
- Dry run (`src/mcp_auditor/audit.py`, `_show_payloads`): the dry-run graph carries the gap to its tool reports, but the dry run writes no report and prints no summary. It prints the same warning line through `print_warning` for each tool report with a gap, after that tool's payload table. Without this, the gap wired through the dry-run subgraph would be shown nowhere.
- Token usage lines (`rendering.py` and `console.py`) keep their current format. The two new fields are in the JSON through the model.

### Instrument: baseline conditions

#### `evals/baseline.py` and `evals/eval_session.py`

`BaselineConditions` gains `reasoning: str | None` and `judge_reasoning: str | None`, filled by `_candidate_conditions` from `settings.resolve_reasoning(settings.resolve_model())` and `settings.resolve_reasoning(settings.resolve_judge_model())` (they differ when the judge model is overridden). `ci_condition_mismatches` adds both to the fields compared against the defaults, so `--record-baseline` refuses a run with an `MCP_AUDITOR_REASONING` override. No baseline is recorded yet, so no file needs migrating. The provider already names the host (`fireworks` is a host) and the structured output method is fixed per provider, so neither needs a field.

### Instrument: the probe

The probe code stays in `evals/`, outside the hexagon. It calls the production adapters through `create_llm` and `create_judge_llm`, so what it measures is what ships.

#### `evals/honeypots.py`

`audit_honeypot` takes the two LLMs instead of `Settings`, so a caller can wrap them:

```python
@dataclass(frozen=True)
class AuditModels:
    llm: LLMPort
    judge_llm: LLMPort

def models_for(settings: Settings) -> AuditModels: ...

async def audit_honeypot(models: AuditModels, honeypot: HoneypotConfig, budget: int) -> AuditReport: ...
```

The two callers in `evals/run_evals.py` pass `models_for(session.settings)`.

#### `evals/probe_corpus.py` (new)

The corpus model, the recording wrapper and the judge sampling.

```python
class ProbeCall(BaseModel):
    call_id: str          # stable, e.g. "honeypot/generate/003"
    schema_name: str      # TestCaseBatch, Judgment, AttackContext, ChainPlanBatch, StepObservation, AuditPayload
    role: Literal["main", "judge"]
    source: Literal["honeypot", "cve"]
    prompt: str

class ReferenceConditions(BaseModel):   # the settings of the capture run
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None

class ProbeCorpus(BaseModel):
    captured_at: str
    commit: str
    reference: ReferenceConditions
    budget: int
    judge_sample_seed: int
    judge_calls_captured: int          # before sampling, to weight judge costs
    calls: list[ProbeCall]

class RecordingLLM:  # implements LLMPort
    def __init__(self, inner: LLMPort, role: Literal["main", "judge"], sink: list[ProbeCall]) -> None: ...
    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> tuple[T, TokenUsage]: ...

def sample_judge_calls(calls: list[ProbeCall], size: int, seed: int) -> list[ProbeCall]: ...
def schema_for(schema_name: str) -> type[BaseModel]: ...
def load_corpus(path: Path) -> ProbeCorpus: ...
def write_corpus(path: Path, corpus: ProbeCorpus) -> None: ...
```

`RecordingLLM` appends a `ProbeCall` and delegates. It only wraps the honeypot runs, so its calls carry source `honeypot`, and its `call_id` is `honeypot/{schema_name}/{index:03d}` with `index = len(sink)` at append time. The main and judge wrappers share one sink, so the ids are unique across both roles and all three honeypots, and they survive the judge sampling unchanged. The CVE calls are built directly by the capture command with ids `cve/TestCaseBatch/{index:03d}`. A generator retry during the capture (incomplete batch) records a second call with the same prompt: it is a call the reference made, and it stays in the corpus. `sample_judge_calls` keeps every non-judge call and draws `size` judge calls with `random.Random(seed).sample`, in capture order, never looking at a response. `schema_for` maps the six schema names to their domain classes and raises on an unknown name.

#### `evals/capture_probe_corpus.py` (new, `uv run python -m evals.capture_probe_corpus`)

1. Refuses to start when the settings are not the reference of ADR 019 (provider `google`, the default model for both `resolve_model()` and `resolve_judge_model()`, reasoning `minimal` for both), naming the mismatch. The judge model is part of the check because `.env.example` suggests a judge override.
2. Runs `audit_honeypot` once per honeypot of `HONEYPOTS`, at budget 10, with both LLMs wrapped in `RecordingLLM`, source `honeypot`. The chain honeypot runs its chains as `HoneypotConfig` sets them, so `ChainPlanBatch`, `StepObservation`, the chain `AuditPayload` and the chain `Judgment` are captured.
3. For each target of `CVE_TARGETS` (`evals/cve_targets.py`), enters its `environment()`, connects `StdioMCPClient.connect(ServerLaunch.declared_container(launch.command, launch.args, docker_client_env(os.environ)), errlog=devnull)` the way `run_cve_benchmark._silent_client` does (`StdioMCPClient` takes a `ServerLaunch`, not the eval's `Launch`), lists the tools, and leaves. `CVETarget` carries no image field (the image is buried in `Launch.args`), so the capture does not group by image. It visits the six targets (no LLM call, a few seconds each) and deduplicates on the whole `ToolDefinition` (name, description, input schema), which folds the two filesystem targets and the two git targets into one tool list each. The whole tool list is kept (not `tools_filter`). For each tool, `build_attack_generation_prompt(tool=..., budget=10, categories=list(AuditCategory), attack_context=None)` becomes a `ProbeCall` with schema `TestCaseBatch`, role `main`, source `cve`. A missing image stops the command with the `docker compose ... build` line to run.
4. Samples 60 judge calls (seed and number of judge calls captured recorded in the corpus) and writes `evals/fixtures/probe_corpus.json`.

The capture makes LLM calls on the reference only. Its verdicts are not read and not stored.

#### `evals/probe_candidates.py` (new)

The candidates, their list prices and their expected reasoning, as data:

```python
@dataclass(frozen=True)
class Prices:           # dollars per million tokens, as listed on PRICES_DATE
    input: float
    cached_input: float
    output: float

@dataclass(frozen=True)
class Candidate:
    name: str
    settings: Settings
    prices: Prices
    reasoning_expected: bool | None   # True: reasoning tokens > 0 on the corpus; False: 0; None: not checked

REFERENCE: Candidate          # google, gemini-3.1-flash-lite, minimal
CHALLENGERS: list[Candidate]  # luna none, luna low, glm (schema enforced)
PRICES_DATE = "2026-09-24"
```

List prices on 2026-09-24, dollars per million tokens (input, cached input, output), verified on the providers' pages: Gemini 3.1 Flash-Lite `0.25, 0.025, 1.50`, `gpt-6-luna` `0.10, 0.01, 0.50`, GLM-5.3-Flash on Fireworks serverless `0.15, 0.03, 0.50`.

Each candidate's `Settings` passes every field explicitly (`provider`, `model`, `judge_model=""`, `reasoning`). Arguments given at construction take precedence over the environment in `pydantic-settings`, but a field left out is read from `MCP_AUDITOR_*`, so an `MCP_AUDITOR_JUDGE_MODEL` in the operator's `.env` would otherwise silently become every candidate's judge.

Gemini `minimal` cannot switch thinking fully off, so `REFERENCE` carries no expectation on reasoning tokens (`None`). Luna `none` expects 0, Luna `low` expects more than 0. GLM is `None`: `langchain-fireworks` does not report reasoning tokens, and the enforced schema disables reasoning anyway. GLM's `reasoning` field is empty, the provider has no default, so no reasoning parameter is sent.

#### `evals/probe.py` (new, pure)

The analysis, with no I/O:

```python
class CallOutcome(StrEnum):
    PARSED = "parsed"
    PARSE_FAILURE = "parse_failure"   # ValueError from the adapter after its attempts
    ERROR = "error"                   # any other exception (API error, timeout)

class ProbeObservation(BaseModel):
    candidate: str
    call_id: str
    schema_name: str
    role: str
    seconds: float
    usage: TokenUsage
    outcome: CallOutcome
    coverage_gap: CoverageGap | None   # TestCaseBatch calls only

class CandidateStats(BaseModel): ...   # per role median seconds, parse failures per schema, refusals, errors, corpus cost, reasoning tokens, and the candidate's reasoning_expected

class Bars(BaseModel):
    max_latency_ratio: float = 3.0
    max_cost_ratio: float = 1.0

class Admission(BaseModel):
    candidate: str
    admitted: bool
    reasons: list[str]    # each failed bar, stated with its numbers

def summarize(candidate: Candidate, observations: list[ProbeObservation], judge_weight: float) -> CandidateStats: ...
def admit(stats: CandidateStats, reference: CandidateStats, bars: Bars) -> Admission: ...
def call_cost(usage: TokenUsage, prices: Prices) -> float: ...
```

`call_cost` prices uncached input, cached input and output separately: `(input - cached) * prices.input + cached * prices.cached_input + output * prices.output`, divided by a million. The cost the bar compares is the **weighted corpus cost**: the sum of `call_cost` over the candidate's calls, each judge call multiplied by `judge_weight = judge_calls_captured / judge calls in the corpus` (recorded in the corpus). The corpus holds every non-judge call of the capture run but only 60 of its judge calls, so without the weight the corpus under-weights judging compared with an audit, and a candidate whose token profile differs by role (Luna `low` reasoning more on generation than on judging, for example) would see its ratio to the reference skewed. The CVE generator calls stay in with weight 1: they are extra generator inputs, and the method note says the weighted cost approximates the capture run's audits plus those calls. Output tokens include reasoning tokens on the providers used here (checked for `langchain-google-genai` 4.2.1, which adds `thoughts_token_count` into `output_tokens`; the others are checked by due diligence and against each provider's billing console after the first run, see the method note. OpenAI documents reasoning tokens as billed output tokens, counted in `output_tokens` with `reasoning_tokens` as a subset. Fireworks does not document it).

`admit` fails a challenger on: any parse failure (reported per schema), any refusal (a `TestCaseBatch` call that failed to parse or carries a coverage gap), any `ERROR` outcome, a median latency above `max_latency_ratio` times the reference's in either role, a weighted corpus cost above `max_cost_ratio` times the reference's, and reasoning tokens that contradict `reasoning_expected` (the setting did not reach the API, so the candidate was not measured as configured). `summarize` copies `reasoning_expected` from the candidate into its stats, so `admit` takes three arguments. An `ERROR` fails admission because a candidate that did not answer every call was not measured on the whole corpus. The method note tells the operator to rerun the probe in that case rather than read it as a verdict on the model.

`admit` is not applied to the reference. Its stats are printed with the bars it would have failed, marked as recorded only.

#### `evals/run_probe.py` (new, `uv run python -m evals.run_probe [--report PATH]`)

Loads the corpus, builds one main and one judge LLM per candidate before any call (a construction failure, such as a missing key, stops the probe naming the candidate and the error, before any call is spent), and for each call in corpus order runs every candidate on it, sequentially, starting from a different candidate at each call (rotation by call index) so no candidate always runs first after a pause. Each call is timed with `time.perf_counter` around `generate_structured`. `ValueError` from the adapter is a parse failure. Any other exception is an `ERROR` with its message. For `TestCaseBatch` calls, `find_coverage_gap` with the corpus budget and all categories. Writes the observations and the admissions to `output/probe_report.json` (default) and prints one table: per candidate, median latency per role, weighted corpus cost and its ratio to the reference, parse failures, refusals, errors, reasoning tokens, admitted or not with reasons. Exits 0 whether or not any challenger is admitted: the verdict is the report, not the exit code.

The judge-role calls use `create_judge_llm`, the others `create_llm`, so the probe measures the two roles as the product builds them. Temperature is left at each provider's default and recorded in the report per candidate as "provider default".

#### `evals/probe_method.md` (new, living method note)

Written and committed before the first probe run, with the values. Sections: what the probe measures and what it does not (no detection quality, no watered-down payloads), the corpus (capture run, sources, the 60-call judge sample and its seed, CVE tool definitions), the refusal rule, the bars and their values, the cost formula and the price date, the reasoning check per candidate, the data-retention fact per provider with its source (Gemini paid tier, OpenAI API default, Fireworks zero data retention by default), the order of calls, and the limits: provider-side retries on HTTP 429 are inside `max_retries=3` and count in the latency, same-session load affects all candidates alike only as far as the rotation spreads it, and a median over the corpus is the statistic because a p95 over about 60 judge calls rests on its third-largest value. It also states the check to do once after the first run: the cost computed for each provider against that provider's billing console for the run's time window.

#### `evals/fixtures/probe_corpus.json` (new, generated then committed)

Produced by the capture command, committed in its own commit before the method note's commit or with it.

### Living docs

- `README.md`: the configuration table gains `MCP_AUDITOR_REASONING`, `OPENAI_API_KEY`, `FIREWORKS_API_KEY`, and the provider line lists the four providers. The paragraph on defaults names each provider's default model and reasoning setting (none for `anthropic` and `fireworks`, the latter because its enforced schema disables reasoning), and says the default reasoning applies to the default model only. A sentence under the report description says a tool whose generated batch stays incomplete after one retry is flagged in every output format.
- `.env.example`: the four providers, the two new variables, the two new keys.
- `CONTRIBUTING.md`: the sentence on eval API keys (currently "`GOOGLE_API_KEY` (default provider) or `ANTHROPIC_API_KEY`") lists the four providers' keys. The recording conditions sentence names `MCP_AUDITOR_REASONING` among the overrides that refuse a recording, and a short paragraph gives the two probe commands and points at `evals/probe_method.md`.
- `CLAUDE.md`: the Commands list gains the capture and probe commands (capture needs Docker, the CVE images and a Google key, the probe needs the keys of every candidate).
- `CHANGELOG.md` `[Unreleased]`: under Added, the two providers and the two settings. Under Changed, Gemini's thinking level now set explicitly to `minimal` (the API default, now pinned), token usage in JSON reports gains cached and reasoning tokens, and an incomplete generated batch is retried once and flagged.

## Out of scope, recorded for the choice

Two follow-ups depend on which model ADR 019 selects. They are recorded here, and in ADR 019's Consequences when it is rewritten to name the default.

- **If Luna is selected: a strict schema.** This plan sends OpenAI a non-strict schema because `AuditPayload.arguments` is an open object. Adopting Luna calls for the schema to be enforced, which needs `arguments` closed per audited tool (a schema built from the tool's `inputSchema`) or another shape strict mode accepts. It changes the domain schema, so it is its own plan.
- **If GLM is selected: its reasoning setting.** This plan measures GLM with the schema enforced, which disables its reasoning. If GLM wins, a GLM setting with reasoning (at `low`) is measured next, to see whether it does better for little more latency. That needs a way to give the model the output schema without enforcing it (the domain prompts would state the output keys, for every provider), and a reasoning-token signal for Fireworks, which `langchain-fireworks` does not report today.

## What stays unchanged

- The default provider (`google`) and model (`gemini-3.1-flash-lite`). ADR 019 names the default only after the procedure.
- ADR 019 stays Draft. Its challenger paragraph, already edited to drop the GLM reasoning setting (see Context), is not touched again. No other ADR is edited.
- Prompts in `graph/prompts.py` and `graph/chain_prompts.py`. The probe replays prompts, it does not add a schema to any prompt.
- The honeypot servers, the ground truth, the labeling log, the scoring in `evals/metrics.py`, the gate in `evals/gate.py`.
- The judge isolation eval (`evals/run_judge_eval.py`, its fixture and threshold) and `run_evals` beyond the `audit_honeypot` signature. Steps 2 and 3 of ADR 019 run them unchanged, with the new environment variables.
- The CVE benchmark runner and its oracle.
- The unconfined thread id hash (`compute_thread_id`): nothing here touches it.

## Edge cases

- **Budget below the number of categories.** `find_coverage_gap(batch, budget=3, ...)` requires 3 cases and 3 distinct categories, and reports no missing category when three are covered.
- **Budget of 1.** One case, one category: never a category gap.
- **Batch longer than the budget.** Not a gap, all cases are kept (current behavior).
- **Retry also incomplete.** The node keeps the retry and its gap, the audit continues, the report flags the tool.
- **Retry fails to parse.** The adapter raises `ValueError` as it does today on the first call: the audit stops as it would today. The retry does not add a new failure mode beyond what the first call already has.
- **Resume from an older checkpoint.** No `coverage_gap` key in state: `state.get` reads `None`, and `ToolReport.coverage_gap` defaults to `None`.
- **`MCP_AUDITOR_REASONING` set with provider `anthropic`.** `resolve_reasoning` raises `ValueError` at settings resolution, before any LLM call, naming the provider and that it takes no reasoning setting.
- **Model override without `MCP_AUDITOR_REASONING`.** `MCP_AUDITOR_MODEL=gemini-3.1-pro-preview` (or the same as judge model) resolves reasoning to `None` for that model: no thinking level is sent, the API decides.
- **Luna returns JSON that does not match the schema.** Non-strict mode lets it happen. `model_validate` raises, the attempt counts as unparsed, the adapter retries, and after its attempts raises `ValueError`: a parse failure in the probe.
- **Missing API key for a probe candidate.** Depending on the provider, the key is checked when the chat model is built (OpenAI) or at the first call. A construction failure stops the probe before any call, naming the candidate. A failure at the first call is recorded as `ERROR` for every call of that candidate, so it is not admitted, and the report shows the message. The method note says to set every candidate's key before running.
- **Missing API key for `openai` or `fireworks` in the CLI.** `mcp-auditor` prints "could not initialize LLM" and exits 1, like `google` and `anthropic` today, and does not print a traceback.
- **A CVE image not built.** The capture checks that every CVE image exists (`docker image inspect`) before the honeypot runs, which cost LLM calls, and stops with the build command otherwise.
- **Judge calls fewer than 60.** `sample_judge_calls` raises, naming how many were captured.
- **A candidate returns `usage_metadata` without details.** Cached and reasoning tokens read 0. For a candidate expected to reason, 0 reasoning tokens fails the reasoning check, which is the intended signal (the setting cannot be shown to have applied).

## Test scenarios

Unit tests, Given/When/Then with `given`/`then` modules (in `tests/unit/support/`) where they abstract something, fakes not mocks.

**Existing fixtures that the completeness check breaks (update them first).** `FakeLLM` pops its responses in order and raises `TypeError` on a schema mismatch. Today's graph fixtures produce batches that the new check calls incomplete: `tests/unit/support/test_graph_given.py` builds `num_cases` payloads (default 1), all in `AuditCategory.INJECTION`, while `an_initial_state` defaults to `test_budget=5` and `test_graph.py` passes 5 explicitly. `TestGenerateTestCases.test_produces_pending_cases` in `test_nodes.py` sends 3 `INJECTION` cases at budget 3. After the change, each of these triggers the retry, which pops the next response (a `Judgment`, or nothing) as a `TestCaseBatch`. That breaks every test in `test_graph.py`, `test_checkpointing.py` (which uses the same builders) and that node test. The fixtures are changed so that a default batch is complete for its budget: the builders cycle the payload categories over `list(AuditCategory)`, and the budget in the state matches the case count (for example, `an_initial_state` takes its budget from the case count, or the builders default to a complete batch of 5). The behavior these tests check does not change. `test_chain_nodes.py` does not go through the generator and is not affected.

**`tests/unit/test_config.py`**
- Each provider resolves its default model, and its default reasoning for that model, when nothing is set.
- A model that is not the provider default resolves reasoning to `None` when `reasoning` is unset, and to the explicit value when set.
- An explicit accepted value is returned as set.
- A value not accepted for the provider raises, and the message names the accepted values (on `openai` and on `google`).
- `anthropic` with a reasoning value raises.
- `fireworks` resolves no reasoning by default, and passes an explicit value through.
- The unknown-provider message names the four providers.

**`tests/unit/test_llm_adapter.py`**
- Token usage with `input_token_details.cache_read` and `output_token_details.reasoning` fills the two new fields.
- Token usage without details leaves them at 0.
- Usage accumulates the four fields across parse retries (extends the existing retry test).
- In the dict-schema mode (OpenAI), a dict matching the schema is returned as the Pydantic model. A dict that fails validation counts as an unparsed attempt: retried, its usage accumulated, and `ValueError` after the last attempt.
- `make_chat_model(settings, model)` builds, for each provider, the chat model with the model name and the reasoning setting (assert on the returned chat model's public fields: `model`/`model_name`, `thinking_level`, `reasoning_effort`). No network: constructing a LangChain chat model does not call the API. Environment keys are set to dummy values with `monkeypatch`.
- `make_chat_model` for `openai` with `OPENAI_API_KEY` unset (or empty) raises `ValueError` naming the variable.

No test records the `method` passed to `with_structured_output`: that asserts on how the adapter calls its dependency, which `docs/adr/003-testing-philosophy.md` rules out. A wrong method shows at run time (OpenAI rejects a strict schema with an open object, which the probe records as `ERROR`).

**`tests/unit/test_coverage.py`** (new)
- `find_coverage_gap`: complete batch at budget 10 returns `None`. Nine cases returns requested 10, received 9. Ten cases over four categories returns the missing one. Budget 3 with three categories returns `None`. Budget 3 with two categories returns a gap whose `missing_categories` lists the three requested categories absent from the batch. Eleven cases returns `None`.

**`tests/unit/test_models.py`**
- `TokenUsage.add` sums the four fields.

**`tests/unit/test_nodes.py`**
- The generator node with a `FakeLLM` returning a complete batch returns its cases, one usage and no gap.
- Returning an incomplete then a complete batch: the second batch's cases, both usages, no gap.
- Returning two incomplete batches: the second batch's cases, both usages, and its gap.

These assert on the node's returned update, not on how many times the fake was called.
- `build_tool_report` copies the gap into the `ToolReport`, and `prepare_tool` resets it.

**`tests/unit/test_graph.py`**
- A full graph run with a fake generator that stays incomplete for one tool yields an `AuditReport` whose tool report carries the gap, and the other tools none (one scenario, the end-to-end wiring through the subgraph).

**`tests/unit/test_rendering.py`, `tests/unit/test_console_display.py`**
- Markdown shows the gap line under the tool heading when present and nothing when absent.
- The console summary prints a warning line for a tool with a gap, in rich mode and in CI mode.
- The dry-run payload display is followed by the warning line for a tool with a gap (if it goes through `Audit._show_payloads`, the test needs a fake-LLM seam: one `test_graph.py` scenario on `build_dry_run_graph` that asserts the gap on the tool report is enough if the display test proves too costly).
- JSON contains `coverage_gap` with its three fields.

**`tests/unit/test_eval_session.py`, `tests/unit/test_eval_baseline.py`**
- Candidate conditions carry the resolved reasoning of the main and of the judge model.
- `ci_condition_mismatches` reports a reasoning override.
- `condition_mismatches` reports a baseline recorded at another reasoning setting.

**`tests/unit/test_probe_corpus.py`** (new)
- `RecordingLLM` records schema name, role and prompt, and returns the inner result unchanged.
- `sample_judge_calls` keeps every non-judge call, draws the requested number of judge calls, is identical for the same seed, keeps capture order, and raises when fewer judge calls exist than requested.
- `schema_for` maps each of the six names and raises on an unknown one.
- A corpus written then loaded round-trips.

**`tests/unit/test_probe.py`** (new)
- `call_cost` prices cached input at the cached price and the rest at the input price.
- `summarize` multiplies each judge call's cost by `judge_weight` and leaves the other calls at weight 1.
- `summarize` computes per-role medians, parse failures per schema, refusals from coverage gaps and from `TestCaseBatch` parse failures.
- `admit`: a challenger clean on every bar is admitted. One parse failure on `StepObservation` rejects it, with the schema named. One refusal rejects it. One `ERROR` rejects it. A judge median at 3.1 times the reference rejects it, at exactly 3 times admits it. A cost 1.01 times the reference rejects it, equal admits it. Reasoning tokens > 0 when 0 is expected rejects it, and 0 when > 0 is expected rejects it. `None` expectation skips the check.

**Integration (`tests/integration/`)**: none added. The probe and the capture need LLM keys, so they stay out of the test suite, like the evals.

## Verification

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.capture_probe_corpus   # once, reference only, needs GOOGLE_API_KEY and the CVE images
uv run python -m evals.run_probe              # after the method note is committed, needs the keys of every candidate
```

The last two commands are the operator's, run after the implementation is merged locally. The implementation stops at a green test suite and a committed method note with the bar values.

The dependency upgrade commit has its own verification, run before the rest of the work: the whole suite, plus the judge isolation eval and one `run_evals --ungated` run on the reference, by the operator (see "The dependency upgrade").

## Commit messages

The commit that pins Gemini's thinking level says, in its body, that the change lands in the system under test and that its justification holds without a measurement (ADR 019 defines the reference at `minimal`, and an unset level follows the API's default), per the four questions of ADR 016. The two instrument commits (baseline conditions, probe) say they change the instrument and nothing the system does. No commit message refers to steps or phases of this plan.

## Bars written before measurement

Committed in `evals/probe_method.md` and as defaults in `evals/probe.py` before the first probe run:

- Parse failures after the adapter's 3 attempts: 0, on each of the six schemas.
- Refusals (unparsed `TestCaseBatch`, fewer cases than the budget, fewer distinct categories than `min(budget, 5)`): 0.
- Errors (any other exception): 0, rerun on an error rather than read it as a verdict.
- Median latency per call, per role: at most 3 times the reference's in the same run.
- Weighted corpus cost (judge calls weighted by captured over sampled): at most the reference's.
- Reasoning tokens consistent with the setting (Luna `none`: 0, Luna `low`: more than 0, reference and GLM: not checked).
- Provider does not train on API data at the tier used: Gemini paid tier, OpenAI API, Fireworks serverless.

The judge isolation F1 threshold (0.90) and the honeypot floors (0.50) are the existing ones, unchanged, applied in steps 2 and 3 of ADR 019.

## Due diligence record

What the due diligence pass concluded about the external facts this plan cites or defers, on 2026-09-24. Later passes, including the implementation-phase fact check, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes the matching line rather than updating it.

- SETTLED: `gpt-6-luna` (OpenAI model page, no dated snapshot listed)
- SETTLED: `accounts/fireworks/models/glm-5p3-flash` (Fireworks model page, serverless available)
- SETTLED: `gemini-3.1-flash-lite`, stable, no dated identifier (Gemini API models page)
- SETTLED: Luna reasoning efforts `none`, `low`, `medium`, `high`, `xhigh`, `max`, API default `medium` (OpenAI model page)
- SETTLED: Gemini 3.1 Flash-Lite thinking levels `minimal`, `low`, `medium`, `high`, API default `minimal`, and `minimal` does not switch thinking off (Gemini thinking docs)
- SETTLED: `gemini-3.1-pro-preview` accepts `low`, `medium`, `high`, not `minimal` (Gemini thinking docs)
- SETTLED: `ChatGoogleGenerativeAI(thinking_level=...)` takes `minimal|low|medium|high`, adds `thoughts_token_count` into `output_tokens`, sets `output_token_details.reasoning`, defaults `with_structured_output` to `json_schema` (installed `langchain-google-genai` 4.2.1 source)
- SETTLED: `ChatAnthropic.with_structured_output` defaults to `function_calling` (installed `langchain-anthropic` 1.3.5 source)
- SETTLED: `ChatFireworks(reasoning_effort=...)`, forwarded as the request's `reasoning_effort` (`langchain-fireworks` 1.6.2 tag and master source)
- SETTLED: `langchain-fireworks` `_usage_to_metadata` fills `input_token_details.cache_read` only, never `output_token_details.reasoning` (1.6.2 tag source)
- SETTLED: `ChatFireworks` raises `ValueError` at construction when `FIREWORKS_API_KEY` is missing (master source)
- SETTLED: Fireworks `response_format` with `json_schema` disables reasoning output, and `$defs`/`$ref` are supported (Fireworks structured output docs)
- SETTLED: `use_responses_api=True`, since `gpt-6-luna` is not in `_RESPONSES_API_ONLY_PREFIXES` in `langchain-openai` 1.6.6 and OpenAI says Chat Completions supports function calling only at effort `none`. Issue langchain-ai/langchain#40346 is closed and about `gpt-6-astra` (corrected in the plan)
- SETTLED: latest `langchain-openai` 1.6.6 (requires `langchain-core>=1.6.4`) and `langchain-fireworks` 1.6.2 (requires `langchain-core>=1.6.0`), against `langchain-core` 1.2.19 in `uv.lock` (PyPI)
- SETTLED: prices per million tokens (input, cached, output): Gemini 3.1 Flash-Lite `0.25, 0.025, 1.50`, `gpt-6-luna` `0.10, 0.01, 0.50`, GLM-5.3-Flash on Fireworks `0.15, 0.03, 0.50` (Gemini pricing page, OpenAI and Fireworks model pages)
- SETTLED: no training on API data: Gemini paid tier "not used to improve our products", OpenAI API not used to train by default (30-day abuse monitoring retention), Fireworks does not log or store prompt or generation data for open models without opt-in (each provider's docs)
- SETTLED: OpenAI reasoning tokens are billed as output tokens, a subset of `output_tokens` (OpenAI reasoning guide)
- SETTLED: `input_token_details.cache_read` and `output_token_details.reasoning` are optional keys of LangChain's `UsageMetadata` (installed `langchain-core` 1.2.19 source)
- SETTLED: constructor arguments override `MCP_AUDITOR_*` variables in `pydantic-settings`, and an omitted field is read from the environment (checked locally)
- SETTLED: `langchain-core` `convert_to_openai_function` accepts a JSON-schema dict with a `title` and no `description`, and `strict=False` adds no `additionalProperties: false` (langchain-core master source)
- OPEN (unverified): how `langchain-openai` 1.6.6 builds the Responses API `text.format` from a dict schema with `strict=False`, and whether it keeps or inlines `$defs`. The source file is too long to read through the fetch tool
- OPEN (unverified): the plan's claim that `langchain-openai` forces strict mode for a Pydantic class (the reason for the dict path). Not read in source
- OPEN (unverified): whether `ChatOpenAI` 1.6.6 raises `openai.OpenAIError` at construction on a missing key or defers it to the first call. The fetched source was truncated
- OPEN (unverified): OpenAI strict mode rejecting open objects (`additionalProperties` must be false). The docs page shows it in every strict example, the rule itself was not quoted
- OPEN (unverified): Fireworks accepted `reasoning_effort` values for `glm-5p3-flash` (`low`, `medium`, `high` in the plan). Fireworks docs give these as examples, not as a closed list
- OPEN (unverified): whether Fireworks `completion_tokens` includes reasoning tokens. Undocumented, matters only for a later GLM reasoning candidate
- OPEN (currency): the check that `langchain-google-genai` 4.2.1 adds thoughts into `output_tokens` holds only if the lock keeps 4.2.1 when `langchain-core` moves to 1.6.x
- OPEN (deferred): the version specifiers for `langchain-openai` and `langchain-fireworks` in `pyproject.toml`. The plan leaves them to the implementer, the verified releases are above

## Implementation steps

Every step runs the same checks before it ends: `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (strict), all green. Each step is one commit, and no commit message refers to a step or a phase of this plan. `tests/unit/test_readme_policy.py` reads `README.md`, so every README edit keeps it green.

### Step 1: Upgrade LangChain alone

- **Files**: `pyproject.toml`, `uv.lock`.
- **Do**:
  - In a temporary copy of the project outside the repo, add `langchain-openai` and `langchain-fireworks` to the dependencies and run `uv lock` there, to learn the `langchain-core` version and the moves the two new packages will require. Do not keep that copy.
  - In the repo, raise `langchain-core` in `pyproject.toml` to `>=1.6.4` and run `uv lock --upgrade-package langchain-core`, adding `--upgrade-package` for every package the resolver needs to move (`langgraph`, `langchain-google-genai`, `langchain-anthropic`, any other that pins an older core). Raise their lower bounds in `pyproject.toml` only where the resolver requires it. Do not add `langchain-openai` nor `langchain-fireworks` here.
  - Read the lock diff and list every package that moved, old and new version, and why.
  - Re-check in the installed upgraded packages (read their source under `.venv`): `langchain-google-genai` still adds `thoughts_token_count` into `output_tokens`, still fills `input_token_details.cache_read` and `output_token_details.reasoning`, `thinking_level` still accepts `minimal`, `with_structured_output` still defaults to `json_schema`. `langchain-anthropic`'s `with_structured_output` still defaults to `function_calling`. `langgraph`'s deserialization warning on unregistered types is still a warning, not an error. If the resolver cannot keep `langchain-google-genai` 4.x, or any of these changed, stop and report without committing.
  - No source change. If an upgrade breaks a test, stop and report rather than adapt the code: this commit must isolate the upgrade.
- **Test**: no new test. The existing suite, `tests/unit/test_checkpointing.py` (the `--resume` path) especially, passes unchanged.
- **Verify**: the four common checks. The commit message answers ADR 016's four questions (lands in the system under test, justification holds with every measurement deleted because the new providers require it) and lists the packages that moved. The implementer does not run the evals. The report back states that the operator runs `uv run python -m evals.run_judge_eval` and `uv run python -m evals.run_evals --ungated` on the reference before Step 2 starts, and records the metrics beside the 2026-09-24 exploratory measurement (R 0.79, P 0.75, C 0.93, 36 cells), a delta below the instrument's resolution being inconclusive.

### Step 2: Reasoning setting, pinned Gemini thinking level, token details

- **Files**: `tests/unit/test_config.py`, `tests/unit/test_llm_adapter.py`, `tests/unit/test_models.py`, `src/mcp_auditor/config.py`, `src/mcp_auditor/adapters/llm.py`, `src/mcp_auditor/domain/models.py`, `README.md`, `.env.example`, `CHANGELOG.md`.
- **Do** (tests first):
  - Tests below, run red.
  - `domain/models.py`: `TokenUsage` gains `cached_input_tokens: int = 0` (comment: subset of `input_tokens`) and `reasoning_tokens: int = 0` (comment: subset of `output_tokens`). `add` sums all four.
  - `config.py`: `Settings.reasoning: str = ""` and `resolve_reasoning(self, model: str) -> str | None`. A module-level per-provider table beside `_default_model` holding, for `google` and `anthropic` only in this step, the default model (unchanged), the default reasoning for that model (`minimal` for google, none for anthropic) and the accepted values (`minimal`, `low`, `medium`, `high` for google, none for anthropic). Resolution: explicit value validated against the provider's accepted values (`ValueError` naming them, and for anthropic a message saying the provider takes no reasoning setting), else the provider default when `model` is the provider's default model, else `None`. Keep `_default_model` reading from the same table.
  - `adapters/llm.py`: `_create_for_provider(settings, model)`, with `reasoning = settings.resolve_reasoning(model)`. Public `make_chat_model(settings, model) -> BaseChatModel` dispatching to `_make_google_model(model, reasoning)` (`ChatGoogleGenerativeAI(model=..., thinking_level=reasoning, max_retries=3)`, `thinking_level` passed only when not `None`) and `_make_anthropic_model(model)` (unchanged). `create_llm` and `create_judge_llm` pass `settings` and the resolved main or judge model. `_UsageMetadata` gains the two optional nested keys (`input_token_details`, `output_token_details`, `NotRequired`), and `_to_token_usage` reads `input_token_details.cache_read` and `output_token_details.reasoning`, defaulting to 0.
  - Docs: README configuration table gains `MCP_AUDITOR_REASONING`, the defaults paragraph names each provider's default reasoning (google `minimal`, anthropic none) and says the default reasoning applies to the default model only. `.env.example` documents `MCP_AUDITOR_REASONING` and keeps its judge override example working. `CHANGELOG.md` `[Unreleased]`: Added the `MCP_AUDITOR_REASONING` setting, Changed Gemini's thinking level now set explicitly to `minimal` (the API default, now pinned), token usage in JSON reports gains cached and reasoning tokens.
- **Test**:
  - `test_config.py`: google resolves `gemini-3.1-flash-lite` and `minimal` when nothing is set. anthropic resolves its default model and `None`. A model other than the provider default (`gemini-3.1-pro-preview`) resolves `None` with `reasoning` unset, and the explicit value when set. An accepted explicit value is returned as set. `reasoning="max"` on google raises, message naming the accepted values. anthropic with any reasoning raises.
  - `test_llm_adapter.py`: usage metadata with `input_token_details.cache_read` and `output_token_details.reasoning` fills the two new fields. Metadata without details leaves them at 0. The existing retry test extended so the four fields accumulate across attempts (the fake's `usage_metadata` type widens to nested dicts). `make_chat_model` for google returns a chat model whose `model` and `thinking_level` are the ones resolved (default model gives `minimal`, a judge override gives `None`). `make_chat_model` for anthropic returns the model name. Dummy keys through `monkeypatch`, no network.
  - `test_models.py`: `TokenUsage.add` sums the four fields.
- **Verify**: the four common checks. The commit message body says the change lands in the system under test and that its justification holds without a measurement (ADR 019 defines the reference at `minimal`, and an unset level follows the API's default), per the four questions of ADR 016.

### Step 3: OpenAI and Fireworks providers

- **Files**: `tests/unit/test_config.py`, `tests/unit/test_llm_adapter.py`, `src/mcp_auditor/config.py`, `src/mcp_auditor/adapters/llm.py`, `pyproject.toml`, `uv.lock`, `README.md`, `.env.example`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do** (tests first):
  - `uv add langchain-openai langchain-fireworks` with lower bounds at the verified releases (`>=1.6.6`, `>=1.6.2`), `uv.lock` committed. The lock must not move the packages Step 1 upgraded beyond what these two need. Report any move.
  - Before writing the OpenAI path, settle in the installed `langchain-openai` source the four OPEN items of the due diligence record: how a dict schema with `method="json_schema", strict=False` becomes the Responses API `text.format` (sent non-strict, open `arguments` object accepted), whether `$defs`/`$ref` from `AuditPayload.model_json_schema()` are kept or need inlining (inline in the adapter only if the library or the API needs it), whether a Pydantic class forces strict, and whether `ChatOpenAI` raises at construction on a missing key. Report each conclusion.
  - Tests below, run red.
  - `config.py`: the table gains `openai` (default `gpt-6-luna`, default reasoning `low`, accepted `none`, `low`, `medium`, `high`, `xhigh`, `max`) and `fireworks` (default `accounts/fireworks/models/glm-5p3-flash`, no default reasoning, accepted `low`, `medium`, `high`). The unknown-provider message names the four providers.
  - `adapters/llm.py`: one small frozen value naming the provider's structured-output choice (method, and whether the schema goes as a dict validated in the adapter), built by the provider dispatch: google `json_schema`, anthropic `function_calling`, fireworks `json_schema`, openai `json_schema` as dict with `strict=False`. `LLM.__init__(model, structured_output, max_parse_attempts)` uses it in `with_structured_output(..., include_raw=True)`. In dict mode the adapter passes `output_schema.model_json_schema()`, validates the parsed dict with `output_schema.model_validate`, and a `ValidationError` (or a `None` parsed result) is an unparsed attempt: retried, usage accumulated, `ValueError` after the last attempt, as today. `_make_openai_model(model, reasoning)`: checks `OPENAI_API_KEY` is set and non-empty (`ValueError` naming the variable otherwise), then `ChatOpenAI(model=..., reasoning_effort=reasoning, use_responses_api=True, max_retries=3)`. `_make_fireworks_model(model, reasoning)`: `ChatFireworks(model=..., reasoning_effort=reasoning, max_retries=3)`. The reasoning argument is passed only when not `None`. `make_chat_model` dispatches to the four. Existing `LLM(...)` constructions in `tests/unit/test_llm_adapter.py` are updated for the new parameter. Keep `llm.py` under 300 lines and functions under 20.
  - Docs: README configuration table gains `OPENAI_API_KEY`, `FIREWORKS_API_KEY`, the provider line lists the four providers, the defaults paragraph names openai (`gpt-6-luna`, `low`) and fireworks (GLM-5.3-Flash, no reasoning because its enforced schema disables it). `.env.example`: the four providers and the two keys. `CONTRIBUTING.md`: the eval API keys sentence lists the four providers' keys. `CHANGELOG.md` `[Unreleased]` Added: the `openai` and `fireworks` providers.
- **Test**:
  - `test_config.py`: openai resolves `gpt-6-luna` and `low` by default. fireworks resolves its default model and `None`, and passes an explicit `high` through. `reasoning="minimal"` on openai raises, message naming the openai accepted values. The unknown-provider message names `google`, `anthropic`, `openai`, `fireworks`.
  - `test_llm_adapter.py`: in dict-schema mode, a dict matching the schema is returned as the Pydantic model. A dict failing validation is retried with its usage accumulated, and after the last attempt raises `ValueError`. `make_chat_model` for openai returns a model whose `model_name` and `reasoning_effort` are the resolved ones, for fireworks the same with `model_name` and `reasoning_effort` (`None` by default). `make_chat_model` for openai with `OPENAI_API_KEY` unset, and set to empty, raises `ValueError` naming the variable. No test asserts on the `method` passed to `with_structured_output`.
- **Verify**: the four common checks.

### Step 4: Batch completeness check in the graph

- **Files**: `tests/unit/support/test_graph_given.py`, `tests/unit/test_nodes.py` (and `tests/unit/support/test_nodes_given.py` / `test_nodes_then.py` where they abstract something), `tests/unit/test_coverage.py` (new), `tests/unit/test_graph.py`, `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/domain/coverage.py` (new), `src/mcp_auditor/graph/nodes.py`, `src/mcp_auditor/graph/state.py`, `src/mcp_auditor/domain/__init__.py` if it re-exports models.
- **Do** (tests first):
  - Repair the fixtures first, before any production change, so that a default batch is complete for its budget: in `test_graph_given.py` the batch builders cycle payload categories over `list(AuditCategory)`, and the state budget matches the case count (for example `an_initial_state` takes its budget from the case count, or the builders default to a complete batch of 5). `TestGenerateTestCases.test_produces_pending_cases` in `test_nodes.py` gets three cases over three categories at budget 3. The suite must stay green after this repair alone, and the behavior these tests check does not change. `test_checkpointing.py` uses the same builders: check it still passes. `test_chain_nodes.py` is not affected.
  - New tests below, run red.
  - `domain/models.py`: `CoverageGap(requested_cases: int, received_cases: int, missing_categories: list[AuditCategory])`, and `ToolReport.coverage_gap: CoverageGap | None = None`.
  - `domain/coverage.py`: pure `find_coverage_gap(batch: TestCaseBatch, budget: int, categories: list[AuditCategory]) -> CoverageGap | None`. `None` when the batch holds at least `budget` cases and at least `min(budget, len(categories))` distinct categories. Otherwise the gap, whose `missing_categories` lists the requested categories absent from the batch only when the distinct-category bar is missed, and is empty otherwise.
  - `graph/nodes.py`: `make_generate_test_cases` calls `find_coverage_gap` after the first call. On a gap, one more call with the same prompt, keeping the retried batch and its gap (possibly `None`), and returning both usages. The update carries `coverage_gap`. `prepare_tool` returns `coverage_gap: None`. `build_tool_report` copies `state.get("coverage_gap")` into the `ToolReport`. Keep `generate_test_cases` under 20 lines (extract a helper right below it if needed).
  - `graph/state.py`: `coverage_gap: CoverageGap | None` in `AuditToolState` and in `GraphState`, so it reaches `build_tool_report` through the audit subgraph and the dry-run subgraph. Every read uses `state.get`, so an older checkpoint resumes.
- **Test**:
  - `test_coverage.py`: complete batch at budget 10 returns `None`. Nine cases returns requested 10, received 9. Ten cases over four categories returns the missing one. Budget 3 with three categories returns `None`. Budget 3 with two categories returns a gap listing the three requested categories absent from the batch. Eleven cases returns `None`. Budget 1 with one case never reports a category gap.
  - `test_nodes.py`: complete batch gives its cases, one usage, no gap. Incomplete then complete gives the second batch's cases, both usages, no gap. Two incomplete batches give the second batch's cases, both usages, and its gap. `build_tool_report` copies the gap, `prepare_tool` resets it. Assertions on the returned update only, never on the fake's call count.
  - `test_graph.py`: a full graph run where one tool's generator stays incomplete (two incomplete batches) yields an `AuditReport` whose tool report carries the gap, the other tools none. One `build_dry_run_graph` scenario asserting the gap reaches the dry-run tool report.
- **Verify**: the four common checks.

### Step 5: Show the coverage gap in every output

- **Files**: `tests/unit/test_rendering.py` (and its `given`/`then` support modules), `tests/unit/test_console_display.py` (and `test_console_given.py`), `src/mcp_auditor/domain/rendering.py`, `src/mcp_auditor/console.py`, `src/mcp_auditor/audit.py`, `README.md`, `CHANGELOG.md`.
- **Do** (tests first):
  - Tests below, run red.
  - `rendering.py`: `_render_tool_section` adds one line right under the tool heading when the report carries a gap, naming requested and received cases and the missing categories. Token usage lines unchanged.
  - `console.py`: after the summary, one `print_warning` line per tool report with a gap, on both paths (after the panel in rich mode, after the one-line summary in CI mode, since `print_summary` returns early in CI mode today). A small method formatting the warning line, reused by the dry run.
  - `audit.py` `_show_payloads`: after each tool's payload table, the same warning line for a tool report with a gap.
  - JSON needs no code: `coverage_gap` serializes with the model.
  - Docs: README, a sentence under the report description saying a tool whose generated batch stays incomplete after one retry is flagged in every output format. `CHANGELOG.md` `[Unreleased]` Changed: an incomplete generated batch is retried once and flagged.
- **Test**:
  - Markdown shows the gap line under the tool heading when present, nothing when absent.
  - JSON of a report with a gap contains `coverage_gap` with its three fields.
  - Console summary prints the warning line for a tool with a gap, in rich mode and in CI mode, and none for a tool without.
  - Dry run: if testing `Audit._show_payloads` needs a fake-LLM seam that proves too costly, the `build_dry_run_graph` scenario of Step 4 is the coverage, and the display test is skipped.
- **Verify**: the four common checks.

### Step 6: Record the reasoning setting in baseline conditions

- **Files**: `tests/unit/test_eval_session.py` (and `test_eval_session_given.py`), `tests/unit/test_eval_baseline.py` (and `test_eval_baseline_given.py`), `evals/baseline.py`, `evals/eval_session.py`, `CONTRIBUTING.md`.
- **Do** (tests first):
  - Tests below, run red.
  - `BaselineConditions` gains `reasoning: str | None` and `judge_reasoning: str | None`. `_candidate_conditions` fills them from `settings.resolve_reasoning(settings.resolve_model())` and `settings.resolve_reasoning(settings.resolve_judge_model())`. `ci_condition_mismatches` compares both against the defaults' resolution. Update every `BaselineConditions` construction in tests and givens. No baseline file exists, so none is migrated.
  - `CONTRIBUTING.md`: the recording conditions sentence names `MCP_AUDITOR_REASONING` among the overrides that refuse a recording.
- **Test**: candidate conditions carry the resolved reasoning of the main and of the judge model (a judge override gives `judge_reasoning=None`). `ci_condition_mismatches` reports a reasoning override. `condition_mismatches` reports a baseline recorded at another reasoning setting.
- **Verify**: the four common checks. The commit message says it changes the instrument and nothing the system does.

### Step 7: Probe corpus and capture command

- **Files**: `tests/unit/test_probe_corpus.py` (new, with `tests/unit/support/test_probe_corpus_given.py` if it abstracts something), `evals/probe_corpus.py` (new), `evals/capture_probe_corpus.py` (new), `evals/honeypots.py`, `evals/run_evals.py`, `CLAUDE.md`.
- **Do** (tests first):
  - Tests below, run red.
  - `evals/honeypots.py`: frozen dataclass `AuditModels(llm: LLMPort, judge_llm: LLMPort)`, `models_for(settings) -> AuditModels`, and `audit_honeypot(models, honeypot, budget)`. The two callers in `evals/run_evals.py` pass `models_for(session.settings)`.
  - `evals/probe_corpus.py`: `ProbeCall`, `ReferenceConditions`, `ProbeCorpus`, `RecordingLLM`, `sample_judge_calls`, `schema_for`, `load_corpus`, `write_corpus`, as specified in "evals/probe_corpus.py (new)". `RecordingLLM` ids `honeypot/{schema_name}/{index:03d}` with `index = len(sink)` at append time, main and judge wrappers sharing one sink. `sample_judge_calls` keeps every non-judge call, draws `size` judge calls with `random.Random(seed).sample`, returns them in capture order, never reads a response, raises naming the captured count when fewer exist. `schema_for` maps the six names (`TestCaseBatch`, `Judgment`, `AttackContext`, `ChainPlanBatch`, `StepObservation`, `AuditPayload`) and raises on an unknown one.
  - `evals/capture_probe_corpus.py` (`uv run python -m evals.capture_probe_corpus`): in this order, refuse when the settings are not the reference (provider `google`, default model for both `resolve_model()` and `resolve_judge_model()`, reasoning `minimal` for both), naming the mismatch. Check every CVE image exists (`docker image inspect` on the images named in each target's `Launch.args`) and stop with the `docker compose -f evals/docker/compose.yml build` line otherwise, before any LLM call. Run `audit_honeypot` once per honeypot of `HONEYPOTS` at budget 10 with both LLMs wrapped in `RecordingLLM`. For each target of `CVE_TARGETS`, enter its `environment()`, connect `StdioMCPClient.connect(ServerLaunch.declared_container(launch.command, launch.args, docker_client_env(os.environ)), errlog=devnull)` as `run_cve_benchmark._silent_client` does, list the tools, deduplicate on the whole `ToolDefinition`, and build one `ProbeCall` per tool from `build_attack_generation_prompt(tool=..., budget=10, categories=list(AuditCategory), attack_context=None)`, schema `TestCaseBatch`, role `main`, source `cve`, id `cve/TestCaseBatch/{index:03d}`. Sample 60 judge calls with a fixed seed, record the seed, the number of judge calls captured, the commit, the date and the reference conditions, and write `evals/fixtures/probe_corpus.json`. Verdicts are not read nor stored. Keep functions short and the module under 300 lines.
  - `CLAUDE.md` Commands: the capture command, noting it needs Docker, the CVE images and a Google key.
  - The implementer does not run the capture (it costs LLM calls). The corpus is generated and committed by the operator later.
- **Test** (`test_probe_corpus.py`): `RecordingLLM` records schema name, role, prompt and a unique id, and returns the inner result unchanged (inner is a `FakeLLM`). Two wrappers on one sink produce unique ids across roles. `sample_judge_calls` keeps every non-judge call, draws the requested number, is identical for the same seed, keeps capture order, raises when fewer judge calls exist than requested. `schema_for` maps each of the six names and raises on an unknown one. A corpus written then loaded round-trips (`tmp_path`).
- **Verify**: the four common checks, and `uv run python -m evals.capture_probe_corpus` with a non-reference setting (for example `MCP_AUDITOR_REASONING=low`) refuses before any call. The commit message says it changes the instrument and nothing the system does.

### Step 8: Probe analysis, runner and method note

- **Files**: `tests/unit/test_probe.py` (new, with `tests/unit/support/test_probe_given.py` / `test_probe_then.py` where they abstract something), `evals/probe_candidates.py` (new), `evals/probe.py` (new), `evals/run_probe.py` (new), `evals/probe_method.md` (new), `CLAUDE.md`, `CONTRIBUTING.md`.
- **Do** (tests first):
  - Tests below, run red.
  - `evals/probe_candidates.py`: `Prices`, `Candidate`, `REFERENCE`, `CHALLENGERS`, `PRICES_DATE = "2026-09-24"`, as specified in "evals/probe_candidates.py (new)". Every candidate `Settings` passes `provider`, `model`, `judge_model=""` and `reasoning` explicitly. Reference: google, `gemini-3.1-flash-lite`, `minimal`, prices `0.25, 0.025, 1.50`, `reasoning_expected=None`. Luna `none` (`False`) and Luna `low` (`True`), prices `0.10, 0.01, 0.50`. GLM with empty reasoning, `None`, prices `0.15, 0.03, 0.50`.
  - `evals/probe.py` (pure, no I/O): `CallOutcome`, `ProbeObservation`, `CandidateStats`, `Bars(max_latency_ratio=3.0, max_cost_ratio=1.0)`, `Admission`, `call_cost`, `summarize(candidate, observations, judge_weight)`, `admit(stats, reference, bars)`, as specified in "evals/probe.py (new, pure)". Refusal: a `TestCaseBatch` observation that is a parse failure or carries a coverage gap. `admit` fails on any parse failure (per schema), any refusal, any `ERROR`, a per-role median latency above the ratio (equal passes), a weighted cost above the ratio (equal passes), and reasoning tokens contradicting `reasoning_expected` (`None` skips). Each reason states its numbers. A function that lists the bars a reference would fail, for display only. Split the module if it passes 300 lines.
  - `evals/run_probe.py` (`uv run python -m evals.run_probe [--report PATH]`): load the corpus, build one main (`create_llm`) and one judge (`create_judge_llm`) LLM per candidate before any call, stopping on a construction failure with the candidate named. For each call in corpus order, run every candidate sequentially, rotation starting at `call_index % len(candidates)`. Time with `time.perf_counter` around `generate_structured`. `ValueError` is a parse failure, any other exception an `ERROR` with its message. For `TestCaseBatch` calls, `find_coverage_gap` with the corpus budget and all categories. `judge_weight = judge_calls_captured / judge calls in the corpus`. Write observations and admissions to `output/probe_report.json` (default) with temperature recorded as "provider default" per candidate, print one table (per candidate: median latency per role, weighted cost and ratio to the reference, parse failures, refusals, errors, reasoning tokens, admitted or not with reasons, the reference's failed bars marked as recorded only). Exit 0 whatever the verdict.
  - `evals/probe_method.md`: the living method note with every section listed in "evals/probe_method.md (new, living method note)" and the values of "Bars written before measurement", including the limits (watered-down payloads not detected, 429 retries inside the latency, rotation, median over p95), the Fireworks reasoning-token gap (`reasoning_expected=None` for GLM), the instruction to rerun on an `ERROR` and to set every candidate's key before running, the data-retention fact per provider with its source, and the one-time billing console check after the first run.
  - `CLAUDE.md` Commands: the probe command, noting it needs the keys of every candidate. `CONTRIBUTING.md`: a short paragraph giving the capture and probe commands and pointing at `evals/probe_method.md`.
  - The implementer does not run the probe.
- **Test** (`test_probe.py`): `call_cost` prices cached input at the cached price and the rest at the input price. `summarize` multiplies each judge call's cost by `judge_weight` and leaves other calls at weight 1. `summarize` computes per-role medians, parse failures per schema, refusals from coverage gaps and from `TestCaseBatch` parse failures. `admit`: clean challenger admitted. One `StepObservation` parse failure rejects, schema named. One refusal rejects. One `ERROR` rejects. Judge median at 3.1 times the reference rejects, exactly 3 times admits. Cost at 1.01 times rejects, equal admits. Reasoning tokens > 0 when 0 is expected rejects, 0 when > 0 is expected rejects, `None` skips the check.
- **Verify**: the four common checks, and `uv run python -m evals.run_probe --help` prints its usage. The commit message says it changes the instrument and nothing the system does. After this step the operator runs the capture, commits the corpus, then runs the probe.
