# Judge reasoning first, then the error_handling guidance

## Context

The plan `2026-10-23_judge-false-alarms.md` ran on 2026-10-23 and none of its two judge changes landed:

- **Change 1, the error_handling guidance**, missed its bar in a paired replay under the default judge (`gpt-6-luna`, reasoning `none`): false-alarm set FAIL 40.6 % under the parent's text, 28.0 % under change 1's (the bar asked at most half), guard set 98.8 % under both. Per tool, `search_products × error_handling` went from 46 % to 21 %, `delete_record × error_handling` from 36 % to 33 %. On `delete_record`, most FAIL verdicts under change 1 carried a justification concluding there was no error_handling failure (85 of 119 by a rough text match, 14 of 131 under the parent). It was discarded uncommitted.
- **Change 2, `Judgment` declaring `justification` before `verdict`**, was committed (`faf3727`). Its order check showed the default `openai` path does not follow the schema's key order: 10 of 10 raw answers opened with `verdict`. The honeypot gate came back red at that commit (`search_products/error_handling`, 4 of 5 replays), and `b8b070d` reverted it. That red does not show a regression: the order check shows `faf3727` changed nothing in the output on the default path, and the cell reads `FFPFPP` in the baseline recorded since (`8a044a3`), unstable, where the previous baseline had seen it stable by chance. The only other explanation, not separated, is that the reordered schema, which is part of the request, was enough to shift the judge. The revert was due under the rule all the same.

Both readings point at one mechanism: with reasoning `none`, the justification is the only place the judge reasons, and the default path writes the verdict before it. The first replay was read to diagnose, which the previous plan allowed. That reading is exploratory and licenses nothing by itself.

The default path binds the `openai` provider with the schema as a dict and `strict=False` (`src/mcp_auditor/adapters/llm.py`, `_STRUCTURED_OUTPUT` and `LLM._bind`), and OpenAI documents the schema's key order only for Structured Outputs, which is the strict mode. With `strict=True`, `langchain_openai` sends the schema with `strict: true` in the Responses API's `text.format`, and the converted `Judgment` schema is valid for it: its three fields are required, its two enums stay under `$defs`/`$ref`, and `additionalProperties: false` is set at the root (checked offline with `ChatOpenAI._get_request_payload`, langchain-openai as locked).

Strict mode cannot be turned on for every schema. On the dict path, `langchain_core.utils.function_calling._recursive_set_additional_properties_false` turns `additionalProperties: true` into `false`, so the open `AuditPayload.arguments` object of `TestCaseBatch`, `ChainPlanBatch` and `AuditPayload` would be closed silently and every payload would come back `{}` with no error. Under strict, langchain also makes every property required, which would change `StepObservation` and `AttackContext`, both generator-side schemas whose fields have defaults. The comment above `_STRUCTURED_OUTPUT` says strict mode "rejects" the open object, which is not what the dict path does.

The cases the red gate of `faf3727` fired on were overwritten by the runs after it: the exports kept are those of the previous plan's sources, the replay results of change 1 (`output/judge-false-alarms-2026-10-23/replay_change1_attempt1.jsonl`) and the judged cases of the second recording at `c7c8d79` (`output/judge-false-alarms-2026-10-23/recording_c7c8d79/judged_cases.jsonl`), all gitignored.

## Approach

Three changes to the system under test, each alone in its commit and measured at that commit before the next lands (ADR 020). The plan is committed alone before the first.

1. **A, strict output for the judge on `openai`.** An explicit opt-in: `Judgment` only, on the `openai` entry of `_STRUCTURED_OUTPUT` only. Justification, without the measurement, two reasons that both hold: the key order the schema declares becomes the order of the output, which OpenAI documents only in strict mode, and the provider enforces the judge's schema instead of the adapter parsing a free answer and retrying. Its commit message gives both, the output order first, so that A does not read as plumbing. A stands on these two reasons whether or not B lands.
2. **B, the judge writes its justification before its verdict**, on top of A: `Judgment` declares `justification` before `verdict` again, and the closing of both judge prompts, which today asks for the decision and then "a justification and severity", asks for the justification first, then the verdict and the severity. Under strict decoding the order is enforced, so this is a different change from `faf3727`, which changed nothing on the default path. Justification, without the measurement, the same for the schema and the closing: a judge running with no reasoning has no other place to reason than the justification, and a verdict generated first cannot depend on it.
3. **C, change 1's text, word for word**, on top of B. The second and last attempt at change 1.

B and C depend on A, and C on B: if A is reverted, the plan stops, and if B is discarded or reverted, C is not attempted, since its rationale needs the justification written first.

What this plan does not touch: `list_items × input_validation`, whose FAIL verdicts after the `c7c8d79` repair read a clamped `limit=0` or `limit=-1` as an invalid input accepted. The input_validation guidance and J2 already state that the nearest valid value is a PASS, and a qualifier written from those verdicts would be phrased from the measurement. `search_users × input_validation` stays out, as in the previous plan.

## Change A: strict output for the judge on `openai`

### `src/mcp_auditor/adapters/llm.py`

`StructuredOutput` gains a field naming the schemas bound strictly, empty by default:

```python
@dataclass(frozen=True)
class StructuredOutput:
    method: Literal["json_schema", "function_calling", "anthropic_json_schema"]
    schema_as_dict: bool = False
    strict_schemas: frozenset[type[BaseModel]] = frozenset()
```

The `openai` entry becomes `StructuredOutput(method="json_schema", schema_as_dict=True, strict_schemas=frozenset({Judgment}))`. No other entry changes: `alibaba` and `openrouter` share the dict path, and on `openrouter` a strict schema with `require_parameters` may change which hosts are eligible, which no gate measures.

`LLM._bind`, on the dict path, passes `strict=output_schema in self._structured_output.strict_schemas` instead of `strict=False`. The Pydantic path and the Anthropic path are unchanged.

The comment above `_STRUCTURED_OUTPUT` is rewritten to state both paths: OpenAI, Alibaba and OpenRouter get a dict, and strict is an explicit opt-in per schema and per provider, for two facts of the two paths: a Pydantic class goes strict through the OpenAI SDK with the open `AuditPayload.arguments` object left open, which the API refuses, and a dict bound strictly has that object closed by langchain, so every payload would come back empty with no error (langchain also makes every property required). Strict is granted only to a schema with no open object and no optional field.

`Judgment` is imported from `mcp_auditor.domain.models` (an adapter may import the domain).

### Tests

`tests/unit/test_llm_adapter.py`, test first, a new class (for example `TestStrictSchemas`), through the request body the OpenAI client actually sends, captured offline with no network and a placeholder key (`monkeypatch.setenv("OPENAI_API_KEY", ...)`): a `ChatOpenAI` with the arguments `_make_openai_model` gives it (`use_responses_api=True`, `reasoning_effort="none"`) plus `http_async_client=httpx2.AsyncClient(transport=httpx2.MockTransport(record))` (`httpx2`, the client the OpenAI SDK is built on), wrapped in `LLM` with `_STRUCTURED_OUTPUT["openai"]` (`# pyright: ignore[reportPrivateUsage]`, as `test_anthropic_structured_output.py` does for the wire classes), and called through `generate_structured`. The recording handler keeps the JSON body and answers a 400: the SDK does not retry it, the adapter re-raises it (`openai.BadRequestError`, not a policy refusal), so one call sends exactly one request, and the test reads `body["text"]["format"]`. Reading `_get_request_payload` instead needs the bound runnable's kwargs, which `with_structured_output(..., include_raw=True)` buries under a `RunnableSequence` / `RunnableAssign` / `RunnableParallel` (its `.first` has no `kwargs`), so the transport is the stable seam (checked offline at langchain-openai 1.7.2: today all five schemas send `strict: false`, and with `strict=True` `Judgment` sends `strict: true`).

- binding `Judgment` sends `text.format` with `strict: true`;
- binding `TestCaseBatch` or `AuditPayload` (which the probe corpus binds) sends `strict: false`, and the `arguments` object of its payload keeps `additionalProperties` other than `false` (`true` today);
- binding `ChainPlanBatch`, `StepObservation` and `AttackContext` sends `strict: false`.

The setup (the model with its recording transport, the `LLM`, the captured body) goes into `tests/unit/support/test_llm_adapter_given.py`. The reads of the captured body (the `strict` flag of `text.format`, the `additionalProperties` of the payload's `arguments` under `$defs`) go into a new `tests/unit/support/test_llm_adapter_then.py`: they abstract the Responses API's body layout, so the test reads as the spec of which schema is bound strictly.

### Verification

- The four closing checks.
- Before the commit, maintainer only: two live calls of the default judge on two collected cases, bound by the adapter, to confirm the API accepts the strict `Judgment` schema (a parsed `Judgment` comes back, no error). If the API rejects it, A is discarded uncommitted and the plan ends.
- After the commit, maintainer only: the three gates (`uv run python -m evals.run_judge_eval`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark`). The honeypot baseline gates 3 of 8 planted FAIL cells and 25 of 28 PASS cells, so the gates here check that stable cells do not collapse, which is what a change expected to cost no stable cell needs. A red gate reverts A and ends the plan.
- `CHANGELOG.md`, `[Unreleased]`, `### Changed`: on the `openai` provider, the judge's answer is bound to its schema in strict mode.
- `evals/probe_method.md`, `## Limits`: one sentence that, from A on, the probe's `openai` candidates (bound through `create_judge_llm`) receive `Judgment` in strict mode, so a probe result taken before A bound the judge non-strictly and is compared only with one taken under the same binding. Line 87 stays as it is: it sits under `## Observations before the ADR 019 revision`, a dated record of the path as it was.
- The commit message answers the four questions of ADR 016. `evals/declared_flips.json` stays empty.

## Change B: the judge writes its justification before its verdict

### `src/mcp_auditor/domain/models.py`

```python
class Judgment(BaseModel):
    """The judge's verdict, decoupled from the identity fields the code stamps itself."""

    justification: str
    verdict: EvalVerdict
    severity: Severity
```

`EvalResult` keeps its order. Both judges use `Judgment` (`graph/nodes.py`, `graph/chain_nodes.py`), so B reaches the CVE chain judge, which only the CVE gate sees.

### `src/mcp_auditor/graph/prompts.py` and `src/mcp_auditor/graph/chain_prompts.py`

The closing of `build_judge_prompt` becomes:

```
First write your justification: what the response or the error shows, read against the rules above. Then decide:
- FAIL: the response or the error shows a **{category}** failure
- PASS: it shows none, even if a failure of another category is shown or a failure of this one remains possible

Then give the severity (low, medium, high, critical).
```

The closing of the chain judge prompt in `chain_prompts.py` changes the same way: "First write your justification: what the responses of the chain show, read against the rules above. Then decide:", its two decision lines unchanged, then "Then give the severity (low, medium, high, critical)." Nothing else in either prompt moves. No test pins the closing's wording, and none is added (the prompt's effect is LLM quality, measured by the replay and the evals): `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py` and the contamination tests stay green.

### Tests

`tests/unit/test_models.py`, test first: `list(Judgment.model_json_schema()["properties"])` puts `justification` before `verdict` (the test `faf3727` added). `tests/unit/test_anthropic_structured_output.py` and the judge node tests stay green unchanged. When a test is run red by stashing the source, the `__pycache__` directories outside `.venv` are deleted after restoring it: a stash and its pop within the same second leave a `.pyc` Python takes as current (it measured `faf3727` with the old order once).

### Measurement, before the commit

**Replay B.** A one-off script outside the repository, not committed, judges the case sets below under two arms, alternating case by case, 20 times per case per arm, with the default judge through the project's model factory. Both arms bind as the adapter binds `Judgment` at A (`method="json_schema"`, `strict=True`, `include_raw=True`). The parent's arm sends `Judgment.model_json_schema()` as A's commit declares it (`verdict`, `justification`, `severity`) with the prompt built by the parent's `build_judge_prompt` (both modules of A's commit loaded by the script), B's arm sends B's order with the prompt B's `build_judge_prompt` builds. The replay measures B as one change and does not separate the schema from the closing. The script counts, under B's arm, the raw answers that open with `justification`.

**Cases.** A case is one judge input with its identity reduced to tool name, category, arguments (serialized with sorted keys), response and error: inputs differing only in their payload description are one case, judged with the description of their first occurrence. Source order: the previous plan's sources in its enumeration (the eight CI runs in the order it lists them, `local_1022.jsonl`, `results/B1`, `B2`, `C1`, `C2`, `D1`, `D2`), then `recording_c7c8d79/judged_cases.jsonl`, then the fixture, in line order within a file. Only single-step cases are taken, from every source. The reduced key is preferred to the exact input for two reasons: the payload description is the generator's text, which rule 3 of `JUDGING_RULES` and J1 make no evidence, so two inputs that differ only there show the judge the same evidence, and the exact input would hold about 165 cases, 6,600 calls at 20 replays, over the $0.5 a measurement may cost. This weighting differs from the previous replay's, so no rate here is compared with that replay's.

- **False-alarm set**: every case of `search_products × error_handling` and `delete_record × error_handling` judged FAIL in the previous plan's sources plus `recording_c7c8d79/judged_cases.jsonl`, 23 cases (15 and 8).
- **Guard set**: every case of `get_user × error_handling` and `delete_record × input_validation` judged FAIL in the same sources, plus the seven FAIL cases of `evals/fixtures/judge_cases.json` in error_handling and input_validation: `aef906ac6a361f21`, `015b054f8f42d65e`, `5a7557a560ec5eef` (J3), `f9ebef7823fc1caf`, `ad14bfd0448baa1e`, `271b26d3c0d826d4`, `59fa83f046c22556` (J2), deduplicated the same way: 17 cases (9 `delete_record × input_validation` and 6 `get_user × error_handling` from the exports, the fixture adding `5a7557a560ec5eef` and `59fa83f046c22556`, its five others falling on export cases).

40 cases, 2 arms, 20 replays: about 1,600 calls, about $0.22 at the prices of `evals/holdout_conditions.json`.

**Missing judgments.** A judgment that ends in a refusal, an unparseable answer or a throttle past every retry is left out of its arm's denominator and reported. If more than 5 % of an arm's judgments are missing, the replay is inconclusive: for B that ends the plan, for C it closes change 1.

**Bar**, written before any replay. B is not expected to lower the false alarms, its justification does not rest on it. The bar guards against a loss, the cell that turned `faf3727` red included, since that cell now reads `FFPFPP` in the baseline and is out of the gate:

- order: at least 95 % of the answers under B's arm open with `justification`. Below, B does not do what it claims, and it is discarded;
- `search_products × error_handling`: the FAIL rate under B no higher than the parent's plus 10 points;
- false-alarm set: the FAIL rate under B no higher than the parent's plus 10 points;
- guard set: the FAIL rate under B no lower than the parent's minus 10 points.

Bar met: B is committed with the replay's result in its message, which also says the red of `faf3727` was seen and that B differs from it by A. Bar missed: B is discarded uncommitted, and C is not attempted.

What bar B licenses: deciding to ship B through the gates, and the exploratory statement that B costs nothing measurable on these cases. The cases were read to diagnose change 1, so the numbers are exploratory (ADR 016), and they license no claim on the judge's precision.

### Verification

- The four closing checks, the replay against the bar, then after the commit the three gates. A red gate reverts B, and C is not attempted.
- `CHANGELOG.md`, `[Unreleased]`, `### Changed`: the judge writes its justification before its verdict.
- The commit message answers the four questions of ADR 016. `evals/declared_flips.json` stays empty.

## Change C: change 1's text, word for word

### What is applied

The text of "Change 1" in `plans/2026-10-23_judge-false-alarms.md`, word for word: rule 4 of `JUDGING_RULES` in `src/mcp_auditor/graph/prompts.py`, `CATEGORY_GUIDANCE[AuditCategory.ERROR_HANDLING]` in `src/mcp_auditor/domain/category_guidance.py`, with that plan's order and tests for the contamination check (`SDK_TEXTS = {"Error executing tool"}` in `tests/unit/support/test_fixture_contamination_given.py`, subtracted in `discriminating_literals()`, the guard test against `inspect.getsource(mcp.server.fastmcp.tools.base)` in `tests/unit/test_fixture_contamination.py`, `test_no_constant_of_src_contains_a_honeypot_literal` seen red after rule 4 and green after the exclusion), and its `CHANGELOG.md` bullet.

### Why a second attempt, and why it is the last

The previous plan allowed one second attempt "written from a rubric reason that is new and named in its commit". C has no new rubric reason: its text does not move. Lifting that requirement for C is a maintainer's decision, taken after the first attempt missed, and this plan and C's commit message say so in those words. Its reason holds without the measurement: the condition under which the text is judged changes (the judge now writes its justification before its verdict), and keeping the text word for word means no wording is chosen from the first replay's results. C is the second and last attempt: a miss, or an inconclusive replay, closes change 1, and the guidance stays at its parent. If C ships, its commit records the first attempt's miss and its numbers, as the previous plan asked of a second attempt.

### Measurement, before the commit

**Replay C.** The script of the first replay, adapted: it judges the case sets of replay B under the parent's text and under C's text, the same day, alternating case by case, 20 times per case per text, with the default judge bound as the adapter binds it at B. Both texts live in one process: `format_judging_criteria` reads the module globals `JUDGING_RULES` and `CATEGORY_GUIDANCE` of `mcp_auditor.graph.prompts`, so the script swaps those two names before each prompt it builds. About 1,600 calls, about $0.22.

**Bar**, written before replay B, so that B's numbers cannot shape it:

- conclusiveness: the parent's text judges the false-alarm set FAIL in at least 10 % of its judgments, and the `delete_record × error_handling` cases FAIL in at least 25 % of theirs. Below either, the replay is inconclusive, and change 1 is closed;
- false-alarm set: the FAIL rate under C at most half the parent's, and at least 4.3 points under it (one case of 23);
- `delete_record × error_handling`: the FAIL rate under C at most half the parent's on its cases, and at least 12.5 points under it (one case of 8). This is the prediction the first replay's pooled rate hid (36 % to 33 % inside 40.6 % to 28.0 %, under that replay's weighting), and C claims to fix it by the order of the output;
- guard set: the FAIL rate under C no lower than the parent's minus 10 points.

Bar met: C is committed with both replays' results in its message (the first attempt's numbers and this one's). Bar missed: C is discarded uncommitted, change 1 is closed, and the miss is recorded nowhere in the repository.

What bar C licenses: deciding to ship C through the gates, and the exploratory statement that the observed false alarms drop on these cases. The cases are those the first attempt was read on, so the numbers are exploratory (ADR 016). They license no choice between wordings and no claim on the judge's precision beyond these cases.

### Verification

- The four closing checks, the replay against the bar, then after the commit the three gates. A red gate reverts C.
- The commit message answers the four questions of ADR 016, says which clauses were brought forward was chosen by reading eval traces (ADR 016 allows it), and says the contradicted-parameter line follows from J2 and J3 by the mechanism and is the line `delete_record × error_handling` (R1) falls under. `evals/declared_flips.json` stays empty.

## What stays unchanged

- The binding of the providers other than `openai`, and of every schema other than `Judgment` on `openai` (B's field order still reaches `Judgment` on every provider, as `faf3727` did).
- The judge prompts' structure apart from B's closing, rules 1, 2, 3 and 5 of `JUDGING_RULES`, the guidance of every category but error_handling.
- The clauses J0 to J11, the ground truth, the honeypot servers, the baselines and fixtures (the judge isolation fixture and its baseline, the CVE fixtures and baselines, the honeypot baseline `8a044a3`).
- The gate and the replay rule.

## Edge cases

- A schema with an open object or an optional field added to `strict_schemas` would be closed or forced silently: the opt-in names `Judgment` alone, and the unit test pins the generator's schemas as non-strict.
- A strict answer refused by the provider: the adapter's refusal and truncation checks are unchanged and still apply.
- The order check of B returning fewer than 95 % justification first under strict decoding would mean the provider does not enforce the order: B is discarded.
- C's replay inconclusive because B already removed the false alarms: change 1 is closed, B stays.

## Verification, every commit

`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.

The measurements are run by the maintainer, never by the implementer: the two live calls of A, replays B and C, the three gates after each commit. Each measurement stays at or under $0.5, its volume and cost stated before it runs. Each of the three gates is a measurement of its own (about $0.04 to $0.07 each under the default model, from their reports of 2026-10-23). Between a measurement and the next commit, the `__pycache__` directories outside `.venv` are cleared.

## Due diligence record

What the due-diligence pass concluded on 2026-10-23 about the external facts this plan cites or defers, read by the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `langchain-openai` `1.7.2` and `langchain-core` `1.7.0` as locked: `with_structured_output(Judgment.model_json_schema(), method="json_schema", strict=True, include_raw=True)` sends `text.format` with `strict: true`, the three fields in `required`, both enums under `$defs`/`$ref` and `additionalProperties: false` at the root (verified offline by capturing the request body through `httpx.MockTransport`)
- SETTLED: under `strict=True` on the dict path langchain closes `$defs.AuditPayload.properties.arguments` (`additionalProperties: true` becomes `false`) and makes `StepObservation.next_step_hint` required, and with `strict=False` today `Judgment`, `TestCaseBatch`, `ChainPlanBatch`, `StepObservation` and `AttackContext` all send `strict: false` with `arguments` at `additionalProperties: true` (verified offline, same capture)
- SETTLED: "When using Structured Outputs, outputs will be produced in the same order as the ordering of keys in the schema." (verified against https://developers.openai.com/api/docs/guides/structured-outputs)
- SETTLED: the Responses API takes the strict schema as `text: { format: { type: "json_schema", strict: true, schema } }`, with every field `required` and `additionalProperties: false` (verified against the same guide)
- SETTLED: `openai` `3.36.1` as locked does not retry a 400 (it retries 408, 409, 429, 5xx or on `x-should-retry: true`), so with `max_retries=3` one `generate_structured` call answered by a 400 sends exactly one request and raises `openai.BadRequestError` (verified in the installed SDK's `_should_retry` and by the offline capture)
- SETTLED: `gpt-6-luna` supports the Responses API, lists `structured_outputs`, and accepts `reasoning.effort` `none` (verified against https://developers.openai.com/api/docs/models/gpt-6-luna)
- OPEN (deferred): the API accepting the strict `Judgment` schema on `gpt-6-luna` at reasoning `none`, the model page lists structured outputs without naming strict mode, settled only by the maintainer's two live calls before A's commit
- OPEN (unverified): on `openrouter`, a strict schema with `require_parameters` changing which hosts are eligible, OpenRouter's provider-routing page says `require_parameters` keeps only providers supporting every request parameter but says nothing of `strict` itself (https://openrouter.ai/docs/features/provider-routing). It only justifies leaving that entry unchanged

## Implementation steps

The plan imposes three commits, each measured at its own commit before the next lands (ADR 020), so each change is its own step, even though each is small. The plan itself is committed alone before step 1. The measurements are run by the maintainer, never by the implementer: the two live calls of A before step 1's commit, replay B before step 2's commit, replay C before step 3's commit, the three gates after each commit. A red gate after step 1 reverts it and ends the plan. A missed bar or a red gate on step 2 ends the plan after it (step 3 is not attempted). Each of the three gates must exit 0 before the next step starts: on exit 3 (not comparable, a run throttled past every retry included) or 4 (crash), the gate is rerun at the same commit, each rerun a measurement of its own under the $0.5 rule. The implementer does not commit.

Checks that close every step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all with no file argument. Short loop while working: `uv run pytest tests/unit -n auto --maxprocesses 4` and `uv run pyright <changed files>`. When a test is run red by stashing or reverting the source, delete the `__pycache__` directories outside `.venv` after restoring it (`find . -path ./.venv -prune -o -name __pycache__ -type d -print -exec rm -rf {} +`).

### Step 1: strict output for the judge on `openai` (change A)

**Files**
- `tests/unit/support/test_llm_adapter_given.py` (modify)
- `tests/unit/support/test_llm_adapter_then.py` (create)
- `tests/unit/test_llm_adapter.py` (modify)
- `src/mcp_auditor/adapters/llm.py` (modify)
- `CHANGELOG.md` (modify)
- `evals/probe_method.md` (modify, line 87)

**Do**, in this order:
1. `tests/unit/support/test_llm_adapter_given.py`: a helper that binds a schema through the real OpenAI path and returns the request body it sent, for example `async def the_openai_request_body(schema: type[BaseModel]) -> dict[str, Any]`. It builds `ChatOpenAI(model="gpt-6-luna", reasoning_effort="none", use_responses_api=True, max_retries=3, http_async_client=httpx2.AsyncClient(transport=httpx2.MockTransport(record)))`, where `record` keeps `json.loads(request.content)` and answers `httpx2.Response(400, json={"error": {"message": "recorded", "type": "invalid_request_error"}})` (`httpx2`, the client the OpenAI SDK is built on, as `test_anthropic_structured_output_given.py` uses). It wraps the model in `LLM(model, _STRUCTURED_OUTPUT["openai"], max_parse_attempts=3)` (`# pyright: ignore[reportPrivateUsage]` on the private import, as `test_anthropic_structured_output.py` does), calls `generate_structured("prompt", schema)` under `pytest.raises(openai.BadRequestError)`, and returns the single body recorded. The test sets the placeholder key with `monkeypatch.setenv("OPENAI_API_KEY", "sk-placeholder")` (pass `monkeypatch` to the helper, or set it in the test, whichever reads better). One call must send exactly one request: the helper may assert it recorded one body.
2. Create `tests/unit/support/test_llm_adapter_then.py` with three asserting helpers on the Responses API body: `bound_strictly(body)` (`body["text"]["format"]["strict"] is True`), `bound_loosely(body)` (`... is False`), and `payload_arguments_stay_open(body)` (the `additionalProperties` of the payload's `arguments` is not `False`, `True` today: under `$defs.AuditPayload.properties.arguments` for a batch, under `properties.arguments` when the schema is `AuditPayload` itself).
3. `tests/unit/test_llm_adapter.py`: import `then`, add a class (for example `TestStrictSchemas`) with:
   - `Judgment` is bound strictly on `openai` (`strict: true`);
   - `TestCaseBatch` and `AuditPayload` (the probe corpus binds it, `evals/probe_corpus.py`) are bound non-strictly and the `arguments` object of their payload stays open;
   - `ChainPlanBatch`, `StepObservation` and `AttackContext` are bound non-strictly (a `pytest.mark.parametrize` over the three is fine).
   Run them: the `Judgment` test is red (today every schema sends `strict: false`), the others green. See the non-strict pins red once by passing `strict=True` for every schema temporarily in `_bind`, then revert that edit (and clear `__pycache__`).
4. `src/mcp_auditor/adapters/llm.py`:
   - `StructuredOutput` gains `strict_schemas: frozenset[type[BaseModel]] = frozenset()`.
   - The `openai` entry of `_STRUCTURED_OUTPUT` becomes `StructuredOutput(method="json_schema", schema_as_dict=True, strict_schemas=frozenset({Judgment}))`. No other entry changes (`alibaba` and `openrouter` included).
   - `LLM._bind`, dict path: `strict=output_schema in self._structured_output.strict_schemas` instead of `strict=False`. The Pydantic and Anthropic paths are unchanged.
   - Import `Judgment` from `mcp_auditor.domain.models` (beside `ProviderUsage`).
   - Rewrite the comment above `_STRUCTURED_OUTPUT` to state both paths: OpenAI, Alibaba and OpenRouter get a dict, and strict is an explicit opt-in per schema and per provider, for two facts of the two paths: a Pydantic class goes strict through the OpenAI SDK with the open `AuditPayload.arguments` object left open, which the API refuses, and a dict bound strictly has that object closed by langchain, so every payload would come back empty with no error (langchain also makes every property required). Strict is granted only to a schema with no open object and no optional field. Keep the Anthropic part of the comment unchanged.
   All new tests green, the existing `TestDictSchema` and the rest of `tests/unit/test_llm_*.py` unchanged and green.
5. `CHANGELOG.md`, `[Unreleased]`, `### Changed` (the first `### Changed` under `[Unreleased]`): one bullet, on the `openai` provider the judge's answer is bound to its schema in strict mode.
6. `evals/probe_method.md`, `## Limits`: add one sentence, that from this change on the probe's `openai` candidates receive the judge's `Judgment` in strict mode, so a probe result taken before it bound the judge non-strictly and is compared only with one taken under the same binding. Line 87, under `## Observations before the ADR 019 revision`, is a dated record and stays as it is.

**Test**
- `Judgment` on `openai`: `body["text"]["format"]["strict"] is True`.
- `TestCaseBatch` on `openai`: `strict` is `False`, `$defs.AuditPayload.properties.arguments.additionalProperties` is not `False`.
- `AuditPayload` on `openai`: `strict` is `False`, `properties.arguments.additionalProperties` is not `False`.
- `ChainPlanBatch`, `StepObservation`, `AttackContext` on `openai`: `strict` is `False`.
- No network: the `MockTransport` answers every request, the SDK does not retry a 400, so each test sends one request.

**Verify**
- The four closing checks, all green.
- Report, for the commit message the orchestrator writes: the four questions of ADR 016 answered, with both reasons, the output order first (the schema's key order becomes the output's order, which OpenAI documents only in strict mode), then the provider enforcing the judge's schema instead of the adapter parsing a free answer and retrying, `evals/declared_flips.json` stays empty.
- Before the commit, maintainer only: two live calls of the default judge on two collected cases, bound by the adapter, a parsed `Judgment` back with no error. If the API rejects the strict schema, A is discarded uncommitted and the plan ends.
- After the commit, maintainer only: `uv run python -m evals.run_judge_eval`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark`. A red gate reverts the commit and ends the plan.

### Step 2: the judge writes its justification before its verdict (change B)

**Files**
- `tests/unit/test_models.py` (modify)
- `src/mcp_auditor/domain/models.py` (modify, `Judgment`)
- `src/mcp_auditor/graph/prompts.py` (modify, the closing of `build_judge_prompt`)
- `src/mcp_auditor/graph/chain_prompts.py` (modify, the closing of the chain judge prompt)
- `CHANGELOG.md` (modify)

**Do**
1. Test first in `tests/unit/test_models.py`: a new class (for example `TestJudgmentSchema`) with one test asserting that `list(Judgment.model_json_schema()["properties"])` puts `justification` before `verdict`. Import `Judgment` from `mcp_auditor.domain.models`. Run it red.
2. Reorder the fields of `Judgment` to `justification`, `verdict`, `severity`, as in "Change B". `EvalResult` keeps its order.
3. Replace the closing of `build_judge_prompt` and of the chain judge prompt with the texts of "Change B, `src/mcp_auditor/graph/prompts.py` and `src/mcp_auditor/graph/chain_prompts.py`", word for word. Nothing else in either prompt moves.
4. `CHANGELOG.md`, `[Unreleased]`, `### Changed`: one bullet, the judge writes its justification before its verdict, in its answer and in what both judge prompts ask.

**Test**
- `Judgment`'s JSON schema lists `justification` before `verdict`.
- Stay green unchanged: `tests/unit/test_anthropic_structured_output.py`, the judge node tests (`graph/nodes.py`, `graph/chain_nodes.py`), `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py`, `tests/unit/test_fixture_contamination.py`, step 1's `TestStrictSchemas`.

**Verify**
- The four closing checks, all green.
- Report, for the commit message: the four questions of ADR 016 (justification without the measurement, for the schema and the closing alike: a judge running with no reasoning has no other place to reason than the justification, and a verdict generated first cannot depend on it), that the prompt closing changed with the schema, that the red gate of `faf3727` was seen, did not show a regression (Context), and that B differs from it by A, `evals/declared_flips.json` stays empty.
- Before the commit, maintainer only: replay B against its bar ("Change B, Measurement"). The commit message carries its result. Bar missed: B is discarded uncommitted, step 3 is not attempted.
- After the commit, maintainer only: the three gates. A red gate reverts B, and step 3 is not attempted.

### Step 3: change 1's text, word for word (change C)

Attempted only if step 2 is committed and its gates are green.

**Files**
- `tests/unit/test_fixture_contamination.py` (modify)
- `tests/unit/support/test_fixture_contamination_given.py` (modify)
- `src/mcp_auditor/graph/prompts.py` (modify, rule 4 of `JUDGING_RULES`)
- `src/mcp_auditor/domain/category_guidance.py` (modify, `CATEGORY_GUIDANCE[AuditCategory.ERROR_HANDLING]`)
- `CHANGELOG.md` (modify)

**Do**, in this order, the texts taken word for word from "Change 1" of `plans/2026-10-23_judge-false-alarms.md` (sections `src/mcp_auditor/graph/prompts.py`, `src/mcp_auditor/domain/category_guidance.py`, `Docs` and `Tests`):
1. Replace rule 4 of `JUDGING_RULES` (line 22 of `src/mcp_auditor/graph/prompts.py`): the first two sentences unchanged, the third becomes "The framework's prefix `Error executing tool <name>:` in front of an exception's text does not make that text a formed error." Run `uv run pytest tests/unit/test_fixture_contamination.py` and confirm `test_no_constant_of_src_contains_a_honeypot_literal` is red on `Error executing tool`.
2. In `tests/unit/test_fixture_contamination.py`, class `TestShippedConstantsNameNoHoneypotLiteral`, add the guard test first: every literal of the new exclusion constant appears in the SDK source the given file returns (a helper in `test_fixture_contamination_given.py` returning `inspect.getsource(mcp.server.fastmcp.tools.base)`). Add an assertion that `"Error executing tool"` is not in `given.discriminating_literals()`. Run it red (the constant does not exist yet).
3. In `tests/unit/support/test_fixture_contamination_given.py`, add `SDK_TEXTS = {"Error executing tool"}` with a one-line comment giving the reason: the MCP SDK's own prefix, which FastMCP puts in front of any exception a tool raises and the honeypots copy to imitate the library, not a text planted to discriminate them. Subtract it in `discriminating_literals()`. All contamination tests green, the excluded-server corpus check included.
4. Replace `CATEGORY_GUIDANCE[AuditCategory.ERROR_HANDLING]` with the previous plan's text: the new opening paragraph ("What counts as an error_handling failure. First tell an error from a result: ..."), the first line with the sentence "A response that carries the result asked for is not an error." removed and the rest kept verbatim from "An error is formed when..." to "or it names no cause.", the second line verbatim, then the four "does NOT count" lines (the contradicted-parameter line new, the info_leakage line now "What a response or an error discloses. That is judged under info_leakage: here, only whether an error is formed."). No other category's guidance changes.
5. `CHANGELOG.md`, `[Unreleased]`, `### Changed`: one bullet with the wording of "Change 1, Docs" of the previous plan.

**Test**
- Guard test: each literal of `SDK_TEXTS` is a substring of the installed `mcp.server.fastmcp.tools.base` source.
- `discriminating_literals()` no longer contains `Error executing tool`, and the existing test that it plants discriminating literals stays green.
- `test_no_constant_of_src_contains_a_honeypot_literal`: red after Do 1, green after Do 3.
- Stay green unchanged: `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py`, the rest of `tests/unit/test_fixture_contamination.py`.

**Verify**
- The four closing checks, all green.
- Report, for the commit message, which names the guidance by its content (the error_handling guidance and rule 4 of the judging rules), not by the plan's labels: the four questions of ADR 016, that the clauses brought forward were chosen by reading eval traces (ADR 016 allows it), that the contradicted-parameter line follows from J2 and J3 by the mechanism and is the line `delete_record × error_handling` (R1) falls under, that this is the second and last attempt at change 1, the requirement of a new rubric reason lifted by a maintainer's decision taken after the first attempt missed, with the first attempt's miss and numbers (false-alarm set 40.6 % to 28.0 %, guard set 98.8 % under both, `search_products × error_handling` 46 % to 21 %, `delete_record × error_handling` 36 % to 33 %), and `evals/declared_flips.json` stays empty.
- Before the commit, maintainer only: replay C against its bar ("Change C, Measurement"). Bar missed or inconclusive: C is discarded uncommitted and change 1 is closed. Bar met: the commit message carries both replays' results.
- After the commit, maintainer only: the three gates. A red gate reverts C.
