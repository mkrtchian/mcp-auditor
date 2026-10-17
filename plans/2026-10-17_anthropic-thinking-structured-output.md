# Anthropic with thinking: force the schema through native structured output

## Context

With thinking on, Anthropic's API drops a forced `tool_choice` (`UserWarning: tool_choice is forced but thinking is enabled ... Tool calls are not guaranteed`). The `anthropic` provider binds the output schema as a tool (`adapters/llm_tool_binding.py`), so the model sometimes answers without the tool, every parse attempt returns nothing, and the step fails. Seen on Anthropic models with reasoning: a generator or judge step is lost often enough to drop whole e2e passes. This breaks any run on an Anthropic model with thinking on, the chain-cost run included (it runs Haiku 5.5 with reasoning).

The fix is to move the `anthropic` provider off tool binding and onto Anthropic's native structured output (`with_structured_output(method="json_schema")`, `langchain-anthropic` 1.7.5, which sends `output_config.format`). The diligence of `plans/2026-10-17_audit-resilience.md` settled that `json_schema` forces the schema even with thinking (a grammar does not constrain thinking blocks), and that the one blocker is `AuditPayload.arguments: dict[str, Any]`: Anthropic structured output requires `additionalProperties: false` on every object, and `anthropic` 1.11.0's `transform_schema` rewrites the open object to one that can only be empty, so every payload would come back with `arguments: {}`. The fix carries `arguments` as a JSON string on the Anthropic path only, and decodes it back to a dict after the parse.

This is an adapter-level fix. No ADR: it does not change a decision ADR 002 (hexagonal, `LLMPort` abstracts structured output) already records, it implements it for one provider. No eval baseline is touched: the honeypot, judge and CVE acceptance baselines run under Luna `none` (the OpenAI path), and no gated cell uses the `anthropic` provider.

## Approach

On the `anthropic` provider, replace the tool-binding structured-output path with native `json_schema`, uniformly (thinking on or off). Confine the open-object fix to an anti-corruption layer in the adapter: a wire model mirrors each generator schema that embeds `AuditPayload`, with `arguments: str`, and a `to_domain()` translator decodes the JSON string back into the domain model. The domain models stay pure (`AuditPayload.arguments: dict[str, Any]` unchanged), the shared prompts stay provider-agnostic (the "arguments as a JSON string" instruction lives in the wire field's `description`, which Anthropic's structured output surfaces to the model, not in `graph/prompts.py` / `graph/chain_prompts.py`), and the generic `generate_structured` retry/`UnparseableOutput` machinery is reused unchanged: a wire parse that fails or an `arguments` string that is not valid JSON decodes to `None`, which the existing loop retries and finally reports as a missed step (the resilience change already makes that visible rather than fatal). The shared body prompt still calls the arguments "a dictionary", and the grammar forces the field to a string but cannot force its contents to be parseable JSON, so the wire field `description` carries an explicit double-quoted example (`{"id": 1}`, "not a Python dict repr") to steer the contents; a residual non-JSON answer degrades to the retried missed step above rather than a lost audit.

Wire models are chosen over a JSON-schema-dict transform plus a structural decode, as the cleaner boundary in the clean-architecture / DDD sense: an explicit, typed anti-corruption layer with the translation made first-class, rather than untyped dict patching coupled to Pydantic's schema-emission internals and Anthropic's `transform_schema`, and immune to a data value that happens to hold a key named `arguments`. A parity test keeps the wire models from drifting from the domain models.

Three generator schemas embed `AuditPayload` and need a wire variant: `TestCaseBatch` (test generation), `AuditPayload` on its own (chain step planning), and `ChainPlanBatch` (chain planning, via `ChainGoal.first_step`). The other Anthropic structured outputs carry no open object and bind to `json_schema` directly, with an identity translation: `Judgment` (judgment, chain judgment), `StepObservation` (chain step observation), `AttackContext` (context extraction).

## Files to modify

### New: `src/mcp_auditor/adapters/anthropic_structured_output.py`

Replaces `adapters/llm_tool_binding.py`. Holds the binding function, the schema-to-wire registry, and the wire models. Per the newspaper rule, the module reads top-down: the public `bind_anthropic_json_schema` first, then the registry and the wire models it reaches, each below its caller. The blocks below are shown bottom-up for explanation only.

Wire models (module-private), each a mirror of its domain model with `arguments` as a JSON string and a `to_domain()` translator:

```python
class _AuditPayloadWire(BaseModel):
    category: AuditCategory
    description: str = Field(description="What this test case verifies")
    arguments: str = Field(
        description='The tool call arguments as a JSON object encoded in a string, double-quoted, e.g. {"id": 1}. Not a Python dict repr.'
    )

    def to_domain(self) -> AuditPayload:
        return AuditPayload(
            category=self.category,
            description=self.description,
            arguments=json.loads(self.arguments),
        )


class _TestCaseBatchWire(BaseModel):
    cases: list[_AuditPayloadWire]

    def to_domain(self) -> TestCaseBatch: ...


class _ChainGoalWire(BaseModel):
    description: str
    category: AuditCategory
    first_step: _AuditPayloadWire

    def to_domain(self) -> ChainGoal: ...


class _ChainPlanBatchWire(BaseModel):
    chains: list[_ChainGoalWire]

    def to_domain(self) -> ChainPlanBatch: ...
```

`json.loads` on a non-string or malformed string raises; the binding wraps the translation so that a raise becomes a `None` parse (the generic loop then retries, then reports `UnparseableOutput`).

A registry maps each domain generator schema to its wire model:

```python
_WIRE_SCHEMAS: dict[type[BaseModel], type[BaseModel]] = {
    AuditPayload: _AuditPayloadWire,
    TestCaseBatch: _TestCaseBatchWire,
    ChainPlanBatch: _ChainPlanBatchWire,
}
```

Binding function, mirroring the shape `adapters/llm.py` already consumes (`{"raw": AIMessage, "parsed": <domain instance | None>}`, so `LLM._unpack_raw_response` stays the single coupling point and does not change):

```python
def bind_anthropic_json_schema(
    model: BaseChatModel, output_schema: type[BaseModel]
) -> Runnable[str, object]:
    wire = _WIRE_SCHEMAS.get(output_schema)
    bind_schema = wire or output_schema
    base = model.with_structured_output(bind_schema, method="json_schema", include_raw=True)
    translate = _to_domain_or_none if wire else _identity  # wire instance -> domain, catching json errors; else passthrough
    return base | RunnablePassthrough.assign(parsed=lambda d: translate(d["parsed"]))
```

`_to_domain_or_none(None) -> None`, `_to_domain_or_none(wire_instance)` returns `wire_instance.to_domain()` and returns `None` on `json.JSONDecodeError` / `ValidationError` so a bad `arguments` string feeds the retry path rather than raising out of the call. The `"raw"` field is left in place by `.assign`, so refusal and truncation detection read it exactly as before.

### Removed: `src/mcp_auditor/adapters/llm_tool_binding.py`

Only `adapters/llm.py` imports it, and only the `anthropic` provider used it. After this change nothing binds a schema as a tool, so the module and its `bind_schema_as_tool` go.

### `src/mcp_auditor/adapters/llm.py`

- `StructuredOutput.method` Literal: drop `"tool_binding"`, add `"anthropic_json_schema"` (keep `"json_schema"`, `"function_calling"`).
- `_STRUCTURED_OUTPUT["anthropic"]`: `StructuredOutput(method="anthropic_json_schema")` (no `schema_as_dict`). Rewrite the comment above `_STRUCTURED_OUTPUT` and the import: Anthropic now uses native structured output, forced even with thinking; `arguments` is carried as a JSON string on this path and decoded in the adapter; an answer without a valid structured output (a refusal, a cut during thinking, a non-JSON `arguments` string) still reaches the refusal and truncation checks.
- `_bind`: route `method == "anthropic_json_schema"` to `bind_anthropic_json_schema(self._model, output_schema)`. Replace the `tool_binding` branch. The two remaining `with_structured_output` branches (dict / model) are unchanged.
- `_unpack_raw_response`, `generate_structured`, `_validated`, usage accounting: unchanged.

### `src/mcp_auditor/adapters/chat_model_factory.py`

Code unchanged, one comment rewritten. The comment above `_anthropic_thinking` ("An explicit adaptive thinking keeps langchain-anthropic from forcing the tool call, which would skip thinking whatever the effort") gives a reason that belongs to the `function_calling` branch of `with_structured_output`, which nothing takes after this change. The explicit `{"type": "adaptive"}` still earns its place: `langchain-anthropic` 1.7.5 defaults an unset `thinking` with an `effort` to `{"type": "adaptive", "display": "summarized"}`, which asks for summarized thinking in every answer. Replace the comment with that reason (pinning the thinking type without the summarized display). `test_anthropic_at_an_effort_thinks_adaptively` pins the behaviour and does not change.

### Tests

- Rename `tests/unit/test_llm_tool_binding.py` -> `tests/unit/test_anthropic_structured_output.py` and `tests/unit/support/test_llm_tool_binding_given.py` -> `tests/unit/support/test_anthropic_structured_output_given.py`. Keep the `httpx2.MockTransport` replay pattern: it exercises the real `with_structured_output(method="json_schema")` path at the adapter level with no API key, by replaying a canned Anthropic message body. The `given` builds a `json_schema` structured-output answer (the JSON text matching the wire schema, with `arguments` as a JSON-encoded string) in place of the tool-use block, and `an_llm_on` builds the `StructuredOutput(method="anthropic_json_schema")` LLM.
- The existing behaviours are kept as scenarios on the new path: a refusal raises `ProviderRefusal` with its category, a cut during thinking counts as truncated, an answer that never yields a valid structured output is retried then `UnparseableOutput`. The "forced tool" no-thinking scenario is replaced by the uniform `json_schema` path with thinking disabled.
- New scenarios: a `TestCaseBatch` answer returns the domain batch with each case's `arguments` decoded to the expected dict (including a nested value and an empty `{}`); a bare `AuditPayload` answer (chain step planning) decodes `arguments`; a `ChainPlanBatch` answer decodes `first_step.arguments`; a `Judgment` answer (no wire) returns the domain `Judgment`; an `arguments` field holding non-JSON text is retried then `UnparseableOutput`.
- A parity test over every mirror pair, not just the `_WIRE_SCHEMAS` registry: the three registry entries (`AuditPayload`, `TestCaseBatch`, `ChainPlanBatch`) plus the embedded `ChainGoal` / `_ChainGoalWire` pair (`ChainGoal` is not in the bind registry, so a parity test that iterated `_WIRE_SCHEMAS` alone would never check it, and a new `ChainGoal` field would slip through). For each pair the wire model's field names equal the domain model's. For each field: a leaf field (a plain, non-mirrored type) must carry the identical annotation on the wire, except `arguments`, whose type is intentionally `dict[str, Any]` on the domain side and `str` on the wire; a field whose domain annotation is a mirrored model, or a list of one (`cases: list[AuditPayload]`, `chains: list[ChainGoal]`, `first_step: AuditPayload`), must reference the corresponding wire model on the wire side rather than match annotations. So a new field on `AuditPayload` or `ChainGoal` that is not mirrored fails the field-name check.
- `tests/unit/test_llm_adapter.py`, `tests/unit/test_chat_model_factory.py`: check for any reference to `tool_binding` / `bind_schema_as_tool` / the removed module and update (the factory itself is unchanged; `_anthropic_thinking` stays).

### Living docs

- `CHANGELOG.md` `[Unreleased]`: the Anthropic entry under `### Changed` that currently ends "It binds the output schema as a tool itself, so an answer without the tool call ... reaches the refusal and truncation checks" is edited in place (tool binding never shipped): the provider now uses Anthropic's native structured output, which forces the schema even with thinking on, carrying a tool call's arguments as a JSON string on that path and decoding them back, so a payload comes back with its arguments instead of being lost when the model answers without a forced tool; an answer with no valid structured output (a refusal, a cut during thinking, a non-JSON arguments string) still reaches the refusal and truncation checks.
- `README.md`: the environment/measurement section names no structured-output mechanism, so no change expected; confirm during implementation.
- `CLAUDE.md` (project) Landmines: add one line next to the `with_structured_output` / `TestCaseBatch` note: on the `anthropic` provider the generator schemas are bound through wire models with `arguments` as a JSON string (`adapters/anthropic_structured_output.py`), because Anthropic structured output forbids the open `AuditPayload.arguments` object; a new field on `AuditPayload` or `ChainGoal` must be mirrored on its wire model (the parity test guards it).

## What stays unchanged

- Domain models: `AuditPayload.arguments: dict[str, Any]`, `TestCaseBatch`, `ChainGoal`, `ChainPlanBatch`, `Judgment`, `StepObservation`, `AttackContext` are untouched. The wire models live only in the adapter.
- `graph/prompts.py` and `graph/chain_prompts.py`: provider-agnostic, unchanged. Past payloads fed back as context (`json.dumps(payload.arguments)`) are unchanged.
- The other providers' structured-output paths (`google`, `openai`, `fireworks`, `alibaba`, `openrouter`) and the code of `chat_model_factory.py` (`_anthropic_thinking` included, only its comment is rewritten, see above).
- `LLMPort`, `generate_structured`'s retry loop, `UnparseableOutput` / `ProviderRefusal` / `ProviderThrottled`, `_unpack_raw_response`, usage accounting, and the missed-step handling in `graph/missed_steps.py`.
- No eval baseline, fixture or gate: the `anthropic` provider is not under any gated baseline.

## Edge cases

- Model emits `arguments` as a non-JSON string (prose, a Python-dict repr): `json.loads` raises, the parse is `None`, the attempt is retried up to `max_parse_attempts`, then `UnparseableOutput` -> a visible missed step. Rare, and no worse than today's silent failure; the wire field `description`'s double-quoted example steers against it.
- Empty arguments: the model emits `"{}"`, decoded to `{}`.
- A schema with no `AuditPayload` (`Judgment`, `StepObservation`, `AttackContext`): bound directly, identity translation, parsed is already the domain instance.
- Thinking disabled (`reasoning="none"`): the uniform `json_schema` path forces the schema just as with thinking on.
- A refusal or a cut at the output cap on the `json_schema` path: detected from the raw message's `response_metadata` (`stop_reason` `refusal` / `max_tokens`), exactly as on the tool-binding path.
- An `arguments` value that itself contains a key named `arguments`: irrelevant, only the schema-level field is a string (the reason wire models beat a structural dict decode).

## Test scenarios

Unit, at the adapter level, with the `MockTransport` replay (no API key):

1. `TestCaseBatch` answer -> domain batch, each `arguments` decoded (nested value and empty `{}` covered). Usage read as before.
2. Bare `AuditPayload` answer -> domain payload, `arguments` decoded.
3. `ChainPlanBatch` answer -> domain batch, `first_step.arguments` decoded.
4. `Judgment` answer (no wire) -> domain `Judgment`.
5. `arguments` holding non-JSON text -> retried then `UnparseableOutput`, usage carried.
6. Refusal -> `ProviderRefusal` with category, usage carried.
7. Cut during thinking -> `truncated_attempts == 3`.
8. Parity: every mirror pair (the three `_WIRE_SCHEMAS` entries plus `ChainGoal` / `_ChainGoalWire`) has matching field names; leaf fields match annotations (`arguments` excepted, `dict` -> `str`), and a field whose domain type is a mirrored model or a list of one points at the matching wire model.

Manual integration (needs `ANTHROPIC_API_KEY`, not in CI): a short audit on `claude-haiku-5-5` with `MCP_AUDITOR_REASONING=low` against a honeypot returns payloads with non-empty `arguments` and no `UnparseableOutput` from missing tool calls.

## Verification

- `uv run pytest -n auto`
- `uv run ruff check .` and `uv run ruff format --check .`
- `uv run pyright`

## Open, to settle in the review/diligence passes

- Confirm Anthropic's native structured output (`json_schema`) is supported by every Claude model this project runs on the `anthropic` provider: the default `claude-haiku-4-5`, `claude-haiku-5-5`, `claude-opus-4-8` and Fable 5.1. The platform docs present structured outputs as available on current Claude models, but this must be verified against the structured-outputs doc (model list, and any beta header the installed `langchain-anthropic` 1.7.5 / `anthropic` 1.11.0 send). If a used model does not support it, decide before implementing whether to keep `function_calling` as a fallback for that model only.
- Confirm `anthropic` 1.11.0's `transform_schema` turns a `str` field into `{"type": "string"}` and does not choke on `list[_AuditPayloadWire]` (a list of closed objects): the open-object rewrite was the only reported blocker.
- Confirm adaptive thinking plus `json_schema` plus `max_tokens=8192` leaves room for the structured answer on the generator batches (the batch sizes seen at `low`/`medium` are well under the cap).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, kept here so the implementation-phase fact check can read it. No pass may treat a line below as a reason to skip a verification: the record says what was concluded once, on 2026-10-17, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `langchain-anthropic` 1.7.5 is installed and `ChatAnthropic.with_structured_output(schema, method="json_schema", include_raw=True)` sends the schema as `output_config.format` and returns `{"raw": AIMessage, "parsed": ...}` with a `parsed=None` fallback on a parse failure, not a raise (verified against the installed `langchain_anthropic/chat_models.py`)
- SETTLED: `anthropic` 1.11.0's `transform_schema`, which `langchain-anthropic` applies on this path, maps a `str` field to `{"type": "string"}` and a `list` of closed objects to an array of `$ref` without choking, and rewrites the open `dict[str, Any]` to `{"type": "object", "properties": {}, "additionalProperties": false}`, the empty object that is the plan's whole reason for the wire models (verified by running `transform_schema` on the installed package against the wire shapes)
- SETTLED: native structured outputs (`output_config.format` / `json_schema`) are supported on every model this project runs on the `anthropic` provider, `claude-haiku-4-5-20251001` (the default), `claude-haiku-5-5`, `claude-opus-4-8` and `claude-fable-5-1`, and no beta header is required for `output_config.format` (verified against platform.claude.com/docs/en/build-with-claude/structured-outputs `supportedModels`, and the installed `langchain-anthropic` note that beta headers are no longer required)
- SETTLED: refusal and truncation detection is the unchanged `response_metadata` read in `adapters/llm.py` (`_was_truncated`, `refusal_from_metadata`), and `stop_reason` `refusal` / `max_tokens` on the structured-output path is documented platform behavior (verified against the structured-outputs doc; the detection code does not change on this path)
- SETTLED: the wire field `description` reaches the request: `anthropic` 1.11.0's `transform_schema` keeps `description` on the `arguments` string field, and `langchain-anthropic` 1.7.5's `_convert_to_anthropic_output_config_format` is that call with no further rewrite (verified by running both on the installed packages against `_TestCaseBatchWire`'s shape); the structured-outputs doc lists `description` among the constraints "sent in the schema" and has the SDK fold unsupported constraints into descriptions for the model to read, which is the mitigation's channel. What the model does with it is the OPEN line below
- SETTLED: on the `json_schema` path `langchain-anthropic` 1.7.5 parses the raw message's text blocks with a `PydanticOutputParser`, thinking blocks skipped, and a message with no parseable text falls back to `parsed=None` under `include_raw=True` (verified on the installed package), so the replay bodies in the given are a `text` block with the JSON document and `stop_reason: "end_turn"`
- OPEN (deferred): whether the model-emitted `arguments` string is valid JSON on the Anthropic path is left to the manual integration test (not in CI, needs `ANTHROPIC_API_KEY`). The shared body prompt says "a dictionary of arguments" while only the wire field `description` asks for a JSON object encoded as a string, and the grammar forces a string but cannot force its contents to be parseable JSON, so a Python-dict repr or prose decodes to `None` and degrades to a retried missed step. The plan mitigates it on the plan side (the wire field `description` carries an explicit double-quoted example), but the live contents stay unverified without the integration test
- OPEN (deferred): that adaptive thinking plus `json_schema` plus `max_tokens=8192` leaves room for a full generator batch is an internal capacity assumption the plan defers to the same manual integration test

## Implementation steps

### Step 1: Move the `anthropic` provider onto native `json_schema` with wire models

Single atomic change: one new adapter module, one removed module, a surgical edit to `adapters/llm.py`, the two renamed/rewritten test files, and the living-docs edits. One commit.

**Files**:
- New: `src/mcp_auditor/adapters/anthropic_structured_output.py`
- Removed: `src/mcp_auditor/adapters/llm_tool_binding.py`
- Modify: `src/mcp_auditor/adapters/llm.py`
- Modify (comment only): `src/mcp_auditor/adapters/chat_model_factory.py`
- Rename: `tests/unit/test_llm_tool_binding.py` -> `tests/unit/test_anthropic_structured_output.py`
- Rename: `tests/unit/support/test_llm_tool_binding_given.py` -> `tests/unit/support/test_anthropic_structured_output_given.py`
- Modify: `CHANGELOG.md`, `CLAUDE.md` (project)

**Do** (tests first, then production):

1. Write the renamed test support file `tests/unit/support/test_anthropic_structured_output_given.py`, adapting the existing `httpx2.MockTransport` replay helpers (`a_chat_model_answering`, `_message`, `_thinking_block`, the refusal/cut builders stay). Changes:
   - `an_llm_on` builds `StructuredOutput(method="anthropic_json_schema")` (drop the `schema_as_dict` param, no longer used on this path).
   - Replace `a_tool_use_answer` with a `json_schema` answer builder: a `{"type": "text", "text": <JSON document>}` content block after the thinking block, the JSON matching the bound (wire) schema with `arguments` as a JSON-encoded string (so the body carries it escaped, `"arguments": "{\"id\": 1}"`), and `stop_reason: "end_turn"`. This is the shape the installed `langchain-anthropic` 1.7.5 parses on the `json_schema` path: `with_structured_output(method="json_schema", include_raw=True)` runs a `PydanticOutputParser` over the raw message's text blocks (thinking blocks are skipped, verified on the installed package), and a message with no text block, a thinking-only cut or a refusal text that is not JSON, raises inside the parser and falls back to `parsed=None`, so `{"raw", "parsed"}` is always returned.
   - Keep domain schema imports (`AuditPayload`, `TestCaseBatch`, `ChainPlanBatch`, `ChainGoal`, `Judgment`) available for the scenario builders; the local `Finding` model can stay for simple cases or be dropped in favor of real schemas.
2. Write the renamed test file `tests/unit/test_anthropic_structured_output.py` with the scenarios of the plan's "Test scenarios" (1 through 8):
   - `TestCaseBatch` answer -> domain batch, each `arguments` decoded, including a nested value and an empty `{}`; usage read as before.
   - Bare `AuditPayload` answer -> domain payload, `arguments` decoded.
   - `ChainPlanBatch` answer -> domain batch, `first_step.arguments` decoded.
   - `Judgment` answer (no wire) -> domain `Judgment`.
   - `arguments` holding non-JSON text -> retried then `UnparseableOutput`, usage carried.
   - Refusal -> `ProviderRefusal` with category, usage carried.
   - Cut during thinking -> `truncated_attempts == 3`.
   - Parity test over every mirror pair: the three `_WIRE_SCHEMAS` entries (`AuditPayload`, `TestCaseBatch`, `ChainPlanBatch`) plus the embedded `ChainGoal` / `_ChainGoalWire` pair. For each pair, wire field names equal domain field names; each leaf field carries the identical annotation except `arguments` (`dict[str, Any]` domain -> `str` wire); each field whose domain annotation is a mirrored model or a list of one references the corresponding wire model.
   - Delete the old "forced tool" no-thinking scenario; replace it with the uniform `json_schema` path (keep a thinking-disabled variant only if it adds signal).
   - Run these and confirm they fail before the production code exists (red first).
3. Create `src/mcp_auditor/adapters/anthropic_structured_output.py`, newspaper order (public `bind_anthropic_json_schema` first, then `_WIRE_SCHEMAS`, then the wire models and `to_domain`/`_to_domain_or_none`/`_identity` helpers below). Follow the plan's "New" section exactly: wire models `_AuditPayloadWire`, `_TestCaseBatchWire`, `_ChainGoalWire`, `_ChainPlanBatchWire`; registry maps `AuditPayload`/`TestCaseBatch`/`ChainPlanBatch` to their wire; binding returns `base | RunnablePassthrough.assign(parsed=...)` preserving the `{"raw", "parsed"}` shape so `_unpack_raw_response` stays the single coupling point. `_to_domain_or_none` returns `None` on `json.JSONDecodeError` / `ValidationError` so a bad `arguments` string feeds the retry path rather than raising.
4. Edit `src/mcp_auditor/adapters/llm.py`:
   - `StructuredOutput.method` Literal: drop `"tool_binding"`, add `"anthropic_json_schema"` (keep `"json_schema"`, `"function_calling"`).
   - `_STRUCTURED_OUTPUT["anthropic"]` -> `StructuredOutput(method="anthropic_json_schema")` (no `schema_as_dict`). Rewrite the comment above `_STRUCTURED_OUTPUT` per the plan (native structured output, forced even with thinking, `arguments` carried as a JSON string and decoded in the adapter, refusal/truncation still reached).
   - Swap the import `from ...llm_tool_binding import bind_schema_as_tool` for `from ...anthropic_structured_output import bind_anthropic_json_schema`.
   - `_bind`: replace the `tool_binding` branch with `if method == "anthropic_json_schema": return bind_anthropic_json_schema(self._model, output_schema)`. Leave the two `with_structured_output` branches (dict / model) unchanged.
   - Everything else (`_unpack_raw_response`, `generate_structured`, `_validated`, usage accounting) unchanged.
5. Delete `src/mcp_auditor/adapters/llm_tool_binding.py`.
5b. `src/mcp_auditor/adapters/chat_model_factory.py`: rewrite the comment above `_anthropic_thinking` per the plan's section (the forced-tool-call reason is gone; the explicit adaptive type keeps `langchain-anthropic` from defaulting to `display: summarized` alongside the effort). No code change.
6. Living docs:
   - `CHANGELOG.md` `[Unreleased]` `### Changed`: edit the existing Anthropic entry in place per the plan's wording (native structured output, forces the schema even with thinking, carries arguments as a JSON string and decodes them back, refusal/cut/non-JSON still reach the checks).
   - `CLAUDE.md` Landmines: add one line next to the `with_structured_output` / `TestCaseBatch` note per the plan (generator schemas bound through wire models with `arguments` as a JSON string in `adapters/anthropic_structured_output.py`; a new field on `AuditPayload` or `ChainGoal` must be mirrored on its wire model, parity test guards it).
   - `README.md`: confirm the environment/measurement section names no structured-output mechanism; no change expected.
   - `tests/unit/test_llm_adapter.py`, `tests/unit/test_chat_model_factory.py`: confirmed clean (no `tool_binding` / `bind_schema_as_tool` references at planning time); re-grep and update only if a reference exists.

**Test**: the 8 scenarios above. Key expectations: arguments decode to the exact dict (nested and `{}`); a non-JSON `arguments` string degrades to `UnparseableOutput` after `max_parse_attempts` with usage carried; `Judgment` (no wire) returns the domain instance via identity translation; the parity test fails if a new unmirrored field is added to `AuditPayload` or `ChainGoal`.

**Verify** (closing-step full checks, no file argument):
- `uv run pytest -n auto`
- `uv run ruff check .` and `uv run ruff format --check .`
- `uv run pyright`
