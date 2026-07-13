# ADR 012: OWASP Enrichment as a Computed Field

**Date:** 2026-07-13
**Status:** Accepted
**Supersedes:** ADR 008 (JSON injection mechanism only)

## Context

ADR 008 chose render-time derivation over a stored field for OWASP codes. The rejected option was a stored field: one that could drift from `category` and would require changes to the model, the node layer, and deserialization. The accepted mechanism enriches JSON output after serialization: `render_json` dumps the report, then `_inject_owasp_into_json` walks the raw dicts and mutates eval results in place. The rest of ADR 008 (the mapping table, the deliberately unmapped categories, the code vs label display choices) remains in force.

Three problems with that mechanism in practice:

- The dict walk re-derives structure the typed model already knows (tool reports, then cases and chains, then eval results). It needs six `type: ignore` comments and parses the category back out of the string it just serialized (`AuditCategory(result["category"])`).
- The same domain fact is encoded through two mechanisms in the same module: the markdown renderer derives OWASP from the typed model, the JSON renderer derives it from untyped dicts.
- ADR 008 framed the choice as a binary, stored field vs render-time injection. A third option was not on the table: a derived, non-stored field on the model itself.

## Decision

`EvalResult` gains a pydantic `@computed_field` named `owasp`. It returns `{"code": ..., "title": ...}` derived from `owasp_mapping_for(self.category)`, or `None` when the category has no mapping. `render_json` becomes a plain `model_dump` plus `json.dumps`. `_inject_owasp_into_json` and `_inject_owasp_on_result` are deleted.

Of ADR 008's rejection arguments, only the model change remains, and it is a single declaration:

- It cannot be inconsistent with `category`. It is recomputed from `category` on every serialization, never stored. A stale `owasp` value in a dump is discarded and recomputed on validation.
- It requires no node layer change and no deserialization change. Pydantic computed fields are output-only, and validation ignores the extra key on input (default model config).

Verified empirically before deciding (2026-07-12): round-trip through the langgraph checkpointer serializer (`JsonPlusSerializer`), `model_validate` on dumps containing the `owasp` key, and the pre-change model reading post-change dumps. All pass.

## Consequences

- OWASP data appears in every serialization of `EvalResult`: JSON report, checkpoints, eval artifacts. One source of truth, slightly larger payloads.
- The JSON report shape changes: `owasp` is now always present on eval results, `null` for unmapped categories. It used to be absent. Consumers must test the value, not the key presence.
- The dict traversal and its six `type: ignore` comments disappear from `domain/rendering.py`.
- Markdown, console, and progress output do not change. Their renderers keep using the display helpers (`category_with_owasp_label`, `category_with_owasp_id`).
