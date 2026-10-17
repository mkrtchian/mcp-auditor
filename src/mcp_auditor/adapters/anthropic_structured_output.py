"""Anthropic native structured output, with a wire layer for the open arguments object.

Anthropic's structured output forbids an open object (AuditPayload.arguments: dict[str, Any]):
its schema transform rewrites one to an object that can only be empty. The generator schemas
that embed AuditPayload are bound through a wire mirror that carries arguments as a JSON string,
decoded back to a dict after the parse. Schemas with no open object bind directly, with an
identity translation. The binding keeps with_structured_output's {"raw", "parsed"} shape, so
LLM._unpack_raw_response stays the single coupling point.
"""

import json
from typing import cast

from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_core.runnables import Runnable, RunnablePassthrough
from pydantic import BaseModel, Field, ValidationError

from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    TestCaseBatch,
)


def bind_anthropic_json_schema(
    model: BaseChatModel,  # pyright: ignore[reportMissingTypeStubs]
    output_schema: type[BaseModel],
) -> Runnable[str, object]:
    wire = _WIRE_SCHEMAS.get(output_schema)
    bind_schema = wire or output_schema
    base = model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
        bind_schema, method="json_schema", include_raw=True
    )
    translate = _to_domain_or_none if wire else _identity
    chain = base | RunnablePassthrough.assign(  # pyright: ignore[reportUnknownVariableType, reportOperatorIssue]
        parsed=lambda response: translate(response["parsed"])
    )
    return cast(Runnable[str, object], chain)


class _AuditPayloadWire(BaseModel):
    category: AuditCategory
    description: str = Field(description="What this test case verifies")
    arguments: str = Field(
        description="The tool call arguments as a JSON object encoded in a string, "
        'double-quoted, e.g. {"id": 1}. Not a Python dict repr.'
    )

    def to_domain(self) -> AuditPayload:
        return AuditPayload(
            category=self.category,
            description=self.description,
            arguments=json.loads(self.arguments),
        )


class _TestCaseBatchWire(BaseModel):
    cases: list[_AuditPayloadWire]

    def to_domain(self) -> TestCaseBatch:
        return TestCaseBatch(cases=[case.to_domain() for case in self.cases])


class _ChainGoalWire(BaseModel):
    description: str
    category: AuditCategory
    first_step: _AuditPayloadWire

    def to_domain(self) -> ChainGoal:
        return ChainGoal(
            description=self.description,
            category=self.category,
            first_step=self.first_step.to_domain(),
        )


class _ChainPlanBatchWire(BaseModel):
    chains: list[_ChainGoalWire]

    def to_domain(self) -> ChainPlanBatch:
        return ChainPlanBatch(chains=[chain.to_domain() for chain in self.chains])


_WIRE_SCHEMAS: dict[type[BaseModel], type[BaseModel]] = {
    AuditPayload: _AuditPayloadWire,
    TestCaseBatch: _TestCaseBatchWire,
    ChainPlanBatch: _ChainPlanBatchWire,
}


def _to_domain_or_none(parsed: object) -> object:
    # A wire parse that fails or an arguments string that is not JSON becomes None, which the
    # generate_structured loop retries and finally reports as UnparseableOutput.
    if parsed is None:
        return None
    try:
        return parsed.to_domain()  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
    except (json.JSONDecodeError, ValidationError):
        return None


def _identity(parsed: object) -> object:
    return parsed
