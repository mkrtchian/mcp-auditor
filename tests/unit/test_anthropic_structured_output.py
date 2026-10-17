import json
from typing import Any, get_args, get_origin

import pytest
from pydantic import BaseModel

import tests.unit.support.test_anthropic_structured_output_given as given
from mcp_auditor.adapters import anthropic_structured_output as wire
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    ProviderUsage,
    Severity,
    TestCaseBatch,
)
from mcp_auditor.domain.ports import ProviderRefusal, UnparseableOutput


def _wire_payload(category: str, description: str, arguments: object) -> dict[str, Any]:
    return {"category": category, "description": description, "arguments": json.dumps(arguments)}


async def test_a_test_case_batch_decodes_each_argument():
    nested = {"query": {"nested": [1, 2]}}
    document = {
        "cases": [
            _wire_payload("injection", "nested args", nested),
            _wire_payload("input_validation", "empty args", {}),
        ]
    }
    llm = given.an_llm_answering(given.a_json_schema_answer(document, 120, 40))

    output, usage = await llm.generate_structured("prompt", TestCaseBatch)

    assert output == TestCaseBatch(
        cases=[
            AuditPayload(
                category=AuditCategory.INJECTION, description="nested args", arguments=nested
            ),
            AuditPayload(
                category=AuditCategory.INPUT_VALIDATION, description="empty args", arguments={}
            ),
        ]
    )
    assert usage == ProviderUsage(input_tokens=120, output_tokens=40, largest_input_tokens=120)


async def test_a_bare_audit_payload_decodes_its_arguments():
    document = _wire_payload("injection", "step", {"id": 1})
    llm = given.an_llm_answering(given.a_json_schema_answer(document, 50, 20))

    output, _usage = await llm.generate_structured("prompt", AuditPayload)

    assert output == AuditPayload(
        category=AuditCategory.INJECTION, description="step", arguments={"id": 1}
    )


async def test_a_chain_plan_batch_decodes_the_first_step_arguments():
    document = {
        "chains": [
            {
                "description": "traverse",
                "category": "injection",
                "first_step": _wire_payload("injection", "read", {"path": "/etc/passwd"}),
            }
        ]
    }
    llm = given.an_llm_answering(given.a_json_schema_answer(document, 60, 30))

    output, _usage = await llm.generate_structured("prompt", ChainPlanBatch)

    assert output == ChainPlanBatch(
        chains=[
            ChainGoal(
                description="traverse",
                category=AuditCategory.INJECTION,
                first_step=AuditPayload(
                    category=AuditCategory.INJECTION,
                    description="read",
                    arguments={"path": "/etc/passwd"},
                ),
            )
        ]
    )


async def test_a_judgment_has_no_wire_and_returns_the_domain_instance():
    document = {"verdict": "fail", "justification": "leaked internals", "severity": "high"}
    llm = given.an_llm_answering(given.a_json_schema_answer(document, 40, 15))

    output, _usage = await llm.generate_structured("prompt", Judgment)

    assert output == Judgment(
        verdict=EvalVerdict.FAIL, justification="leaked internals", severity=Severity.HIGH
    )


async def test_non_json_arguments_is_retried_then_unparseable_with_usage():
    document = {"cases": [{"category": "injection", "description": "d", "arguments": "not json"}]}
    llm = given.an_llm_answering(given.a_json_schema_answer(document, 120, 40))

    with pytest.raises(UnparseableOutput) as raised:
        await llm.generate_structured("prompt", TestCaseBatch)

    assert raised.value.truncated_attempts == 0
    assert raised.value.usage == ProviderUsage(
        input_tokens=360, output_tokens=120, largest_input_tokens=120
    )


async def test_a_refusal_raises_provider_refusal_with_usage():
    llm = given.an_llm_answering(given.a_refusal())

    with pytest.raises(ProviderRefusal, match="stop_reason refusal, category cyber") as raised:
        await llm.generate_structured("prompt", Judgment)

    assert raised.value.usage == ProviderUsage(
        input_tokens=100, output_tokens=10, largest_input_tokens=100
    )


async def test_an_answer_cut_during_thinking_counts_as_truncated():
    llm = given.an_llm_answering(given.a_cut_during_thinking())

    with pytest.raises(UnparseableOutput) as raised:
        await llm.generate_structured("prompt", Judgment)

    assert raised.value.truncated_attempts == 3


_MIRROR_PAIRS: dict[type[BaseModel], type[BaseModel]] = {
    AuditPayload: wire._AuditPayloadWire,  # pyright: ignore[reportPrivateUsage]
    TestCaseBatch: wire._TestCaseBatchWire,  # pyright: ignore[reportPrivateUsage]
    ChainPlanBatch: wire._ChainPlanBatchWire,  # pyright: ignore[reportPrivateUsage]
    ChainGoal: wire._ChainGoalWire,  # pyright: ignore[reportPrivateUsage]
}


@pytest.mark.parametrize(("domain", "wire_model"), _MIRROR_PAIRS.items())
def test_wire_models_mirror_their_domain_models(
    domain: type[BaseModel], wire_model: type[BaseModel]
):
    assert set(domain.model_fields) == set(wire_model.model_fields)
    for name in domain.model_fields:
        domain_type = domain.model_fields[name].annotation
        wire_type = wire_model.model_fields[name].annotation
        if name == "arguments":
            assert wire_type is str
        else:
            assert wire_type == _expected_wire_annotation(domain_type)


def _expected_wire_annotation(domain_type: object) -> object:
    for domain_model, wire_model in _MIRROR_PAIRS.items():
        if domain_type is domain_model:
            return wire_model
        if get_origin(domain_type) is list and get_args(domain_type) == (domain_model,):
            return list[wire_model]
    return domain_type
