import pytest

import tests.unit.support.test_llm_tool_binding_given as given
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal, UnparseableOutput


@pytest.mark.parametrize("schema_as_dict", [False, True])
async def test_a_tool_call_returns_the_schema_instance_and_its_usage(schema_as_dict: bool):
    chat_model = given.a_chat_model_answering(given.a_tool_use_answer(120, 40))
    llm = given.an_llm_on(chat_model, schema_as_dict)

    output, usage = await llm.generate_structured("prompt", given.Finding)

    assert output == given.Finding(value="ok")
    assert usage == ProviderUsage(input_tokens=120, output_tokens=40, largest_input_tokens=120)


async def test_an_answer_without_a_tool_call_is_retried_then_unparseable():
    llm = given.an_llm_answering(given.a_thinking_only_answer())

    with pytest.raises(UnparseableOutput) as raised:
        await llm.generate_structured("prompt", given.Finding)

    assert raised.value.truncated_attempts == 0
    assert raised.value.usage == ProviderUsage(
        input_tokens=300, output_tokens=150, largest_input_tokens=100
    )


async def test_a_refusal_raises_provider_refusal_on_the_first_attempt():
    llm = given.an_llm_answering(given.a_refusal())

    with pytest.raises(ProviderRefusal, match="stop_reason refusal, category cyber") as raised:
        await llm.generate_structured("prompt", given.Finding)

    assert raised.value.usage == ProviderUsage(
        input_tokens=100, output_tokens=10, largest_input_tokens=100
    )


async def test_an_answer_cut_during_thinking_counts_as_truncated():
    llm = given.an_llm_answering(given.a_cut_during_thinking())

    with pytest.raises(UnparseableOutput) as raised:
        await llm.generate_structured("prompt", given.Finding)

    assert raised.value.truncated_attempts == 3


async def test_a_refusal_with_the_tool_call_forced_raises_provider_refusal():
    llm = given.an_llm_answering(given.a_refusal(), thinking="disabled")

    with pytest.raises(ProviderRefusal, match="stop_reason refusal"):
        await llm.generate_structured("prompt", given.Finding)
