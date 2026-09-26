from pathlib import Path

import pytest
from pydantic import BaseModel

from evals.probe import CallOutcome, ProbeObservation
from evals.probe_candidates import REFERENCE
from evals.probe_corpus import ProbeCall
from evals.run_probe import CandidateModels, append_observation, observe
from mcp_auditor.domain.models import TokenUsage
from mcp_auditor.domain.ports import ProviderRefusal, UnparseableOutput

A_JUDGE_CALL = ProbeCall(
    call_id="honeypot/Judgment/000",
    schema_name="Judgment",
    role="judge",
    source="honeypot",
    prompt="prompt",
)


class _RaisingLLM:
    def __init__(self, error: Exception):
        self._error = error

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        raise self._error


def _models_raising(error: Exception) -> CandidateModels:
    llm = _RaisingLLM(error)
    return CandidateModels(candidate=REFERENCE, main=llm, judge=llm)


@pytest.mark.asyncio
async def test_unparseable_output_is_a_parse_failure():
    models = _models_raising(
        UnparseableOutput(attempts=3, truncated_attempts=0, usage=TokenUsage())
    )

    observation = await observe(models, A_JUDGE_CALL, budget=10)

    assert observation.outcome == CallOutcome.PARSE_FAILURE


@pytest.mark.asyncio
async def test_a_parse_failure_keeps_the_usage_and_the_truncation_of_its_attempts():
    usage = TokenUsage(input_tokens=100, output_tokens=8192)
    models = _models_raising(UnparseableOutput(attempts=3, truncated_attempts=1, usage=usage))

    observation = await observe(models, A_JUDGE_CALL, budget=10)

    assert observation.outcome == CallOutcome.PARSE_FAILURE
    assert observation.usage == usage
    assert observation.truncated_attempts == 1


@pytest.mark.asyncio
async def test_a_provider_refusal_is_a_parse_failure_carrying_its_usage_and_message():
    usage = TokenUsage(input_tokens=120, output_tokens=5)
    models = _models_raising(ProviderRefusal("flagged by the usage policy", usage))

    observation = await observe(models, A_JUDGE_CALL, budget=10)

    assert observation.outcome == CallOutcome.PARSE_FAILURE
    assert observation.usage == usage
    assert observation.error == "flagged by the usage policy"


@pytest.mark.asyncio
async def test_any_other_value_error_is_an_error_carrying_its_message():
    models = _models_raising(ValueError("400 invalid request"))

    observation = await observe(models, A_JUDGE_CALL, budget=10)

    assert observation.outcome == CallOutcome.ERROR
    assert observation.error == "ValueError: 400 invalid request"


@pytest.mark.asyncio
async def test_each_observation_is_appended_as_one_json_line(tmp_path: Path):
    sink = tmp_path / "probe_report.jsonl"
    first = await observe(_models_raising(ValueError("first")), A_JUDGE_CALL, budget=10)
    second = await observe(_models_raising(ValueError("second")), A_JUDGE_CALL, budget=10)

    append_observation(sink, first)
    append_observation(sink, second)

    lines = sink.read_text().splitlines()
    assert [ProbeObservation.model_validate_json(line) for line in lines] == [first, second]
