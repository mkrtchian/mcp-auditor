import pytest
from pydantic import BaseModel

from evals.probe import CallOutcome
from evals.probe_candidates import REFERENCE
from evals.probe_corpus import ProbeCall
from evals.run_probe import CandidateModels, observe
from mcp_auditor.domain.models import TokenUsage
from mcp_auditor.domain.ports import UnparseableOutput

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
    models = _models_raising(UnparseableOutput("unparseable output after 3 attempts"))

    observation = await observe(models, A_JUDGE_CALL, budget=10)

    assert observation.outcome == CallOutcome.PARSE_FAILURE


@pytest.mark.asyncio
async def test_any_other_value_error_is_an_error_carrying_its_message():
    models = _models_raising(ValueError("400 invalid request"))

    observation = await observe(models, A_JUDGE_CALL, budget=10)

    assert observation.outcome == CallOutcome.ERROR
    assert observation.error == "ValueError: 400 invalid request"
