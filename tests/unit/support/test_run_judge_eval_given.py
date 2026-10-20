from dataclasses import dataclass

from pydantic import BaseModel

from evals.judge_fixture import JudgeCase
from mcp_auditor.domain.models import EvalVerdict, Judgment, Severity
from mcp_auditor.domain.ports import ProviderUsage
from tests.unit.support.test_judge_baseline_given import a_judge_fixture


def a_judge_case() -> JudgeCase:
    return a_judge_fixture().cases[0]


@dataclass
class AnsweringLLM:
    verdict: EvalVerdict
    usage: ProviderUsage

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        judgment = Judgment(verdict=self.verdict, justification="judged", severity=Severity.LOW)
        return output_schema.model_validate(judgment.model_dump()), self.usage
