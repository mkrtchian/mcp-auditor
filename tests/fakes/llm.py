from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import BaseModel

from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal, ProviderThrottled, UnparseableOutput

FAKE_USAGE = ProviderUsage(input_tokens=10, output_tokens=5)

type ModelFailure = ProviderRefusal | ProviderThrottled | UnparseableOutput


class FakeLLM:
    """Pops one scripted response per call. A `ModelFailure` in the script is raised."""

    def __init__(self, responses: Sequence[BaseModel | ModelFailure]):
        self._responses: deque[BaseModel | ModelFailure] = deque(responses)
        self.total_usage = ProviderUsage()
        self.prompts: list[str] = []

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        self.prompts.append(prompt)
        response = self._responses.popleft()
        if isinstance(response, ProviderRefusal | ProviderThrottled | UnparseableOutput):
            self.total_usage = self.total_usage.add(response.usage)
            raise response
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        self.total_usage = self.total_usage.add(FAKE_USAGE)
        return response, FAKE_USAGE  # type: ignore[return-value]


@dataclass
class RaisingLLM:
    error: Exception

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        raise self.error
