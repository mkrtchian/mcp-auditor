from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel

from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ModelCallMissed

FAKE_USAGE = ProviderUsage(input_tokens=10, output_tokens=5)

type Billing = Callable[[type[BaseModel], int], ProviderUsage]


def flat_billing(output_schema: type[BaseModel], call_index: int) -> ProviderUsage:
    return FAKE_USAGE


class FakeLLM:
    """Pops one scripted response per call. A `ModelCallMissed` in the script is raised."""

    def __init__(
        self, responses: Sequence[BaseModel | ModelCallMissed], billing: Billing = flat_billing
    ):
        self._responses: deque[BaseModel | ModelCallMissed] = deque(responses)
        self._billing = billing
        self.billed: list[ProviderUsage] = []
        self.total_usage = ProviderUsage()
        self.prompts: list[str] = []

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        self.prompts.append(prompt)
        response = self._responses.popleft()
        if isinstance(response, ModelCallMissed):
            self.total_usage = self.total_usage.add(response.usage)
            raise response
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        usage = self._billing(output_schema, len(self.billed))
        self.billed.append(usage)
        self.total_usage = self.total_usage.add(usage)
        return response, usage


@dataclass
class RaisingLLM:
    error: Exception

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        raise self.error
