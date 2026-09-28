from collections import deque
from collections.abc import Sequence

from pydantic import BaseModel

from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal

_FAKE_USAGE = ProviderUsage(input_tokens=10, output_tokens=5)


class FakeLLM:
    """Pops one scripted response per call. A `ProviderRefusal` in the script is raised."""

    def __init__(self, responses: Sequence[BaseModel | ProviderRefusal]):
        self._responses: deque[BaseModel | ProviderRefusal] = deque(responses)
        self.total_usage = ProviderUsage()

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        response = self._responses.popleft()
        if isinstance(response, ProviderRefusal):
            self.total_usage = self.total_usage.add(response.usage)
            raise response
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        self.total_usage = self.total_usage.add(_FAKE_USAGE)
        return response, _FAKE_USAGE  # type: ignore[return-value]
