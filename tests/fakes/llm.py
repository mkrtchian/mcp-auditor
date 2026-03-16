from collections import deque

from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage


class FakeLLM:
    def __init__(self, responses: list[BaseModel]):
        self._responses: deque[BaseModel] = deque(responses)
        self._usage = TokenUsage()

    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T:
        response = self._responses.popleft()
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        self._usage = self._usage.add(TokenUsage(input_tokens=10, output_tokens=5))
        return response  # type: ignore[return-value]

    @property
    def usage_stats(self) -> TokenUsage:
        return self._usage
