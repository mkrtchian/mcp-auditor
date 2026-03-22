from collections import deque

from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage

_FAKE_USAGE = TokenUsage(input_tokens=10, output_tokens=5)


class FakeLLM:
    def __init__(self, responses: list[BaseModel]):
        self._responses: deque[BaseModel] = deque(responses)

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        response = self._responses.popleft()
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        return response, _FAKE_USAGE  # type: ignore[return-value]
