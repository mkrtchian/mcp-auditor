from typing import Any, cast

from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage


class AnthropicLLM:
    def __init__(self, model: str = "claude-sonnet-4-6-latest", max_retries: int = 3):
        self._model = ChatAnthropic(
            model=model,  # type: ignore[arg-type]
            max_retries=max_retries,
        )
        self._usage = TokenUsage()

    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T:
        structured = self._model.with_structured_output(  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
            output_schema, include_raw=True
        )
        raw_response = await structured.ainvoke(prompt)  # pyright: ignore[reportUnknownVariableType]
        response = cast(dict[str, Any], raw_response)
        self._accumulate_usage(response["raw"].usage_metadata)
        return cast(T, response["parsed"])

    @property
    def usage_stats(self) -> TokenUsage:
        return self._usage

    def _accumulate_usage(self, metadata: dict[str, Any] | None) -> None:
        if metadata:
            self._usage = self._usage.add(
                TokenUsage(
                    input_tokens=int(metadata["input_tokens"]),
                    output_tokens=int(metadata["output_tokens"]),
                )
            )
