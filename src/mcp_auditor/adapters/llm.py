from typing import Any, TypedDict, cast

from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage


class _UsageMetadata(TypedDict):
    input_tokens: int
    output_tokens: int


class AnthropicLLM:
    def __init__(self, model: str = "claude-sonnet-4-6-latest", max_retries: int = 3):
        self._model = ChatAnthropic(
            model=model,  # type: ignore[arg-type]
            max_retries=max_retries,
        )
        self._usage = TokenUsage()

    @property
    def usage_stats(self) -> TokenUsage:
        return self._usage

    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T:
        structured = self._model.with_structured_output(  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
            output_schema, include_raw=True
        )
        raw_response = await structured.ainvoke(prompt)  # pyright: ignore[reportUnknownVariableType]
        parsed, usage = self._unpack_raw_response(cast(object, raw_response))
        self._accumulate_usage(usage)
        return cast(T, parsed)

    def _unpack_raw_response(self, raw_response: object) -> tuple[BaseModel, _UsageMetadata | None]:
        """Langchain's include_raw=True returns {"raw": AIMessage, "parsed": BaseModel}.

        Single coupling point with that contract.
        """
        response = cast(dict[str, Any], raw_response)
        return response["parsed"], response["raw"].usage_metadata

    def _accumulate_usage(self, metadata: _UsageMetadata | None) -> None:
        if metadata:
            self._usage = self._usage.add(
                TokenUsage(
                    input_tokens=metadata["input_tokens"],
                    output_tokens=metadata["output_tokens"],
                )
            )
