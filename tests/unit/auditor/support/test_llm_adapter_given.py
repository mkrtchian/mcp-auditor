import httpx
import httpx2
import openai
from langchain_anthropic.chat_models import AnthropicContextOverflowError
from langchain_core.exceptions import ContextOverflowError
from langchain_fireworks.chat_models import FireworksContextOverflowError
from langchain_google_genai.chat_models import GoogleContextOverflowError
from langchain_openai.chat_models.base import (
    OpenAIAPIContextOverflowError,
    OpenAIContextOverflowError,
)
from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.completion_usage import CompletionUsage

from mcp_auditor.adapters.llm import StructuredOutput
from tests.unit.auditor.support.scripted_llms import a_completion

PYDANTIC_SCHEMA = StructuredOutput(method="json_schema")


_OVERFLOW_MESSAGE = "prompt is too long: 1200000 tokens > 1000000 maximum"
_OVERFLOW_REQUEST = httpx2.Request("POST", "https://provider.test/v1/messages")


def _a_400() -> httpx2.Response:
    return httpx2.Response(400, request=_OVERFLOW_REQUEST)


# Every ContextOverflowError subclass of the installed LangChain integrations, as each one
# raises it on its provider's overflow text.
CONTEXT_OVERFLOWS: dict[str, ContextOverflowError] = {
    "anthropic": AnthropicContextOverflowError(_OVERFLOW_MESSAGE, response=_a_400(), body=None),
    "openai": OpenAIContextOverflowError(_OVERFLOW_MESSAGE, response=_a_400(), body=None),
    "openai_api": OpenAIAPIContextOverflowError(_OVERFLOW_MESSAGE, _OVERFLOW_REQUEST, body=None),
    "google": GoogleContextOverflowError(
        400, {"error": {"message": _OVERFLOW_MESSAGE, "status": "INVALID_ARGUMENT"}}
    ),
    "fireworks": FireworksContextOverflowError(
        _OVERFLOW_MESSAGE,
        response=httpx.Response(400, request=httpx.Request("POST", "https://provider.test/v1")),
        body=None,
    ),
}


def token_details(cache_read: int, reasoning: int) -> dict[str, dict[str, int]]:
    return {
        "input_token_details": {"cache_read": cache_read},
        "output_token_details": {"reasoning": reasoning},
    }


def a_cut_completion(usage: CompletionUsage | None) -> openai.LengthFinishReasonError:
    message = ChatCompletionMessage(role="assistant", content='{"value": "c')
    return openai.LengthFinishReasonError(completion=a_completion("length", message, usage))
