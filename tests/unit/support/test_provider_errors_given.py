import httpx
import httpx2
import openai
from google.genai.errors import ClientError
from langchain_google_genai.chat_models import ChatGoogleGenerativeAIError

_URL = "https://provider.test/v1/messages"


class AnUnmappedError(Exception):
    """An error a provider path raises outside the `ModelError` taxonomy."""

    def __init__(self, *, status_code: int | None = None, code: object = None) -> None:
        super().__init__("secret provider message")
        self.status_code = status_code
        self.code = code


def an_openai_billing_limit() -> openai.RateLimitError:
    response = httpx2.Response(429, request=httpx2.Request("POST", _URL))
    body = {"message": "You exceeded your current quota", "code": "insufficient_quota"}
    return openai.RateLimitError("Error code: 429", response=response, body=body)


def a_google_error_caused_by_status(status: int) -> ChatGoogleGenerativeAIError:
    # langchain_google_genai raises an unmapped client status as a plain error, its code on the
    # google-genai error it is raised from.
    response = httpx.Response(status, request=httpx.Request("POST", _URL))
    cause = ClientError(status, {"error": {"code": status, "status": "PAYMENT_REQUIRED"}}, response)
    try:
        raise ChatGoogleGenerativeAIError("Error calling model 'gemini'") from cause
    except ChatGoogleGenerativeAIError as error:
        return error
