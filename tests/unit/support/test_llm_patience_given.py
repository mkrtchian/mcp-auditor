import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx2
import openai
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, StructuredOutput
from mcp_auditor.adapters.llm_throttling import ThrottlePatience
from mcp_auditor.adapters.throttling import install_throttle_log_handler
from tests.fakes.chat_model import FakeChatModel, ScriptedResponse, Throttled, raw_response
from tests.unit.support.test_llm_throttling_given import an_openai_rate_limit

PROVIDER_MESSAGE = "Error code: 429 - slow down"


class Output(BaseModel):
    value: str


@dataclass
class RecordingSleep:
    delays: list[float] = field(default_factory=list[float])

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def a_patience(sleep: RecordingSleep, max_total_wait: float = 300.0) -> ThrottlePatience:
    return ThrottlePatience(max_total_wait=max_total_wait, sleep=sleep, jitter=lambda: 0.0)


def an_llm(chat_model: FakeChatModel, patience: ThrottlePatience) -> LLM:
    install_throttle_log_handler()
    return LLM(
        chat_model,  # pyright: ignore[reportArgumentType]
        StructuredOutput(method="json_schema", schema_as_dict=True),
        max_parse_attempts=3,
        patience=patience,
    )


def a_throttle(headers: dict[str, str] | None = None) -> Throttled:
    return Throttled(an_openai_rate_limit(headers))


def throttled_forever(count: int = 20) -> list[ScriptedResponse]:
    return [a_throttle() for _ in range(count)]


def an_answer(value: str = "ok") -> dict[str, Any]:
    return raw_response({"value": value}, 100, 50)


def an_unreadable_answer() -> dict[str, Any]:
    return raw_response({"unexpected": 1}, 100, 50)


def a_refusal() -> openai.BadRequestError:
    request = httpx2.Request("POST", "https://provider.test/v1/responses")
    body = {"message": "Invalid prompt", "type": "invalid_request_error", "code": "invalid_prompt"}
    response = httpx2.Response(400, request=request)
    return openai.BadRequestError(f"Error code: 400 - {body}", response=response, body=body)


@dataclass
class GatedSleep:
    """A wait that lasts until the gate opens, so another call can run meanwhile."""

    gate: asyncio.Event = field(default_factory=asyncio.Event)

    async def __call__(self, _delay: float) -> None:
        await self.gate.wait()
