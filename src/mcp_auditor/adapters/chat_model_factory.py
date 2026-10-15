import os
from typing import Any

import httpx
from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from pydantic import SecretStr

from mcp_auditor.config import Settings


# Each factory imports its provider's SDK, so an audit loads the one it uses and starting the
# CLI pays for none of the others.
def make_chat_model(settings: Settings, model: str) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    reasoning = settings.resolve_reasoning(model)
    if settings.provider == "anthropic":
        return _make_anthropic_model(model, reasoning)
    if settings.provider == "google":
        return _make_google_model(model, reasoning)
    if settings.provider == "openai":
        return _make_openai_model(model, reasoning)
    if settings.provider == "fireworks":
        return _make_fireworks_model(model, reasoning)
    if settings.provider == "alibaba":
        return _make_alibaba_model(model)
    if settings.provider == "openrouter":
        return _make_openrouter_model(model, reasoning, settings.resolve_openrouter_hosts())
    raise ValueError(
        f"Unknown provider: {settings.provider!r}. "
        "Use 'google', 'anthropic', 'openai', 'fireworks', 'alibaba' or 'openrouter'."
    )


def _make_google_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    from langchain_google_genai import (
        ChatGoogleGenerativeAI,  # pyright: ignore[reportMissingTypeStubs]
    )

    # An httpx transport keeps google-genai off aiohttp, so its 429s reach the httpx log the
    # throttle count reads. It also reaches the sync client, which would fail a sync call:
    # the auditor makes none, LLM only calls ainvoke.
    client_args = {"transport": httpx.AsyncHTTPTransport()}
    if reasoning is None:
        return ChatGoogleGenerativeAI(model=model, max_retries=3, client_args=client_args)  # pyright: ignore[reportUnknownArgumentType]
    return ChatGoogleGenerativeAI(  # pyright: ignore[reportUnknownArgumentType]
        model=model,
        thinking_level=reasoning,  # pyright: ignore[reportArgumentType]
        max_retries=3,
        client_args=client_args,
    )


# Without it, a probe run once hung 17 minutes on one OpenAI response.
_REQUEST_TIMEOUT_SECONDS = 120
# Bounds a loop: gpt-6-luna was seen writing a literal "very long string" payload up to
# its 128k-token limit. The cap counts reasoning on some providers, and a batch at
# medium reasoning was seen near 3,000 tokens.
_MAX_OUTPUT_TOKENS = 8192


def _make_anthropic_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    from langchain_anthropic import ChatAnthropic

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise ValueError("ANTHROPIC_API_KEY is not set.")
    return ChatAnthropic(
        model=model,  # pyright: ignore[reportCallIssue]
        max_retries=3,
        max_tokens=_MAX_OUTPUT_TOKENS,  # pyright: ignore[reportCallIssue]
        timeout=_REQUEST_TIMEOUT_SECONDS,
        **_anthropic_thinking(reasoning),
    )


# An explicit adaptive thinking keeps langchain-anthropic from forcing the tool call,
# which would skip thinking whatever the effort.
def _anthropic_thinking(reasoning: str | None) -> dict[str, Any]:
    if reasoning is None:
        return {}
    if reasoning == "none":
        return {"thinking": {"type": "disabled"}}
    return {"effort": reasoning, "thinking": {"type": "adaptive"}}


def _make_openai_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    from langchain_openai import ChatOpenAI

    # ChatOpenAI raises openai.OpenAIError on a missing key, which the CLI does not catch.
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY is not set.")
    if reasoning is None:
        return ChatOpenAI(
            model=model,
            use_responses_api=True,
            max_retries=3,
            timeout=_REQUEST_TIMEOUT_SECONDS,
            max_completion_tokens=_MAX_OUTPUT_TOKENS,
        )
    return ChatOpenAI(
        model=model,
        reasoning_effort=reasoning,
        use_responses_api=True,
        max_retries=3,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        max_completion_tokens=_MAX_OUTPUT_TOKENS,
    )


def _make_fireworks_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    from langchain_fireworks import ChatFireworks

    if reasoning is None:
        return ChatFireworks(
            model=model,
            max_retries=3,
            timeout=_REQUEST_TIMEOUT_SECONDS,
            max_tokens=_MAX_OUTPUT_TOKENS,
        )
    return ChatFireworks(
        model=model,
        reasoning_effort=reasoning,
        max_retries=3,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        max_tokens=_MAX_OUTPUT_TOKENS,
    )


_ALIBABA_BASE_URL = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"


def _make_alibaba_model(model: str) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("DASHSCOPE_API_KEY")
    if not api_key:
        raise ValueError("DASHSCOPE_API_KEY is not set.")
    # Qwen thinks by default, for minutes per batch.
    return ChatOpenAI(
        model=model,
        base_url=_ALIBABA_BASE_URL,
        api_key=SecretStr(api_key),
        use_responses_api=False,
        extra_body={"enable_thinking": False},
        max_retries=3,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        max_completion_tokens=_MAX_OUTPUT_TOKENS,
    )


_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def _make_openrouter_model(
    model: str, reasoning: str | None, hosts: tuple[str, ...]
) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is not set.")
    return ChatOpenAI(
        model=model,
        base_url=_OPENROUTER_BASE_URL,
        api_key=SecretStr(api_key),
        use_responses_api=False,
        extra_body=_openrouter_body(reasoning, hosts),
        max_retries=3,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        max_completion_tokens=_MAX_OUTPUT_TOKENS,
    )


# require_parameters keeps off a host that ignores response_format or reasoning. Pinned hosts
# get no fallback, so a failure on them is an error rather than a silent switch to a host
# that may filter security content or serve a lower quantization.
def _openrouter_body(reasoning: str | None, hosts: tuple[str, ...]) -> dict[str, Any]:
    provider: dict[str, Any] = {"require_parameters": True}
    if hosts:
        provider["order"] = list(hosts)
        provider["allow_fallbacks"] = False
    body: dict[str, Any] = {"provider": provider}
    # reasoning.effort, unlike the top-level reasoning_effort, takes max.
    if reasoning is not None:
        body["reasoning"] = {"effort": reasoning}
    return body
