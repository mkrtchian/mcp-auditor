"""Recognition of a provider's policy refusal, in an error or in a response."""

from typing import Any, cast

import openai

# OpenAI's policy flag, code "invalid_prompt", seen on 2026-09-26. Alibaba's content
# inspection through the same SDK, code "data_inspection_failed", seen in the probe of
# ADR 019. langchain-openai re-raises both as a subclass of openai.BadRequestError.
_REFUSAL_CODES = frozenset({"invalid_prompt", "data_inspection_failed"})
# Fallback on the message text, since a provider can change the code without the wording.
_REFUSAL_WORDING = (
    "invalid_prompt",
    "flagged as potentially violating our usage policy",
    "DataInspectionFailed",
)


def refusal_from_error(error: BaseException) -> str | None:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, openai.BadRequestError) and _is_policy_refusal(current):
            return _provider_message(current)
        current = current.__cause__
    return None


def _is_policy_refusal(error: openai.BadRequestError) -> bool:
    text = str(error)
    return error.code in _REFUSAL_CODES or any(wording in text for wording in _REFUSAL_WORDING)


def _provider_message(error: openai.BadRequestError) -> str:
    body: object = error.body
    if isinstance(body, dict):
        message = cast(dict[str, Any], body).get("message")
        if isinstance(message, str) and message:
            return message
    return error.message


def refusal_from_metadata(raw_message: Any) -> str | None:
    return (
        _anthropic_refusal(raw_message.response_metadata)
        or _google_refusal(raw_message.response_metadata)
        or _openai_refusal(raw_message)
    )


def _anthropic_refusal(response_metadata: dict[str, Any]) -> str | None:
    # langchain-anthropic copies the API's stop_reason into response_metadata.
    if response_metadata.get("stop_reason") == "refusal":
        return "Anthropic stopped the answer: stop_reason refusal"
    return None


# The safety values of google-genai's FinishReason, whose name langchain-google-genai
# writes into response_metadata["finish_reason"].
_GOOGLE_SAFETY_FINISH_REASONS = frozenset(
    {
        "SAFETY",
        "BLOCKLIST",
        "PROHIBITED_CONTENT",
        "SPII",
        "IMAGE_SAFETY",
        "IMAGE_PROHIBITED_CONTENT",
    }
)


def _google_refusal(response_metadata: dict[str, Any]) -> str | None:
    finish_reason = response_metadata.get("finish_reason")
    if finish_reason in _GOOGLE_SAFETY_FINISH_REASONS:
        return f"Google stopped the candidate: finish_reason {finish_reason}"
    return _google_prompt_block(response_metadata.get("prompt_feedback") or {})


def _google_prompt_block(prompt_feedback: dict[str, Any]) -> str | None:
    # A prompt blocked before any candidate: langchain-core merges the single generation's
    # llm_output, which holds prompt_feedback, into response_metadata.
    block_reason = prompt_feedback.get("block_reason")
    reason = getattr(block_reason, "name", block_reason)
    if not reason or reason == "BLOCKED_REASON_UNSPECIFIED":
        return None
    return prompt_feedback.get("block_reason_message") or (
        f"Google blocked the prompt: block_reason {reason}"
    )


def _openai_refusal(raw_message: Any) -> str | None:
    # Chat Completions (Alibaba's path): langchain-openai puts the refusal in additional_kwargs.
    refusal = raw_message.additional_kwargs.get("refusal")
    if refusal:
        return str(refusal)
    # Responses API (OpenAI's path): a {"type": "refusal", "refusal": ...} content block.
    content: object = raw_message.content
    blocks = cast(list[object], content) if isinstance(content, list) else []
    for block in blocks:
        if isinstance(block, dict):
            fields = cast(dict[str, Any], block)
            if fields.get("type") == "refusal":
                return str(fields.get("refusal") or "refusal")
    return None
