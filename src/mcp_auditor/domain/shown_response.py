"""What a prompt shows of a tool response or error.

The bound keeps the context extraction prompt, which copies every response of a tool, inside the
base price tier and the context window of the models in use at the default test budget. The
report keeps every response whole: only what a model is shown is bounded.
"""

import json
from typing import Any

MAX_SHOWN_LENGTH = 20_000  # characters of one tool response or error a prompt shows

_HEAD_LENGTH = MAX_SHOWN_LENGTH // 2
_TAIL_LENGTH = MAX_SHOWN_LENGTH - _HEAD_LENGTH


def shown_to_model(text: str) -> str:
    if not is_cut(text):
        return text
    cut = len(text) - MAX_SHOWN_LENGTH
    noun = "character" if cut == 1 else "characters"
    marker = f"[{cut} {noun} cut by mcp-auditor]"
    return f"{text[:_HEAD_LENGTH]}\n{marker}\n{text[-_TAIL_LENGTH:]}"


def is_cut(text: str) -> bool:
    return len(text) > MAX_SHOWN_LENGTH


def rendered_response(response: dict[str, Any] | str) -> str:
    return json.dumps(response) if isinstance(response, dict) else response
