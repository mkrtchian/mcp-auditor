"""What a prompt shows of a tool response or error.

The bound keeps the context extraction prompt, which copies every response of a tool, inside the
base price tier and the context window of the models in use at the default test budget. The
report keeps every response whole: only what a model is shown is bounded.
"""

import json
from typing import Any

from mcp_auditor.domain.models import ToolReport

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


def cut_responses(tool_report: ToolReport) -> int:
    shown: list[str] = []
    for case in tool_report.cases:
        if case.response is not None:
            shown.append(rendered_response(case.response))
        if case.error is not None:
            shown.append(case.error)
    for chain in tool_report.chains:
        shown.extend(text for step in chain.steps for text in (step.response, step.error) if text)
    return sum(1 for text in shown if is_cut(text))


def rendered_response(response: dict[str, Any] | str) -> str:
    return json.dumps(response) if isinstance(response, dict) else response
