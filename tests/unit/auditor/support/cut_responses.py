from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH

NEEDLE = "NEEDLE-FROM-THE-CUT-MIDDLE"
HEAD_LENGTH = MAX_SHOWN_LENGTH // 2
TAIL_LENGTH = MAX_SHOWN_LENGTH - HEAD_LENGTH


def a_long_text(label: str = "text", length: int = 50_000) -> str:
    """Its head and tail name the label, so a prompt shows which text it kept, and its middle
    holds NEEDLE, so a prompt shows whether the middle was cut."""
    head = f"{label}-head-"
    tail = f"-{label}-tail"
    filler = length - len(head) - len(tail) - len(NEEDLE)
    return head + "h" * (filler // 2) + NEEDLE + "t" * (filler - filler // 2) + tail


def shows_cut(prompt: str, text: str) -> None:
    assert text[:HEAD_LENGTH] in prompt
    assert text[-TAIL_LENGTH:] in prompt
    assert f"[{len(text) - MAX_SHOWN_LENGTH} characters cut by mcp-auditor]" in prompt
    assert NEEDLE not in prompt
