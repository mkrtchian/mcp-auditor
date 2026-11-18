from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH
from tests.unit.auditor.support.test_shown_response_given import NEEDLE

HEAD_LENGTH = MAX_SHOWN_LENGTH // 2
TAIL_LENGTH = MAX_SHOWN_LENGTH - HEAD_LENGTH


def shows_cut(prompt: str, text: str) -> None:
    assert text[:HEAD_LENGTH] in prompt
    assert text[-TAIL_LENGTH:] in prompt
    assert f"[{len(text) - MAX_SHOWN_LENGTH} characters cut by mcp-auditor]" in prompt
    assert NEEDLE not in prompt
