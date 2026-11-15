"""Merge of one context extraction answer into the bounded attack context (ADR 035).

The bounds are set so that the merge drops nothing on a server of five to ten tools.
For the lists this assumes about three new items per tool and per list, or fewer.
The last item of a list is the most recently reported, and eviction starts at the front.
"""

import re

from mcp_auditor.domain.models import AttackContext

MAX_LIST_ITEMS = 30
MAX_ITEM_LENGTH = 300
MAX_NOTES = 15
MAX_NOTE_LENGTH = 400


def merge_attack_context(
    carried: AttackContext, reported: AttackContext, tool_name: str
) -> AttackContext:
    return AttackContext(
        db_engine=_merge_scalar(carried.db_engine, reported.db_engine),
        framework=_merge_scalar(carried.framework, reported.framework),
        language=_merge_scalar(carried.language, reported.language),
        exposed_internals=_merge_list(carried.exposed_internals, reported.exposed_internals),
        effective_payloads=_merge_list(carried.effective_payloads, reported.effective_payloads),
        observations=_merge_notes(carried.observations, reported.observations, tool_name),
    )


def _merge_scalar(carried: str | None, reported: str | None) -> str | None:
    if reported is not None and 0 < len(reported.strip()) <= MAX_ITEM_LENGTH:
        return reported.strip()
    if carried is not None and len(carried) > MAX_ITEM_LENGTH:
        return None
    return carried


def _merge_list(carried: list[str], reported: list[str]) -> list[str]:
    by_key: dict[str, str] = {}
    for item in [*carried, *reported]:
        text = _collapse(item)
        if not text or len(text) > MAX_ITEM_LENGTH:
            continue
        key = text.casefold()
        by_key.pop(key, None)
        by_key[key] = text
    return list(by_key.values())[-MAX_LIST_ITEMS:]


def _merge_notes(carried: str, reported: str, tool_name: str) -> str:
    notes = [line.strip()[:MAX_NOTE_LENGTH] for line in carried.splitlines() if line.strip()]
    prefix = f"{_collapse(tool_name)}: "
    text = _collapse(reported).removeprefix(prefix)
    if text:
        notes = [note for note in notes if not note.startswith(prefix)]
        notes.append(f"{prefix}{text}"[:MAX_NOTE_LENGTH])
    return "\n".join(notes[-MAX_NOTES:])


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
