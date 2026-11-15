from mcp_auditor.domain.attack_context import (
    MAX_ITEM_LENGTH,
    MAX_LIST_ITEMS,
    MAX_NOTE_LENGTH,
    MAX_NOTES,
)
from mcp_auditor.domain.models import AttackContext

_LABEL_ALLOWANCE = 500


def within_every_bound(context: AttackContext) -> None:
    for items in (context.exposed_internals, context.effective_payloads):
        assert len(items) <= MAX_LIST_ITEMS
        assert all(len(item) <= MAX_ITEM_LENGTH for item in items)
    notes = context.observations.split("\n")
    assert len(notes) <= MAX_NOTES
    assert all(len(note) <= MAX_NOTE_LENGTH for note in notes)
    for scalar in (context.db_engine, context.framework, context.language):
        assert scalar is None or len(scalar) <= MAX_ITEM_LENGTH


def rendering_within_the_bound(rendered: str) -> None:
    separators = len(", ") * (MAX_LIST_ITEMS - 1)
    lists = 2 * (MAX_LIST_ITEMS * MAX_ITEM_LENGTH + separators)
    notes = MAX_NOTES * MAX_NOTE_LENGTH + (MAX_NOTES - 1)
    scalars = 3 * MAX_ITEM_LENGTH
    assert len(rendered) <= lists + notes + scalars + _LABEL_ALLOWANCE
