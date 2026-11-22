from mcp_auditor.domain.attack_context import MAX_ITEM_LENGTH, MAX_LIST_ITEMS, MAX_NOTE_LENGTH
from mcp_auditor.domain.models import AttackContext


def a_context_over_every_bound() -> AttackContext:
    return AttackContext(
        db_engine=a_text_of(MAX_ITEM_LENGTH + 1),
        framework="Flask",
        exposed_internals=[*items(MAX_LIST_ITEMS + 10, "internal"), a_text_of(MAX_ITEM_LENGTH + 1)],
        effective_payloads=items(MAX_LIST_ITEMS + 10, "payload"),
        observations="\n".join(f"tool_{index}: {'n' * MAX_NOTE_LENGTH}" for index in range(20)),
    )


def items(count: int, prefix: str = "item") -> list[str]:
    return [f"{prefix} {index}" for index in range(count)]


def a_text_of(length: int, seed: str = "x") -> str:
    return (seed + " " + "a" * length)[:length]


def synthetic_reports(count: int) -> list[tuple[str, AttackContext]]:
    return [(f"tool_{index}", _a_full_report(index)) for index in range(count)]


def _a_full_report(index: int) -> AttackContext:
    return AttackContext(
        db_engine=a_text_of(MAX_ITEM_LENGTH, f"engine {index}"),
        framework=a_text_of(MAX_ITEM_LENGTH, f"framework {index}"),
        language=a_text_of(MAX_ITEM_LENGTH, f"language {index}"),
        exposed_internals=[a_text_of(MAX_ITEM_LENGTH, f"internal {index} {n}") for n in range(3)],
        effective_payloads=[a_text_of(MAX_ITEM_LENGTH, f"payload {index} {n}") for n in range(3)],
        observations="o" * (MAX_NOTE_LENGTH * 2),
    )
