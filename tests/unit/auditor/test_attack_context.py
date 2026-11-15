import tests.unit.auditor.support.test_attack_context_given as given
import tests.unit.auditor.support.test_attack_context_then as then
from mcp_auditor.domain.attack_context import (
    MAX_ITEM_LENGTH,
    MAX_LIST_ITEMS,
    MAX_NOTE_LENGTH,
    MAX_NOTES,
    merge_attack_context,
)
from mcp_auditor.domain.models import AttackContext
from mcp_auditor.graph.prompts import format_attack_context


def test_merging_into_an_empty_context_returns_the_reported_items():
    reported = AttackContext(
        db_engine="SQLite",
        exposed_internals=["path /srv/app", "Path  /srv/app"],
        effective_payloads=["' OR 1=1"],
        observations="Errors leak the query.",
    )

    merged = merge_attack_context(AttackContext(), reported, "get_user")

    assert merged == AttackContext(
        db_engine="SQLite",
        exposed_internals=["Path /srv/app"],
        effective_payloads=["' OR 1=1"],
        observations="get_user: Errors leak the query.",
    )


def test_lists_are_the_union_of_carried_then_new_reported_items():
    carried = AttackContext(exposed_internals=["a", "b"])
    reported = AttackContext(exposed_internals=["c", "d"])

    merged = merge_attack_context(carried, reported, "tool")

    assert merged.exposed_internals == ["a", "b", "c", "d"]


def test_an_item_differing_by_case_and_whitespace_is_kept_once_in_the_reported_wording():
    carried = AttackContext(effective_payloads=["Path  traversal via ..", "other"])
    reported = AttackContext(effective_payloads=["path traversal\tvia .."])

    merged = merge_attack_context(carried, reported, "tool")

    assert merged.effective_payloads == ["other", "path traversal via .."]


def test_a_re_reported_item_moves_to_the_end_and_survives_an_eviction():
    carried = AttackContext(exposed_internals=given.items(MAX_LIST_ITEMS))
    reported = AttackContext(exposed_internals=["item 0", "new"])

    merged = merge_attack_context(carried, reported, "tool")

    assert merged.exposed_internals[-2:] == ["item 0", "new"]
    assert "item 1" not in merged.exposed_internals
    assert len(merged.exposed_internals) == MAX_LIST_ITEMS


def test_a_list_over_the_bound_is_cut_from_the_front():
    reported = AttackContext(exposed_internals=given.items(MAX_LIST_ITEMS + 5))

    merged = merge_attack_context(AttackContext(), reported, "tool")

    assert merged.exposed_internals == given.items(MAX_LIST_ITEMS + 5)[5:]


def test_an_over_long_item_is_dropped_and_one_at_the_bound_is_kept():
    at_bound = given.a_text_of(MAX_ITEM_LENGTH, "kept")
    over_bound = given.a_text_of(MAX_ITEM_LENGTH + 1, "dropped")
    reported = AttackContext(exposed_internals=[at_bound, over_bound])

    merged = merge_attack_context(AttackContext(), reported, "tool")

    assert merged.exposed_internals == [at_bound]


def test_a_blank_item_is_skipped():
    reported = AttackContext(effective_payloads=["", "  \n ", "kept"])

    merged = merge_attack_context(AttackContext(), reported, "tool")

    assert merged.effective_payloads == ["kept"]


def test_an_item_with_an_inner_newline_is_stored_on_one_line():
    reported = AttackContext(exposed_internals=["stack trace\n  at app.py:12"])

    merged = merge_attack_context(AttackContext(), reported, "tool")

    assert merged.exposed_internals == ["stack trace at app.py:12"]


def test_a_reported_scalar_replaces_the_carried_one_stored_stripped():
    carried = AttackContext(db_engine="SQLite")

    merged = merge_attack_context(carried, AttackContext(db_engine="  PostgreSQL 16 "), "tool")

    assert merged.db_engine == "PostgreSQL 16"


def test_a_missing_or_blank_scalar_keeps_the_carried_one():
    carried = AttackContext(framework="Flask", language="Python")

    merged = merge_attack_context(carried, AttackContext(language="   "), "tool")

    assert (merged.framework, merged.language) == ("Flask", "Python")


def test_an_over_long_reported_scalar_keeps_the_carried_one():
    carried = AttackContext(language="Python")
    reported = AttackContext(language=given.a_text_of(MAX_ITEM_LENGTH + 1))

    merged = merge_attack_context(carried, reported, "tool")

    assert merged.language == "Python"


def test_an_over_long_carried_scalar_with_nothing_reported_is_dropped():
    carried = AttackContext(db_engine=given.a_text_of(MAX_ITEM_LENGTH + 1))

    merged = merge_attack_context(carried, AttackContext(), "tool")

    assert merged.db_engine is None


def test_a_note_is_prefixed_by_the_tool_collapsed_and_cut():
    reported = AttackContext(observations="Line one.\nLine two " + "z" * MAX_NOTE_LENGTH)

    merged = merge_attack_context(AttackContext(), reported, "read_file")

    assert merged.observations.startswith("read_file: Line one. Line two zzz")
    assert len(merged.observations) == MAX_NOTE_LENGTH
    assert "\n" not in merged.observations


def test_a_second_report_of_a_tool_replaces_its_note_at_the_end():
    carried = AttackContext(observations="read_file: old\nlist_dir: listing")

    merged = merge_attack_context(carried, AttackContext(observations="new"), "read_file")

    assert merged.observations == "list_dir: listing\nread_file: new"


def test_a_blank_report_keeps_the_earlier_note_and_adds_none():
    carried = AttackContext(observations="read_file: old\nlist_dir: listing")

    merged = merge_attack_context(carried, AttackContext(observations=" \n\t "), "read_file")

    assert merged.observations == "read_file: old\nlist_dir: listing"


def test_a_note_already_prefixed_is_not_prefixed_twice():
    reported = AttackContext(observations="read_file: leaks paths")

    merged = merge_attack_context(AttackContext(), reported, "read_file")

    assert merged.observations == "read_file: leaks paths"


def test_the_oldest_notes_are_evicted_past_the_bound():
    carried = AttackContext(
        observations="\n".join(f"tool_{index}: note" for index in range(MAX_NOTES))
    )

    merged = merge_attack_context(carried, AttackContext(observations="latest"), "last_tool")

    notes = merged.observations.split("\n")
    assert len(notes) == MAX_NOTES
    assert notes[0] == "tool_1: note"
    assert notes[-1] == "last_tool: latest"


def test_a_carried_context_over_every_bound_comes_back_within_them():
    merged = merge_attack_context(given.a_context_over_every_bound(), AttackContext(), "tool")

    then.within_every_bound(merged)
    assert merged.framework == "Flask"


def test_many_reports_keep_the_context_and_its_rendering_bounded():
    merged = AttackContext()
    for tool_name, report in given.synthetic_reports(300):
        merged = merge_attack_context(merged, report, tool_name)

    assert len(merged.exposed_internals) == MAX_LIST_ITEMS
    assert len(merged.effective_payloads) == MAX_LIST_ITEMS
    assert len(merged.observations.split("\n")) == MAX_NOTES
    then.within_every_bound(merged)
    then.rendering_within_the_bound(format_attack_context(merged))
