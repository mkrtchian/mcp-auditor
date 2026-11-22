import tests.unit.auditor.support.cut_responses as cuts
import tests.unit.auditor.support.test_context_extraction_prompt_given as given
from mcp_auditor.domain import AttackContext
from mcp_auditor.domain.attack_context import MAX_ITEM_LENGTH, MAX_NOTE_LENGTH
from mcp_auditor.graph.prompts import build_context_extraction_prompt


class TestContextExtractionPrompt:
    def test_includes_tool_name(self):
        report = given.a_tool_report(tool_name="get_user")

        prompt = build_context_extraction_prompt(report, AttackContext())

        assert "get_user" in prompt

    def test_includes_response_content(self):
        report = given.a_tool_report(response="sqlite3.OperationalError: no such table")

        prompt = build_context_extraction_prompt(report, AttackContext())

        assert "sqlite3.OperationalError" in prompt

    def test_bounds_the_response_and_the_error_of_each_case_apart(self):
        response, error = cuts.a_long_text("response"), cuts.a_long_text("error")
        report = given.a_tool_report(response=response, error=error)

        prompt = build_context_extraction_prompt(report, AttackContext())

        cuts.shows_cut(prompt, response)
        cuts.shows_cut(prompt, error)

    def test_includes_existing_context_when_non_empty(self):
        existing = AttackContext(db_engine="sqlite")

        prompt = build_context_extraction_prompt(given.a_tool_report(), existing)

        assert "sqlite" in prompt

    def test_omits_blocked_case(self):
        report = given.a_tool_report_with_a_blocked_case()

        prompt = build_context_extraction_prompt(report, AttackContext())

        assert "test injection" in prompt
        assert "destructive payload that was never sent" not in prompt

    def test_states_that_no_case_ran_when_every_case_is_blocked(self):
        report = given.a_tool_report_with_only_a_blocked_case()

        prompt = build_context_extraction_prompt(report, AttackContext())

        assert "No test results available." in prompt

    def test_omits_existing_context_when_empty(self):
        prompt = build_context_extraction_prompt(given.a_tool_report(), AttackContext())

        assert "What we already know" not in prompt

    def test_shows_each_carried_item_on_its_own_line_under_what_we_already_know(self):
        existing = AttackContext(
            db_engine="sqlite",
            language="Python",
            exposed_internals=["/srv/app/config.yaml", "users table"],
            observations="read_file: echoes the path\nlist_users: paginates",
        )

        prompt = build_context_extraction_prompt(given.a_tool_report(), existing)

        known = prompt.split("What we already know:", 1)[1]
        lines = [line.strip() for line in known.splitlines()]
        for value in ("sqlite", "Python"):
            assert any(value in line for line in lines)
        for item in ("/srv/app/config.yaml", "users table", "read_file: echoes the path"):
            assert any(line.endswith(item) for line in lines)
        assert "/srv/app/config.yaml, users table" not in prompt

    def test_asks_to_repeat_a_confirmed_item_in_the_same_words(self):
        prompt = build_context_extraction_prompt(given.a_tool_report(), AttackContext())

        assert "same words" in prompt

    def test_states_the_length_bounds(self):
        prompt = build_context_extraction_prompt(given.a_tool_report(), AttackContext())

        assert str(MAX_ITEM_LENGTH) in prompt
        assert str(MAX_NOTE_LENGTH) in prompt
