import json

import pytest

import tests.unit.auditor.support.cut_responses as cuts
import tests.unit.auditor.support.test_shown_response_given as given
from mcp_auditor.domain import ToolReport
from mcp_auditor.domain.shown_response import (
    MAX_SHOWN_LENGTH,
    cut_responses,
    rendered_response,
    shown_to_model,
)


class TestShownToModel:
    def test_keeps_a_text_at_the_bound_whole(self):
        text = "a" * MAX_SHOWN_LENGTH

        assert shown_to_model(text) == text

    def test_cuts_one_character_past_the_bound_from_the_middle(self):
        half = MAX_SHOWN_LENGTH // 2
        text = "h" * half + "m" + "t" * half

        assert shown_to_model(text) == (
            "h" * half + "\n[1 character cut by mcp-auditor]\n" + "t" * half
        )

    def test_names_how_many_characters_were_cut(self):
        text = cuts.a_long_text(length=50_000)

        shown = shown_to_model(text)

        cuts.shows_cut(shown, text)


class TestRenderedResponse:
    def test_renders_a_dict_as_json(self):
        response = {"rows": [1, 2], "name": "é"}

        assert rendered_response(response) == json.dumps(response)

    def test_keeps_a_string_as_it_is(self):
        assert rendered_response("plain text") == "plain text"


@pytest.mark.parametrize(
    "tool_report",
    [
        given.a_tool_report(
            cases=[given.a_case(response=given.a_dict_response_rendering_over_the_bound())]
        ),
        given.a_tool_report(cases=[given.a_case(response=None, error=given.OVER_THE_BOUND)]),
        given.a_tool_report(steps=[given.a_step(response=given.OVER_THE_BOUND)]),
        given.a_tool_report(steps=[given.a_step(response=None, error=given.OVER_THE_BOUND)]),
    ],
    ids=["case dict response", "case error", "step response", "step error"],
)
def test_counts_a_response_or_error_over_the_bound(tool_report: ToolReport):
    assert cut_responses(tool_report) == 1


def test_counts_nothing_for_short_responses_and_a_blocked_case():
    tool_report = given.a_tool_report(
        cases=[given.a_case(response="ok", error="short error"), given.a_blocked_case()],
        steps=[given.a_step(response="ok", error="short error")],
    )

    assert cut_responses(tool_report) == 0


def test_counts_the_response_and_the_error_of_one_case_apart():
    tool_report = given.a_tool_report(
        cases=[given.a_case(response=given.OVER_THE_BOUND, error=given.OVER_THE_BOUND)]
    )

    assert cut_responses(tool_report) == 2
