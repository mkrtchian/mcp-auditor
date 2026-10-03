from mcp_auditor.domain import ToolDefinition, ToolResponse
from mcp_auditor.domain.redaction import Redaction, marker

_TOKEN = "s3cr3t-t0ken-value"
_TOKEN_MARKER = "[value of TOKEN, redacted by mcp-auditor]"
_REDACTION = Redaction({"TOKEN": _TOKEN})


def test_marker_names_the_variable():
    assert marker("TOKEN") == _TOKEN_MARKER


def test_text_without_secret_is_unchanged():
    assert Redaction.none().text(f"env: {_TOKEN}") == f"env: {_TOKEN}"


def test_text_replaces_the_value_with_its_marker():
    assert _REDACTION.text(f"TOKEN={_TOKEN}") == f"TOKEN={_TOKEN_MARKER}"


def test_text_replaces_every_occurrence():
    redacted = _REDACTION.text(f"{_TOKEN} and {_TOKEN}")

    assert redacted == f"{_TOKEN_MARKER} and {_TOKEN_MARKER}"


def test_text_replaces_the_longer_value_first_when_one_contains_the_other():
    redaction = Redaction({"SHORT": "abcdefgh", "LONG": "xx-abcdefgh-yy"})

    redacted = redaction.text("leak: xx-abcdefgh-yy")

    assert redacted == f"leak: {marker('LONG')}"


def test_response_redacts_the_content_and_keeps_the_error_fields():
    response = ToolResponse(content=f"boom {_TOKEN}", is_error=True, error_type="ValueError")

    assert _REDACTION.response(response) == ToolResponse(
        content=f"boom {_TOKEN_MARKER}", is_error=True, error_type="ValueError"
    )


def test_tool_redacts_name_description_and_every_string_of_the_schema():
    tool = ToolDefinition(
        name=f"get_{_TOKEN}",
        description=f"Uses {_TOKEN}",
        input_schema={
            "type": "object",
            "properties": {_TOKEN: {"type": "string", "enum": ["a", _TOKEN]}},
            "maxLength": 12,
            "additionalProperties": False,
        },
    )

    assert _REDACTION.tool(tool) == ToolDefinition(
        name=f"get_{_TOKEN_MARKER}",
        description=f"Uses {_TOKEN_MARKER}",
        input_schema={
            "type": "object",
            "properties": {_TOKEN_MARKER: {"type": "string", "enum": ["a", _TOKEN_MARKER]}},
            "maxLength": 12,
            "additionalProperties": False,
        },
    )


def test_stream_redacts_a_value_split_over_two_chunks():
    stream = _REDACTION.stream()

    emitted = stream.feed(f"start {_TOKEN[:5]}") + stream.feed(f"{_TOKEN[5:]} end") + stream.flush()

    assert emitted == f"start {_TOKEN_MARKER} end"


def test_stream_redacts_a_value_fed_one_character_per_chunk():
    stream = _REDACTION.stream()
    text = f"a {_TOKEN} b"

    emitted = "".join(stream.feed(character) for character in text) + stream.flush()

    assert emitted == f"a {_TOKEN_MARKER} b"


def test_stream_redacts_a_value_spanning_a_newline():
    stream = Redaction({"PEM": "line-one\nline-two"}).stream()

    emitted = stream.feed("key: line-one\n") + stream.feed("line-two\nnext\n") + stream.flush()

    assert emitted == f"key: {marker('PEM')}\nnext\n"


def test_stream_without_secret_returns_each_chunk_as_is():
    stream = Redaction.none().stream()

    assert stream.feed("first ") == "first "
    assert stream.feed("second") == "second"
    assert stream.flush() == ""


def test_stream_flush_returns_the_held_carry():
    stream = _REDACTION.stream()

    held = stream.feed("tail")

    assert held == ""
    assert stream.flush() == "tail"
