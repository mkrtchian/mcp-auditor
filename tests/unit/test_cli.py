from mcp_auditor.cli import parse_tools_filter


def test_parses_comma_separated():
    assert parse_tools_filter("a,b,c") == frozenset({"a", "b", "c"})


def test_none_when_not_provided():
    assert parse_tools_filter(None) is None


def test_none_for_empty_string():
    assert parse_tools_filter("") is None


def test_strips_whitespace():
    assert parse_tools_filter(" a , b ") == frozenset({"a", "b"})
