from click.testing import CliRunner

from mcp_auditor.cli import cli, parse_tools_filter


def test_parses_comma_separated():
    assert parse_tools_filter("a,b,c") == frozenset({"a", "b", "c"})


def test_none_when_not_provided():
    assert parse_tools_filter(None) is None


def test_none_for_empty_string():
    assert parse_tools_filter("") is None


def test_strips_whitespace():
    assert parse_tools_filter(" a , b ") == frozenset({"a", "b"})


def test_chains_option_is_parsed():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--chains", "3", "--help"])

    assert result.exit_code == 0
    assert "--chains" in result.output


def test_confinement_options_are_documented():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--help"])

    assert result.exit_code == 0
    assert "--unconfined" in result.output
    assert "--image" in result.output
    assert "--mount" in result.output


def test_a_launcher_without_a_confinement_profile_stops_the_run():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--", "python", "x.py"])

    assert result.exit_code == 1
    assert "no confinement profile" in result.output
    # The refusal precedes the LLM initialization, so the run stops the same way on a
    # machine that holds an API key and on one that does not.
    assert "could not initialize LLM" not in result.output
