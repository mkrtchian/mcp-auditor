from click.testing import CliRunner

import tests.unit.support.test_cli_given as given
from mcp_auditor.audit import CIOptions
from mcp_auditor.cli import ci_exit_code, cli, parse_tools_filter
from mcp_auditor.domain import Severity
from mcp_auditor.domain.models import MissCause

CI = CIOptions(enabled=True, severity_threshold=Severity.MEDIUM)


def test_parses_comma_separated():
    assert parse_tools_filter("a,b,c") == frozenset({"a", "b", "c"})


def test_none_when_not_provided():
    assert parse_tools_filter(None) is None


def test_none_for_empty_string():
    assert parse_tools_filter("") is None


def test_strips_whitespace():
    assert parse_tools_filter(" a , b ") == frozenset({"a", "b"})


def test_a_negative_chain_count_is_refused():
    result = CliRunner().invoke(cli, ["run", "--chains", "-1", "--", "python", "x.py"])

    assert result.exit_code == 2
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


def test_a_name_repeated_across_relay_options_is_refused():
    environ = {"FIRST": "first-value", "SECOND": "second-value", "THIRD": "third-value"}
    relays = ["--env", "FIRST", "--env", "SECOND", "--env-plain", "THIRD"]
    relays += ["--env-plain", "SECOND"]

    result = CliRunner(env=environ).invoke(
        cli, ["run", "--unconfined", *relays, "--", "python", "x.py"]
    )

    assert result.exit_code == 1
    assert "SECOND is named twice" in result.output


def test_a_plain_relay_steering_the_docker_client_is_refused():
    relay = ["--env-plain", "DOCKER_HOST=tcp://elsewhere:2375"]

    result = CliRunner().invoke(cli, ["run", *relay, "--", "npx", "a-server"])

    assert result.exit_code == 1
    assert "DOCKER_HOST steers the docker client" in result.output


class TestCIExitCode:
    def test_an_incomplete_audit_without_findings_exits_3(self):
        report = given.a_report(missed=MissCause.PROVIDER_REFUSAL)

        assert ci_exit_code(report, CI) == 3

    def test_an_audit_with_an_unreadable_answer_exits_3(self):
        report = given.a_report(missed=MissCause.UNREADABLE_ANSWER)

        assert ci_exit_code(report, CI) == 3

    def test_an_audit_with_a_throttled_step_exits_3(self):
        report = given.a_report(missed=MissCause.PROVIDER_THROTTLED)

        assert ci_exit_code(report, CI) == 3

    def test_a_coverage_gap_alone_exits_3(self):
        report = given.a_report(coverage_gap=True)

        assert ci_exit_code(report, CI) == 3

    def test_findings_at_the_threshold_exit_1_on_a_complete_audit(self):
        report = given.a_report(finding=Severity.MEDIUM)

        assert ci_exit_code(report, CI) == 1

    def test_findings_take_precedence_over_an_incomplete_audit(self):
        report = given.a_report(finding=Severity.HIGH, missed=MissCause.PROVIDER_REFUSAL)

        assert ci_exit_code(report, CI) == 1

    def test_findings_below_the_threshold_on_a_complete_audit_exit_0(self):
        report = given.a_report(finding=Severity.LOW)

        assert ci_exit_code(report, CI) == 0

    def test_a_complete_audit_without_findings_exits_0(self):
        report = given.a_report()

        assert ci_exit_code(report, CI) == 0

    def test_an_incomplete_audit_exits_0_outside_ci(self):
        report = given.a_report(missed=MissCause.PROVIDER_REFUSAL)

        assert ci_exit_code(report, CIOptions(enabled=False)) == 0
