import json
import re

import pytest

import tests.unit.auditor.support.test_execution_rendering_given as given
import tests.unit.auditor.support.test_execution_rendering_then as then
from mcp_auditor.domain.models import ExecutionRecord, ExecutionRegime
from mcp_auditor.domain.rendering import render_json, render_markdown
from tests.unit.auditor.support.report_builders import (
    a_report_with_a_refused_judgment_on_get_user,
    a_report_with_pass_case_and_fail_chain,
    a_two_tool_report,
)


def test_markdown_shows_a_confined_execution_with_a_short_digest():
    report = given.a_report_with_execution(given.a_confined_record())

    result = render_markdown(report)

    assert re.search(
        r"^\*\*Execution\*\*: confined, node:24-bookworm-slim@sha256:[0-9a-f]{12}$",
        result,
        re.MULTILINE,
    )


def test_markdown_shows_the_image_alone_when_the_digest_is_unknown():
    report = given.a_report_with_execution(given.a_confined_record(image_digest=None))

    result = render_markdown(report)

    assert "**Execution**: confined, node:24-bookworm-slim\n" in result
    assert "@" not in result


def test_markdown_places_the_execution_line_right_after_the_server_command():
    report = given.a_report_with_execution(given.a_confined_record())

    lines = render_markdown(report).splitlines()

    command_index = next(i for i, line in enumerate(lines) if line.startswith("**Server command**"))
    assert lines[command_index + 1].startswith("**Execution**")


def test_markdown_shows_a_declared_container_execution_without_mounts():
    record = ExecutionRecord(regime=ExecutionRegime.DECLARED_CONTAINER)
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Execution**: declared container\n" in result
    then.markdown_has_no_confined_lines(result)


def test_markdown_shows_an_unconfined_execution_without_mounts():
    report = given.a_report_with_execution(ExecutionRecord(regime=ExecutionRegime.UNCONFINED))

    result = render_markdown(report)

    assert "**Execution**: unconfined\n" in result
    then.markdown_has_no_confined_lines(result)


def test_markdown_lists_the_writable_paths_of_a_confined_execution():
    record = given.a_confined_record(writable_paths=["/tmp/a", "/tmp/b"])
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Writable on host**: /tmp/a, /tmp/b" in result


def test_markdown_shows_none_when_nothing_is_writable():
    report = given.a_report_with_execution(given.a_confined_record(writable_paths=[]))

    result = render_markdown(report)

    assert "**Writable on host**: none" in result


def test_markdown_lists_the_read_only_paths_when_there_are_some():
    record = given.a_confined_record(read_only_paths=["/data"])
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Read-only on host**: /data" in result


def test_markdown_omits_the_read_only_line_when_there_are_none():
    report = given.a_report_with_execution(given.a_confined_record(read_only_paths=[]))

    result = render_markdown(report)

    assert "**Read-only on host**" not in result


def test_markdown_reports_a_memory_kill():
    report = given.a_report_with_execution(given.a_confined_record(oom_killed=True))

    result = render_markdown(report)

    assert "**Killed on memory**: yes" in result


def test_markdown_reports_an_unreadable_kill_state_as_unknown():
    report = given.a_report_with_execution(given.a_confined_record(oom_killed=None))

    result = render_markdown(report)

    assert "**Killed on memory**: unknown" in result


def test_markdown_omits_the_kill_line_when_the_server_was_not_killed():
    report = given.a_report_with_execution(given.a_confined_record(oom_killed=False))

    result = render_markdown(report)

    assert "**Killed on memory**" not in result


def test_markdown_without_execution_has_no_execution_line():
    report = a_two_tool_report()

    result = render_markdown(report)

    assert "**Execution**" not in result


RELAYED_LINE = "**Relayed environment**: GITHUB_TOKEN (redacted), AWS_REGION=eu-west-1"


@pytest.mark.parametrize(
    "record",
    [
        ExecutionRecord(regime=ExecutionRegime.UNCONFINED),
        ExecutionRecord(regime=ExecutionRegime.DECLARED_CONTAINER),
        given.a_confined_record(),
    ],
    ids=lambda record: record.regime,
)
def test_markdown_shows_the_relayed_environment_under_every_regime(record: ExecutionRecord):
    relaying = record.model_copy(
        update={
            "redacted_variables": ["GITHUB_TOKEN"],
            "plain_variables": {"AWS_REGION": "eu-west-1"},
        }
    )
    report = given.a_report_with_execution(relaying)

    result = render_markdown(report)

    assert f"{RELAYED_LINE}\n" in result


def test_markdown_shows_plain_variables_alone_when_nothing_is_redacted():
    record = ExecutionRecord(
        regime=ExecutionRegime.UNCONFINED, plain_variables={"AWS_REGION": "eu-west-1"}
    )
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Relayed environment**: AWS_REGION=eu-west-1\n" in result


def test_markdown_omits_the_relayed_environment_without_relays():
    report = given.a_report_with_execution(given.a_confined_record())

    result = render_markdown(report)

    assert "**Relayed environment**" not in result


def test_json_carries_the_execution_record_with_the_full_digest():
    report = given.a_report_with_execution(given.a_confined_record())

    execution = json.loads(render_json(report))["execution"]

    assert set(execution) == {
        "regime",
        "image",
        "image_digest",
        "writable_paths",
        "read_only_paths",
        "oom_killed",
        "redacted_variables",
        "plain_variables",
    }
    assert execution["regime"] == "confined"
    assert execution["image_digest"] == given.FULL_DIGEST


def test_json_names_the_server_command_the_redacted_variables_and_the_missed_model_calls():
    report = a_report_with_a_refused_judgment_on_get_user()
    report.execution = given.a_confined_record()

    data = json.loads(render_json(report))

    assert data["server_command"] == report.server_command
    assert "redacted_variables" in data["execution"]
    assert [missed["kind"] for missed in data["missed_model_calls"]] == ["judgment"]


def test_json_names_each_judgment_judge_result_and_its_arguments():
    report = a_report_with_pass_case_and_fail_chain()

    data = json.loads(render_json(report))

    [tool] = data["tool_reports"]
    judged = [*tool["cases"], *tool["chains"]]
    assert judged
    assert all("eval_result" not in item for item in judged)
    assert all("arguments" in item["judge_result"] for item in judged)
    assert all("payload" not in item["judge_result"] for item in judged)


def test_json_execution_is_null_without_a_record():
    report = a_two_tool_report()

    data = json.loads(render_json(report))

    assert data["execution"] is None
