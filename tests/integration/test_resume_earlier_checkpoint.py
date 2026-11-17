import io
import pathlib

import pytest

import tests.integration.support.test_resume_earlier_checkpoint_given as given
from mcp_auditor.adapters.server_launch import ServerLaunch


# The refusal is raised inside the MCP session, whose task group wraps it, or lets it out
# bare when the server logs its shutdown to stdout: this pins that the operator still reads
# the message alone, not a traceback, after an SDK upgrade.
@pytest.mark.parametrize("launch", [given.HONEYPOT, given.NOISY_SHUTDOWN_SERVER])
async def test_resuming_a_checkpoint_from_an_earlier_version_stops_with_its_message(
    launch: ServerLaunch, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    await given.a_checkpoint_from_an_earlier_version(launch)
    output = io.StringIO()

    with pytest.raises(SystemExit) as exited:
        await given.an_audit_resuming(launch, output).run()

    assert exited.value.code == 1
    assert "checkpoint written by an earlier version, run without --resume" in output.getvalue()
    assert "MCP server failed" not in output.getvalue()
