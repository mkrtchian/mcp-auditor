import io
import pathlib

import pytest

import tests.integration.support.test_resume_earlier_checkpoint_given as given
from mcp_auditor.adapters.server_launch import ServerLaunch


# The refusal is raised while the MCP session is open and leaves the client bare, whatever the
# server writes at shutdown, since the session's task groups live in the task that owns the
# session: this pins that the operator still reads the message alone, not a traceback, after an
# SDK upgrade.
@pytest.mark.parametrize("launch", [given.HONEYPOT, given.NOISY_SHUTDOWN_SERVER])
async def test_resuming_a_checkpoint_from_an_earlier_version_stops_with_its_message(
    launch: ServerLaunch, tmp_path: pathlib.Path
) -> None:
    checkpoint_db = str(tmp_path / "checkpoints.db")
    await given.a_checkpoint_from_an_earlier_version(launch, checkpoint_db)
    output = io.StringIO()

    with pytest.raises(SystemExit) as exited:
        await given.an_audit_resuming(launch, output, checkpoint_db).run()

    assert exited.value.code == 1
    assert "checkpoint written by an earlier version, run without --resume" in output.getvalue()
    assert "MCP server failed" not in output.getvalue()
