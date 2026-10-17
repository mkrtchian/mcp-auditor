import io
import pathlib

import pytest

import tests.integration.support.test_resume_earlier_checkpoint_given as given


# The refusal is raised inside the MCP session, whose task group wraps it: this pins
# that the operator still reads the message alone, not a traceback, after an SDK upgrade.
async def test_resuming_a_checkpoint_from_an_earlier_version_stops_with_its_message(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    await given.a_checkpoint_from_an_earlier_version(given.HONEYPOT)
    output = io.StringIO()

    with pytest.raises(SystemExit) as exited:
        await given.an_audit_resuming(given.HONEYPOT, output).run()

    assert exited.value.code == 1
    assert "checkpoint written by an earlier version, run without --resume" in output.getvalue()
    assert "MCP server failed" not in output.getvalue()
