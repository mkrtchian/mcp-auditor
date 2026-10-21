import pathlib
import subprocess

from mcp_auditor.domain.models import ExecutionRecord, ToolResponse


def the_read_only_mount_refused_the_write(refused: ToolResponse, reference: pathlib.Path) -> None:
    assert refused.is_error
    assert "read-only file system" in refused.content
    assert not (reference / "note.txt").exists()


def the_record_lists_the_mounts(
    record: ExecutionRecord | None, writable: pathlib.Path, read_only: pathlib.Path
) -> None:
    assert record is not None
    assert record.oom_killed is False
    assert str(writable.resolve()) in (record.writable_paths or [])
    assert str(read_only.resolve()) in (record.read_only_paths or [])


def no_container_is_left(name: str) -> None:
    listing = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}"],
        capture_output=True,
        text=True,
    )
    assert listing.stdout.splitlines()[1:] == []
