from mcp_auditor.domain.execution import ExecutionRecord, ExecutionRegime
from mcp_auditor.domain.models import AuditReport
from tests.unit.auditor.support.report_builders import a_report

FULL_DIGEST = "sha256:abc123def4567890abc123def4567890abc123def4567890abc123def4567890"


def a_confined_record(
    image_digest: str | None = FULL_DIGEST,
    writable_paths: list[str] | None = None,
    read_only_paths: list[str] | None = None,
    oom_killed: bool | None = False,
) -> ExecutionRecord:
    return ExecutionRecord(
        regime=ExecutionRegime.CONFINED,
        image="node:24-bookworm-slim",
        image_digest=image_digest,
        writable_paths=writable_paths if writable_paths is not None else ["/tmp/sandbox"],
        read_only_paths=read_only_paths if read_only_paths is not None else [],
        oom_killed=oom_killed,
    )


def a_report_with_execution(record: ExecutionRecord) -> AuditReport:
    return a_report(server_command="npx server", tool_reports=[], execution=record)
