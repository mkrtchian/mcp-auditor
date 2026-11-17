import io
import pathlib
import sys

from rich.console import Console

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Analysts, Audit, AuditConfig, AuditRunOptions, CIOptions
from mcp_auditor.config import Settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.report_files import ReportPaths
from mcp_auditor.server_execution import LaunchOptions, ServerExecution
from tests.fakes import FakeContainerRuntime, FakeLLM, RaisingLLM

_SUPPORT = pathlib.Path(__file__).resolve().parent
COMMAND_NOT_FOUND = ServerLaunch.unconfined("mcp-auditor-no-such-command", [])
PROVIDER_FAILURE = "the model provider went away"


def a_stalling_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(_SUPPORT / "stalling_server.py"), *flags])


def a_read_server(*flags: str) -> ServerLaunch:
    script = _SUPPORT / "detection_replay_read_server.py"
    return ServerLaunch.unconfined(sys.executable, [str(script), *flags])


def an_audit_of(launch: ServerLaunch, output: io.StringIO, llm: LLMPort | None = None) -> Audit:
    model = llm or FakeLLM([])
    config = AuditConfig(
        run_options=AuditRunOptions(budget=1, chains=0, resume=False, dry_run=False),
        report_paths=ReportPaths(),
        ci=CIOptions(),
        launch=LaunchOptions(unconfined=True, image=None, mounts=()),
    )
    return Audit(
        config=config,
        execution=ServerExecution(launch, FakeContainerRuntime(untouchable=True)),
        analysts=Analysts(llm=model, judge=model, settings=Settings()),
        display=AuditDisplay(console=Console(file=output, width=200)),
    )


def a_failing_model() -> RaisingLLM:
    return RaisingLLM(RuntimeError(PROVIDER_FAILURE))
