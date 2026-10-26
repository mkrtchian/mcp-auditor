import asyncio
import os
import threading
from collections.abc import Generator
from contextlib import contextmanager
from io import StringIO
from typing import Any

import pytest
from rich.console import Console

from evals import nuisance_audit as nuisance_audit_module
from evals.concurrency import entered_in_thread
from evals.cve_audit import Auditor, RunOverrides
from evals.cve_environments import Launch
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_audit import (
    BACKENDS,
    NUISANCE_INFRA_ATTEMPTS,
    DroppedRun,
    LaunchFailed,
    audit_once,
    benign_call_failure,
    gate_run,
    is_incomplete,
    nuisance_audit,
    nuisance_environment,
)
from evals.nuisance_backends import RegisteredBackend
from evals.nuisance_results import NotRunCause
from mcp_auditor.domain import ToolResponse
from mcp_auditor.domain.models import AuditReport, AuditStep, MissCause, MissedStep
from tests.fakes.llm import FakeLLM
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support import test_nuisance_run_given as run_given
from tests.unit.support.test_nuisance_admission_given import (
    FIRST_FLAW,
    SECOND_FLAW,
    a_backend_registry,
    a_flaw_record,
    a_server,
    with_a_backend,
    with_host,
)

SERVER = a_server(
    [
        a_flaw_record(FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, "1.2.0"),
        a_flaw_record(SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, "1.2.0"),
    ]
)
FIRST_TOOL = f"{FIRST_FLAW}_read"
SECOND_TOOL = f"{SECOND_FLAW}_read"


def test_the_crafted_server_launches_unprivileged_at_the_root_with_no_network():
    args = _launch_args(SERVER)

    assert _follows(args, "--network", "none")
    assert "bridge" not in args
    assert _follows(args, "--user", "65534:65534")
    assert _follows(args, "-w", "/")


def test_a_networked_host_launches_on_the_default_bridge():
    server = with_host(SERVER, PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True))

    assert _follows(_launch_args(server), "--network", "bridge")


def test_a_host_user_launches_as_the_invoking_user_in_its_working_directory():
    server = with_host(SERVER, PlantingHost(SymbolicUser.HOST, "/srv", has_network=False))

    args = _launch_args(server)

    assert _follows(args, "--user", f"{os.getuid()}:{os.getgid()}")
    assert _follows(args, "-w", "/srv")


def test_the_launch_runs_the_patched_image_confined_with_no_mount():
    with nuisance_environment(SERVER) as launch:
        assert launch.command == "docker"
        assert launch.args[-3:] == [f"mcp-auditor-nuisance-{SERVER.service}:local", *SERVER.launch]
        assert _follows(launch.args, "--cap-drop", "ALL")
        assert "-v" not in launch.args
        assert "--mount" not in launch.args


def test_a_backend_server_launches_through_its_registered_provisioner():
    server = with_a_backend(
        SERVER, BackendFixture(provisioner="fake", image="fake/backend:1.0", network="fake-net")
    )

    with nuisance_environment(server, backends=a_backend_registry()) as launch:
        assert launch == Launch("docker", ["run", "fake"])


async def test_a_provisioner_failing_on_enter_is_a_launch_failure():
    @contextmanager
    def failing_provisioner(server: AdmittedServer) -> Generator[Launch]:
        raise RuntimeError("cluster never healthy")
        yield Launch("docker", [])

    registry = {"fail": RegisteredBackend(failing_provisioner, "fake-net", "fake/backend:1.0")}
    server = with_a_backend(
        SERVER, BackendFixture(provisioner="fail", image="fake/backend:1.0", network="fake-net")
    )

    outcome = await audit_once(
        server,
        Auditor(FakeLLM([]), FakeLLM([]), 1),
        RunOverrides(None, None, None),
        backends=registry,
    )

    assert isinstance(outcome, LaunchFailed)
    assert "cluster never healthy" in outcome.reason


async def test_two_concurrent_environments_of_one_backend_server_both_complete():
    lock = threading.Lock()

    @contextmanager
    def blocking_provisioner(server: AdmittedServer) -> Generator[Launch]:
        with lock:
            yield Launch("docker", ["run", "blocked"])

    registry = {"block": RegisteredBackend(blocking_provisioner, "fake-net", "fake/backend:1.0")}
    server = with_a_backend(
        SERVER, BackendFixture(provisioner="block", image="fake/backend:1.0", network="fake-net")
    )

    async def enter_once() -> None:
        async with entered_in_thread(nuisance_environment(server, backends=registry)):
            await asyncio.sleep(0.01)

    await asyncio.wait_for(asyncio.gather(enter_once(), enter_once()), timeout=5)


async def test_clean_benign_calls_give_no_failure():
    client = FakeMCPClient([])

    reason = await benign_call_failure(SERVER, client)

    assert reason is None
    assert sorted(name for name, _ in client.calls) == sorted([FIRST_TOOL, SECOND_TOOL])


async def test_a_benign_call_answering_an_error_names_the_tool():
    client = FakeMCPClient([], {SECOND_TOOL: ToolResponse(content="boom", is_error=True)})

    reason = await benign_call_failure(SERVER, client)

    assert reason is not None
    assert SECOND_TOOL in reason
    assert "boom" in reason


async def test_a_benign_call_raising_names_the_tool():
    reason = await benign_call_failure(SERVER, _RaisingClient(FIRST_TOOL))

    assert reason is not None
    assert FIRST_TOOL in reason


async def test_a_clean_report_stands_at_the_first_call(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    report = grammar.a_report()
    attempt = _ScriptedAttempts([report])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome is report
    assert attempt.calls == 1


async def test_a_refused_step_with_a_fail_is_kept(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    report = _missing_a_step(grammar.a_report([grammar.a_case()]), MissCause.PROVIDER_REFUSAL)
    attempt = _ScriptedAttempts([report])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome is report
    assert attempt.calls == 1


async def test_an_unreadable_step_with_no_fail_is_kept_as_incomplete(
    monkeypatch: pytest.MonkeyPatch,
):
    _captured_console(monkeypatch)
    report = _missing_a_step(grammar.a_report(), MissCause.UNREADABLE_ANSWER)

    outcome = await nuisance_audit(SERVER, _ScriptedAttempts([report]))

    assert outcome is report
    assert is_incomplete(report)


def test_a_report_with_no_missed_step_is_complete():
    assert not is_incomplete(grammar.a_report())


async def test_a_launch_failing_at_every_attempt_drops_the_run(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([LaunchFailed("no image")] * 3)

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS == 3


async def test_a_run_throttled_at_any_attempt_drops_as_throttled(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)
    throttled = _missing_a_step(grammar.a_report(), MissCause.PROVIDER_THROTTLED)

    attempt = _ScriptedAttempts([throttled, LaunchFailed("no image"), throttled])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome == DroppedRun(NotRunCause.THROTTLED)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS
    assert f"attempt 1/{NUISANCE_INFRA_ATTEMPTS}" in output.getvalue()


async def test_a_launch_failure_is_retried_and_a_later_report_stands(
    monkeypatch: pytest.MonkeyPatch,
):
    _captured_console(monkeypatch)
    report = grammar.a_report()
    attempt = _ScriptedAttempts([LaunchFailed("no image"), report])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome is report
    assert attempt.calls == 2


async def test_a_gate_run_with_a_counted_alarm_stands_despite_a_refused_step(
    monkeypatch: pytest.MonkeyPatch,
):
    _captured_console(monkeypatch)
    report = run_given.a_report(True, missed=MissCause.PROVIDER_REFUSAL)
    audit = _ScriptedAudits([report])

    run = await gate_run(run_given.a_server(), audit)

    assert run is not None
    assert run.flagged
    assert run.report is report
    assert audit.calls == 1


async def test_a_gate_run_incomplete_without_an_alarm_is_attempted_again(
    monkeypatch: pytest.MonkeyPatch,
):
    output = _captured_console(monkeypatch)
    clean = run_given.a_report(False)
    audit = _ScriptedAudits([run_given.a_report(False, missed=MissCause.UNREADABLE_ANSWER), clean])

    run = await gate_run(run_given.a_server(), audit)

    assert run is not None
    assert not run.flagged
    assert run.report is clean
    assert audit.calls == 2
    assert "attempt 1/3" in output.getvalue()


async def test_a_gate_run_incomplete_at_every_attempt_does_not_complete(
    monkeypatch: pytest.MonkeyPatch,
):
    output = _captured_console(monkeypatch)
    incomplete = run_given.a_report(False, missed=MissCause.PROVIDER_REFUSAL)
    audit = _ScriptedAudits([incomplete] * 3)

    run = await gate_run(run_given.a_server(), audit)

    assert run is None
    assert audit.calls == 3
    assert "all 3 attempts" in output.getvalue()


async def test_a_dropped_gate_run_does_not_complete_at_once(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    audit = _ScriptedAudits([DroppedRun(NotRunCause.THROTTLED)])

    run = await gate_run(run_given.a_server(), audit)

    assert run is None
    assert audit.calls == 1


def _launch_args(server: AdmittedServer, backends: Any = BACKENDS) -> list[str]:
    with nuisance_environment(server, backends=backends) as launch:
        return launch.args


def _follows(args: list[str], flag: str, value: str) -> bool:
    return any(args[i : i + 2] == [flag, value] for i in range(len(args) - 1))


def _missing_a_step(report: AuditReport, cause: MissCause) -> AuditReport:
    missed = MissedStep(tool_name="read_file", step=AuditStep.JUDGMENT, cause=cause, detail="")
    return report.model_copy(update={"missed_steps": [missed]})


class _RaisingClient(FakeMCPClient):
    def __init__(self, failing_tool: str) -> None:
        super().__init__([])
        self._failing_tool = failing_tool

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if name == self._failing_tool:
            raise RuntimeError("connection closed")
        return await super().call_tool(name, args)


class _ScriptedAttempts:
    def __init__(self, outcomes: list[AuditReport | LaunchFailed]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> AuditReport | LaunchFailed:
        self.calls += 1
        return self._outcomes.pop(0)


class _ScriptedAudits:
    def __init__(self, outcomes: list[AuditReport | DroppedRun]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> AuditReport | DroppedRun:
        self.calls += 1
        return self._outcomes.pop(0)


def _captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(nuisance_audit_module, "console", Console(file=output, width=200))
    return output
