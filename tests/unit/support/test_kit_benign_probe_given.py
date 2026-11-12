import json
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.kit import benign_probe
from evals.cve.kit.benign_probe import ProbeCall, ProbeOutcome, ProbeReport
from evals.cve.kit.client import KitResponse, KitTool
from evals.cve.nuisance.admission import AdmittedServer, BackendFixture
from evals.cve.planting_base import PlantingHost
from tests.fakes import FakeKitClient


def a_server() -> AdmittedServer:
    return admission_given.an_admission().servers[0]


def the_record_of(server: AdmittedServer) -> dict[str, Any]:
    return json.loads(server.model_dump_json())


def a_record_with_benign_calls(*per_flaw: list[dict[str, Any]]) -> dict[str, Any]:
    record = the_record_of(a_server())
    template = record["flaws"][0]
    record["flaws"] = [{**template, "benign_calls": calls} for calls in per_flaw]
    return record


def a_call(tool: str, **arguments: Any) -> dict[str, Any]:
    return {"tool": tool, "arguments": arguments, "expect": None, "before": None}


def a_record_with_a_backend() -> dict[str, Any]:
    backend = BackendFixture(provisioner="fake", image="fake/backend:1.0", network="fake-net")
    return the_record_of(admission_given.with_a_backend(a_server(), backend))


def a_fake_lifecycle_resolved_by_key(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Resolves every backend key to a lifecycle whose ensure and remove do nothing and whose
    server argv is `run --name <name> <image> <working directory> <launch...>`. Returns the keys
    asked for."""
    asked: list[str] = []

    def resolve(key: str) -> BackendLifecycle:
        asked.append(key)
        return BackendLifecycle(key, threading.Lock(), lambda: None, _server_args, lambda _: None)

    monkeypatch.setattr(benign_probe, "lifecycle_of", resolve)
    return asked


def _server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return ["run", "--name", name, image, host.working_directory, *server_launch]


class PrerequisiteFakeKitClient(FakeKitClient):
    """Answers `read_note` only once `create_note` was called."""

    def __init__(self) -> None:
        super().__init__(
            [KitTool("create_note", None, {}), KitTool("read_note", None, {})],
            {"create_note": KitResponse("created", False)},
        )

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        response = await super().call_tool(name, args)
        if name != "read_note":
            return response
        if any(called == "create_note" for called, _ in self.calls):
            return KitResponse("the note", False)
        return KitResponse("no such note", True)


def a_probe_call(tool: str, expect: str | None = None, before: Sequence[str] = ()) -> ProbeCall:
    return ProbeCall(tool, {}, expect, tuple((name, {}) for name in before))


def a_report(listed: Sequence[str], *outcomes: ProbeOutcome) -> ProbeReport:
    return ProbeReport(frozenset(listed), tuple(outcomes))


def an_outcome(
    call: ProbeCall, response: KitResponse, before: Sequence[KitResponse] = ()
) -> ProbeOutcome:
    return ProbeOutcome(call, tuple(before), response)


def ok(content: str) -> KitResponse:
    return KitResponse(content, False)


def error(content: str) -> KitResponse:
    return KitResponse(content, True)


def a_probe_answering(
    monkeypatch: pytest.MonkeyPatch, report: ProbeReport
) -> list[list[ProbeCall]]:
    """Returns the calls each probe received."""
    probed: list[list[ProbeCall]] = []

    async def probe(launch: object, calls: list[ProbeCall], tool_call_timeout: int) -> ProbeReport:
        probed.append(calls)
        return report

    monkeypatch.setattr(benign_probe, "probe", probe)
    return probed


def a_record_with_one_benign_call() -> dict[str, Any]:
    return a_record_with_benign_calls([a_call("read")])


def written(path: Path, content: object) -> Path:
    path.write_text(json.dumps(content))
    return path
