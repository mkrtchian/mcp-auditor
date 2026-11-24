import json
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any, override

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.kit.benign_probe import ProbeCall, ProbeOutcome, ProbeReport
from evals.cve.kit.client import KitResponse, KitTool
from evals.cve.kit.launch import Launch
from evals.cve.nuisance.admission.admission import AdmittedServer, BackendFixture
from evals.cve.planting_base import LayoutMount, PlantingHost, PublicNames, SymbolicUser
from tests.fakes import FakeKitClient


def a_record_with_a_backend() -> dict[str, Any]:
    backend = BackendFixture(provisioner="fake", images=["fake/backend:1.0"], network="fake-net")
    return the_record_of(mutations.with_a_backend(a_server(), backend))


def a_server() -> AdmittedServer:
    return admissions.an_admission().servers[0]


def a_record_whose_host_omits_public_names() -> dict[str, Any]:
    record = the_record_of(a_server())
    del record["host"]["public_names"]
    return record


def a_server_with_every_host_field_set() -> AdmittedServer:
    names = PublicNames(("api.example.com",), ("SSL_CERT_FILE",), ("nip.io",))
    host = PlantingHost(
        SymbolicUser.UNPRIVILEGED,
        "/srv/app",
        has_network=True,
        public_names=names,
        layout_mount=LayoutMount.READ_WRITE,
        baked_work=True,
    )
    return mutations.with_host(a_server(), host)


def the_record_of(server: AdmittedServer) -> dict[str, Any]:
    return json.loads(server.model_dump_json())


class RecordingLifecycles:
    """Resolves every backend key to a lifecycle whose ensure and remove do nothing and whose
    server argv is `run --name <name> <image> <working directory> <launch...>`, and records the
    keys asked for."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, key: str) -> BackendLifecycle:
        self.asked.append(key)
        return BackendLifecycle(key, threading.Lock(), lambda: None, _server_args, lambda _: None)


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

    @override
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


class ScriptedProbe:
    """Answers every probe with one report, and records the calls each probe received."""

    def __init__(self, report: ProbeReport) -> None:
        self.report = report
        self.probed: list[list[ProbeCall]] = []

    async def __call__(
        self, launch: Launch, calls: Sequence[ProbeCall], tool_call_timeout: int
    ) -> ProbeReport:
        self.probed.append(list(calls))
        return self.report


def a_record_with_one_benign_call() -> dict[str, Any]:
    return a_record_with_benign_calls([a_call("read")])


def a_record_with_benign_calls(*per_flaw: list[dict[str, Any]]) -> dict[str, Any]:
    record = the_record_of(a_server())
    template = record["flaws"][0]
    record["flaws"] = [{**template, "benign_calls": calls} for calls in per_flaw]
    return record


def a_call(tool: str, **arguments: Any) -> dict[str, Any]:
    return {"tool": tool, "arguments": arguments, "expect": None, "before": None}


def written(path: Path, content: object) -> Path:
    path.write_text(json.dumps(content))
    return path
