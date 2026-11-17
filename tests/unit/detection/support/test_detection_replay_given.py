"""Reports, recorded calls and responses the replay unit tests build, and a patched version that
stands in for `connect`. No Docker, no LLM: the target plants nothing on disk and launches no
container, and each launch of the patched version answers from a script.
"""

import dataclasses
import re
from collections.abc import AsyncGenerator, Generator, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import tests.unit.cve.support.test_cve_grammar_given as grammar
from evals.cve.detection.replay import RecordedCall, RunToCheck
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, Target
from evals.cve.environments import Launch, LaunchShape
from evals.cve.grammar import FlawClass, PlantedTarget
from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting_base import PlantingSpec
from mcp_auditor.domain.models import AttackChain, AuditReport, ToolResponse
from tests.fakes.mcp_client import FakeMCPClient, a_lost_connection_response, a_timeout_response

FLAW_PATH = "/outside/flag"
OTHER_PATH = "/outside/other"
PLACE_ID = "fict-flag"
OLD_NONCE = "MCPAUDIT-" + "a" * 32
OK = ToolResponse(content="ok")
LOST = a_lost_connection_response()
TIMEOUT = a_timeout_response()
# Stands, in a patched version's script, for the response that serves the launch's fresh nonce.
SERVES_THE_NONCE = ToolResponse(content="<the launch's fresh nonce>")


def a_case_report(path: str = FLAW_PATH) -> AuditReport:
    return grammar.a_report(cases=[grammar.a_case(response="ok", arguments={"path": path})])


def a_chain_report(first: str, second: str) -> AuditReport:
    return grammar.a_report(chains=[_a_chain(first, second)])


def a_blocked_case_report() -> AuditReport:
    return grammar.a_report(cases=[grammar.a_blocked_case({"path": FLAW_PATH})])


def a_blocked_case_and_chain_report(first: str, second: str) -> AuditReport:
    # One tool report, so the blocked case, which sent no call, comes before the chain's steps.
    return grammar.a_report(
        cases=[grammar.a_blocked_case({"path": FLAW_PATH})], chains=[_a_chain(first, second)]
    )


def _a_chain(first: str, second: str) -> AttackChain:
    # A step that reached the server carries the response it drew, as every step of a real report.
    steps = [
        grammar.a_step(arguments={"path": first}, response="ok"),
        grammar.a_step(arguments={"path": second}, response="ok"),
    ]
    return grammar.a_chain(steps)


def calls(*paths: str) -> list[RecordedCall]:
    return [("read", {"path": path}, a_response(None, "ok")) for path in paths]


def a_response(error_type: str | None, content: str) -> ToolResponse:
    return ToolResponse(content=content, is_error=error_type is not None, error_type=error_type)


# --- a detecting run and the patched version it is replayed on ---


def a_detecting_run(
    *earlier: ToolResponse, relaunched_after: Sequence[int] = (), launch_args: Sequence[str] = ()
) -> RunToCheck:
    """One case per response of `earlier`, the vulnerable version's answer to a read of its own
    path, then a last case that read the flaw path and leaked the run's nonce, judged FAIL. The
    patched target launches `launch_args` before the fresh nonce of its one kept place."""
    reads = [{"path": f"/outside/{index}"} for index in range(len(earlier))]
    leaked = ToolResponse(content=f"leaked {OLD_NONCE}")
    recorded = [
        *(("read", args, response) for args, response in zip(reads, earlier, strict=True)),
        ("read", {"path": FLAW_PATH}, leaked),
    ]
    report = grammar.a_report(
        cases=[
            grammar.a_case(response=response.content, arguments=args, verdict=grammar.PASS)
            for _, args, response in recorded[:-1]
        ]
        + [grammar.a_case(response=leaked.content, arguments={"path": FLAW_PATH})]
    )
    return RunToCheck(
        target=_a_target_serving_its_nonce(launch_args),
        run_target=PlantedTarget(
            frozenset({FlawClass.READ_OUTSIDE_SCOPE}), _AIM, {PLACE_ID: OLD_NONCE}
        ),
        report=report,
        recorded_calls=recorded,
        records=(_A_FILE_PLACE,),
        relaunched_after=list(relaunched_after),
    )


_AIM = re.compile(r"^/outside/")
_A_FILE_PLACE = Place(
    id=PLACE_ID,
    family="fictional",
    reaches=frozenset({"arbitrary_read"}),
    kind=PlaceKind.FILE,
    coordinates=Coordinates(PlaceKind.FILE, path=FLAW_PATH),
)


def _a_target_serving_its_nonce(launch_args: Sequence[str]) -> Target:
    (target,) = [target for target in ACCEPTANCE_TARGETS if target.flaw_id == "CVE-2025-53109"]

    @contextmanager
    def no_container(_tag: str, spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield Launch("docker", ["run", *launch_args, "patched", spec.nonces[PLACE_ID]])

    return dataclasses.replace(target, kept_places=(PLACE_ID,), builder=no_container)


@dataclass
class APatchedVersion:
    """Stands in for `connect`. Each launch answers its calls with `responses` in order,
    `SERVES_THE_NONCE` standing for the launch's fresh nonce, and its pings and relaunches with
    their scripted answers, the last one repeated. Every call, ping and relaunch of every launch
    lands in `events`, in order."""

    responses: Sequence[ToolResponse]
    ping_answers: Sequence[bool] = (True,)
    relaunch_answers: Sequence[bool] = (True,)
    events: list[str] = field(default_factory=list[str])
    launches: list[Launch] = field(default_factory=list[Launch])

    @asynccontextmanager
    async def __call__(
        self, launch: Launch, _stderr: object, *, tool_call_timeout: int
    ) -> AsyncGenerator[FakeMCPClient]:
        self.launches.append(launch)
        yield _ScriptedClient(self, nonce=launch.args[-1])


class _ScriptedClient(FakeMCPClient):
    def __init__(self, version: APatchedVersion, nonce: str) -> None:
        served = ToolResponse(content=f"leaked {nonce}")
        script = [
            served if response is SERVES_THE_NONCE else response for response in version.responses
        ]
        super().__init__(
            [],
            {"read": script},
            ping_answers=version.ping_answers,
            relaunch_answers=version.relaunch_answers,
        )
        self._events = version.events

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        self._events.append("call")
        return await super().call_tool(name, args)

    async def ping(self) -> bool:
        self._events.append("ping")
        return await super().ping()

    async def relaunch(self) -> bool:
        self._events.append("relaunch")
        return await super().relaunch()
