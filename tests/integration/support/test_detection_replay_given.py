"""Fake targets, builders and runs for the replay integration test (no Docker, no LLM).

A vulnerable run is simulated by a hand-built report whose outputs carry the run's old nonces,
so no vulnerable launch is needed. Only the patched version is launched, through the read server,
whose builder serves the launch's fresh nonces on the command line, so each attempt draws fresh
ones and an old nonce never fools the strike.
"""

import dataclasses
import os
import sys
from collections.abc import AsyncGenerator, Callable, Generator
from contextlib import asynccontextmanager, contextmanager
from typing import IO

import tests.unit.support.grammar_inputs as grammar
from evals.cve.detection.replay import RecordedCall, RunToCheck
from evals.cve.detection.targets import Target
from evals.cve.environments import Launch, LaunchShape
from evals.cve.grammar import FlawClass, PlantedTarget
from evals.cve.launch_audit import Connect
from evals.cve.places import Places, kept_records
from evals.cve.planting import PlantingSpec
from mcp_auditor.adapters.docker import docker_client_env
from mcp_auditor.adapters.mcp_client import SessionBounds, StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import AuditReport, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from tests.integration.support.detection_fake_targets import (
    OUTSIDE_AIM,
    a_fake_target,
    a_file_place,
    reading,
)
from tests.integration.support.support_servers import READ_SERVER_PATH

FLAW_ID = "fict-flaw"
OTHER_ID = "fict-other"
FLAW_PATH = "/outside/flag"  # the path the shared fake target's exploit reads
PREP_PATH = "/outside/prep"
OTHER_PATH = "/outside/other"
OLD_FLAW = "MCPAUDIT-" + "a" * 32
OLD_OTHER = "MCPAUDIT-" + "b" * 32
_OLD_NONCES = {FLAW_ID: OLD_FLAW, OTHER_ID: OLD_OTHER}

Serve = Callable[[PlantingSpec], list[str]]


# --- the runs, each a RunToCheck the replay settles ---


def a_declared_run() -> RunToCheck:
    # The location is reached by a declared path, so the patched version serves it too: struck.
    return _single_run(_serving({FLAW_PATH: FLAW_ID}))


def a_flaw_run() -> RunToCheck:
    # Only the flaw reaches the location, so the patched version serves nothing: kept.
    return _single_run(_serving({}))


def a_chain_run() -> RunToCheck:
    # A two-step chain whose second step reaches the location only via the flaw: kept.
    return _run(_serving({}), _prep_then_flaw_chain_report(), _calls(PREP_PATH, FLAW_PATH))


def an_echoed_old_nonce_run() -> RunToCheck:
    # The second step's argument carries the leaked old nonce. The patched read server echoes it,
    # but the strike matches the fresh nonces, so the echo does not fool it: kept.
    report = grammar.a_report(
        chains=[
            grammar.a_chain(
                [
                    grammar.a_step(arguments={"path": FLAW_PATH}, response=f"leaked {OLD_FLAW}"),
                    grammar.a_step(arguments={"path": OLD_FLAW}, response=f"echo {OLD_FLAW}"),
                ]
            )
        ]
    )
    return _run(_echoing(), report, _calls(FLAW_PATH, OLD_FLAW))


def a_fresh_other_location_run() -> RunToCheck:
    # The patched version surfaces a fresh nonce for another location on the recorded path, which
    # the run never proved, so nothing is struck: kept.
    return _run(
        _serving({FLAW_PATH: OTHER_ID}),
        _flaw_report(),
        _calls(FLAW_PATH),
        kept=(FLAW_ID, OTHER_ID),
    )


def a_declared_run_on_a_server_noisy_at_shutdown() -> RunToCheck:
    # Every call is answered, then the patched server writes to stdout as it exits, which the
    # MCP client raises on when the launch is left: the complete attempt still decides.
    return _single_run(_serving({FLAW_PATH: FLAW_ID}, noisy_shutdown=True))


def a_patched_launch_failure_run() -> RunToCheck:
    return _single_run(_dead())


def a_server_dying_while_answering_run() -> RunToCheck:
    return _single_run(_serving({}, exit_on_call=1))


def a_server_dying_after_a_call_run() -> RunToCheck:
    return _run(
        _serving({}, exit_on_call=2), _prep_then_flaw_chain_report(), _calls(PREP_PATH, FLAW_PATH)
    )


def a_detection_kept_when_the_patched_dies_where_the_vulnerable_did_run() -> RunToCheck:
    # Detected at call 1, then call 2 lost the vulnerable connection. The patched server also
    # dies on call 2, so the replay ends where the vulnerable run did and keeps the call-1 credit.
    report = grammar.a_report(
        cases=[
            grammar.a_case(response=f"leaked {OLD_FLAW}", arguments={"path": FLAW_PATH}),
            grammar.a_case(
                response="Connection closed", arguments={"path": PREP_PATH}, verdict=grammar.PASS
            ),
        ]
    )
    return _run(
        _serving({}, exit_on_call=2),
        report,
        _calls_ending_in_lost_connection(FLAW_PATH, PREP_PATH),
    )


def a_straddling_chain_struck_despite_a_lost_connection_run() -> RunToCheck:
    # The credit is earned at step 1, the vulnerable connection is lost at step 2, but the patched
    # server survives and serves the fresh nonce at step 2: ending at the first vulnerable loss
    # would leave step 2 empty and keep a credit the full replay strikes.
    return _straddling_run(_serving({PREP_PATH: FLAW_ID}))


def a_transient_patched_death_at_the_vulnerable_loss_run() -> RunToCheck:
    # The first patched launch dies by chance at step 2, where the vulnerable run lost its
    # connection. Later launches survive and serve the fresh nonce there, so a retry strikes.
    return _straddling_run(_dying_by_launch({PREP_PATH: FLAW_ID}, (2,)))


def a_truncated_then_failed_attempts_run() -> RunToCheck:
    # Truncated at step 2 on the first launch, then lost at step 1, which the vulnerable run
    # answered, on the two later launches: no attempt completes.
    return _straddling_run(_dying_by_launch({PREP_PATH: FLAW_ID}, (2, 1, 1)))


def a_lost_connection_at_a_relaunch_point_run() -> RunToCheck:
    # The vulnerable server lost its connection at call 2 and the auditor relaunched it there.
    # The patched server dies at call 2 too, and the relaunched one serves the declared path at
    # call 3: struck.
    lost = _a_response("McpError", "Connection closed")
    return _relaunched_at_call_2_run(_serving({FLAW_PATH: FLAW_ID}, exit_on_call=2), lost)


def a_timeout_at_a_relaunch_point_run() -> RunToCheck:
    # As above, with the second call timing out on a server whose loop it blocks.
    timed_out = _a_response("TimeoutError", "Tool call timed out after 2s")
    return _relaunched_at_call_2_run(_serving({FLAW_PATH: FLAW_ID}, hang_on_call=2), timed_out)


def a_patched_server_stopping_answering_run() -> RunToCheck:
    # The vulnerable run answered its one call. The patched server blocks its loop on it, so the
    # call times out and the ping after it gets no answer.
    return _single_run(_serving({FLAW_PATH: FLAW_ID}, hang_on_call=1))


def connect_pinging_within(seconds: float) -> Connect:
    """The suites' own `connect`, with the ping bounded to `seconds`."""

    @asynccontextmanager
    async def connect(
        launch: Launch, server_stderr: IO[str], *, tool_call_timeout: int
    ) -> AsyncGenerator[MCPClientPort]:
        async with StdioMCPClient.connect(
            ServerLaunch.declared_container(
                launch.command, launch.args, docker_client_env(os.environ)
            ),
            errlog=server_stderr,
            tool_call_timeout=tool_call_timeout,
            bounds=SessionBounds(ping=seconds),
        ) as client:
            yield client

    return connect


# --- builders and run assembly ---


def _relaunched_at_call_2_run(serve: Serve, second: ToolResponse) -> RunToCheck:
    report = grammar.a_report(
        cases=[
            grammar.a_case(response="ok", arguments={"path": PREP_PATH}, verdict=grammar.PASS),
            grammar.a_case(
                response=second.content, arguments={"path": PREP_PATH}, verdict=grammar.PASS
            ),
            grammar.a_case(response=f"leaked {OLD_FLAW}", arguments={"path": FLAW_PATH}),
        ]
    )
    calls = _calls(PREP_PATH)
    calls.append(("read", {"path": PREP_PATH}, second))
    calls.extend(_calls(FLAW_PATH))
    run = _run(serve, report, calls)
    return dataclasses.replace(run, relaunched_after=[2])


def _straddling_run(serve: Serve) -> RunToCheck:
    report = grammar.a_report(
        chains=[
            grammar.a_chain(
                [
                    grammar.a_step(arguments={"path": FLAW_PATH}, response=f"leaked {OLD_FLAW}"),
                    grammar.a_step(arguments={"path": PREP_PATH}, response="Connection closed"),
                ]
            )
        ]
    )
    return _run(serve, report, _calls_ending_in_lost_connection(FLAW_PATH, PREP_PATH))


def _single_run(serve: Serve | None) -> RunToCheck:
    return _run(serve, _flaw_report(), _calls(FLAW_PATH))


def _run(
    serve: Serve | None,
    report: AuditReport,
    calls: list[RecordedCall],
    kept: tuple[str, ...] = (FLAW_ID,),
) -> RunToCheck:
    places = a_places_mapping()
    nonces = {place: _OLD_NONCES[place] for place in kept}
    return RunToCheck(
        target=_a_target(serve, kept),
        run_target=PlantedTarget(frozenset({FlawClass.READ_OUTSIDE_SCOPE}), OUTSIDE_AIM, nonces),
        report=report,
        recorded_calls=calls,
        records=kept_records(kept, places),
    )


def a_places_mapping() -> Places:
    return {
        FLAW_ID: a_file_place(FLAW_ID, FLAW_PATH),
        OTHER_ID: a_file_place(OTHER_ID, OTHER_PATH),
    }


def _flaw_report() -> AuditReport:
    return grammar.a_report(
        cases=[grammar.a_case(response=f"leaked {OLD_FLAW}", arguments={"path": FLAW_PATH})]
    )


def _prep_then_flaw_chain_report() -> AuditReport:
    return grammar.a_report(
        chains=[
            grammar.a_chain(
                [
                    grammar.a_step(arguments={"path": PREP_PATH}, response="ok"),
                    grammar.a_step(arguments={"path": FLAW_PATH}, response=f"leaked {OLD_FLAW}"),
                ]
            )
        ]
    )


def _calls(*paths: str) -> list[RecordedCall]:
    return [("read", {"path": path}, _a_response(None, "ok")) for path in paths]


def _calls_ending_in_lost_connection(*paths: str) -> list[RecordedCall]:
    *answered, last = paths
    lost = _a_response("McpError", "Connection closed")
    return [*_calls(*answered), ("read", {"path": last}, lost)]


def _a_response(error_type: str | None, content: str) -> ToolResponse:
    return ToolResponse(content=content, is_error=error_type is not None, error_type=error_type)


def _serving(
    paths_to_ids: dict[str, str],
    *,
    exit_on_call: int = 0,
    hang_on_call: int = 0,
    noisy_shutdown: bool = False,
) -> Serve:
    def serve(spec: PlantingSpec) -> list[str]:
        args = [f"{path}={spec.nonces[place_id]}" for path, place_id in paths_to_ids.items()]
        if exit_on_call:
            args.append(f"exit_on_call={exit_on_call}")
        if hang_on_call:
            args.append(f"hang_on_call={hang_on_call}")
        if noisy_shutdown:
            args.append("noisy_shutdown")
        return args

    return serve


def _dying_by_launch(paths_to_ids: dict[str, str], exits: tuple[int, ...]) -> Serve:
    # The target's builder calls serve once per launch, so the n-th call picks the n-th exit.
    # 0, or a launch past the end of exits, serves without exiting.
    remaining = iter(exits)

    def serve(spec: PlantingSpec) -> list[str]:
        return _serving(paths_to_ids, exit_on_call=next(remaining, 0))(spec)

    return serve


def _echoing() -> Serve:
    return lambda _spec: ["echo"]


def _dead() -> Serve | None:
    return None


def _a_target(serve: Serve | None, kept: tuple[str, ...]) -> Target:
    @contextmanager
    def builder(_image: str, spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        if serve is None:
            yield Launch("docker", ["run", sys.executable, "-c", "import sys; sys.exit('boom')"])
        else:
            yield Launch("docker", ["run", sys.executable, str(READ_SERVER_PATH), *serve(spec)])

    return a_fake_target("CVE-REPLAY", builder, reading(PREP_PATH), kept_places=kept)
