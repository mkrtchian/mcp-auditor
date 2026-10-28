"""Stub targets, builders and runs for the replay integration test (no Docker, no LLM).

A vulnerable run is simulated by a hand-built report whose outputs carry the run's old nonces,
so no vulnerable launch is needed. Only the patched version is launched, through the stub, whose
builder serves the launch's fresh nonces on the command line, so each attempt draws fresh ones
and an old nonce never fools the strike.
"""

import pathlib
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager

import tests.unit.support.test_cve_grammar_given as grammar
from evals.cve_environments import Launch, LaunchShape
from evals.cve_grammar import MechanismClass, PlantedTarget
from evals.cve_places import Places, kept_records
from evals.cve_planting import PlantingSpec
from evals.cve_replay import RecordedCall, RunToCheck
from evals.cve_targets import CVETarget
from mcp_auditor.domain.models import AuditReport, ToolResponse
from tests.integration.support.cve_stub_target import (
    OUTSIDE_AIM,
    a_file_place,
    a_stub_target,
    reading,
)

STUB_PATH = pathlib.Path(__file__).resolve().parent / "cve_replay_stub_server.py"

FLAW_ID = "fict-flaw"
OTHER_ID = "fict-other"
FLAW_PATH = "/outside/flag"  # the path the shared stub target's exploit reads
PREP_PATH = "/outside/prep"
OTHER_PATH = "/outside/other"
OLD_FLAW = "MCPAUDIT-" + "a" * 32
OLD_OTHER = "MCPAUDIT-" + "b" * 32

Serve = Callable[[PlantingSpec], list[str]]


def a_places_mapping() -> Places:
    return {
        FLAW_ID: a_file_place(FLAW_ID, FLAW_PATH),
        OTHER_ID: a_file_place(OTHER_ID, OTHER_PATH),
    }


# --- the runs, each a RunToCheck the replay settles ---


def a_declared_run() -> RunToCheck:
    # The location is reached by a declared path, so the patched version serves it too: struck.
    return _single_run(_serving({FLAW_PATH: FLAW_ID}), (FLAW_ID,))


def a_flaw_run() -> RunToCheck:
    # Only the flaw reaches the location, so the patched version serves nothing: kept.
    return _single_run(_serving({}), (FLAW_ID,))


def a_chain_run() -> RunToCheck:
    # A two-step chain whose second step reaches the location only via the flaw: kept.
    report = grammar.a_report(
        chains=[
            grammar.a_chain(
                [
                    grammar.a_step(arguments={"path": PREP_PATH}, response="ok"),
                    grammar.a_step(arguments={"path": FLAW_PATH}, response=f"leaked {OLD_FLAW}"),
                ]
            )
        ]
    )
    return _run(_serving({}), (FLAW_ID,), report, _calls(PREP_PATH, FLAW_PATH), {FLAW_ID: OLD_FLAW})


def an_echoed_old_nonce_run() -> RunToCheck:
    # The second step's argument carries the leaked old nonce. The patched stub echoes it, but the
    # strike matches the fresh nonces, so the echo does not fool it: kept.
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
    return _run(_echoing(), (FLAW_ID,), report, _calls(FLAW_PATH, OLD_FLAW), {FLAW_ID: OLD_FLAW})


def a_fresh_other_location_run() -> RunToCheck:
    # The patched version surfaces a fresh nonce for another location on the recorded path, which
    # the run never proved, so nothing is struck: kept.
    return _run(
        _serving({FLAW_PATH: OTHER_ID}),
        (FLAW_ID, OTHER_ID),
        _flaw_report(),
        _calls(FLAW_PATH),
        {FLAW_ID: OLD_FLAW, OTHER_ID: OLD_OTHER},
    )


def a_declared_run_on_a_server_noisy_at_shutdown() -> RunToCheck:
    # Every call is answered, then the patched server writes to stdout as it exits, which the
    # MCP client raises on when the launch is left: the complete attempt still decides.
    return _single_run(_serving({FLAW_PATH: FLAW_ID}, noisy_shutdown=True), (FLAW_ID,))


def a_patched_launch_failure_run() -> RunToCheck:
    return _single_run(_dead(), (FLAW_ID,))


def a_server_dying_while_answering_run() -> RunToCheck:
    return _single_run(_serving({}, exit_on_call=1), (FLAW_ID,))


def a_server_dying_after_a_call_run() -> RunToCheck:
    report = grammar.a_report(
        chains=[
            grammar.a_chain(
                [
                    grammar.a_step(arguments={"path": PREP_PATH}, response="ok"),
                    grammar.a_step(arguments={"path": FLAW_PATH}, response=f"leaked {OLD_FLAW}"),
                ]
            )
        ]
    )
    return _run(
        _serving({}, exit_on_call=2),
        (FLAW_ID,),
        report,
        _calls(PREP_PATH, FLAW_PATH),
        {FLAW_ID: OLD_FLAW},
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
        (FLAW_ID,),
        report,
        _calls_ending_in_lost_connection(FLAW_PATH, PREP_PATH),
        {FLAW_ID: OLD_FLAW},
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


# --- builders and run assembly ---


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
    return _run(
        serve,
        (FLAW_ID,),
        report,
        _calls_ending_in_lost_connection(FLAW_PATH, PREP_PATH),
        {FLAW_ID: OLD_FLAW},
    )


def _single_run(serve: Serve | None, kept: tuple[str, ...]) -> RunToCheck:
    return _run(serve, kept, _flaw_report(), _calls(FLAW_PATH), {FLAW_ID: OLD_FLAW})


def _run(
    serve: Serve | None,
    kept: tuple[str, ...],
    report: AuditReport,
    calls: list[RecordedCall],
    nonces: dict[str, str],
) -> RunToCheck:
    places = a_places_mapping()
    return RunToCheck(
        target=_a_target(serve, kept),
        run_target=PlantedTarget(MechanismClass.READ_OUTSIDE_SCOPE, OUTSIDE_AIM, nonces),
        report=report,
        recorded_calls=calls,
        records=kept_records(kept, places),
    )


def _flaw_report() -> AuditReport:
    return grammar.a_report(
        cases=[grammar.a_case(response=f"leaked {OLD_FLAW}", arguments={"path": FLAW_PATH})]
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
    paths_to_ids: dict[str, str], *, exit_on_call: int = 0, noisy_shutdown: bool = False
) -> Serve:
    def serve(spec: PlantingSpec) -> list[str]:
        args = [f"{path}={spec.nonces[place_id]}" for path, place_id in paths_to_ids.items()]
        if exit_on_call:
            args.append(f"exit_on_call={exit_on_call}")
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


def _a_target(serve: Serve | None, kept: tuple[str, ...]) -> CVETarget:
    @contextmanager
    def builder(_image: str, spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        if serve is None:
            yield Launch("docker", ["run", sys.executable, "-c", "import sys; sys.exit('boom')"])
        else:
            yield Launch("docker", ["run", sys.executable, str(STUB_PATH), *serve(spec)])

    return a_stub_target("CVE-REPLAY", builder, reading(PREP_PATH), kept_places=kept)
