"""The `vet` subcommand of run_nuisance: rebuild the run's images and make each audited server's
benign calls on the run's own launch path, with the run's container hygiene around them (Docker,
no LLM). It finds a broken image or launch before an audit is paid for, and writes no result."""

import argparse
import asyncio
import functools
import sys
import traceback
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from evals.concurrency import bounded, positive_int
from evals.cve.census.census import CENSUS_PATH
from evals.cve.closed_network import check_closed_network_support
from evals.cve.environments import TOOL_CALL_TIMEOUT
from evals.cve.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.cve.nuisance.admission.admission import ADMISSION_PATH, AdmittedServer
from evals.cve.nuisance.admission.unrecorded import unrecorded_fields
from evals.cve.nuisance.admission.walk import acceptance_target_servers, reached_servers
from evals.cve.nuisance.commands import (
    CRASHED_EXIT,
    UNKNOWN_SERVER_EXIT,
    WALK_RECORD_PATH,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
)
from evals.cve.nuisance.holdout_servers import run_population
from evals.cve.nuisance.run import NUISANCE_CONCURRENCY
from evals.cve.nuisance.run_containers import (
    refuse_server_containers,
    remove_backend_containers,
    run_images,
    sweep_run_containers,
)
from evals.cve.nuisance.vetting import VetResult, benign_call, drop_failing_servers
from evals.cve.run_images import (
    rebuild_images,
    refuse_without_closed_networks,
    remove_containers,
    running_containers,
)
from evals.eval_session import Refused

_REFUSAL = "nuisance vet refused"


@dataclass(frozen=True)
class VetDeps:
    rebuild: Callable[[Sequence[str]], None]
    running_containers: Callable[[Sequence[str]], list[str]]
    remove_containers: Callable[[Sequence[str]], None]
    benign_call: Callable[[AdmittedServer], Awaitable[str | None]]  # its failure reason, or None
    check_networks: Callable[[], None]
    # Whether each server answered a ping after its handshake, by package, filled by benign_call.
    ping_answers: dict[str, bool] = field(default_factory=dict[str, bool])


def add_vet_arguments(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(command=vet)
    parser.add_argument(
        "--server", action="append", default=[], help="vet only this server, repeatable"
    )
    parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    parser.add_argument(
        "--tool-call-timeout",
        type=positive_int,
        default=None,
        help="default: the run conditions' timeout",
    )
    parser.add_argument("--census", type=Path, default=CENSUS_PATH)
    parser.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)


def vet(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
        if admission is None or not admission.servers:
            print("no server is admitted")
            return 0
        audited = run_population(
            reached_servers(walk_inputs), admission, acceptance_target_servers(walk_inputs)
        ).audited
    packages = [server.server_package for server in audited]
    unknown = [package for package in args.server if package not in packages]
    if unknown:
        print(f"not an audited server: {', '.join(unknown)}", file=sys.stderr)
        return UNKNOWN_SERVER_EXIT
    servers = [s for s in audited if not args.server or s.server_package in args.server]
    try:
        deps = default_vet_deps(_tool_call_timeout(args), args.concurrency)
        result = asyncio.run(vet_servers(servers, deps))
    except Refused:
        raise
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT
    _print_vet_results(servers, result, deps.ping_answers)
    _print_unrecorded(servers)
    return 0 if not result.not_run else 1


def _tool_call_timeout(args: argparse.Namespace) -> int:
    if args.tool_call_timeout is not None:
        return args.tool_call_timeout
    return load_conditions(CONDITIONS_PATH).tool_call_timeout or TOOL_CALL_TIMEOUT


def default_vet_deps(tool_call_timeout: int, concurrency: int) -> VetDeps:
    ping_answers: dict[str, bool] = {}

    def record_ping(server: AdmittedServer, answered: bool) -> None:
        ping_answers[server.server_package] = answered

    call = functools.partial(benign_call, timeout=tool_call_timeout, on_ping=record_ping)
    return VetDeps(
        rebuild=rebuild_images,
        running_containers=running_containers,
        remove_containers=remove_containers,
        benign_call=bounded(call, concurrency),
        check_networks=check_closed_network_support,
        ping_answers=ping_answers,
    )


async def vet_servers(servers: Sequence[AdmittedServer], deps: VetDeps) -> VetResult:
    """In the run's order, so a vet proves the launch a run makes."""
    refuse_without_closed_networks(deps.check_networks)
    images = run_images(servers)
    refuse_server_containers(deps, images, _REFUSAL)
    remove_backend_containers(deps, images)
    deps.rebuild(images.services)
    refuse_server_containers(deps, images, _REFUSAL)
    try:
        return await drop_failing_servers(servers, deps.benign_call, deps)
    finally:
        sweep_run_containers(deps, images)


def _print_vet_results(
    servers: Sequence[AdmittedServer], result: VetResult, ping_answers: Mapping[str, bool]
) -> None:
    outcomes = {
        **{
            package: f"ok, on its second pass (first pass: {reason})"
            for package, reason in result.second_pass.items()
        },
        **{entry.server_package: entry.reason for entry in result.not_run},
    }
    for server in servers:
        package = server.server_package
        ping = _PING_ANSWER[ping_answers.get(package)]
        print(f"{package}: {outcomes.get(package, 'ok')}, answers the ping: {ping}")
    print(f"{len(result.surviving)} of {len(servers)} servers answer their benign calls")


_PING_ANSWER = {True: "yes", False: "no", None: "unknown"}  # None: the server never connected


def _print_unrecorded(servers: Sequence[AdmittedServer]) -> None:
    gaps = unrecorded_fields(servers)
    if gaps:
        print(
            f"{len(gaps)} of {len(servers)} servers have fields nuisance suite rule v3 or v4 adds"
            " not yet recorded (run and gate refuse them)"
        )
