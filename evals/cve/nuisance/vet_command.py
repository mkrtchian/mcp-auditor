"""The `vet` subcommand of run_nuisance: rebuild the run's images and make each audited server's
benign calls on the run's own launch path, with the run's container hygiene around them (Docker,
no LLM). It finds a broken image or launch before an audit is paid for, and writes no result."""

import argparse
import asyncio
import functools
import sys
import traceback
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from evals.cli_arguments import positive_int
from evals.concurrency import bounded
from evals.cve.closed_network import check_closed_network_support
from evals.cve.environments import TOOL_CALL_TIMEOUT
from evals.cve.holdout_conditions import HoldoutConditions, committed_conditions
from evals.cve.images import ComposeImageStore
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.unrecorded import unrecorded_fields
from evals.cve.nuisance.benign_call import BenignCallCheck
from evals.cve.nuisance.commands import (
    CRASHED_EXIT,
    NUISANCE_CONCURRENCY,
    UNKNOWN_SERVER_EXIT,
    add_committed_input_arguments,
    committed_run_population,
)
from evals.cve.nuisance.containers import rebuilt_run_images
from evals.cve.nuisance.vetting import (
    LaunchedBenignCall,
    ServerLauncher,
    VetResult,
    drop_failing_servers,
)
from evals.cve.run_images import DOCKER_SWEEP, ContainerSweep
from evals.eval_session import Refused

_REFUSAL = "nuisance vet refused"


@dataclass(frozen=True)
class VetDeps:
    rebuild: Callable[[Sequence[str]], None]
    sweep: ContainerSweep
    benign_call: BenignCallCheck
    check_networks: Callable[[], None]
    # Whether each server answered a ping after its handshake, by package, filled by benign_call.
    ping_answers: dict[str, bool]


def default_vet_deps(
    tool_call_timeout: int, concurrency: int, launcher: ServerLauncher | None = None
) -> VetDeps:
    ping_answers: dict[str, bool] = {}

    def record_ping(server: AdmittedServer, answered: bool) -> None:
        ping_answers[server.server_package] = answered

    call = LaunchedBenignCall(tool_call_timeout, record_ping, launcher or ServerLauncher())
    return VetDeps(
        rebuild=ComposeImageStore().build,
        sweep=DOCKER_SWEEP,
        benign_call=bounded(call, concurrency),
        check_networks=check_closed_network_support,
        ping_answers=ping_answers,
    )


@dataclass(frozen=True)
class VetCommandDeps:
    conditions: Callable[[], HoldoutConditions] = committed_conditions
    vet_deps: Callable[[int, int], VetDeps] = default_vet_deps


def add_vet_arguments(parser: argparse.ArgumentParser, deps: VetCommandDeps) -> None:
    parser.set_defaults(command=functools.partial(vet, deps=deps))
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
    add_committed_input_arguments(parser)


def vet(args: argparse.Namespace, deps: VetCommandDeps) -> int:
    committed = committed_run_population(args.census, args.walk_record, args.admission)
    if committed is None:
        print("no server is admitted")
        return 0
    _, population = committed
    audited = population.audited
    packages = [server.server_package for server in audited]
    unknown = [package for package in args.server if package not in packages]
    if unknown:
        print(f"not an audited server: {', '.join(unknown)}", file=sys.stderr)
        return UNKNOWN_SERVER_EXIT
    servers = [s for s in audited if not args.server or s.server_package in args.server]
    try:
        vet_deps = deps.vet_deps(_tool_call_timeout(args, deps.conditions), args.concurrency)
        result = asyncio.run(vet_servers(servers, vet_deps))
    except Refused:
        raise
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT
    _print_vet_results(servers, result, vet_deps.ping_answers)
    _print_unrecorded(servers)
    return 0 if not result.not_run else 1


def _tool_call_timeout(
    args: argparse.Namespace, conditions: Callable[[], HoldoutConditions]
) -> int:
    if args.tool_call_timeout is not None:
        return args.tool_call_timeout
    return conditions().tool_call_timeout or TOOL_CALL_TIMEOUT


async def vet_servers(servers: Sequence[AdmittedServer], deps: VetDeps) -> VetResult:
    with rebuilt_run_images(servers, deps, _REFUSAL):
        return await drop_failing_servers(servers, deps.benign_call, deps.sweep)


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
    unrecorded = unrecorded_fields(servers)
    if unrecorded:
        print(
            f"{len(unrecorded)} of {len(servers)} servers have fields nuisance suite rule v3"
            " or v4 adds not yet recorded (run and gate refuse them)"
        )
