"""The `fix-check` subcommand of run_nuisance: rebuild each fix-check fixture's images, bring the
sentinel and stand-in images and the built backend images its fixtures stand up to their compose
fingerprint (the services a fixture names, else the run backend's of the servers it checks), and
reproduce each flaw against the admission's recorded fix_check (Docker, no LLM)."""

import argparse
import asyncio
import functools
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from evals.cli_arguments import positive_int
from evals.concurrency import bounded
from evals.cve.closed_network import check_closed_network_support
from evals.cve.docker_paths import DOCKER_DIRECTORY
from evals.cve.images import ComposeImageStore, ensure_images
from evals.cve.images import image_tag as backend_image_tag
from evals.cve.kit.fix_check import FixCheckFixture, FixCheckResult, check_fix
from evals.cve.kit.launch import build_images, image_tag
from evals.cve.nuisance.admission.admission import AdmittedServer, FixCheckRecord, NuisanceAdmission
from evals.cve.nuisance.backend_registry import built_backend_services, built_backend_tags
from evals.cve.nuisance.commands import (
    CRASHED_EXIT,
    NUISANCE_CONCURRENCY,
    add_committed_input_arguments,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
)
from evals.cve.nuisance.fixtures import FIX_CHECK_FIXTURES
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.cve.run_images import (
    DOCKER_SWEEP,
    ContainerSweep,
    refuse_without_closed_networks,
    sweep_containers,
)

UNKNOWN_FLAW_EXIT = 2
# Refreshed but never swept: every planted launch's namespace holder runs the sentinel image, and a
# run in progress may hold containers of both.
PLANTING_SERVICES = (SENTINEL_SERVICE, STAND_IN_SERVICE)


@dataclass(frozen=True)
class FixCheckDeps:
    build_images: Callable[[Sequence[str]], None]
    # A builder builds a compose image only when its tag is absent, which would stand an image an
    # older Dockerfile built.
    refresh_compose_images: Callable[[Sequence[str]], None]
    check_fix: Callable[[FixCheckFixture], Awaitable[FixCheckResult]]
    check_networks: Callable[[], None]
    sweep: ContainerSweep


def default_fix_check_deps(concurrency: int, show_exploit_responses: bool) -> FixCheckDeps:
    return FixCheckDeps(
        build_images=functools.partial(build_images, DOCKER_DIRECTORY),
        refresh_compose_images=_ensure_compose_images,
        check_fix=bounded(
            functools.partial(check_fix, show_exploit_responses=show_exploit_responses),
            concurrency,
        ),
        check_networks=check_closed_network_support,
        sweep=DOCKER_SWEEP,
    )


def _ensure_compose_images(services: Sequence[str]) -> None:
    ensure_images(services, ComposeImageStore())


class FixCheckDepsFactory(Protocol):
    def __call__(self, concurrency: int, show_exploit_responses: bool, /) -> FixCheckDeps: ...


@dataclass(frozen=True)
class FixCheckCommandDeps:
    fixtures: Sequence[FixCheckFixture] = FIX_CHECK_FIXTURES
    fix_check_deps: FixCheckDepsFactory = default_fix_check_deps


def add_fix_check_arguments(parser: argparse.ArgumentParser, deps: FixCheckCommandDeps) -> None:
    parser.set_defaults(command=functools.partial(fix_check, deps=deps))
    parser.add_argument("--flaw", help="fix-check only this flaw, default: every admitted flaw")
    parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    parser.add_argument(
        "--show-exploit-responses",
        action="store_true",
        help="print each exploit's responses on every version, the vulnerable one first",
    )
    add_committed_input_arguments(parser)


def fix_check(args: argparse.Namespace, deps: FixCheckCommandDeps) -> int:
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
    if admission is None or not admission.servers:
        print("no server is admitted")
        return 0
    fixtures = _selected_fixtures(deps.fixtures, args.flaw)
    if not fixtures:
        print(f"unknown flaw: {args.flaw} matches no fix-check fixture", file=sys.stderr)
        return UNKNOWN_FLAW_EXIT
    docker = deps.fix_check_deps(args.concurrency, args.show_exploit_responses)
    refuse_without_closed_networks(docker.check_networks)
    backend_services = _backend_services(fixtures, admission.servers)
    tags = _swept_tags(fixtures, backend_services, admission.servers)
    try:
        docker.refresh_compose_images(list(dict.fromkeys([*PLANTING_SERVICES, *backend_services])))
        return asyncio.run(check_fixes(fixtures, _recorded_fix_checks(admission), docker))
    finally:
        sweep_containers(tags, docker.sweep)


def _selected_fixtures(
    fixtures: Sequence[FixCheckFixture], flaw: str | None
) -> list[FixCheckFixture]:
    return [fixture for fixture in fixtures if flaw is None or fixture.flaw == flaw]


def _recorded_fix_checks(admission: NuisanceAdmission) -> dict[str, FixCheckRecord]:
    return {flaw.flaw: flaw.fix_check for server in admission.servers for flaw in server.flaws}


def _swept_tags(
    fixtures: Sequence[FixCheckFixture],
    backend_services: Sequence[str],
    servers: Sequence[AdmittedServer],
) -> list[str]:
    kit_tags = [image_tag(service) for service in _services(fixtures)]
    backend_tags = [*built_backend_tags(servers), *map(backend_image_tag, backend_services)]
    return list(dict.fromkeys([*kit_tags, *backend_tags]))


def _backend_services(
    fixtures: Sequence[FixCheckFixture], servers: Sequence[AdmittedServer]
) -> list[str]:
    services = (
        service
        for fixture in fixtures
        for service in (
            fixture.backend_services
            if fixture.backend_services is not None
            else _run_backend_services(fixture.flaw, servers)
        )
    )
    return list(dict.fromkeys(services))


def _run_backend_services(flaw: str, servers: Sequence[AdmittedServer]) -> list[str]:
    return built_backend_services(
        [server for server in servers if flaw in {carried.flaw for carried in server.flaws}]
    )


async def check_fixes(
    fixtures: Sequence[FixCheckFixture],
    records: Mapping[str, FixCheckRecord],
    deps: FixCheckDeps,
) -> int:
    """0 when every fixture reproduces its flaw as the admission recorded it, 1 on a departure,
    CRASHED_EXIT when a fix check raised."""
    deps.build_images(_services(fixtures))
    results = await asyncio.gather(
        *(deps.check_fix(fixture) for fixture in fixtures), return_exceptions=True
    )
    clean = True
    crashed = False
    for fixture, result in zip(fixtures, results, strict=True):
        if isinstance(result, BaseException):
            print(f"{fixture.flaw}: crashed: {result}", file=sys.stderr)
            crashed = True
            continue
        print(f"{fixture.flaw}: {result.to_json()}")
        problems = _fix_check_problems(result, records.get(fixture.flaw))
        for problem in problems:
            print(f"  {problem}")
        clean = clean and not problems
    if crashed:
        return CRASHED_EXIT
    return 0 if clean else 1


def _fix_check_problems(result: FixCheckResult, record: FixCheckRecord | None) -> list[str]:
    reported: dict[str, str] = {}
    if not result.vulnerable_surfaces:
        reported["vulnerable_surfaces"] = "the witness does not surface on the vulnerable version"
    if result.patched_surfaces:
        reported["patched_surfaces"] = "the witness surfaces on the patched version"
    if result.server_patched_surfaces:
        reported["server_patched_surfaces"] = "the witness surfaces on the server's patched version"
    problems = [*reported.values(), *result.unreached_patched_exploits]
    if record is None:
        return [*problems, "no admission fix_check records this flaw"]
    mismatches = fix_check_mismatches(result, record)
    return problems + [text for name, text in mismatches.items() if name not in reported]


def fix_check_mismatches(result: FixCheckResult, record: FixCheckRecord) -> dict[str, str]:
    """Where a re-run fix-check result departs from the admission's recorded fix_check, field by
    field. The witness is drawn fresh each run (check_fix plants RANDOM_NONCES), so it never equals
    the recorded witness and is not compared. A holdout calibration copy (source
    detection_holdout_calibration) carries the provenance of a holdout target's calibration, not a
    fresh fix check, so its source field is not compared either. Whether the positive control rests
    on a relaying stand-in is a judgment the admission records, and the fingerprint a holdout
    calibration copy was taken at is the copy's provenance: the kit observes neither."""
    skip = {"witness", "relies_on_relaying_stand_in", "holdout_fingerprint"}
    if record.is_holdout_calibration_copy:
        skip.add("source")
    mismatches: dict[str, str] = {}
    for name in FixCheckRecord.model_fields:
        if name in skip:
            continue
        got = getattr(result, name)
        want = getattr(record, name)
        if got != want:
            mismatches[name] = f"{name}: fix check {got!r} does not match admission {want!r}"
    return mismatches


def _services(fixtures: Sequence[FixCheckFixture]) -> list[str]:
    services: list[str] = []
    for fixture in fixtures:
        for service in (
            fixture.vulnerable_service,
            fixture.patched_service,
            fixture.server_patched_service,
        ):
            if service is not None and service not in services:
                services.append(service)
    return services
