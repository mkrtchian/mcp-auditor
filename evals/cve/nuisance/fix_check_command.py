"""The `fix-check` subcommand of run_nuisance: rebuild each fix-check fixture's images and
reproduce its flaw against the admission's recorded fix_check (Docker, no LLM)."""

import argparse
import asyncio
import functools
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.closed_network import check_closed_network_support
from evals.concurrency import bounded, positive_int
from evals.cve.kit.fix_check import FixCheckFixture, FixCheckResult, check_fix
from evals.cve.kit.launch import build_images, image_tag
from evals.cve.nuisance.backend_registry import built_backend_tags
from evals.cve.nuisance.commands import (
    CENSUS_PATH,
    CRASHED_EXIT,
    UNKNOWN_SERVER_EXIT,
    WALK_RECORD_PATH,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
)
from evals.cve.nuisance.fixtures import FIX_CHECK_FIXTURES
from evals.cve.nuisance.run import NUISANCE_CONCURRENCY
from evals.cve.run_images import DOCKER_SWEEP, refuse_without_closed_networks, sweep_containers
from evals.docker_paths import DOCKER_DIRECTORY
from evals.nuisance_admission import ADMISSION_PATH, FixCheckRecord


@dataclass(frozen=True)
class FixCheckDeps:
    build_images: Callable[[Sequence[str]], None]
    check_fix: Callable[[FixCheckFixture], Awaitable[FixCheckResult]]


def add_fix_check_arguments(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(command=fix_check)
    parser.add_argument("--flaw", help="fix-check only this flaw, default: every admitted flaw")
    parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    parser.add_argument("--census", type=Path, default=CENSUS_PATH)
    parser.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)


def fix_check(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
    if admission is None or not admission.servers or not FIX_CHECK_FIXTURES:
        print("no server is admitted")
        return 0
    fixtures = [
        fixture for fixture in FIX_CHECK_FIXTURES if args.flaw is None or fixture.flaw == args.flaw
    ]
    if not fixtures:
        print(f"unknown flaw: {args.flaw} matches no fix-check fixture", file=sys.stderr)
        return UNKNOWN_SERVER_EXIT
    records = {flaw.flaw: flaw.fix_check for server in admission.servers for flaw in server.flaws}
    refuse_without_closed_networks(check_closed_network_support)
    kit_tags = [image_tag(service) for service in _services(fixtures)]
    tags = [*kit_tags, *built_backend_tags(admission.servers)]
    try:
        deps = default_fix_check_deps(args.concurrency)
        return asyncio.run(check_fixes(fixtures, records, deps))
    finally:
        sweep_containers(tags, DOCKER_SWEEP.running_containers, DOCKER_SWEEP.remove_containers)


def default_fix_check_deps(concurrency: int) -> FixCheckDeps:
    return FixCheckDeps(
        build_images=functools.partial(build_images, DOCKER_DIRECTORY),
        check_fix=bounded(check_fix, concurrency),
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
    problems = list(reported.values())
    if record is None:
        return [*problems, "no admission fix_check records this flaw"]
    mismatches = _field_mismatches(result, record)
    return problems + [text for name, text in mismatches.items() if name not in reported]


def fix_check_mismatches(result: FixCheckResult, record: FixCheckRecord) -> list[str]:
    """Where a re-run fix-check result departs from the admission's recorded fix_check, field by
    field. The witness is a fresh random nonce each run (check_fix plants RANDOM_NONCES), so it
    never equals the recorded nonce and is not compared. A holdout calibration copy (source
    holdout_calibration) carries the provenance of a holdout target's calibration, not a fresh fix
    check, so its source field is not compared either. Whether the positive control rests on a
    relaying stand-in is a judgment the admission records, and the fingerprint a holdout
    calibration copy was taken at is the copy's provenance: the kit observes neither."""
    return list(_field_mismatches(result, record).values())


def _field_mismatches(result: FixCheckResult, record: FixCheckRecord) -> dict[str, str]:
    # The admission records these two, the kit observes neither.
    skip = {"witness", "relies_on_relaying_stand_in", "holdout_fingerprint"}
    if record.source == "holdout_calibration":
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
