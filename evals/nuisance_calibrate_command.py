"""The `calibrate` subcommand of run_nuisance: rebuild and reproduce each fix-check fixture
against the admission's recorded fix_check (Docker, no LLM)."""

import argparse
import asyncio
import sys
from pathlib import Path

from evals import nuisance_fixtures
from evals.concurrency import bounded, positive_int
from evals.cve_targets import DOCKER_DIRECTORY
from evals.holdout_census import load_census
from evals.holdout_kit import kit_launch
from evals.holdout_kit.fix_check import FixCheckResult, FixCheckTarget, check_fix
from evals.nuisance_admission import ADMISSION_PATH, FixCheckRecord
from evals.nuisance_commands import (
    CENSUS_PATH,
    CRASHED_EXIT,
    UNKNOWN_SERVER_EXIT,
    committed_admission,
    malformed_input_refused,
)
from evals.nuisance_run import NUISANCE_CONCURRENCY


def add_calibrate_arguments(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(command=calibrate)
    parser.add_argument("--cve", help="calibrate only this flaw; default: every drawn fixture")
    parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    parser.add_argument("--census", type=Path, default=CENSUS_PATH)
    parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)


def calibrate(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        census = load_census(args.census)
        admission = committed_admission(args.admission, census)
    if admission is None or not admission.servers or not nuisance_fixtures.FIX_CHECK_TARGETS:
        print("nothing is drawn")
        return 0
    targets = [
        target
        for target in nuisance_fixtures.FIX_CHECK_TARGETS
        if args.cve is None or target.flaw == args.cve
    ]
    if not targets:
        print(f"unknown flaw: {args.cve} matches no fix-check target", file=sys.stderr)
        return UNKNOWN_SERVER_EXIT
    records = {flaw.flaw: flaw.fix_check for server in admission.servers for flaw in server.flaws}
    kit_launch.build_images(DOCKER_DIRECTORY, _services(targets))
    return asyncio.run(_calibrate_targets(targets, records, args.concurrency))


async def _calibrate_targets(
    targets: list[FixCheckTarget],
    records: dict[str, FixCheckRecord],
    concurrency: int,
) -> int:
    calibrate = bounded(check_fix, concurrency)
    results = await asyncio.gather(
        *(calibrate(target) for target in targets), return_exceptions=True
    )
    clean = True
    crashed = False
    for target, result in zip(targets, results, strict=True):
        if isinstance(result, BaseException):
            print(f"{target.flaw}: crashed: {result}", file=sys.stderr)
            crashed = True
            continue
        print(f"{target.flaw}: {result.to_json()}")
        problems = _calibration_problems(result, records.get(target.flaw))
        for problem in problems:
            print(f"  {problem}")
        clean = clean and not problems
    if crashed:
        return CRASHED_EXIT
    return 0 if clean else 1


def _calibration_problems(result: FixCheckResult, record: FixCheckRecord | None) -> list[str]:
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
    never equals the recorded nonce and is not compared. A record copied from the holdout
    calibration (source holdout_calibration) carries the calibration's provenance, not a fresh
    fix-check run, so its source field is not compared either."""
    return list(_field_mismatches(result, record).values())


def _field_mismatches(result: FixCheckResult, record: FixCheckRecord) -> dict[str, str]:
    skip = {"witness"}
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


def _services(targets: list[FixCheckTarget]) -> list[str]:
    services: list[str] = []
    for target in targets:
        for service in (
            target.vulnerable_service,
            target.patched_service,
            target.server_patched_service,
        ):
            if service is not None and service not in services:
                services.append(service)
    return services
