"""The two no-LLM modes of run_detection, the calibration check and the survey."""

import argparse

from evals.concurrency import bounded
from evals.cve.detection.calibration_check_exit import (
    default_calibration_check_deps,
    run_calibration_check,
)
from evals.cve.detection.survey import survey_all, survey_one
from evals.cve.detection.targets import Target
from evals.cve.places import Places


async def calibration_check(args: argparse.Namespace, graded: list[Target], places: Places) -> int:
    # ADR 031 layout and route checks, confirmed before a draw: Docker-dependent, deterministic,
    # run only under the maintainer paths (--calibration-check and --record-baseline), never on a
    # gated comparison and not beside the synchronous preflight (no container exists there).
    deps = default_calibration_check_deps(args.concurrency, ci=args.ci)
    return await run_calibration_check(graded, places, deps)


async def survey(args: argparse.Namespace, graded: list[Target], places: Places) -> int:
    await survey_all(graded, bounded(lambda t: survey_one(t, places), args.concurrency))
    return 0
