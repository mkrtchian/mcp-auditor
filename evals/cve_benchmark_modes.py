"""The two no-LLM modes of run_cve_benchmark, the calibration and the survey."""

import argparse

from evals.admission_calibration import calibrate_admitted, default_calibration_deps
from evals.concurrency import bounded
from evals.cve_places import Places
from evals.cve_survey import survey_all, survey_one
from evals.cve_targets import CVETarget


async def calibrate(args: argparse.Namespace, graded: list[CVETarget], places: Places) -> int:
    # ADR 031 admission, confirmed before a draw: Docker-dependent, deterministic, run only under
    # the maintainer paths (calibrate and record-baseline), never on a gated comparison and not
    # beside the synchronous preflight (no container exists there).
    deps = default_calibration_deps(args.concurrency, ci=args.ci)
    return await calibrate_admitted(graded, places, deps)


async def survey(args: argparse.Namespace, graded: list[CVETarget], places: Places) -> int:
    await survey_all(graded, bounded(lambda t: survey_one(t, places), args.concurrency))
    return 0
