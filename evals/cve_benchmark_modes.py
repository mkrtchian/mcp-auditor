"""The two no-LLM modes of run_cve_benchmark, the calibration and the survey."""

import argparse

from evals.concurrency import bounded
from evals.cve_calibration import calibrate_all, calibrate_one
from evals.cve_layout_check import confirm_admission
from evals.cve_places import Places
from evals.cve_survey import survey_all, survey_one
from evals.cve_targets import CVETarget


async def calibrate(args: argparse.Namespace, graded: list[CVETarget], places: Places) -> int:
    # ADR 031 admission, confirmed before a draw: Docker-dependent, deterministic, run only
    # under the maintainer paths (calibrate and record-baseline), never on a gated comparison
    # and not beside the synchronous preflight (no container exists there). The rule runs the
    # layout check before the exploits (holdout-rule.md:159), so it reports its break first.
    admission_failures = await confirm_admission(graded, places, ci=args.ci)
    all_live = await calibrate_all(
        graded, bounded(lambda t: calibrate_one(t, places), args.concurrency), ci=args.ci
    )
    return 0 if all_live and not admission_failures else 1


async def survey(args: argparse.Namespace, graded: list[CVETarget], places: Places) -> int:
    await survey_all(graded, bounded(lambda t: survey_one(t, places), args.concurrency))
    return 0
