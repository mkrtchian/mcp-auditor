"""Draw the judge isolation fixture from the judged cases of fresh source runs.

The rule (strata, quotas, seed, complement) is fixed before any draw: see
evals/judge_fixture_method.md. The drawn file carries the judge inputs only, never the
judge's verdict nor anything that would tell the labeler what the source cell expects.
"""

import argparse
import getpass
import json
import random
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evals import eval_display as display
from evals.cve_targets import CVE_TARGETS
from evals.eval_session import Refused
from evals.gate import Cell, cell_key
from evals.ground_truth import GroundTruth
from evals.honeypots import MERGED_GROUND_TRUTH, REPO_ROOT
from evals.judge_draw_checks import SourceReport, leaked_secrets, source_refusals, source_run
from evals.judge_fixture import (
    CaseLabel,
    CaseSource,
    DrawRecord,
    JudgeCase,
    JudgeFixture,
    JudgeInputs,
    SourceRun,
    case_id,
    load_drawn,
)
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

DRAW_SEED = 20260928
FAIL_CELL_QUOTA = 4
PASS_CELL_QUOTA = 1
CVE_TARGET_QUOTA = 3
COMPLEMENT_FAIL_SHARE = 0.4
DRAWN_PATH = REPO_ROOT / "evals" / "fixtures" / "judge_cases_drawn.json"
REFUSED_EXIT = 3


@dataclass(frozen=True)
class Strata:
    fail_cells: dict[str, list[JudgeCase]]
    pass_cells: dict[str, list[JudgeCase]]
    cve_targets: dict[str, list[JudgeCase]]


def main() -> None:
    args = _parse_args()
    try:
        _draw(args)
    except Refused as refusal:
        display.print_refusal(refusal.title, refusal.reasons)
        sys.exit(REFUSED_EXIT)


def candidates_from_honeypot(
    lines: Iterable[dict[str, Any]], ground_truth: GroundTruth
) -> dict[Cell, list[JudgeCase]]:
    """Every cell of the ground truth, with its distinct single-step cases."""
    candidates: dict[Cell, dict[str, JudgeCase]] = {cell: {} for cell in ground_truth}
    for line in lines:
        cell = (line["tool_name"], AuditCategory(line["category"]))
        if line["type"] != "single_step" or cell not in candidates:
            continue
        case = _candidate(line, CaseSource.HONEYPOT, f"cell {cell_key(cell)}")
        candidates[cell][case.id] = case
    return {cell: list(cases.values()) for cell, cases in candidates.items()}


def candidates_from_cve(lines: Iterable[dict[str, Any]]) -> dict[str, list[JudgeCase]]:
    candidates: dict[str, dict[str, JudgeCase]] = {}
    for line in lines:
        case = _candidate(line, CaseSource.CVE, f"cve {line['cve_id']}")
        candidates.setdefault(line["cve_id"], {})[case.id] = case
    return {cve_id: list(cases.values()) for cve_id, cases in candidates.items()}


def _candidate(line: dict[str, Any], source: CaseSource, origin: str) -> JudgeCase:
    inputs = JudgeInputs.model_validate(line)
    return JudgeCase(
        id=case_id(inputs), source=source, origin=origin, inputs=inputs, label=None, clause=None
    )


def draw(
    strata: dict[str, list[JudgeCase]], quota: int, rng: random.Random
) -> tuple[list[JudgeCase], list[str]]:
    drawn: list[JudgeCase] = []
    shortfalls: list[str] = []
    for key in sorted(strata):
        candidates = sorted(strata[key], key=lambda case: case.id)
        if len(candidates) < quota:
            shortfalls.append(f"{key}: {len(candidates)} candidates for a quota of {quota}")
            drawn.extend(candidates)
        else:
            drawn.extend(rng.sample(candidates, quota))
    return drawn, shortfalls


def draw_fixture(strata: Strata, sources: list[SourceRun]) -> JudgeFixture:
    rng = random.Random(DRAW_SEED)
    draws = [
        draw(strata.fail_cells, FAIL_CELL_QUOTA, rng),
        draw(strata.pass_cells, PASS_CELL_QUOTA, rng),
        draw(strata.cve_targets, CVE_TARGET_QUOTA, rng),
    ]
    record = DrawRecord(
        seed=DRAW_SEED,
        quotas={
            "fail_cell": FAIL_CELL_QUOTA,
            "pass_cell": PASS_CELL_QUOTA,
            "cve_target": CVE_TARGET_QUOTA,
        },
        sources=sources,
        shortfalls=[line for _, shortfalls in draws for line in shortfalls],
    )
    return JudgeFixture(draw=record, cases=[case for cases, _ in draws for case in cases])


def complement_refusals(fixture: JudgeFixture) -> list[str]:
    if fixture.draw is not None and fixture.draw.complement_seed is not None:
        return ["the complement is already drawn"]
    unlabeled = sum(case.label is None for case in fixture.cases)
    if unlabeled:
        return [f"{unlabeled} unlabeled case(s): label every case first"]
    fails = sum(case.label == CaseLabel.FAIL for case in fixture.cases)
    decided = sum(case.label in (CaseLabel.PASS, CaseLabel.FAIL) for case in fixture.cases)
    if decided and fails / decided >= COMPLEMENT_FAIL_SHARE:
        return []
    return [
        f"the complement rule does not fire: {fails} FAIL cases of {decided} labeled pass or"
        f" fail, under {COMPLEMENT_FAIL_SHARE * 100:.0f} %"
    ]


def complement(fixture: JudgeFixture, strata: Strata) -> JudgeFixture:
    """One more case per PASS cell, among the candidates not drawn yet."""
    assert fixture.draw is not None
    seed = DRAW_SEED + 1
    drawn_ids = {case.id for case in fixture.cases}
    remaining = {
        key: [case for case in cases if case.id not in drawn_ids]
        for key, cases in strata.pass_cells.items()
    }
    added, shortfalls = draw(remaining, PASS_CELL_QUOTA, random.Random(seed))
    record = fixture.draw.model_copy(
        update={
            "complement_seed": seed,
            "shortfalls": [*fixture.draw.shortfalls, *(f"complement, {s}" for s in shortfalls)],
        }
    )
    return JudgeFixture(draw=record, cases=[*fixture.cases, *added])


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"Draw the judge isolation cases into {DRAWN_PATH.relative_to(REPO_ROOT)}"
    )
    parser.add_argument("--honeypot-export", action="append", required=True, type=Path)
    parser.add_argument("--cve-export", required=True, type=Path)
    parser.add_argument(
        "--complement",
        action="store_true",
        help="draw one more case per PASS cell into the labeled drawn file (complement rule)",
    )
    return parser.parse_args()


def _draw(args: argparse.Namespace) -> None:
    reports = {path: path.with_name("eval_report.json") for path in args.honeypot_export}
    reports[args.cve_export] = args.cve_export.with_name("cve_report.json")
    sources = _sources(reports)
    strata = _strata_of(
        [line for path in args.honeypot_export for line in _lines(path)],
        _lines(args.cve_export),
    )
    if args.complement:
        fixture = _complemented(load_drawn(DRAWN_PATH), strata, sources)
    else:
        fixture = draw_fixture(strata, sources)
    leaks = leaked_secrets(fixture.cases, str(Path.home()), getpass.getuser())
    if leaks:
        raise Refused("Draw refused: inspect and rerun the source runs.", leaks)
    DRAWN_PATH.write_text(fixture.model_dump_json(indent=2) + "\n")
    print(f"{len(fixture.cases)} cases written to {DRAWN_PATH}")


def _sources(report_paths: dict[Path, Path]) -> list[SourceRun]:
    """`report_paths` maps each export to the report its run wrote beside it."""
    reports = {
        str(export): SourceReport.model_validate_json(report.read_text())
        for export, report in report_paths.items()
    }
    refusals = source_refusals(reports)
    if refusals:
        raise Refused("Draw refused.", refusals)
    return [
        source_run(str(export), export.read_bytes(), reports[str(export)])
        for export in report_paths
    ]


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _strata_of(honeypot_lines: list[dict[str, Any]], cve_lines: list[dict[str, Any]]) -> Strata:
    cells = candidates_from_honeypot(honeypot_lines, MERGED_GROUND_TRUTH)
    # Every benchmarked target is a stratum, so one with no judged case shows as a shortfall.
    none_judged: dict[str, list[JudgeCase]] = {target.cve_id: [] for target in CVE_TARGETS}
    targets = none_judged | candidates_from_cve(cve_lines)
    return Strata(
        fail_cells=_cells_labeled(cells, EvalVerdict.FAIL),
        pass_cells=_cells_labeled(cells, EvalVerdict.PASS),
        cve_targets=targets,
    )


def _cells_labeled(
    cells: dict[Cell, list[JudgeCase]], verdict: EvalVerdict
) -> dict[str, list[JudgeCase]]:
    return {
        cell_key(cell): cases
        for cell, cases in cells.items()
        if MERGED_GROUND_TRUTH[cell] == verdict
    }


def _complemented(fixture: JudgeFixture, strata: Strata, sources: list[SourceRun]) -> JudgeFixture:
    refusals = complement_refusals(fixture)
    recorded = [] if fixture.draw is None else fixture.draw.sources
    if sorted(s.sha256 for s in recorded) != sorted(s.sha256 for s in sources):
        refusals.append("the exports differ from the sources the draw recorded")
    if refusals:
        raise Refused("Complement refused.", refusals)
    return complement(fixture, strata)


if __name__ == "__main__":
    main()
