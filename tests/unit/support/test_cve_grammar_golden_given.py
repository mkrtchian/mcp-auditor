"""The golden master of the CVE grammar: what `grade_run`, `proofs_in`, `is_aimed`, `resolve`,
`dead_conditions` and `struck_by_replay` return on a fixed corpus, recorded in
`cve_grammar_golden.json`.

The corpus is built by `cve_grammar_golden_corpus`: the reports and units of the grammar unit
tests, the CVE cases of the judge fixture pinned by id, each judged FAIL and PASS with nonce
variants and chains of each target's cases, and the credit-check and replay-strike cases. A
case is graded against its target's mechanism and aim, with the planted nonce as the only
proof.

The file is regenerated only in a commit that changes what the grammar grades, beside its
labeling log entry, or in the commit of a fixture that changes a target's mechanism or aim.
A refactoring never regenerates it.
"""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import tests.unit.support.cve_grammar_golden_corpus as corpus
import tests.unit.support.test_cve_grammar_given as given
import tests.unit.support.test_cve_strike_given as strike
from evals.cve_calibration import dead_conditions
from evals.cve_grammar import CreditCheck, GradedTarget, grade_run, resolve
from evals.cve_proofs import GradedRun, UnitPlace, is_aimed, proofs_in, struck_by_replay
from evals.cve_report_units import units_of
from evals.cve_targets import CVE_TARGETS
from evals.cve_units import Unit
from evals.judge_fixture import JudgeCase, JudgeInputs
from mcp_auditor.domain.models import AuditReport

GOLDEN_PATH = Path(__file__).parent / "cve_grammar_golden.json"


def golden_entries() -> dict[str, Any]:
    entries: dict[str, Any] = {
        f"tests/{name}": _graded(target, report)
        for target, reports in (
            (given.a_read_target(), corpus.read_target_reports()),
            (given.a_command_target(), corpus.command_target_reports()),
        )
        for name, report in reports.items()
    }
    entries |= {
        f"tests/exchanges/{name}": _unit_entry(unit, given.a_read_target())
        for name, unit in corpus.test_exchanges().items()
    }
    entries |= {
        f"resolve/tests/{name}": resolve(grades).model_dump(mode="json")
        for name, grades in corpus.test_resolutions().items()
    }
    for cve_id, cases in corpus.cases_by_target().items():
        entries |= _target_entries(cve_id, cases)
    entries |= {
        f"strike/{name}": _struck(run, replay) for name, (run, replay) in _strike_pairs().items()
    }
    entries |= {
        f"check/{name}": grade_run(target, units, check).model_dump(mode="json")
        for name, (target, units, check) in _check_cases().items()
    }
    return entries


def _graded(target: GradedTarget, report: AuditReport) -> dict[str, Any]:
    return {
        "grade": grade_run(target, units_of(report)).model_dump(mode="json"),
        "units": [_unit_entry(unit, target) for unit in units_of(report)],
    }


def _unit_entry(unit: Unit, target: GradedTarget) -> dict[str, Any]:
    return {"proofs": proofs_in(unit, target), "aimed": is_aimed(unit, target.aim)}


def _target_entries(cve_id: str, cases: list[JudgeCase]) -> dict[str, Any]:
    target = _graded_target(cve_id)
    real = {f"real/{cve_id}/{key}": report for key, report in corpus.real_reports(cases).items()}
    variants = {
        f"variant/{cve_id}/{key}": report for key, report in corpus.variant_reports(cases).items()
    }
    chains = {
        f"chain/{cve_id}/{name}": report for name, report in corpus.chain_reports(cases).items()
    }
    reports = real | variants | chains
    return {
        **{key: _graded(target, report) for key, report in reports.items()},
        f"resolve/{cve_id}/real": _resolved(target, real.values()),
        f"resolve/{cve_id}/all": _resolved(target, reports.values()),
        **{
            f"dead_conditions/{cve_id}/{case.id}": _dead_conditions(target, case.inputs)
            for case in cases
        },
    }


def _dead_conditions(target: GradedTarget, inputs: JudgeInputs) -> list[str]:
    exploit, benign = corpus.dead_conditions_units(inputs)
    return dead_conditions(target, exploit, benign)


def _graded_target(cve_id: str) -> given.FakeTarget:
    [target] = [target for target in CVE_TARGETS if target.cve_id == cve_id]
    return given.FakeTarget(target.mechanism, {given.PLACE: given.SENTINEL}, target.aim)


def _resolved(target: GradedTarget, reports: Iterable[AuditReport]) -> dict[str, Any]:
    return resolve([grade_run(target, units_of(report)) for report in reports]).model_dump(
        mode="json"
    )


def _struck(run: GradedRun, replay: GradedRun) -> list[list[Any]]:
    return sorted([pair.unit_index, pair.place_id] for pair in struck_by_replay(run, replay))


def _strike_pairs() -> dict[str, tuple[GradedRun, GradedRun]]:
    a, b = strike.PLACE_A, strike.PLACE_B
    nonce, fresh = {a: strike.NONCE_A}, {a: strike.FRESH_A}
    return {
        "same_place_resurfaced": (
            GradedRun(strike.a_target(nonce), [strike.leaking_unit(strike.NONCE_A)]),
            GradedRun(strike.a_target(fresh), [strike.leaking_unit(strike.FRESH_A)]),
        ),
        "another_unit_resurfaced": (
            GradedRun(
                strike.a_target(nonce), [strike.leaking_unit(strike.NONCE_A), strike.leaking_unit()]
            ),
            GradedRun(
                strike.a_target(fresh), [strike.leaking_unit(), strike.leaking_unit(strike.FRESH_A)]
            ),
        ),
        "another_place_resurfaced": (
            GradedRun(strike.a_target(nonce), [strike.leaking_unit(strike.NONCE_A)]),
            GradedRun(
                strike.a_target({a: strike.FRESH_A, b: strike.FRESH_B}),
                [strike.leaking_unit(strike.FRESH_B)],
            ),
        ),
        "echo_only": (
            GradedRun(strike.a_target(nonce), [strike.leaking_unit(strike.NONCE_A)]),
            GradedRun(strike.a_target(fresh), [strike.echoing_unit(strike.FRESH_A)]),
        ),
    }


def _check_cases() -> dict[str, tuple[GradedTarget, list[Unit], CreditCheck]]:
    target = strike.a_target({strike.PLACE_A: strike.NONCE_A})
    leaking = f"leaked {strike.NONCE_A}"
    two_units = units_of(
        given.a_report(
            cases=[
                given.a_case(response=leaking, verdict=given.FAIL),
                given.a_case(response=leaking, verdict=given.PASS),
            ]
        )
    )
    one_unit = units_of(given.a_report(cases=[given.a_case(response=leaking)]))
    struck = CreditCheck(frozenset({UnitPlace(0, strike.PLACE_A)}), False)
    return {
        "struck_pair": (target, two_units, struck),
        "unchecked": (target, one_unit, CreditCheck(frozenset(), True)),
    }


if __name__ == "__main__":
    GOLDEN_PATH.write_text(json.dumps(golden_entries(), indent=2, sort_keys=True) + "\n")
