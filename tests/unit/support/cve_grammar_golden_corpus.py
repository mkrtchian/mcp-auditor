"""The fixed corpus the CVE grammar golden master grades: the reports and units of the
grammar unit tests, and the CVE cases of the judge fixture pinned by id. The generator
(`test_cve_grammar_golden_given`) grades it and freezes the result."""

from collections import defaultdict
from pathlib import Path
from typing import Any

import tests.unit.support.test_cve_grammar_given as given
from evals.cve_grammar import MissClass, RunGrade
from evals.cve_report_units import units_of
from evals.cve_units import Unit, unit_of_exchanges
from evals.judge_fixture import JudgeCase, JudgeInputs, load_fixture
from mcp_auditor.domain.models import AttackChain, AuditReport, ChainStep, EvalVerdict, TestCase

JUDGE_FIXTURE_PATH = Path(__file__).parents[3] / "evals" / "fixtures" / "judge_cases.json"
SENTINEL = given.SENTINEL
FAIL = given.FAIL
PASS = given.PASS

# Pinned by id and in this order, which chains follow, so that a later draw adding a CVE case
# to the judge fixture, or a reordering of it, leaves the corpus.
CVE_CASE_IDS = (
    "16dc8fc2429b406b",
    "7cde8d7d4e2b16e7",
    "70c0a82182501d2c",
    "1bd34b1116070f03",
    "9e21d0c88a2d982e",
    "139837768dbf40e7",
    "2408cfbcf161b971",
    "d6e753db6ac1a9a2",
    "db4f9795d19e00da",
    "14c23b05fd176310",
    "b32cbcdfa17696c7",
    "8e0a6cc08886cf2b",
    "cf0b0ffd63fae844",
    "778083fe8ebf0b2d",
    "7e10eae7aeac6a30",
    "ca03d12903e6e812",
    "39e1994c0f9f37b0",
    "299a26557c7674cc",
)


def read_target_reports() -> dict[str, AuditReport]:
    return {**_nonce_reports(), **_miss_reports(), **_blocked_chain_reports()}


def command_target_reports() -> dict[str, AuditReport]:
    aimed = {"command": "id; whoami"}
    return {
        "nonce_under_fail": _of_cases(
            given.a_case(response=f"FLAG={SENTINEL}", category=given.INJECTION)
        ),
        "fail_without_proof_injection": _of_cases(
            given.a_case(response="denied", arguments=aimed, category=given.INJECTION)
        ),
        "fail_without_proof_outside_class": _of_cases(
            given.a_case(response="denied", arguments=aimed, category=given.INFO_LEAKAGE)
        ),
    }


def test_exchanges() -> dict[str, Unit]:
    return {
        "aim_in_a_nested_dict": unit_of_exchanges(
            [({"options": {"source": given.AIMED_PATH}}, "ok")]
        ),
        "aim_in_a_list": unit_of_exchanges([({"paths": ["/inside/a", given.AIMED_PATH]}, "ok")]),
        "aim_in_a_list_of_dicts": unit_of_exchanges(
            [({"batch": [{"files": [given.AIMED_PATH]}]}, "ok")]
        ),
        "non_string_argument_values": unit_of_exchanges(
            [({"depth": 3, "recursive": True, "path": None}, "ok")]
        ),
        "proof_in_the_last_output": unit_of_exchanges(
            [({"path": "/a"}, "ok"), ({"path": "/b"}, "ok"), ({"path": "/c"}, f"leaked {SENTINEL}")]
        ),
        "echo_from_the_first_exchange": unit_of_exchanges(
            [({"path": SENTINEL}, "ok"), ({"path": "/b"}, "ok"), ({"path": "/c"}, SENTINEL)]
        ),
    }


def test_resolutions() -> dict[str, list[RunGrade]]:
    return {
        "highest_rung_over_runs": [
            given.a_missed_run(MissClass.NOT_AIMED),
            given.a_reached_run(),
            given.a_detected_run(),
        ],
        "best_miss_class_over_missed_runs": [
            given.a_missed_run(MissClass.NOT_AIMED, aimed=False),
            given.a_missed_run(MissClass.AIMED_NO_PROOF),
            given.a_missed_run(MissClass.AIMED_BLOCKED),
        ],
        "each_condition_per_run": [
            given.a_detected_run(),
            given.a_reached_run(),
            given.a_missed_run(MissClass.AIMED_NO_PROOF, fail_without_proof=True),
            given.a_missed_run(MissClass.NOT_AIMED, aimed=False),
        ],
    }


def cases_by_target() -> dict[str, list[JudgeCase]]:
    cases = {case.id: case for case in load_fixture(JUDGE_FIXTURE_PATH).cases}
    by_target: defaultdict[str, list[JudgeCase]] = defaultdict(list)
    for case_id in CVE_CASE_IDS:
        by_target[cases[case_id].origin.removeprefix("cve ")].append(cases[case_id])
    return by_target


def real_reports(cases: list[JudgeCase]) -> dict[str, AuditReport]:
    return {
        f"{case.id}/{verdict.value}": _of_cases(_case_of(case.inputs, verdict))
        for case in cases
        for verdict in (FAIL, PASS)
    }


def variant_reports(cases: list[JudgeCase]) -> dict[str, AuditReport]:
    return {
        f"{case.id}/{name}": _of_cases(_case_of(inputs, verdict))
        for case in cases
        for name, (inputs, verdict) in _variants(case.inputs).items()
    }


def chain_reports(cases: list[JudgeCase]) -> dict[str, AuditReport]:
    first, second, third = (case.inputs for case in cases)
    leaking = _step(_with_response(second, SENTINEL))
    echoing = _step(first.model_copy(update={"arguments": _echoing(first.arguments)}))
    blocked = "destructive payload"
    return {
        "nonce_in_step_2": _of_chain([_step(first), leaking, _step(third)]),
        "nonce_in_step_2_echoed_from_step_1": _of_chain([echoing, leaking, _step(third)]),
        "blocked_after_step_1": _of_chains(given.a_chain([_step(first)], blocked_reason=blocked)),
        "blocked_at_first_step": _of_chains(given.a_chain_blocked_at_first_step(first.arguments)),
    }


def dead_conditions_units(inputs: JudgeInputs) -> tuple[Unit, Unit]:
    [exploit] = units_of(_of_cases(_case_of(_with_response(inputs, SENTINEL), FAIL)))
    [benign] = units_of(_of_cases(_case_of(inputs, FAIL)))
    return exploit, benign


def _nonce_reports() -> dict[str, AuditReport]:
    leaking = f"leaked {SENTINEL}"
    return {
        "nonce_in_a_fail_case/response": _of_cases(given.a_case(response=leaking)),
        "nonce_in_a_fail_case/error": _of_cases(given.a_case(error=f"boom {SENTINEL}")),
        "nonce_in_a_fail_case/dict_response": _of_cases(
            given.a_case(response={"content": SENTINEL})
        ),
        "nonce_echoed_from_the_case_arguments": _of_cases(
            given.a_case(response=f"no file {SENTINEL}", arguments={"path": SENTINEL})
        ),
        "nonce_carried_by_an_earlier_chain_step": _of_chain(
            [given.a_step(arguments={"path": SENTINEL}), given.a_step(response=f"echo {SENTINEL}")]
        ),
        "nonce_carried_only_by_a_later_chain_step": _of_chain(
            [
                given.a_step(),
                given.a_step(response=leaking),
                given.a_step(arguments={"path": SENTINEL}),
            ]
        ),
        "nonce_only_in_the_report_target": given.a_report(
            cases=[given.a_case(response="nothing")], target=f"docker run -e FLAG={SENTINEL}"
        ),
        "nonce_only_in_a_step_observation": _of_chain(
            [given.a_step(response="nothing", observation=f"saw {SENTINEL}")]
        ),
        "nonce_under_pass": _of_cases(given.a_case(response=leaking, verdict=PASS)),
        "proof_and_fail_on_different_cases": _of_cases(
            given.a_case(response=leaking, verdict=PASS),
            given.a_case(response="nothing", verdict=FAIL),
        ),
        "nonce_under_fail_in_any_category": _of_cases(
            given.a_case(response=leaking, category=given.RESOURCE_ABUSE)
        ),
    }


def _miss_reports() -> dict[str, AuditReport]:
    aimed = {"path": given.AIMED_PATH}
    return {
        "missed/not_aimed": _of_cases(given.a_case(response="nothing")),
        "missed/aimed_blocked": _of_cases(given.a_blocked_case(aimed)),
        "missed/aimed_no_proof": _of_cases(given.a_case(response="nothing", arguments=aimed)),
        "missed/blocked_and_unblocked": _of_cases(
            given.a_blocked_case(aimed), given.a_case(response="nothing", arguments=aimed)
        ),
        "fail_without_proof/aimed_valid_category": _of_cases(
            given.a_case(response="denied", arguments=aimed, category=given.INJECTION)
        ),
        "fail_without_proof/category_outside_class": _of_cases(
            given.a_case(response="denied", arguments=aimed, category=given.RESOURCE_ABUSE)
        ),
        "fail_without_proof/not_aimed": _of_cases(
            given.a_case(response="denied", category=given.INJECTION)
        ),
    }


def _blocked_chain_reports() -> dict[str, AuditReport]:
    blocked = "destructive payload"
    return {
        "chain_blocked_at_first_step": _of_chains(
            given.a_chain_blocked_at_first_step({"path": given.AIMED_PATH})
        ),
        "chain_blocked_after_a_leaking_first_step": _of_chains(
            given.a_chain([given.a_step(response=f"leaked {SENTINEL}")], blocked_reason=blocked)
        ),
        "chain_blocked_after_its_first_step": _of_chains(
            given.a_chain(
                [given.a_step(arguments={"path": given.AIMED_PATH})], blocked_reason=blocked
            )
        ),
    }


def _variants(inputs: JudgeInputs) -> dict[str, tuple[JudgeInputs, EvalVerdict]]:
    leaking = _with_response(inputs, SENTINEL)
    return {
        "response_nonce_fail": (leaking, FAIL),
        "response_nonce_pass": (leaking, PASS),
        "error_nonce_fail": (
            inputs.model_copy(update={"error": _spliced(inputs.error, SENTINEL)}),
            FAIL,
        ),
        "echo_fail": (leaking.model_copy(update={"arguments": _echoing(inputs.arguments)}), FAIL),
    }


def _of_cases(*cases: TestCase) -> AuditReport:
    return given.a_report(cases=list(cases))


def _of_chains(*chains: AttackChain) -> AuditReport:
    return given.a_report(chains=list(chains))


def _of_chain(steps: list[ChainStep]) -> AuditReport:
    return _of_chains(given.a_chain(steps))


def _case_of(inputs: JudgeInputs, verdict: EvalVerdict) -> TestCase:
    return given.a_case(
        response=inputs.response,
        error=inputs.error,
        verdict=verdict,
        category=inputs.category,
        arguments=inputs.arguments,
    )


def _step(inputs: JudgeInputs) -> ChainStep:
    response = None if inputs.response is None else str(inputs.response)
    return given.a_step(arguments=inputs.arguments, response=response, error=inputs.error)


def _with_response(inputs: JudgeInputs, text: str) -> JudgeInputs:
    return inputs.model_copy(update={"response": _spliced(inputs.response, text)})


def _spliced(output: str | dict[str, Any] | None, text: str) -> str:
    return text if output is None else f"{output}\n{text}"


def _echoing(arguments: dict[str, Any]) -> dict[str, Any]:
    key = next(key for key, value in arguments.items() if isinstance(value, str))
    return arguments | {key: f"{arguments[key]}{SENTINEL}"}
