"""The golden master of the CVE grammar: what `grade_run`, `proofs_in`, `is_aimed`, `resolve`
and `dead_conditions` return on a fixed corpus, recorded in `cve_grammar_golden.json`.

The corpus is the reports and units of the grammar unit tests, and the CVE cases of the judge
fixture pinned by id, each judged FAIL and PASS, with sentinel variants and chains of each
target's cases. A case is graded against its target's mechanism and aim, with a fixed sentinel.

The file is regenerated only in a commit that changes what the grammar grades, beside its
labeling log entry, or in the commit of a fixture that changes a target's mechanism or aim.
A refactoring never regenerates it.
"""

import json
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import tests.unit.support.test_cve_grammar_given as given
from evals.cve_calibration import dead_conditions
from evals.cve_grammar import (
    MechanismClass,
    MissClass,
    RunGrade,
    grade_run,
    is_aimed,
    proofs_in,
    resolve,
)
from evals.cve_targets import CVE_TARGETS
from evals.cve_units import Unit, unit_of_exchanges, units_of
from evals.judge_fixture import JudgeCase, JudgeInputs, load_fixture
from mcp_auditor.domain.models import AttackChain, AuditReport, ChainStep, EvalVerdict, TestCase

GOLDEN_PATH = Path(__file__).parent / "cve_grammar_golden.json"
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


def golden_entries() -> dict[str, Any]:
    entries: dict[str, Any] = {
        f"tests/{name}": _graded(target, report)
        for target, reports in (
            (given.a_read_target(), _read_target_reports()),
            (given.a_command_target(), _command_target_reports()),
        )
        for name, report in reports.items()
    }
    entries |= {
        f"tests/exchanges/{name}": _unit_entry(unit, given.a_read_target())
        for name, unit in _test_exchanges().items()
    }
    entries |= {
        f"resolve/tests/{name}": resolve(grades).model_dump(mode="json")
        for name, grades in _test_resolutions().items()
    }
    for cve_id, cases in _cases_by_target().items():
        entries |= _target_entries(cve_id, cases)
    return entries


def _graded(target: given.FakeTarget, report: AuditReport) -> dict[str, Any]:
    return {
        "grade": grade_run(target, report).model_dump(mode="json"),
        "units": [_unit_entry(unit, target) for unit in units_of(report)],
    }


def _unit_entry(unit: Unit, target: given.FakeTarget) -> dict[str, Any]:
    proofs = proofs_in(unit, target)
    return {
        "proofs": {kind.value: output for kind, output in proofs.items()},
        "aimed": is_aimed(unit, target),
    }


def _read_target_reports() -> dict[str, AuditReport]:
    return {**_nonce_reports(), **_miss_reports(), **_blocked_chain_reports()}


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
        "computed_output_on_a_read_target": _of_cases(given.a_case(response="uid=0 gid=0")),
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


def _command_target_reports() -> dict[str, AuditReport]:
    outputs = {
        "id_without_names": "uid=65534 gid=65534 groups=65534",
        "id_with_names": "uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)",
        "passwd_root_line": (
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"
        ),
    }
    echoed = {"ascii": "uid=65534 gid=65534", "non_ascii": "uid=1000(josé) gid=1000"}
    return {
        **{
            f"computed_output_under_fail/{name}": _of_cases(
                given.a_case(response=output, category=given.INJECTION)
            )
            for name, output in outputs.items()
        },
        **{
            f"computed_output_echoed_from_the_arguments/{name}": _of_cases(
                given.a_case(response=f"unknown command {text}", arguments={"command": text})
            )
            for name, text in echoed.items()
        },
        "nonce_and_computed_output_in_one_run": _of_cases(
            given.a_case(response="uid=65534 gid=65534", category=given.INJECTION),
            given.a_case(response=f"FLAG={SENTINEL}", category=given.INJECTION),
        ),
    }


def _of_cases(*cases: TestCase) -> AuditReport:
    return given.a_report(cases=list(cases))


def _of_chains(*chains: AttackChain) -> AuditReport:
    return given.a_report(chains=list(chains))


def _of_chain(steps: list[ChainStep]) -> AuditReport:
    return _of_chains(given.a_chain(steps))


def _test_exchanges() -> dict[str, Unit]:
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


def _test_resolutions() -> dict[str, list[RunGrade]]:
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


def _cases_by_target() -> dict[str, list[JudgeCase]]:
    cases = {case.id: case for case in load_fixture(JUDGE_FIXTURE_PATH).cases}
    by_target: defaultdict[str, list[JudgeCase]] = defaultdict(list)
    for case_id in CVE_CASE_IDS:
        by_target[cases[case_id].origin.removeprefix("cve ")].append(cases[case_id])
    return by_target


def _target_entries(cve_id: str, cases: list[JudgeCase]) -> dict[str, Any]:
    target = _graded_target(cve_id)
    real = {
        f"real/{cve_id}/{case.id}/{verdict.value}": _of_cases(_case_of(case.inputs, verdict))
        for case in cases
        for verdict in (FAIL, PASS)
    }
    variants = {
        f"variant/{cve_id}/{case.id}/{name}": _of_cases(_case_of(inputs, verdict))
        for case in cases
        for name, (inputs, verdict) in _variants(case.inputs, target).items()
    }
    chains = {f"chain/{cve_id}/{name}": report for name, report in _chains(cases).items()}
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


def _dead_conditions(target: given.FakeTarget, inputs: JudgeInputs) -> list[str]:
    [exploit] = units_of(_of_cases(_case_of(_with_response(inputs, SENTINEL), FAIL)))
    [benign] = units_of(_of_cases(_case_of(inputs, FAIL)))
    return dead_conditions(target, exploit, benign)


def _graded_target(cve_id: str) -> given.FakeTarget:
    [target] = [target for target in CVE_TARGETS if target.cve_id == cve_id]
    return given.FakeTarget(target.mechanism, SENTINEL, target.aim)


def _case_of(inputs: JudgeInputs, verdict: EvalVerdict) -> TestCase:
    return given.a_case(
        response=inputs.response,
        error=inputs.error,
        verdict=verdict,
        category=inputs.category,
        arguments=inputs.arguments,
    )


def _variants(
    inputs: JudgeInputs, target: given.FakeTarget
) -> dict[str, tuple[JudgeInputs, EvalVerdict]]:
    leaking = _with_response(inputs, SENTINEL)
    variants = {
        "response_nonce_fail": (leaking, FAIL),
        "response_nonce_pass": (leaking, PASS),
        "error_nonce_fail": (
            inputs.model_copy(update={"error": _spliced(inputs.error, SENTINEL)}),
            FAIL,
        ),
        "echo_fail": (leaking.model_copy(update={"arguments": _echoing(inputs.arguments)}), FAIL),
    }
    if target.mechanism == MechanismClass.COMMAND_EXECUTION:
        variants["computed_output_fail"] = (_with_response(inputs, "uid=0(root) gid=0(root)"), FAIL)
        variants["passwd_root_line_fail"] = (
            _with_response(inputs, "root:x:0:0:root:/root:/bin/bash"),
            FAIL,
        )
    return variants


def _chains(cases: list[JudgeCase]) -> dict[str, AuditReport]:
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


def _resolved(target: given.FakeTarget, reports: Iterable[AuditReport]) -> dict[str, Any]:
    return resolve([grade_run(target, report) for report in reports]).model_dump(mode="json")


if __name__ == "__main__":
    GOLDEN_PATH.write_text(json.dumps(golden_entries(), indent=2, sort_keys=True) + "\n")
