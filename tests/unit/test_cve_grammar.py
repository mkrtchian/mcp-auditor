from typing import Any

import pytest

import tests.unit.support.test_cve_grammar_given as given
from evals.cve_grammar import (
    CVEStatus,
    MissClass,
    ProofKind,
    grade_run,
    is_aimed,
    proofs_in,
    resolve,
)
from evals.cve_report_units import units_of
from evals.cve_units import unit_of_exchanges
from mcp_auditor.domain.models import TestCase

SENTINEL = given.SENTINEL
AIMED = {"path": given.AIMED_PATH}


@pytest.mark.parametrize(
    "case",
    [
        given.a_case(response=f"leaked {SENTINEL}"),
        given.a_case(error=f"boom {SENTINEL}"),
        given.a_case(response={"content": SENTINEL}),
    ],
    ids=["response", "error", "dict_response"],
)
def test_nonce_in_a_fail_case_output_is_detected(case: TestCase):
    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.DETECTED
    assert grade.evidence is not None and SENTINEL in grade.evidence
    assert grade.category == given.INFO_LEAKAGE


def test_nonce_echoed_from_the_case_arguments_is_not_a_proof():
    case = given.a_case(response=f"no file {SENTINEL}", arguments={"path": SENTINEL})

    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.MISSED


def test_nonce_carried_by_an_earlier_chain_step_is_not_a_proof():
    chain = given.a_chain(
        [
            given.a_step(arguments={"path": SENTINEL}),
            given.a_step(response=f"echo {SENTINEL}"),
        ]
    )

    grade = grade_run(given.a_read_target(), units_of(given.a_report(chains=[chain])))

    assert grade.status == CVEStatus.MISSED


def test_nonce_carried_only_by_a_later_chain_step_is_a_proof():
    chain = given.a_chain(
        [
            given.a_step(),
            given.a_step(response=f"leaked {SENTINEL}"),
            given.a_step(arguments={"path": SENTINEL}),
        ]
    )

    grade = grade_run(given.a_read_target(), units_of(given.a_report(chains=[chain])))

    assert grade.status == CVEStatus.DETECTED


def test_nonce_only_in_the_report_target_is_not_a_proof():
    report = given.a_report(
        cases=[given.a_case(response="nothing")], target=f"docker run -e FLAG={SENTINEL}"
    )

    grade = grade_run(given.a_read_target(), units_of(report))

    assert grade.status == CVEStatus.MISSED
    assert not grade.surfaced


def test_nonce_only_in_a_step_observation_is_not_a_proof():
    chain = given.a_chain([given.a_step(response="nothing", observation=f"saw {SENTINEL}")])

    grade = grade_run(given.a_read_target(), units_of(given.a_report(chains=[chain])))

    assert grade.status == CVEStatus.MISSED


def test_nonce_under_pass_is_reached_but_judged_pass():
    case = given.a_case(response=f"leaked {SENTINEL}", verdict=given.PASS)

    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.REACHED_BUT_JUDGED_PASS
    assert grade.surfaced


def test_proof_and_fail_on_different_cases_is_not_detected():
    proof = given.a_case(response=f"leaked {SENTINEL}", verdict=given.PASS)
    fail = given.a_case(response="nothing", verdict=given.FAIL)

    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[proof, fail])))

    assert grade.status == CVEStatus.REACHED_BUT_JUDGED_PASS


@pytest.mark.parametrize(
    "output",
    [
        "uid=65534 gid=65534 groups=65534",
        "uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
    ],
    ids=["id_without_names", "id_with_names", "passwd_root_line"],
)
def test_computed_output_under_fail_on_command_execution_is_execution_only(output: str):
    case = given.a_case(response=output, category=given.INJECTION)

    grade = grade_run(given.a_command_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.DETECTED_EXECUTION_ONLY
    assert grade.evidence == output


@pytest.mark.parametrize(
    "echoed", ["uid=65534 gid=65534", "uid=1000(josé) gid=1000"], ids=["ascii", "non_ascii"]
)
def test_computed_output_echoed_from_the_arguments_is_not_a_proof(echoed: str):
    case = given.a_case(response=f"unknown command {echoed}", arguments={"command": echoed})

    grade = grade_run(given.a_command_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.MISSED


def test_computed_output_is_not_a_proof_on_a_read_target():
    case = given.a_case(response="uid=0 gid=0")

    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.MISSED
    assert not grade.surfaced


def test_nonce_and_computed_output_in_one_run_is_detected():
    computed = given.a_case(response="uid=65534 gid=65534", category=given.INJECTION)
    nonce = given.a_case(response=f"FLAG={SENTINEL}", category=given.INJECTION)

    grade = grade_run(given.a_command_target(), units_of(given.a_report(cases=[computed, nonce])))

    assert grade.status == CVEStatus.DETECTED
    assert grade.evidence == f"FLAG={SENTINEL}"


def test_nonce_under_fail_in_any_category_is_detected():
    case = given.a_case(response=f"leaked {SENTINEL}", category=given.RESOURCE_ABUSE)

    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[case])))

    assert grade.status == CVEStatus.DETECTED
    assert grade.category == given.RESOURCE_ABUSE


@pytest.mark.parametrize(
    ("cases", "miss_class"),
    [
        ([given.a_case(response="nothing")], MissClass.NOT_AIMED),
        ([given.a_blocked_case(AIMED)], MissClass.AIMED_BLOCKED),
        ([given.a_case(response="nothing", arguments=AIMED)], MissClass.AIMED_NO_PROOF),
        (
            [given.a_blocked_case(AIMED), given.a_case(response="nothing", arguments=AIMED)],
            MissClass.AIMED_NO_PROOF,
        ),
    ],
    ids=["not_aimed", "aimed_blocked", "aimed_no_proof", "blocked_and_unblocked"],
)
def test_a_missed_run_is_classed_by_its_best_aimed_unit(
    cases: list[TestCase], miss_class: MissClass
):
    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=cases)))

    assert grade.status == CVEStatus.MISSED
    assert grade.miss_class == miss_class


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        (given.a_case(response="denied", arguments=AIMED, category=given.INJECTION), True),
        (given.a_case(response="denied", arguments=AIMED, category=given.RESOURCE_ABUSE), False),
        (given.a_case(response="denied", category=given.INJECTION), False),
    ],
    ids=["aimed_valid_category", "category_outside_class", "not_aimed"],
)
def test_fail_without_proof_needs_an_aimed_fail_in_a_valid_category(case: TestCase, expected: bool):
    grade = grade_run(given.a_read_target(), units_of(given.a_report(cases=[case])))

    assert grade.fail_without_proof is expected


@pytest.mark.parametrize(
    "arguments",
    [
        {"options": {"source": given.AIMED_PATH}},
        {"paths": ["/inside/a", given.AIMED_PATH]},
        {"batch": [{"files": [given.AIMED_PATH]}]},
    ],
    ids=["nested_dict", "list", "list_of_dicts"],
)
def test_aim_reads_nested_argument_values(arguments: dict[str, Any]):
    unit = unit_of_exchanges([(arguments, "ok")])

    assert is_aimed(unit, given.a_read_target())


def test_non_string_argument_values_are_not_aimed():
    unit = unit_of_exchanges([({"depth": 3, "recursive": True, "path": None}, "ok")])

    assert not is_aimed(unit, given.a_read_target())


def test_chain_blocked_at_its_first_step_is_aimed_blocked():
    chain = given.a_chain_blocked_at_first_step(AIMED)

    grade = grade_run(given.a_read_target(), units_of(given.a_report(chains=[chain])))

    assert grade.status == CVEStatus.MISSED
    assert grade.miss_class == MissClass.AIMED_BLOCKED


def test_chain_blocked_after_a_leaking_first_step_is_detected():
    chain = given.a_chain(
        [given.a_step(response=f"leaked {SENTINEL}")], blocked_reason="destructive payload"
    )

    grade = grade_run(given.a_read_target(), units_of(given.a_report(chains=[chain])))

    assert grade.status == CVEStatus.DETECTED


def test_chain_blocked_after_its_first_step_is_a_blocked_judged_unit():
    chain = given.a_chain([given.a_step(arguments=AIMED)], blocked_reason="destructive payload")

    [unit] = units_of(given.a_report(chains=[chain]))

    assert unit.blocked
    assert unit.verdict == given.FAIL


def test_resolve_keeps_the_highest_rung_over_runs():
    resolution = resolve(
        [given.a_missed_run(MissClass.NOT_AIMED), given.a_reached_run(), given.a_detected_run()]
    )

    assert resolution.status == CVEStatus.DETECTED
    assert resolution.miss_class is None
    assert resolution.evidence == f"leaked {SENTINEL}"
    assert resolution.category == given.INFO_LEAKAGE


def test_resolve_keeps_the_best_miss_class_over_missed_runs():
    resolution = resolve(
        [
            given.a_missed_run(MissClass.NOT_AIMED, aimed=False),
            given.a_missed_run(MissClass.AIMED_NO_PROOF),
            given.a_missed_run(MissClass.AIMED_BLOCKED),
        ]
    )

    assert resolution.status == CVEStatus.MISSED
    assert resolution.miss_class == MissClass.AIMED_NO_PROOF


def test_resolve_counts_each_condition_per_run():
    resolution = resolve(
        [
            given.a_detected_run(),
            given.a_reached_run(),
            given.a_missed_run(MissClass.AIMED_NO_PROOF, fail_without_proof=True),
            given.a_missed_run(MissClass.NOT_AIMED, aimed=False),
        ]
    )

    assert resolution.detected_runs == 1
    assert resolution.surfaced_runs == 2
    assert resolution.aimed_runs == 3
    assert resolution.fail_without_proof_runs == 1


def test_unit_of_exchanges_finds_a_proof_in_the_last_output():
    unit = unit_of_exchanges(
        [({"path": "/a"}, "ok"), ({"path": "/b"}, "ok"), ({"path": "/c"}, f"leaked {SENTINEL}")]
    )

    assert proofs_in(unit, given.a_read_target()) == {ProofKind.PLANTED_NONCE: f"leaked {SENTINEL}"}


def test_unit_of_exchanges_reads_every_exchange_for_the_anti_echo():
    unit = unit_of_exchanges(
        [({"path": SENTINEL}, "ok"), ({"path": "/b"}, "ok"), ({"path": "/c"}, SENTINEL)]
    )

    assert proofs_in(unit, given.a_read_target()) == {}
