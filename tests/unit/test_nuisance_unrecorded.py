from collections.abc import Callable

import pytest

import tests.unit.support.test_nuisance_unrecorded_given as given
from evals.eval_session import Refused
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_unrecorded import refuse_unrecorded, unrecorded_fields


def test_a_recorded_server_has_no_gap():
    assert unrecorded_fields([given.a_recorded_server()]) == []


def test_every_unset_field_is_named_for_its_server_with_its_count():
    gaps = unrecorded_fields([given.a_server_with_every_field_unrecorded()])

    assert gaps == [
        f"{given.SERVER}: real_software (2 tools), expect (2 benign calls),"
        " before (2 benign calls), relies_on_relaying_stand_in (2 flaws), stand_ins, seeds"
    ]


@pytest.mark.parametrize(
    ("unset", "gap"),
    [
        (given.without_a_real_software_record, "real_software (1 tool)"),
        (given.without_an_expected_text, "expect (1 benign call)"),
        (given.without_prerequisite_calls, "before (1 benign call)"),
        (given.without_a_relaying_stand_in_judgment, "relies_on_relaying_stand_in (1 flaw)"),
        (given.without_stand_ins, "stand_ins"),
        (given.without_seeds, "seeds"),
    ],
)
def test_each_unset_field_is_named_alone(
    unset: Callable[[AdmittedServer], AdmittedServer], gap: str
):
    assert unrecorded_fields([unset(given.a_recorded_server())]) == [f"{given.SERVER}: {gap}"]


def test_an_uncounted_flaw_is_never_read():
    server = given.with_the_second_flaw_uncounted_and_unrecorded(given.a_recorded_server())

    assert unrecorded_fields([server]) == []


def test_a_removed_tool_needs_no_real_software_record():
    server = given.with_a_removed_tool_without_a_real_software_record(given.a_recorded_server())

    assert unrecorded_fields([server]) == []


def test_refusal_lists_the_gaps():
    server = given.without_seeds(given.a_recorded_server())

    with pytest.raises(Refused) as refusal:
        refuse_unrecorded([server], "nuisance run refused")

    assert refusal.value.title == "nuisance run refused"
    assert refusal.value.reasons == [
        "fields rule v3 adds are not yet recorded",
        f"{given.SERVER}: seeds",
    ]


def test_no_refusal_without_a_gap():
    refuse_unrecorded([given.a_recorded_server()], "nuisance run refused")
