from collections.abc import Callable

import pytest

import tests.unit.nuisance.admission.support.test_nuisance_unrecorded_given as given
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.unrecorded import refuse_unrecorded, unrecorded_fields
from evals.eval_session import Refused


def test_a_recorded_server_has_no_unrecorded_field():
    assert unrecorded_fields([given.a_recorded_server()]) == []


def test_every_unset_field_is_named_for_its_server_with_its_count():
    unrecorded = unrecorded_fields([given.a_server_with_every_field_unrecorded()])

    assert unrecorded == [
        f"{given.SERVER}: real_software (2 tools), declared_function_is_effect (2 tools),"
        " expect (2 benign calls), before (2 benign calls), relies_on_relaying_stand_in (2 flaws),"
        " stand_ins, seeds, software_releases"
    ]


@pytest.mark.parametrize(
    ("unset", "unrecorded_field"),
    [
        (given.without_a_real_software_record, "real_software (1 tool)"),
        (given.without_a_declared_function_record, "declared_function_is_effect (1 tool)"),
        (
            given.with_a_tool_left_out_by_its_declared_function_unrecorded,
            "declared_function_is_effect (1 tool)",
        ),
        (given.a_holdout_copy_without_its_fingerprint, "holdout_fingerprint (1 flaw)"),
        (given.without_an_expected_text, "expect (1 benign call)"),
        (given.without_prerequisite_calls, "before (1 benign call)"),
        (given.without_a_relaying_stand_in_judgment, "relies_on_relaying_stand_in (1 flaw)"),
        (given.without_stand_ins, "stand_ins"),
        (given.without_seeds, "seeds"),
        (given.without_software_releases, "software_releases"),
    ],
)
def test_each_unset_field_is_named_alone(
    unset: Callable[[AdmittedServer], AdmittedServer], unrecorded_field: str
):
    assert unrecorded_fields([unset(given.a_recorded_server())]) == [
        f"{given.SERVER}: {unrecorded_field}"
    ]


def test_an_uncounted_flaw_is_never_read():
    server = given.with_the_second_flaw_uncounted_and_unrecorded(given.a_recorded_server())

    assert unrecorded_fields([server]) == []


def test_a_removed_tool_needs_no_real_software_or_declared_function_record():
    server = given.with_a_removed_tool_without_its_records(given.a_recorded_server())

    assert unrecorded_fields([server]) == []


def test_refusal_lists_the_unrecorded_fields():
    server = given.without_seeds(given.a_recorded_server())

    with pytest.raises(Refused) as refusal:
        refuse_unrecorded([server], "nuisance holdout run refused")

    assert refusal.value.title == "nuisance holdout run refused"
    assert refusal.value.reasons == [
        "fields nuisance suite rule v3 or v4 adds are not yet recorded",
        f"{given.SERVER}: seeds",
    ]


def test_no_refusal_when_every_field_is_recorded():
    refuse_unrecorded([given.a_recorded_server()], "nuisance holdout run refused")
