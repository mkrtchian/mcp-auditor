import tests.unit.support.test_nuisance_holdout_copies_given as given
from evals.nuisance_holdout_copies import stale_holdout_copies

_CURRENT = {given.COPIED_FLAW: given.RECORDED}
_MOVED = {given.COPIED_FLAW: "b" * 64}


def test_a_copy_at_the_current_fingerprint_is_not_listed():
    server = given.a_server_copying_the_holdout_calibration_at(given.RECORDED)

    assert stale_holdout_copies([server], _CURRENT) == []


def test_a_copy_whose_fixture_has_changed_is_listed():
    server = given.a_server_copying_the_holdout_calibration_at(given.RECORDED)

    assert stale_holdout_copies([server], _MOVED) == [
        f"{given.SERVER}: {given.COPIED_FLAW} copied at {given.RECORDED}, its fixture is now at "
        f"{'b' * 64}"
    ]


def test_a_copy_whose_flaw_left_the_holdout_is_listed():
    server = given.a_server_copying_the_holdout_calibration_at(given.RECORDED)

    assert stale_holdout_copies([server], {}) == [
        f"{given.SERVER}: {given.COPIED_FLAW} is no longer a drawn holdout target"
    ]


def test_a_fix_check_run_is_never_read():
    server = given.a_server_copying_the_holdout_calibration_at(given.RECORDED, "fix_check")

    assert stale_holdout_copies([server], {}) == []


def test_a_flaw_that_does_not_count_is_never_read():
    server = given.not_counting(given.a_server_copying_the_holdout_calibration_at(given.RECORDED))

    assert stale_holdout_copies([server], {}) == []


def test_a_copy_with_no_recorded_fingerprint_is_never_read():
    server = given.a_server_copying_the_holdout_calibration_at(None)

    assert stale_holdout_copies([server], {}) == []
