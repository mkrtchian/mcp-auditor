import tests.unit.support.test_fix_check_given as given
from evals.holdout_kit.fix_check import fix_check_result
from evals.nuisance_admission import FixCheckRecord


def test_surfaces_on_vulnerable_and_is_fixed_on_the_patched_version():
    target = given.a_fix_check_target()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(target, vulnerable, patched, None)

    assert result.vulnerable_surfaces is True
    assert result.patched_surfaces is False
    assert result.server_patched_surfaces is None
    assert result.patched_benign_errored is False
    assert result.exploit_calls == ["read_file"]
    assert result.witness == given.NONCE


def test_still_surfaces_on_the_patched_version():
    target = given.a_fix_check_target()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.exchanges_surfacing(given.NONCE)])

    result = fix_check_result(target, vulnerable, patched, None)

    assert result.patched_surfaces is True


def test_a_clean_server_patched_exercise_fills_the_field_false():
    target = given.a_fix_check_target(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(target, vulnerable, patched, server_patched)

    assert result.server_patched_surfaces is False


def test_a_surfacing_server_patched_exercise_fills_the_field_true():
    target = given.a_fix_check_target(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.exchanges_surfacing(given.NONCE)])

    result = fix_check_result(target, vulnerable, patched, server_patched)

    assert result.server_patched_surfaces is True


def test_a_benign_call_errored_on_the_patched_exercise():
    target = given.a_fix_check_target()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()], benign=given.errored_exchanges())

    result = fix_check_result(target, vulnerable, patched, None)

    assert result.patched_benign_errored is True


def test_a_benign_call_errored_only_on_the_vulnerable_exercise_does_not_count():
    target = given.a_fix_check_target()
    vulnerable = given.an_exercise(
        [given.exchanges_surfacing(given.NONCE)], benign=given.errored_exchanges()
    )
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(target, vulnerable, patched, None)

    assert result.patched_benign_errored is False


def test_the_nonce_surfaces_but_no_exploit_is_aimed():
    target = given.a_fix_check_target()
    vulnerable = given.an_exercise([given.unaimed_exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(target, vulnerable, patched, None)

    assert result.vulnerable_surfaces is False


def test_either_of_two_exploits_surfacing_the_witness_counts():
    target = given.a_fix_check_target()
    vulnerable = given.an_exercise(
        [given.clean_exchanges("list_dir"), given.exchanges_surfacing(given.NONCE)]
    )
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(target, vulnerable, patched, None)

    assert result.vulnerable_surfaces is True
    assert result.exploit_calls == ["list_dir", "read_file"]


def test_to_json_round_trips_to_a_valid_fix_check_record():
    target = given.a_fix_check_target(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(target, vulnerable, patched, server_patched)
    record = FixCheckRecord.model_validate_json(result.to_json())

    assert record.source == "fix_check"
    assert record.witness == given.NONCE
    assert record.vulnerable_surfaces is True
    assert record.patched_surfaces is False
    assert record.server_patched_surfaces is False
    assert record.exploit_calls == ["read_file"]
