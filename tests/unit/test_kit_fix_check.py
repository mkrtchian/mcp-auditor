import tests.unit.support.test_kit_fix_check_given as given
from evals.cve.kit.client import KitResponse
from evals.cve.kit.fix_check import benign_transcript, fix_check_result
from evals.cve.nuisance.admission import FixCheckRecord


def test_surfaces_on_vulnerable_and_is_fixed_on_the_patched_version():
    fixture = given.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.vulnerable_surfaces is True
    assert result.patched_surfaces is False
    assert result.server_patched_surfaces is None
    assert result.patched_benign_errored is False
    assert result.exploit_calls == ["read_file"]
    assert result.witness == given.NONCE


def test_still_surfaces_on_the_patched_version():
    fixture = given.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.exchanges_surfacing(given.NONCE)])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.patched_surfaces is True


def test_a_clean_server_patched_exercise_fills_the_field_false():
    fixture = given.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, server_patched)

    assert result.server_patched_surfaces is False


def test_a_surfacing_server_patched_exercise_fills_the_field_true():
    fixture = given.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.exchanges_surfacing(given.NONCE)])

    result = fix_check_result(fixture, vulnerable, patched, server_patched)

    assert result.server_patched_surfaces is True


def test_a_benign_call_errored_on_the_patched_exercise():
    fixture = given.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()], benign=given.errored_exchanges())

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.patched_benign_errored is True


def test_a_benign_call_errored_only_on_the_vulnerable_exercise_does_not_count():
    fixture = given.a_fix_check_fixture()
    vulnerable = given.an_exercise(
        [given.exchanges_surfacing(given.NONCE)], benign=given.errored_exchanges()
    )
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.patched_benign_errored is False


def test_the_nonce_surfaces_but_no_exploit_is_aimed():
    fixture = given.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.unaimed_exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.vulnerable_surfaces is False


def test_either_of_two_exploits_surfacing_the_witness_counts():
    fixture = given.a_fix_check_fixture()
    vulnerable = given.an_exercise(
        [given.clean_exchanges("list_dir"), given.exchanges_surfacing(given.NONCE)]
    )
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.vulnerable_surfaces is True
    assert result.exploit_calls == ["list_dir", "read_file"]


def test_to_json_round_trips_to_a_valid_fix_check_record():
    fixture = given.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.NONCE)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, server_patched)
    record = FixCheckRecord.model_validate_json(result.to_json())

    assert record.source == "fix_check"
    assert record.witness == given.NONCE
    assert record.vulnerable_surfaces is True
    assert record.patched_surfaces is False
    assert record.server_patched_surfaces is False
    assert record.exploit_calls == ["read_file"]


def test_the_benign_transcript_shows_each_exchange_on_one_line():
    exercise = given.an_exercise(
        [],
        benign=[
            ("show", {"file_path": "agents.yaml"}, KitResponse("roles:\n  analyst", False)),
            ("list", {}, KitResponse("backend unavailable", True)),
        ],
    )

    transcript = benign_transcript("CVE-2025-0001", "patched", exercise)

    assert transcript.splitlines() == [
        "CVE-2025-0001 patched: benign show -> ok 'roles:\\n  analyst'",
        "CVE-2025-0001 patched: benign list -> error 'backend unavailable'",
    ]


def test_a_fix_check_working_in_work_holds_its_witness_there_with_no_tmpfs():
    fixture = given.a_fix_check_fixture(working_directory="/work", witness_path="/work/secret.md")

    spec = fixture.planting_spec()

    assert [intent.container_path for intent in spec.files] == ["/work/secret.md"]
    assert "--tmpfs" not in given.launch_args(spec).run_args()
