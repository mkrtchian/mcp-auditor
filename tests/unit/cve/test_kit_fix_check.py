import tests.unit.cve.support.test_kit_fix_check_given as given
import tests.unit.support.fix_check_fixtures as fix_check_fixtures
from evals.cve.kit.client import KitResponse
from evals.cve.kit.driver import exploit_transcript
from evals.cve.kit.fix_check import benign_transcript, fix_check_notes, fix_check_result
from evals.cve.nuisance.admission.admission import FixCheckRecord


def test_surfaces_on_vulnerable_and_is_fixed_on_the_patched_version():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.vulnerable_surfaces is True
    assert result.patched_surfaces is False
    assert result.server_patched_surfaces is None
    assert result.patched_benign_errored is False
    assert result.exploit_calls == ["read_file"]
    assert result.witness == given.WITNESS


def test_still_surfaces_on_the_patched_version():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.patched_surfaces is True


def test_a_clean_server_patched_exercise_fills_the_field_false():
    fixture = fix_check_fixtures.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, server_patched)

    assert result.server_patched_surfaces is False


def test_a_surfacing_server_patched_exercise_fills_the_field_true():
    fixture = fix_check_fixtures.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])

    result = fix_check_result(fixture, vulnerable, patched, server_patched)

    assert result.server_patched_surfaces is True


def test_a_benign_call_errored_on_the_patched_exercise():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()], benign=given.errored_exchanges())

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.patched_benign_errored is True


def test_a_benign_call_errored_only_on_the_vulnerable_exercise_does_not_count():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise(
        [given.exchanges_surfacing(given.WITNESS)], benign=given.errored_exchanges()
    )
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.patched_benign_errored is False


def test_the_witness_surfaces_but_no_exploit_is_aimed():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.unaimed_exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.vulnerable_surfaces is False


def test_either_of_two_exploits_surfacing_the_witness_counts():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise(
        [given.clean_exchanges("list_dir"), given.exchanges_surfacing(given.WITNESS)]
    )
    patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.vulnerable_surfaces is True
    assert result.exploit_calls == ["list_dir", "read_file"]


def test_a_patched_exploit_missing_a_required_argument_is_named_with_its_version():
    fixture = fix_check_fixtures.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise(
        [given.exchanges_rejected_for_a_missing_file()], required={"read_file": frozenset({"file"})}
    )

    result = fix_check_result(fixture, vulnerable, patched, server_patched)

    assert result.unreached_patched_exploits == [
        "server's patched version: exploit 0 (read_file) lacks file, which the schema requires,"
        " and the SDK rejects every call of it at argument validation, so it never reaches the"
        " patched code"
    ]


def test_a_patched_call_the_server_runs_despite_a_missing_argument_leaves_nothing_reported():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise(
        [given.clean_exchanges()], required={"read_file": frozenset({"file"})}
    )

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.unreached_patched_exploits == []


def test_a_patched_call_to_a_tool_the_version_does_not_list_is_a_note_with_no_verdict():
    fixture = fix_check_fixtures.a_fix_check_fixture()
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()], required={"list_dir": frozenset()})

    result = fix_check_result(fixture, vulnerable, patched, None)

    assert result.unreached_patched_exploits == []
    assert fix_check_notes(patched, None) == [
        "patched version: exploit 0 calls read_file, which this version does not list"
    ]


def test_the_exploit_transcript_shows_each_call_with_its_arguments_and_cut_response():
    exercise = given.an_exercise([given.exchanges_surfacing("x" * 600)])

    transcript = exploit_transcript("CVE-FAKE", "fake-patched", exercise.exploits)

    assert transcript.startswith(
        'CVE-FAKE fake-patched: exploit 0 read_file({"path": "cat /tmp/witness"}) -> ok '
    )
    assert len(transcript) < 600


def test_to_json_round_trips_to_a_valid_fix_check_record():
    fixture = fix_check_fixtures.a_fix_check_fixture(server_patched_service="server-patched")
    vulnerable = given.an_exercise([given.exchanges_surfacing(given.WITNESS)])
    patched = given.an_exercise([given.clean_exchanges()])
    server_patched = given.an_exercise([given.clean_exchanges()])

    result = fix_check_result(fixture, vulnerable, patched, server_patched)
    record = FixCheckRecord.model_validate_json(result.to_json())

    assert record.source == "fix_check"
    assert record.witness == given.WITNESS
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
    fixture = fix_check_fixtures.a_fix_check_fixture(
        working_directory="/work", witness_path="/work/secret.md"
    )

    spec = fixture.planting_spec()

    assert [intent.container_path for intent in spec.files] == ["/work/secret.md"]
    assert "--tmpfs" not in given.launch_args(spec).run_args()
