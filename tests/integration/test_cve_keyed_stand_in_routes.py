# The integration test of keyed stand-in routes: the stand-in image chooses a keyed action's route
# on the value of its identifier, and answers any other value, or none, with the action's error
# route.
#
# Skipped without Docker or openssl. `CVE_PLANTING_REQUIRED=1` turns that skip into a failure,
# as in `test_cve_planting.py`.
from pathlib import Path

import pytest

import tests.integration.support.stand_in_answers as stand_in_answers
import tests.integration.support.stand_in_capture as stand_in_capture
import tests.integration.support.stand_in_fetches as stand_in_fetches
import tests.integration.support.test_cve_keyed_stand_in_routes_given as given
from evals.cve.planting import DockerPlanting, planted
from evals.cve.planting_base import SENTINEL_IMAGE
from tests.integration.support.docker_prerequisites import stand_in_prerequisites
from tests.unit.support.fictional_stand_ins import HOST as STAND_IN_HOST


@pytest.fixture(autouse=True, scope="module")
def _stand_in_prerequisites() -> None:
    stand_in_prerequisites()


def test_a_json_protocol_action_answers_its_keyed_member_value_and_errs_on_any_other(
    tmp_path: Path,
):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{STAND_IN_HOST}/"
    requests = [
        given.a_secret_request(f'{{"SecretId": "{given.SECRET_ID}"}}'),
        given.a_secret_request('{"SecretId": "AnotherSecret"}'),
        given.a_secret_request("{}"),
        given.a_secret_request(f"SecretId={given.SECRET_ID}"),
    ]

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        keyed, *others = [
            stand_in_fetches.fetch_as_target(args, url, "POST", each) for each in requests
        ]

    stand_in_answers.answered_by_its_route(keyed, given.DESCRIBED_ANSWER)
    for other in others:
        stand_in_answers.answered_with(other, given.SECRET_NOT_FOUND)


def test_a_query_protocol_action_answers_its_keyed_field_value_and_errs_on_any_other(
    tmp_path: Path,
):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{STAND_IN_HOST}/"
    requests = [
        given.a_clusters_request(f"&DBClusterIdentifier={given.CLUSTER_ID}"),
        given.a_clusters_request("&DBClusterIdentifier=other-cluster"),
        given.a_clusters_request(""),
    ]

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        keyed, *others = [
            stand_in_fetches.fetch_as_target(args, url, "POST", each) for each in requests
        ]

    stand_in_answers.answered_by_its_route(keyed, given.CLUSTERS_ANSWER)
    for other in others:
        stand_in_answers.answered_with(other, given.CLUSTER_NOT_FOUND)


def test_a_graphql_operation_keyed_on_an_integer_answers_the_integer_and_not_its_string(
    tmp_path: Path,
):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{STAND_IN_HOST}{stand_in_capture.GRAPHQL_REQUEST_TARGET}"

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        integer = stand_in_fetches.fetch_as_target(args, url, "POST", given.an_issue_request(1))
        string = stand_in_fetches.fetch_as_target(args, url, "POST", given.an_issue_request("1"))

    stand_in_answers.answered_by_its_route(integer, given.ISSUE_ANSWER)
    stand_in_answers.answered_with(string, given.ISSUE_NOT_FOUND)


def test_an_unkeyed_action_keeps_its_answer_whatever_its_body(tmp_path: Path):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{STAND_IN_HOST}/"
    bodies = ['{"SecretId": "AnotherSecret"}', "not json"]

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        answers = [
            stand_in_fetches.fetch_as_target(
                args, url, "POST", given.a_secret_request(body, stand_in_capture.SECRET_ACTION)
            )
            for body in bodies
        ]

    for answer in answers:
        stand_in_answers.answered_by_its_route(answer, stand_in_capture.SECRET_ANSWER)
