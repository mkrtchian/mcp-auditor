# The integration test of keyed stand-in routes: the stand-in image chooses a keyed action's route
# on the value of its identifier, and answers any other value, or none, with the action's error
# route.
#
# Skipped without Docker or openssl. `CVE_PLANTING_REQUIRED=1` turns that skip into a failure,
# as in `test_cve_planting.py`.
from pathlib import Path

import pytest

import tests.integration.support.test_cve_keyed_stand_in_routes_given as given
import tests.integration.support.test_cve_planting_stand_ins_given as stand_ins
import tests.integration.support.test_cve_planting_stand_ins_then as then
from evals.cve.planting import DockerPlanting, planted
from evals.cve.planting_base import SENTINEL_IMAGE
from tests.integration.support.docker_prerequisites import stand_in_prerequisites


@pytest.fixture(autouse=True, scope="module")
def _stand_in_prerequisites() -> None:
    stand_in_prerequisites()


def test_a_json_protocol_action_answers_its_keyed_member_value_and_errs_on_any_other(
    tmp_path: Path,
):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{stand_ins.STAND_IN_HOST}/"
    requests = [
        given.a_secret_request(f'{{"SecretId": "{given.SECRET_ID}"}}'),
        given.a_secret_request('{"SecretId": "AnotherSecret"}'),
        given.a_secret_request("{}"),
        given.a_secret_request(f"SecretId={given.SECRET_ID}"),
    ]

    with planted(stand_ins.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        keyed, *others = [stand_ins.fetch_as_target(args, url, "POST", each) for each in requests]

    then.answered_by_its_route(keyed, given.DESCRIBED_HEADERS, given.DESCRIBED_BODY)
    for other in others:
        then.answered_with(other, *given.SECRET_NOT_FOUND)


def test_a_query_protocol_action_answers_its_keyed_field_value_and_errs_on_any_other(
    tmp_path: Path,
):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{stand_ins.STAND_IN_HOST}/"
    requests = [
        given.a_clusters_request(f"&DBClusterIdentifier={given.CLUSTER_ID}"),
        given.a_clusters_request("&DBClusterIdentifier=other-cluster"),
        given.a_clusters_request(""),
    ]

    with planted(stand_ins.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        keyed, *others = [stand_ins.fetch_as_target(args, url, "POST", each) for each in requests]

    then.answered_by_its_route(keyed, given.CLUSTERS_HEADERS, given.CLUSTERS_BODY)
    for other in others:
        then.answered_with(other, *given.CLUSTER_NOT_FOUND)


def test_a_graphql_operation_keyed_on_an_integer_answers_the_integer_and_not_its_string(
    tmp_path: Path,
):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{stand_ins.STAND_IN_HOST}{stand_ins.GRAPHQL_TARGET}"

    with planted(stand_ins.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        integer = stand_ins.fetch_as_target(args, url, "POST", given.an_issue_request(1))
        string = stand_ins.fetch_as_target(args, url, "POST", given.an_issue_request("1"))

    then.answered_by_its_route(integer, given.ISSUE_HEADERS, given.ISSUE_BODY)
    then.answered_with(string, *given.ISSUE_NOT_FOUND)


def test_an_unkeyed_action_keeps_its_answer_whatever_its_body(tmp_path: Path):
    directory = given.a_keyed_stand_ins_directory(tmp_path)
    url = f"https://{stand_ins.STAND_IN_HOST}/"
    bodies = ['{"SecretId": "AnotherSecret"}', "not json"]

    with planted(stand_ins.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        answers = [
            stand_ins.fetch_as_target(
                args, url, "POST", given.a_secret_request(body, stand_ins.SECRET_ACTION)
            )
            for body in bodies
        ]

    for answer in answers:
        then.answered_by_its_route(answer, stand_ins.SECRET_HEADERS, stand_ins.SECRET_BODY)
