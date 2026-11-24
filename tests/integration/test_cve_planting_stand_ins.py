# The integration test of a planted stand-in: the stand-in image serving a capture written here,
# read by a container started with the target's planted arguments, over plain HTTP and over
# TLS against the fixture authority.
#
# Skipped without Docker or openssl. `CVE_PLANTING_REQUIRED=1` turns that skip into a failure,
# as in `test_cve_planting.py`.
import logging
from pathlib import Path

import pytest

import tests.integration.support.stand_in_answers as stand_in_answers
import tests.integration.support.stand_in_capture as stand_in_capture
import tests.integration.support.stand_in_fetches as stand_in_fetches
import tests.integration.support.test_cve_planting_stand_ins_given as given
import tests.integration.support.test_cve_planting_stand_ins_then as then
from evals.cve import planting_docker
from evals.cve.planting import DockerPlanting, planted
from evals.cve.planting_base import SENTINEL_IMAGE
from tests.integration.support.docker_prerequisites import stand_in_prerequisites
from tests.integration.support.recording_planting import RecordingPlanting, nothing_it_made_outlives


@pytest.fixture(autouse=True, scope="module")
def _stand_in_prerequisites() -> None:
    stand_in_prerequisites()


def test_a_planted_stand_in_serves_its_capture_by_name_and_its_default_for_anything_else(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    stand_ins_directory = stand_in_capture.a_stand_ins_directory(tmp_path)
    docker = RecordingPlanting()
    host = stand_in_capture.STAND_IN_HOST

    with (
        caplog.at_level(logging.WARNING, logger=planting_docker.__name__),
        planted(
            stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, docker, stand_ins_directory
        ) as args,
    ):
        plain = stand_in_fetches.fetch_as_target(args, f"http://{host}/")
        secure = stand_in_fetches.fetch_as_target(args, f"https://{host}/")
        head = stand_in_fetches.fetch_as_target(args, f"https://{host}/", method="HEAD")
        unknown = stand_in_fetches.fetch_as_target(args, f"https://{host}/uncaptured")
        redirected = stand_in_fetches.fetch_as_target(
            args, f"http://{host}{stand_in_capture.QUOTED_REQUEST}"
        )

    assert (plain.body, secure.body) == (stand_in_capture.PLAIN_BODY, stand_in_capture.SECURE_BODY)
    then.answered_without_its_body(head, 200, stand_in_capture.SECURE_BODY)
    assert (unknown.status, unknown.body) == (404, stand_in_capture.MISSING_BODY)
    then.redirects_to(redirected, f"https://{host}{stand_in_capture.QUOTED_REQUEST}")
    then.logged_its_default_for(
        caplog.text, host, ["https GET /uncaptured", f"http GET {stand_in_capture.QUOTED_REQUEST}"]
    )
    assert docker.stand_ins
    nothing_it_made_outlives(docker)


@pytest.mark.parametrize("case", sorted(stand_in_capture.QUOTING_CASES))
def test_a_planted_stand_in_quotes_the_request_where_its_default_quotes_the_probe(
    case: str, tmp_path: Path
):
    quoting = stand_in_capture.QUOTING_CASES[case]
    directory = stand_in_capture.a_stand_ins_directory(tmp_path, quoting)
    host = stand_in_capture.STAND_IN_HOST

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        route = stand_in_fetches.fetch_as_target(args, f"https://{host}/")
        unknown = stand_in_fetches.fetch_as_target(
            args, f"https://{host}{stand_in_capture.QUOTED_REQUEST}"
        )

    assert route.body == stand_in_capture.SECURE_BODY
    stand_in_answers.answered_with(
        unknown, stand_in_capture.StandInAnswer(quoting.answer(quoting.quoted_request), status=404)
    )


def test_a_planted_stand_in_serves_the_captured_headers_without_the_connection_ones(
    tmp_path: Path,
):
    directory = stand_in_capture.a_stand_ins_directory(tmp_path)
    host = stand_in_capture.STAND_IN_HOST
    secure_length = len(stand_in_capture.SECURE_BODY.encode())

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        route = stand_in_fetches.fetch_as_target(args, f"https://{host}/")
        fallback = stand_in_fetches.fetch_as_target(args, f"https://{host}/", method="HEAD")
        head_route = stand_in_fetches.fetch_as_target(
            args, f"https://{host}{stand_in_capture.HEAD_ONLY_REQUEST_TARGET}", method="HEAD"
        )
        default = stand_in_fetches.fetch_as_target(args, f"http://{host}/uncaptured")

    stand_in_answers.carries(route, stand_in_capture.SECURE_SERVED, secure_length)
    stand_in_answers.carries(fallback, stand_in_capture.SECURE_SERVED, secure_length)
    stand_in_answers.carries(head_route, stand_in_capture.HEAD_ONLY_SERVED, None)
    stand_in_answers.carries(
        default, [("Location", f"https://{host}/uncaptured"), stand_in_capture.REDIRECT_SERVER], 0
    )


def test_a_planted_stand_in_answers_a_post_by_its_aws_action(tmp_path: Path):
    directory = stand_in_capture.a_stand_ins_directory(tmp_path)
    url = f"https://{stand_in_capture.STAND_IN_HOST}/"

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        json_protocol = stand_in_fetches.fetch_as_target(
            args, url, "POST", given.JSON_PROTOCOL_REQUEST
        )
        query_protocol = stand_in_fetches.fetch_as_target(
            args, url, "POST", given.QUERY_PROTOCOL_REQUEST
        )
        unknown = stand_in_fetches.fetch_as_target(args, url, "POST", given.UNKNOWN_ACTION_REQUEST)

    stand_in_answers.answered_by_its_route(json_protocol, stand_in_capture.SECRET_ANSWER)
    stand_in_answers.answered_by_its_route(query_protocol, stand_in_capture.INSTANCES_ANSWER)
    stand_in_answers.answered_with(unknown, stand_in_capture.MISSING_ANSWER)


def test_a_planted_stand_in_answers_a_graphql_post_by_its_operation_name(tmp_path: Path):
    directory = stand_in_capture.a_stand_ins_directory(tmp_path)
    url = f"https://{stand_in_capture.STAND_IN_HOST}{stand_in_capture.GRAPHQL_REQUEST_TARGET}"

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        named = stand_in_fetches.fetch_as_target(args, url, "POST", given.ISSUES_REQUEST)
        other = stand_in_fetches.fetch_as_target(args, url, "POST", given.OTHER_OPERATION_REQUEST)
        anonymous = stand_in_fetches.fetch_as_target(
            args, url, "POST", given.ANONYMOUS_OPERATION_REQUEST
        )

    stand_in_answers.answered_by_its_route(named, stand_in_capture.ISSUES_ANSWER)
    stand_in_answers.answered_by_its_route(other, stand_in_capture.GRAPHQL_FALLBACK_ANSWER)
    stand_in_answers.answered_by_its_route(anonymous, stand_in_capture.GRAPHQL_FALLBACK_ANSWER)


def test_a_planted_stand_in_answers_a_form_post_by_the_field_it_carries(tmp_path: Path):
    directory = stand_in_capture.a_stand_ins_directory(tmp_path)
    url = f"https://{stand_in_capture.STAND_IN_HOST}{stand_in_capture.FORM_REQUEST_TARGET}"

    with planted(
        stand_in_capture.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory
    ) as args:
        carrying = stand_in_fetches.fetch_as_target(args, url, "POST", given.SEARCH_REQUEST)
        lacking = stand_in_fetches.fetch_as_target(
            args, url, "POST", given.FIELDLESS_SEARCH_REQUEST
        )

    stand_in_answers.answered_by_its_route(carrying, stand_in_capture.RESULTS_ANSWER)
    stand_in_answers.answered_with(lacking, stand_in_capture.MISSING_ANSWER)
