# The acceptance test of a planted stand-in: the stand-in image serving a capture written here,
# read by a container started with the target's planted arguments, over plain HTTP and over
# TLS against the fixture authority.
#
# Skipped without Docker or openssl. `CVE_PLANTING_REQUIRED=1` turns that skip into a failure,
# as in `test_cve_planting.py`.
import logging
import os
from pathlib import Path

import pytest

import tests.integration.support.test_cve_planting_given as planting
import tests.integration.support.test_cve_planting_stand_ins_given as given
import tests.integration.support.test_cve_planting_stand_ins_then as then
from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_planting import DockerPlanting, planted
from evals.cve_planting_base import SENTINEL_IMAGE, SENTINEL_SERVICE, STAND_IN_SERVICE
from tests.integration.support.test_cve_planting_then import nothing_it_made_outlives


@pytest.fixture(autouse=True, scope="module")
def _stand_in_prerequisites() -> None:
    missing = planting.missing_prerequisite() or given.missing_openssl()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([SENTINEL_SERVICE, STAND_IN_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def test_a_planted_stand_in_serves_its_capture_by_name_and_its_default_for_anything_else(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    stand_ins_directory = given.a_stand_ins_directory(tmp_path)
    docker = planting.RecordingPlanting()
    host = given.STAND_IN_HOST

    with (
        caplog.at_level(logging.WARNING, logger="evals.cve_planting_docker"),
        planted(given.a_stand_in_spec(), SENTINEL_IMAGE, docker, stand_ins_directory) as args,
    ):
        plain = given.fetch_as_target(args, f"http://{host}/")
        secure = given.fetch_as_target(args, f"https://{host}/")
        head = given.fetch_as_target(args, f"https://{host}/", method="HEAD")
        unknown = given.fetch_as_target(args, f"https://{host}/uncaptured")
        redirected = given.fetch_as_target(args, f"http://{host}{given.QUOTED_REQUEST}")

    assert (plain.body, secure.body) == (given.PLAIN_BODY, given.SECURE_BODY)
    then.answered_without_its_body(head, 200, given.SECURE_BODY)
    assert (unknown.status, unknown.body) == (404, given.MISSING_BODY)
    then.redirects_to(redirected, f"https://{host}{given.QUOTED_REQUEST}")
    then.logged_its_default_for(
        caplog.text, host, ["https GET /uncaptured", f"http GET {given.QUOTED_REQUEST}"]
    )
    assert docker.stand_ins
    nothing_it_made_outlives(docker)


@pytest.mark.parametrize("case", sorted(given.QUOTING_CASES))
def test_a_planted_stand_in_quotes_the_request_where_its_default_quotes_the_probe(
    case: str, tmp_path: Path
):
    quoting = given.QUOTING_CASES[case]
    directory = given.a_stand_ins_directory(tmp_path, quoting)
    host = given.STAND_IN_HOST

    with planted(given.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        route = given.fetch_as_target(args, f"https://{host}/")
        unknown = given.fetch_as_target(args, f"https://{host}{given.QUOTED_REQUEST}")

    assert route.body == given.SECURE_BODY
    then.answered_with(unknown, 404, quoting.answer(quoting.quoted_request))


def test_a_planted_stand_in_replays_the_captured_headers_without_the_connection_ones(
    tmp_path: Path,
):
    directory = given.a_stand_ins_directory(tmp_path)
    host = given.STAND_IN_HOST
    secure_length = len(given.SECURE_BODY.encode())

    with planted(given.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        route = given.fetch_as_target(args, f"https://{host}/")
        fallback = given.fetch_as_target(args, f"https://{host}/", method="HEAD")
        head_route = given.fetch_as_target(
            args, f"https://{host}{given.HEAD_ONLY_TARGET}", method="HEAD"
        )
        default = given.fetch_as_target(args, f"http://{host}/uncaptured")

    then.carries(route, given.SECURE_REPLAYED, secure_length)
    then.carries(fallback, given.SECURE_REPLAYED, secure_length)
    then.carries(head_route, given.HEAD_ONLY_REPLAYED, None)
    then.carries(default, [("Location", f"https://{host}/uncaptured"), given.REDIRECT_SERVER], 0)


def test_a_planted_stand_in_answers_a_post_by_its_aws_action(tmp_path: Path):
    directory = given.a_stand_ins_directory(tmp_path)
    url = f"https://{given.STAND_IN_HOST}/"

    with planted(given.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        json_protocol = given.fetch_as_target(args, url, "POST", given.JSON_PROTOCOL_REQUEST)
        query_protocol = given.fetch_as_target(args, url, "POST", given.QUERY_PROTOCOL_REQUEST)
        unknown = given.fetch_as_target(args, url, "POST", given.UNKNOWN_ACTION_REQUEST)

    then.answered_by_its_route(json_protocol, given.SECRET_HEADERS, given.SECRET_BODY)
    then.answered_by_its_route(query_protocol, given.INSTANCES_HEADERS, given.INSTANCES_BODY)
    then.answered_with(unknown, 404, given.MISSING_BODY)


def test_a_planted_stand_in_answers_a_graphql_post_by_its_operation_name(tmp_path: Path):
    directory = given.a_stand_ins_directory(tmp_path)
    url = f"https://{given.STAND_IN_HOST}{given.GRAPHQL_TARGET}"

    with planted(given.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        named = given.fetch_as_target(args, url, "POST", given.ISSUES_REQUEST)
        other = given.fetch_as_target(args, url, "POST", given.OTHER_OPERATION_REQUEST)
        anonymous = given.fetch_as_target(args, url, "POST", given.ANONYMOUS_OPERATION_REQUEST)

    then.answered_by_its_route(named, given.ISSUES_HEADERS, given.ISSUES_BODY)
    fallback = (given.GRAPHQL_FALLBACK_HEADERS, given.GRAPHQL_FALLBACK_BODY)
    then.answered_by_its_route(other, *fallback)
    then.answered_by_its_route(anonymous, *fallback)


def test_a_planted_stand_in_answers_a_form_post_by_the_field_it_carries(tmp_path: Path):
    directory = given.a_stand_ins_directory(tmp_path)
    url = f"https://{given.STAND_IN_HOST}{given.FORM_TARGET}"

    with planted(given.a_stand_in_spec(), SENTINEL_IMAGE, DockerPlanting(), directory) as args:
        carrying = given.fetch_as_target(args, url, "POST", given.SEARCH_REQUEST)
        lacking = given.fetch_as_target(args, url, "POST", given.FIELDLESS_SEARCH_REQUEST)

    then.answered_by_its_route(carrying, given.RESULTS_HEADERS, given.RESULTS_BODY)
    then.answered_with(lacking, 404, given.MISSING_BODY)
