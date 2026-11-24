from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import tests.unit.cve.support.test_cve_keyed_stand_in_routes_given as given
from evals.cve.public_stand_ins import stand_in
from tests.unit.support.fictional_stand_ins import (
    HOST,
    a_route,
    a_stand_ins_directory,
)


@pytest.mark.parametrize(
    "routes",
    [
        [given.a_keyed_route("app-cluster"), given.an_error_route()],
        [
            given.a_keyed_route("app-cluster"),
            given.a_keyed_route("other-cluster"),
            given.an_error_route(),
        ],
        [
            given.an_issue_route(1),
            given.an_issue_route("1"),
            given.an_error_route(given.ISSUE_OPERATION),
        ],
    ],
    ids=["one_value", "two_values", "an_integer_and_a_string_variable"],
)
def test_keyed_routes_beside_their_error_route_load(tmp_path: Path, routes: list[dict[str, Any]]):
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    assert stand_in(HOST, directory).host == HOST


@pytest.mark.parametrize(
    ("routes", "reason"),
    [
        (
            [given.a_keyed_route("app-cluster", action=None), given.an_error_route()],
            "identifier keys a route that carries an action",
        ),
        ([given.a_keyed_route("app-cluster")], "keyed action needs its error route"),
        (
            [given.a_keyed_route("app-cluster"), given.an_error_route("DescribeDBInstances")],
            "keyed action needs its error route",
        ),
        (
            [
                given.a_keyed_route("app-cluster"),
                given.a_keyed_route("other-cluster", name="DBInstanceIdentifier"),
                given.an_error_route(),
            ],
            "one location and one name",
        ),
        (
            [
                given.a_keyed_route("app-cluster"),
                given.a_keyed_route("other-cluster", location="json_member"),
                given.an_error_route(),
            ],
            "one location and one name",
        ),
        (
            [
                given.a_keyed_route("app-cluster"),
                given.a_keyed_route("app-cluster"),
                given.an_error_route(),
            ],
            "two routes answer",
        ),
        ([given.a_keyed_route(1), given.an_error_route()], "form identifier's value is a string"),
        (
            [given.a_keyed_route(True, location="json_member"), given.an_error_route()],
            r"identifier\.value",
        ),
    ],
    ids=[
        "no_action",
        "no_error_route",
        "error_route_of_another_action",
        "two_names",
        "two_locations",
        "one_value_twice",
        "integer_form_value",
        "boolean_value",
    ],
)
def test_a_keyed_route_the_stand_in_could_not_serve_unambiguously_is_refused(
    tmp_path: Path, routes: list[dict[str, Any]], reason: str
):
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match=reason):
        stand_in(HOST, directory)


@pytest.mark.parametrize("location", ["path", "header"])
def test_an_identifier_location_outside_the_three_is_refused(tmp_path: Path, location: str):
    routes = [given.a_keyed_route("app-cluster", location=location), given.an_error_route()]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match=r"identifier\.location"):
        stand_in(HOST, directory)


def test_an_identifier_with_an_empty_name_is_refused(tmp_path: Path):
    routes = [given.a_keyed_route("app-cluster", name=""), given.an_error_route()]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match=r"identifier\.name"):
        stand_in(HOST, directory)


@pytest.mark.parametrize(
    "routes",
    [
        [a_route("https"), a_route("https")],
        [a_route("https", "POST", "Describe"), a_route("https", "POST", "Describe")],
        [
            a_route("https", "POST", form_field="q"),
            a_route("https", "POST", form_field="q"),
        ],
    ],
    ids=["action_less", "one_action", "one_form_field"],
)
def test_two_routes_with_one_key_are_refused(tmp_path: Path, routes: list[dict[str, object]]):
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match="two routes answer"):
        stand_in(HOST, directory)


@pytest.mark.parametrize(
    "actions",
    [
        ["secretsmanager.GetSecretValue", "GetSecretValue"],
        ["secretsmanager.GetSecretValue", "secretsmanager.ListSecrets"],
        [None, "DescribeDBInstances"],
    ],
    ids=["json_and_query_spellings", "two_actions", "action_less_beside_an_action"],
)
def test_one_post_request_target_answering_distinct_actions_loads(
    tmp_path: Path, actions: list[str | None]
):
    routes = [a_route("https", "POST", action) for action in actions]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    assert stand_in(HOST, directory).host == HOST


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT"])
def test_an_action_on_a_route_other_than_post_is_refused(tmp_path: Path, method: str):
    routes = [a_route("https", method, "GetSecretValue")]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match="only a POST route"):
        stand_in(HOST, directory)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_a_form_field_on_a_route_other_than_post_is_refused(tmp_path: Path, method: str):
    routes = [a_route("https", method, form_field="q")]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match="only a POST route"):
        stand_in(HOST, directory)


def test_a_form_field_beside_an_action_is_refused(tmp_path: Path):
    routes = [a_route("https", "POST", "DescribeDBInstances", form_field="q")]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match="action or a form field"):
        stand_in(HOST, directory)


def test_routes_of_one_request_target_differing_only_by_their_form_field_load(tmp_path: Path):
    routes = [a_route("https", "POST", form_field=field) for field in (None, "q", "query")]
    directory = a_stand_ins_directory(tmp_path, routes=routes)

    assert stand_in(HOST, directory).host == HOST
