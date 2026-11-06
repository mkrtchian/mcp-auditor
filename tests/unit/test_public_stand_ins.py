from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_public_stand_ins_given as given
from evals.cve_planting_base import StandIn
from evals.public_stand_ins import (
    STAND_INS_DIRECTORY,
    StandInFiles,
    body_quoting,
    media_type,
    stand_in,
    stand_in_files,
)


def test_a_capture_loads_with_its_leaf_key_and_authority(tmp_path: Path):
    directory = given.a_stand_in_directory(tmp_path)

    loaded = stand_in(given.HOST, directory)

    assert loaded == StandIn(
        host=given.HOST,
        address="93.184.215.14",
        capture=(directory / f"{given.HOST}.json").read_text(),
        certificate="leaf",
        key="key",
        authority="authority",
    )


def test_a_capture_naming_another_host_than_its_file_is_refused(tmp_path: Path):
    directory = given.a_stand_in_directory(tmp_path, host="www.example.com")

    with pytest.raises(ValueError, match=r"host is www\.example\.com"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize("address", ["10.0.0.7", "127.0.0.1", "198.18.0.1", "198.19.255.1"])
def test_an_address_that_is_not_global_unicast_is_refused(tmp_path: Path, address: str):
    directory = given.a_stand_in_directory(tmp_path, address=address)

    with pytest.raises(ValidationError, match="address"):
        stand_in(given.HOST, directory)


def test_a_route_scheme_other_than_http_or_https_is_refused(tmp_path: Path):
    directory = given.a_stand_in_directory(tmp_path, routes=[given.a_route("ftp")])

    with pytest.raises(ValidationError, match="scheme"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize(
    "routes",
    [
        [given.a_route("https"), given.a_route("https")],
        [given.a_route("https", "POST", "Describe"), given.a_route("https", "POST", "Describe")],
    ],
    ids=["action_less", "one_action"],
)
def test_two_routes_with_one_key_are_refused(tmp_path: Path, routes: list[dict[str, object]]):
    directory = given.a_stand_in_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match="two routes answer"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize(
    "actions",
    [
        ["secretsmanager.GetSecretValue", "GetSecretValue"],
        ["secretsmanager.GetSecretValue", "secretsmanager.ListSecrets"],
        [None, "DescribeDBInstances"],
    ],
    ids=["json_and_query_spellings", "two_actions", "action_less_beside_an_action"],
)
def test_one_post_target_answering_distinct_actions_loads(
    tmp_path: Path, actions: list[str | None]
):
    routes = [given.a_route("https", "POST", action) for action in actions]
    directory = given.a_stand_in_directory(tmp_path, routes=routes)

    assert stand_in(given.HOST, directory).host == given.HOST


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT"])
def test_an_action_on_a_route_other_than_post_is_refused(tmp_path: Path, method: str):
    routes = [given.a_route("https", method, "GetSecretValue")]
    directory = given.a_stand_in_directory(tmp_path, routes=routes)

    with pytest.raises(ValidationError, match="only a POST route"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize("field", ["command", "captured_at"])
def test_an_empty_provenance_field_is_refused(tmp_path: Path, field: str):
    directory = given.a_stand_in_directory(tmp_path, **{field: ""})

    with pytest.raises(ValidationError, match=field):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize(
    "schemes", [[], ["https"], ["http", "http"]], ids=["none", "https_only", "two_http"]
)
def test_a_capture_without_exactly_one_default_per_scheme_is_refused(
    tmp_path: Path, schemes: list[str]
):
    defaults = [given.a_default(scheme) for scheme in schemes]
    directory = given.a_stand_in_directory(tmp_path, defaults=defaults)

    with pytest.raises(ValidationError, match="answer to an unknown path on each"):
        stand_in(given.HOST, directory)


_HTML = ["Content-Type", "text/html; charset=utf-8"]
_JSON = ["Content-Type", "application/json"]
_QUOTED = given.PROBED_TARGET
_HEX = given.PROBED_TARGET[1:]


@pytest.mark.parametrize(
    "default",
    [
        given.a_default(
            "https", headers=[_HTML], body=f"<a href='{_QUOTED}'>{_QUOTED}</a>", path_form="decoded"
        ),
        given.a_default("https", headers=[_JSON], body=f'{{"path": "{_QUOTED}"}}', path_form="raw"),
        given.a_default("https", headers=[["Location", f"https://{given.HOST}{_QUOTED}"]]),
    ],
    ids=["html_body", "json_body", "location"],
)
def test_a_default_quoting_its_probed_target_where_the_stand_in_substitutes_it_loads(
    tmp_path: Path, default: dict[str, object]
):
    directory = given.a_stand_in_directory(tmp_path, defaults=[given.a_default("http"), default])

    assert stand_in(given.HOST, directory).host == given.HOST


@pytest.mark.parametrize(
    ("default", "reason"),
    [
        (
            given.a_default("http", headers=[_HTML, ["X-Request-Path", _QUOTED]]),
            "in a header other than its Location",
        ),
        (
            given.a_default("http", headers=[_HTML], body=f'<div id="{_HEX}"></div>'),
            "outside path position",
        ),
        (
            given.a_default(
                "http", headers=[_JSON], body=f'{{"p": "\\{_QUOTED}"}}', path_form="raw"
            ),
            "outside path position",
        ),
        (
            given.a_default(
                "http", headers=[["Content-Type", "text/plain"]], body=_QUOTED, path_form="raw"
            ),
            "neither HTML nor JSON",
        ),
        (
            given.a_default("http", headers=[], body=_QUOTED, path_form="raw"),
            "neither HTML nor JSON",
        ),
        (given.a_default("http", headers=[_HTML], body=_QUOTED), "path_form must say"),
        (given.a_default("http", headers=[_HTML], path_form="decoded"), "path_form must say"),
    ],
    ids=[
        "other_header",
        "html_attribute",
        "json_escaped_slash",
        "plain_text_body",
        "no_content_type",
        "quoting_without_path_form",
        "path_form_without_quoting",
    ],
)
def test_a_default_whose_quote_the_stand_in_cannot_substitute_is_refused(
    tmp_path: Path, default: dict[str, object], reason: str
):
    directory = given.a_stand_in_directory(tmp_path, defaults=[default, given.a_default("https")])

    with pytest.raises(ValidationError, match=reason):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize("path_form", ["encoded", "missing"])
def test_a_path_form_other_than_decoded_raw_or_null_is_refused(tmp_path: Path, path_form: str):
    default = given.a_default("http", headers=[_HTML], body=_QUOTED, path_form=path_form)
    if path_form == "missing":
        del default["path_form"]
    directory = given.a_stand_in_directory(tmp_path, defaults=[default, given.a_default("https")])

    with pytest.raises(ValidationError, match="path_form"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([("Content-Type", "Text/HTML; charset=utf-8")], "text/html"),
        ([("content-type", "application/json"), ("Content-Type", "text/html")], "application/json"),
        ([("Server", "nginx")], None),
    ],
    ids=["parameters_and_case", "first_of_two", "none"],
)
def test_the_media_type_is_the_first_content_type_without_its_parameters(
    headers: list[tuple[str, str]], expected: str | None
):
    assert media_type(headers) == expected


def test_an_html_quote_is_escaped_with_markupsafes_table():
    assert body_quoting("/a&<b>\"'", "text/html") == "/a&amp;&lt;b&gt;&#34;&#39;"


def test_a_json_quote_is_the_content_of_a_json_string():
    value = "/a<b>\"'\\c"

    assert body_quoting(value, "application/json") == "/a<b>\\\"'\\\\c"


def test_a_quote_in_another_media_type_has_no_escaping():
    with pytest.raises(ValueError, match="text/plain"):
        body_quoting("/a", "text/plain")


@pytest.mark.parametrize("probed_target", ["/0123456789ABCDEF", "/0123", "0123456789abcdef"])
def test_a_probed_target_other_than_a_slash_and_16_hex_digits_is_refused(
    tmp_path: Path, probed_target: str
):
    default = given.a_default("http", probed_target=probed_target)
    directory = given.a_stand_in_directory(tmp_path, defaults=[default, given.a_default("https")])

    with pytest.raises(ValidationError, match="probed_target"):
        stand_in(given.HOST, directory)


def test_the_files_of_a_stand_in_are_named_without_being_read(tmp_path: Path):
    files = stand_in_files(given.HOST, tmp_path)

    assert files == StandInFiles(
        capture=tmp_path / "example.com.json",
        certificate=tmp_path / "tls" / "example.com.pem",
        key=tmp_path / "tls" / "example.com-key.pem",
        authority=tmp_path / "tls" / "fixture-authority.pem",
    )


def test_every_committed_capture_loads_with_its_leaf():
    hosts = [path.stem for path in STAND_INS_DIRECTORY.glob("*.json")]

    loaded = [stand_in(host) for host in hosts]

    assert all(each.certificate.startswith("-----BEGIN CERTIFICATE-----") for each in loaded)


def test_the_committed_captures_are_exactly_the_declared_stand_ins():
    captured = {path.stem for path in STAND_INS_DIRECTORY.glob("*.json")}

    assert captured == given.declared_stand_in_hosts()


def test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    critical, permitted, excluded = given.committed_authority_constraints(STAND_INS_DIRECTORY)

    assert critical
    assert permitted == hosts
    assert excluded == {f".{host}" for host in hosts}


def test_every_committed_leaf_names_an_https_stand_in_host():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    leaves = given.committed_leaf_names(STAND_INS_DIRECTORY)

    assert {name: names for name, names in leaves.items() if not names <= hosts} == {}
    assert all(len(names) == 1 for names in leaves.values())
