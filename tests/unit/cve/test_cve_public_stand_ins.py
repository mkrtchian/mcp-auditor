from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.cve.support.stand_in_captures as captures
from evals.cve.planting_base import StandIn
from evals.cve.public_stand_ins import StandInFiles, stand_in, stand_in_files
from evals.cve.stand_in_defaults import body_quoting, media_type


def test_a_capture_loads_with_its_leaf_key_and_authority(tmp_path: Path):
    directory = captures.a_stand_in_directory(tmp_path)

    loaded = stand_in(captures.HOST, directory)

    assert loaded == StandIn(
        host=captures.HOST,
        address="93.184.215.14",
        capture=(directory / f"{captures.HOST}.json").read_text(),
        certificate="leaf",
        key="key",
        authority="authority",
    )


def test_a_capture_naming_another_host_than_its_file_is_refused(tmp_path: Path):
    directory = captures.a_stand_in_directory(tmp_path, host="www.example.com")

    with pytest.raises(ValueError, match=r"host is www\.example\.com"):
        stand_in(captures.HOST, directory)


@pytest.mark.parametrize("address", ["10.0.0.7", "127.0.0.1", "198.18.0.1", "198.19.255.1"])
def test_an_address_that_is_not_global_unicast_is_refused(tmp_path: Path, address: str):
    directory = captures.a_stand_in_directory(tmp_path, address=address)

    with pytest.raises(ValidationError, match="address"):
        stand_in(captures.HOST, directory)


def test_a_route_scheme_other_than_http_or_https_is_refused(tmp_path: Path):
    directory = captures.a_stand_in_directory(tmp_path, routes=[captures.a_route("ftp")])

    with pytest.raises(ValidationError, match="scheme"):
        stand_in(captures.HOST, directory)


@pytest.mark.parametrize("field", ["command", "captured_at"])
def test_an_empty_provenance_field_of_a_capture_is_refused(tmp_path: Path, field: str):
    directory = captures.a_stand_in_directory(tmp_path, **{field: ""})

    with pytest.raises(ValidationError, match=field):
        stand_in(captures.HOST, directory)


def test_a_capture_without_its_date_is_refused(tmp_path: Path):
    directory = captures.a_stand_in_directory(tmp_path, captured_at=None)

    with pytest.raises(ValidationError, match="captured_at"):
        stand_in(captures.HOST, directory)


def test_a_file_written_from_the_software_sources_loads_without_a_date(tmp_path: Path):
    directory = captures.a_stand_in_directory(
        tmp_path, source="software_sources", captured_at=None, command="the AWS API reference"
    )

    assert stand_in(captures.HOST, directory).host == captures.HOST


def test_a_file_written_from_the_software_sources_with_a_date_is_refused(tmp_path: Path):
    directory = captures.a_stand_in_directory(tmp_path, source="software_sources")

    with pytest.raises(ValidationError, match="captured_at"):
        stand_in(captures.HOST, directory)


def test_a_source_other_than_capture_or_software_sources_is_refused(tmp_path: Path):
    directory = captures.a_stand_in_directory(tmp_path, source="invented")

    with pytest.raises(ValidationError, match="source"):
        stand_in(captures.HOST, directory)


@pytest.mark.parametrize(
    "schemes", [[], ["https"], ["http", "http"]], ids=["none", "https_only", "two_http"]
)
def test_a_capture_without_exactly_one_default_per_scheme_is_refused(
    tmp_path: Path, schemes: list[str]
):
    defaults = [captures.a_default(scheme) for scheme in schemes]
    directory = captures.a_stand_in_directory(tmp_path, defaults=defaults)

    with pytest.raises(ValidationError, match="answer to an unknown path on each"):
        stand_in(captures.HOST, directory)


_HTML = ["Content-Type", "text/html; charset=utf-8"]
_JSON = ["Content-Type", "application/json"]
_QUOTED = captures.PROBED_TARGET
_HEX = captures.PROBED_TARGET[1:]


@pytest.mark.parametrize(
    "default",
    [
        captures.a_default(
            "https", headers=[_HTML], body=f"<a href='{_QUOTED}'>{_QUOTED}</a>", path_form="decoded"
        ),
        captures.a_default(
            "https", headers=[_JSON], body=f'{{"path": "{_QUOTED}"}}', path_form="raw"
        ),
        captures.a_default("https", headers=[["Location", f"https://{captures.HOST}{_QUOTED}"]]),
    ],
    ids=["html_body", "json_body", "location"],
)
def test_a_default_quoting_its_probed_target_where_the_stand_in_substitutes_it_loads(
    tmp_path: Path, default: dict[str, object]
):
    directory = captures.a_stand_in_directory(
        tmp_path, defaults=[captures.a_default("http"), default]
    )

    assert stand_in(captures.HOST, directory).host == captures.HOST


@pytest.mark.parametrize(
    ("default", "reason"),
    [
        (
            captures.a_default("http", headers=[_HTML, ["X-Request-Path", _QUOTED]]),
            "in a header other than its Location",
        ),
        (
            captures.a_default("http", headers=[_HTML], body=f'<div id="{_HEX}"></div>'),
            "outside path position",
        ),
        (
            captures.a_default(
                "http", headers=[_JSON], body=f'{{"p": "\\{_QUOTED}"}}', path_form="raw"
            ),
            "outside path position",
        ),
        (
            captures.a_default(
                "http", headers=[["Content-Type", "text/plain"]], body=_QUOTED, path_form="raw"
            ),
            "neither HTML nor JSON",
        ),
        (
            captures.a_default("http", headers=[], body=_QUOTED, path_form="raw"),
            "neither HTML nor JSON",
        ),
        (captures.a_default("http", headers=[_HTML], body=_QUOTED), "path_form must say"),
        (captures.a_default("http", headers=[_HTML], path_form="decoded"), "path_form must say"),
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
    directory = captures.a_stand_in_directory(
        tmp_path, defaults=[default, captures.a_default("https")]
    )

    with pytest.raises(ValidationError, match=reason):
        stand_in(captures.HOST, directory)


@pytest.mark.parametrize("path_form", ["encoded", "missing"])
def test_a_path_form_other_than_decoded_raw_or_null_is_refused(tmp_path: Path, path_form: str):
    default = captures.a_default("http", headers=[_HTML], body=_QUOTED, path_form=path_form)
    if path_form == "missing":
        del default["path_form"]
    directory = captures.a_stand_in_directory(
        tmp_path, defaults=[default, captures.a_default("https")]
    )

    with pytest.raises(ValidationError, match="path_form"):
        stand_in(captures.HOST, directory)


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


@pytest.mark.parametrize(
    "probed_request_target", ["/0123456789ABCDEF", "/0123", "0123456789abcdef"]
)
def test_a_probed_target_other_than_a_slash_and_16_hex_digits_is_refused(
    tmp_path: Path, probed_request_target: str
):
    default = captures.a_default("http", probed_request_target=probed_request_target)
    directory = captures.a_stand_in_directory(
        tmp_path, defaults=[default, captures.a_default("https")]
    )

    with pytest.raises(ValidationError, match="probed_request_target"):
        stand_in(captures.HOST, directory)


def test_the_files_of_a_stand_in_are_named_without_being_read(tmp_path: Path):
    files = stand_in_files(captures.HOST, tmp_path)

    assert files == StandInFiles(
        capture=tmp_path / "example.com.json",
        certificate=tmp_path / "tls" / "example.com.pem",
        key=tmp_path / "tls" / "example.com-key.pem",
        authority=tmp_path / "tls" / "fixture-authority.pem",
    )
