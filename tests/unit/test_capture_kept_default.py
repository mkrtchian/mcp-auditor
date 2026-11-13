import json
from pathlib import Path

import httpx
import pytest

import tests.unit.support.test_capture_kept_default_given as given
from evals.capture_defaults import FORM_SUFFIX
from evals.capture_stand_in import main


def _capture_keeping(out: Path, scheme: str, seen: list[httpx.URL]) -> None:
    main(
        ["--out", str(out), "--keep-default", scheme, given.AN_ADDRESS_HOST_URL],
        transport=given.a_recording_host(seen),
    )


def test_a_kept_default_is_carried_over_from_the_old_file_byte_for_byte(tmp_path: Path):
    out = given.an_old_capture(tmp_path)

    _capture_keeping(out, "http", [])

    http = json.loads(out.read_text())["defaults"][0]
    assert json.dumps(http) == json.dumps(given.OLD_HTTP_DEFAULT)


def test_no_request_goes_to_the_kept_scheme_and_the_other_is_probed_as_today(tmp_path: Path):
    out = given.an_old_capture(tmp_path)
    seen: list[httpx.URL] = []

    _capture_keeping(out, "http", seen)

    https = json.loads(out.read_text())["defaults"][1]
    probed = https["probed_request_target"]
    assert [(url.scheme, url.raw_path.decode()) for url in seen] == [
        ("https", "/core/v2/rest/product/A"),
        ("https", probed),
        ("https", probed + FORM_SUFFIX),
    ]
    assert (https["scheme"], https["status"], https["body"]) == ("https", 404, "not found")


def test_the_command_records_the_kept_default_with_the_other_arguments(tmp_path: Path):
    out = given.an_old_capture(tmp_path)

    _capture_keeping(out, "http", [])

    assert json.loads(out.read_text())["command"] == (
        "uv run python -m evals.capture_stand_in"
        f" --out {out} --keep-default http {given.AN_ADDRESS_HOST_URL}"
    )


def test_a_kept_default_from_a_missing_file_is_refused_before_any_request(tmp_path: Path):
    seen: list[httpx.URL] = []

    with pytest.raises(SystemExit, match="cannot be read"):
        _capture_keeping(tmp_path / "absent.json", "http", seen)

    assert seen == []


def test_a_kept_default_from_a_file_that_does_not_load_as_a_capture_is_refused(tmp_path: Path):
    out = tmp_path / "x.json"
    out.write_text('{"host": "example.com"}')
    seen: list[httpx.URL] = []

    with pytest.raises(SystemExit, match="does not load"):
        _capture_keeping(out, "http", seen)

    assert seen == []


def test_a_kept_default_on_a_scheme_other_than_http_or_https_is_refused(tmp_path: Path):
    seen: list[httpx.URL] = []

    with pytest.raises(SystemExit):
        _capture_keeping(given.an_old_capture(tmp_path), "ftp", seen)

    assert seen == []
