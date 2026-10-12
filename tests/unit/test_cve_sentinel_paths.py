from urllib.parse import unquote

import pytest

from evals.cve_planting_spec import request_target, served_file


@pytest.mark.parametrize(
    "path",
    [
        "/fict/x",
        "/fict/dir/",
        "/",
        "/fict/meta?api-version=1",
        "/fict/a#frag",
        "/fict/sp ace/x",
        "/fict/a%20b",
        "/fict/café",
    ],
)
def test_the_file_httpd_maps_the_request_target_to_is_the_served_file(path: str):
    assert _file_httpd_maps(request_target(path)) == served_file(path)


def _file_httpd_maps(target: str) -> str:
    decoded = unquote(target.partition("?")[0])
    return f"{decoded}index.html" if decoded.endswith("/") else decoded


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/fict/dir/", "/fict/dir/index.html"),
        ("/", "/index.html"),
        ("/fict/meta?api-version=1", "/fict/meta"),
        ("/fict/a#frag", "/fict/a"),
        ("/fict/a%20b", "/fict/a b"),
    ],
)
def test_the_served_file(path: str, expected: str):
    assert served_file(path) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/fict/a#frag", "/fict/a"),
        ("/fict/sp ace/x", "/fict/sp%20ace/x"),
        ("/fict/a%20b", "/fict/a%20b"),
        ("/fict/meta?api-version=1", "/fict/meta?api-version=1"),
    ],
)
def test_the_request_target(path: str, expected: str):
    assert request_target(path) == expected
