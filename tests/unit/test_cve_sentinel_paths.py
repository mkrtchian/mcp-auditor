import pytest

from evals.cve_planting_spec import request_target, served_file


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/fict/x", "/fict/x"),
        ("/fict/dir/", "/fict/dir/index.html"),
        ("/", "/index.html"),
        ("/fict/meta?api-version=1", "/fict/meta"),
        ("/fict/a#frag", "/fict/a"),
        ("/fict/sp ace/x", "/fict/sp ace/x"),
        ("/fict/a%20b", "/fict/a b"),
        ("/fict/café", "/fict/café"),
    ],
)
def test_the_served_file(path: str, expected: str):
    assert served_file(path) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/fict/x", "/fict/x"),
        ("/fict/dir/", "/fict/dir/"),
        ("/", "/"),
        ("/fict/meta?api-version=1", "/fict/meta?api-version=1"),
        ("/fict/a#frag", "/fict/a"),
        ("/fict/sp ace/x", "/fict/sp%20ace/x"),
        ("/fict/a%20b", "/fict/a%20b"),
        ("/fict/café", "/fict/caf%C3%A9"),
    ],
)
def test_the_request_target(path: str, expected: str):
    assert request_target(path) == expected
