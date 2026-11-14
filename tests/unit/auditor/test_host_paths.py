from pathlib import Path

import pytest

from mcp_auditor.adapters.host_paths import existing_paths


def test_maps_an_existing_absolute_spelling_to_its_resolved_path(tmp_path: Path):
    (tmp_path / "data").mkdir()

    assert existing_paths([str(tmp_path / "data")]) == {
        str(tmp_path / "data"): (tmp_path / "data").resolve()
    }


def test_resolves_a_relative_spelling_against_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)

    assert existing_paths(["./data"]) == {"./data": (tmp_path / "data").resolve()}


def test_resolves_the_working_directory_itself(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)

    assert existing_paths(["."]) == {".": tmp_path.resolve()}


def test_follows_a_symlink_to_its_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "target").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "target")
    monkeypatch.chdir(tmp_path)

    assert existing_paths(["./link"]) == {"./link": (tmp_path / "target").resolve()}


def test_omits_a_spelling_that_does_not_exist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)

    assert existing_paths(["./data", "./missing", "server"]) == {
        "./data": (tmp_path / "data").resolve()
    }


def test_maps_nothing_for_no_spelling():
    assert existing_paths([]) == {}
