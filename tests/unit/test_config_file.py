from pathlib import Path

import pytest

import tests.unit.support.test_config_file_given as given
from mcp_auditor.config_file import UnknownKeyError, load_config_file


def test_returns_empty_dict_when_no_file(tmp_path: Path) -> None:
    assert load_config_file(tmp_path / ".mcp-auditor.yml") == {}


def test_loads_all_supported_keys(tmp_path: Path) -> None:
    path = given.a_config_file_containing(
        tmp_path,
        budget=15,
        severity_threshold="high",
        tools=["get_user", "list_items"],
        output="report.json",
        markdown="report.md",
        ci=True,
        dry_run=True,
        resume=True,
    )

    result = load_config_file(path)

    assert result == {
        "budget": 15,
        "severity_threshold": "high",
        "tools": "get_user,list_items",
        "output": "report.json",
        "markdown": "report.md",
        "ci": True,
        "dry_run": True,
        "resume": True,
    }


def test_loads_partial_config(tmp_path: Path) -> None:
    path = given.a_config_file_containing(tmp_path, budget=20)

    result = load_config_file(path)

    assert result == {"budget": 20}


def test_rejects_unknown_keys(tmp_path: Path) -> None:
    path = given.a_config_file_containing(tmp_path, budget=10, unknown_key="value")

    with pytest.raises(UnknownKeyError, match="unknown_key"):
        load_config_file(path)


def test_converts_tools_list_to_comma_string(tmp_path: Path) -> None:
    path = given.a_config_file_containing(tmp_path, tools=["read_file", "write_file"])

    result = load_config_file(path)

    assert result["tools"] == "read_file,write_file"


def test_passes_through_tools_string(tmp_path: Path) -> None:
    path = given.a_config_file_containing(tmp_path, tools="read_file,write_file")

    result = load_config_file(path)

    assert result["tools"] == "read_file,write_file"


def test_returns_empty_dict_for_empty_file(tmp_path: Path) -> None:
    path = tmp_path / ".mcp-auditor.yml"
    path.write_text("")

    assert load_config_file(path) == {}
