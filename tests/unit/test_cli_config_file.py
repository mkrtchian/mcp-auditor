from mcp_auditor.config_file import merge_defaults


def test_file_defaults_fill_in_non_explicit_params() -> None:
    cli_params = {"budget": 10, "tools": None, "ci": False}
    file_defaults = {"budget": 25, "tools": "read_file"}
    explicit_keys: set[str] = set()

    result = merge_defaults(cli_params, file_defaults, explicit_keys)

    assert result["budget"] == 25
    assert result["tools"] == "read_file"


def test_explicit_cli_args_override_file_defaults() -> None:
    cli_params = {"budget": 5, "tools": None}
    file_defaults = {"budget": 25}
    explicit_keys = {"budget"}

    result = merge_defaults(cli_params, file_defaults, explicit_keys)

    assert result["budget"] == 5


def test_empty_file_defaults_returns_cli_params() -> None:
    cli_params = {"budget": 10, "ci": False}

    result = merge_defaults(cli_params, file_defaults={}, explicit_keys=set())

    assert result == cli_params
