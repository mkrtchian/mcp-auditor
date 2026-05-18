from pathlib import Path
from typing import Any, cast

import yaml

KNOWN_KEYS = frozenset(
    {
        "budget",
        "chains",
        "severity_threshold",
        "tools",
        "output",
        "markdown",
        "ci",
        "dry_run",
        "resume",
    }
)


class UnknownKeyError(ValueError):
    pass


def merge_defaults(
    cli_params: dict[str, Any],
    file_defaults: dict[str, Any],
    explicit_keys: set[str],
) -> dict[str, Any]:
    result = dict(cli_params)
    for key, value in file_defaults.items():
        if key not in explicit_keys:
            result[key] = value
    return result


def load_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    raw = yaml.safe_load(path.read_text())
    if raw is None:
        return {}

    unknown = set(raw.keys()) - KNOWN_KEYS
    if unknown:
        raise UnknownKeyError(f"Unknown config keys: {', '.join(sorted(unknown))}")

    result = dict(raw)
    tools = result.get("tools")
    if isinstance(tools, list):
        result["tools"] = ",".join(cast(list[str], tools))
    return result
