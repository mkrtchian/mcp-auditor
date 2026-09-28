import json
from pathlib import Path
from typing import Any

from evals.declared_flips import DeclaredFlip, Suite

BASE = "0123456789abcdef0123456789abcdef01234567"
OTHER_BASE = "fedcba9876543210fedcba9876543210fedcba98"
KNOWN_KEYS = frozenset({"get_user/input_validation", "get_user/error_handling"})


def an_entry(key: str = "get_user/input_validation", base: str = BASE) -> DeclaredFlip:
    return DeclaredFlip(
        suite=Suite.HONEYPOT,
        key=key,
        mechanism="the generator no longer probes this category",
        base=base,
        runs_seen=[],
    )


def a_raw_entry(**overrides: Any) -> dict[str, Any]:
    return {**an_entry().model_dump(mode="json"), **overrides}


def a_file_holding(tmp_path: Path, *entries: dict[str, Any]) -> Path:
    path = tmp_path / "declared_flips.json"
    path.write_text(json.dumps({"entries": list(entries)}))
    return path
