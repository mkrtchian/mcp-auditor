"""The golden master of the layout-effect check: what `layout_effect` returns on a fixed corpus
of (empty surface, planted surface, nonces) cases, recorded in `cve_layout_check_golden.json`.

The corpus is fictional: a healthy case where the ordinary surface is identical with and without
the nonces and no nonce leaks, a case where the planted surface differs, and a case where a nonce
leaks into the ordinary surface. Regenerate only in a commit that changes what `layout_effect`
grades, never on a refactor:

    uv run python -m tests.unit.support.test_cve_layout_check_golden_given
"""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from evals.cve_layout_check import LayoutSurface, layout_effect

GOLDEN_PATH = Path(__file__).parent / "cve_layout_check_golden.json"

_NONCE = "MCPAUDIT-7f3a9c"
_SURFACE = LayoutSurface(
    tool_names=("git_log", "git_show"),
    responses=("commit 0abc...\n", "leak0\nleak7\n"),
)


def _cases() -> dict[str, tuple[LayoutSurface, LayoutSurface, tuple[str, ...]]]:
    changed = LayoutSurface(_SURFACE.tool_names, ("commit 0abc...\n", "leak0\nleak7\nleak9\n"))
    leaking = LayoutSurface(_SURFACE.tool_names, (f"commit 0abc...\n{_NONCE}\n", "leak0\nleak7\n"))
    return {
        "tree_invisible_to_the_ordinary_surface": (_SURFACE, _SURFACE, (_NONCE,)),
        "planted_surface_differs": (_SURFACE, changed, (_NONCE,)),
        "nonce_leaks_into_the_ordinary_surface": (_SURFACE, leaking, (_NONCE,)),
    }


def golden_entries() -> dict[str, dict[str, Any]]:
    return {
        name: asdict(layout_effect(empty, planted, nonces))
        for name, (empty, planted, nonces) in _cases().items()
    }


if __name__ == "__main__":
    GOLDEN_PATH.write_text(json.dumps(golden_entries(), indent=2, sort_keys=True) + "\n")
