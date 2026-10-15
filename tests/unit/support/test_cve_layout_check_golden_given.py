"""The golden master of the layout check: what the break detector (`layout_breaks`,
`layout_breaks_any`) and the anti-leak guard (`nonce_in_surface`) return on a fixed corpus of
surfaces, recorded in `cve_layout_check_golden.json`.

The corpus is fictional. For the break detector, two collected surfaces for one version (one
launched with the valid-by-type reference arm, one with the layout): a healthy pair (no break), a
pair where tools/list is lost with the layout, a pair where a call errors only with the layout, and
the two false reds the old byte-for-byte check produced (a discovery symlink in a listing and a
shifted deterministic HEAD SHA), which are not breaks. For the two-version detector, a sequence of
version pairs where only the patched pair breaks (a break on either version is a break). For the
anti-leak guard, a planted surface where a nonce leaks into the ordinary surface and one where none
does. Regenerate only in a commit that changes what the layout check grades, never on a refactor:

    uv run python -m tests.unit.support.test_cve_layout_check_golden_given
"""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from evals.cve_layout_check import (
    LayoutSurface,
    layout_breaks,
    layout_breaks_any,
    nonce_in_surface,
)

GOLDEN_PATH = Path(__file__).parent / "cve_layout_check_golden.json"

_NONCE = "MCPAUDIT-7f3a9c"
_HEALTHY = LayoutSurface(
    tool_names=("git_log", "git_show"),
    responses=("commit 0abc...\n", "leak0\nleak7\n"),
    call_errored=(False, False),
    tools_list_succeeded=True,
)


def _break_cases() -> dict[str, tuple[LayoutSurface, LayoutSurface]]:
    tools_list_lost = replace(_HEALTHY, responses=(), call_errored=(), tools_list_succeeded=False)
    call_errors = replace(_HEALTHY, call_errored=(False, True))
    discovery_symlink = replace(
        _HEALTHY, responses=("commit 0abc...\n", "leak0\nleak7\nreport -> /srv/app.git\n")
    )
    shifted_sha = replace(_HEALTHY, responses=("commit 9f2e...\n", "leak0\nleak7\n"))
    return {
        "both_healthy_no_break": (_HEALTHY, _HEALTHY),
        "tools_list_lost_with_the_layout": (_HEALTHY, tools_list_lost),
        "call_errors_only_with_the_layout": (_HEALTHY, call_errors),
        "discovery_symlink_in_a_listing_is_not_a_break": (_HEALTHY, discovery_symlink),
        "shifted_head_sha_is_not_a_break": (_HEALTHY, shifted_sha),
    }


def _any_cases() -> dict[str, tuple[tuple[LayoutSurface, LayoutSurface], ...]]:
    # The two-version break: one pair per version, a break on either is a break. Here only the
    # second pair (the patched version) breaks, so the verdict is True.
    call_errors = replace(_HEALTHY, call_errored=(False, True))
    return {
        "break_on_the_patched_version_only": ((_HEALTHY, _HEALTHY), (_HEALTHY, call_errors)),
    }


def _leak_cases() -> dict[str, tuple[LayoutSurface, tuple[str, ...]]]:
    leaking = replace(_HEALTHY, responses=(f"commit 0abc...\n{_NONCE}\n", "leak0\nleak7\n"))
    return {
        "nonce_leaks_into_the_ordinary_surface": (leaking, (_NONCE,)),
        "no_nonce_in_the_ordinary_surface": (_HEALTHY, (_NONCE,)),
    }


def golden_entries() -> dict[str, dict[str, Any]]:
    entries = {
        name: {"breaks": layout_breaks(reference, with_layout)}
        for name, (reference, with_layout) in _break_cases().items()
    }
    entries |= {
        name: {"breaks": layout_breaks_any(list(pairs))} for name, pairs in _any_cases().items()
    }
    entries |= {
        name: {"leaks": nonce_in_surface(planted, nonces)}
        for name, (planted, nonces) in _leak_cases().items()
    }
    return entries


if __name__ == "__main__":
    GOLDEN_PATH.write_text(json.dumps(golden_entries(), indent=2, sort_keys=True) + "\n")
