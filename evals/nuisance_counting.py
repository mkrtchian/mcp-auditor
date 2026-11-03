"""The derived reads the nuisance measurement consumes: the flaws that count and the tools
they reach with the judge categories valid for each.

A flaw counts when it sets the version (a graded class, a tool reached, effect visible,
pinnable, all settled upstream) and its fix check passes on every patched version, with a positive
control that does not rest on a stand-in relaying the flaw's effect. A counted tool is one such
flaw reaches that still exists on the patched version, whose real software can answer it (a tool
with no such record yet stays counted), whose backend is not one the fixture cannot provide and
whose declared function is not the effect of its class. The categories come from
`cve_grammar.VALID_CATEGORIES`, read, never redefined here.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from evals.cve_grammar import VALID_CATEGORIES
from evals.cve_units import JudgeCategory

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, FlawRecord


def counted_flaws(server: AdmittedServer) -> list[FlawRecord]:
    return [flaw for flaw in server.flaws if _counts(flaw)]


def counted_tools(server: AdmittedServer) -> dict[str, frozenset[JudgeCategory]]:
    categories: dict[str, set[JudgeCategory]] = defaultdict(set)
    for flaw in counted_flaws(server):
        if flaw.effect_class is None:
            continue
        for name in flaw_counted_tools(flaw):
            categories[name] |= VALID_CATEGORIES[flaw.effect_class]
    return {name: frozenset(cats) for name, cats in categories.items()}


def flaw_counted_tools(flaw: FlawRecord) -> frozenset[str]:
    if (
        flaw.effect_class is None
        or flaw.backend_need == "external"
        or flaw.declared_function_is_effect
    ):
        return frozenset()
    answering = {
        tool.patched_name
        for tool in flaw.tools
        if tool.real_software is None or tool.real_software.answers
    }
    return flaw_tools(flaw) & answering


def flaw_tools(flaw: FlawRecord) -> frozenset[str]:
    return frozenset(
        tool.patched_name
        for tool in flaw.tools
        if tool.status != "removed" and tool.patched_name is not None
    )


def _counts(flaw: FlawRecord) -> bool:
    check = flaw.fix_check
    return (
        flaw.effect_class is not None
        and flaw.patched_version is not None
        and bool(flaw.tools)
        and check.vulnerable_surfaces
        and not check.patched_surfaces
        and not check.server_patched_surfaces
        and not check.patched_benign_errored
        and check.relies_on_relaying_stand_in is not True
    )
