"""The derived reads the nuisance measurement consumes: the flaws that count and the tools
they reach with the judge categories valid for each.

A flaw counts when it sets the version (a graded class, a tool reached, effect visible,
pinnable, all settled upstream) and its fix check passes on every patched version, with a positive
control that does not rest on a stand-in relaying the flaw's effect. A counted tool is one such
flaw reaches that still exists on the patched version, whose real software can answer it (a tool
with no such record yet stays counted), whose backend is not one the fixture cannot provide and
whose declared function is not the effect of its class. The declared function is read per tool,
from the tool's own record, falling back to the flaw's for a tool that records none. The
categories come from `cve_grammar.VALID_CATEGORIES`, read, never redefined here.

The declared-function tools are the ones a counted flaw reaches that their declared function
alone leaves out: the tools it would count were their function not its effect, with the same
categories. The run reports the FAILs on them beside the raw count, and nothing compares or gates
on them.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import TYPE_CHECKING

from evals.cve_grammar import VALID_CATEGORIES
from evals.cve_units import JudgeCategory

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, FlawRecord, ToolRecord


def counted_flaws(server: AdmittedServer) -> list[FlawRecord]:
    return [flaw for flaw in server.flaws if _counts(flaw)]


def counted_tools(server: AdmittedServer) -> dict[str, frozenset[JudgeCategory]]:
    return _categories_per_tool((flaw, flaw_counted_tools(flaw)) for flaw in counted_flaws(server))


def declared_function_tools(server: AdmittedServer) -> dict[str, frozenset[JudgeCategory]]:
    return _categories_per_tool(
        (flaw, _reachable_tools(flaw, declared_function_is_effect=True))
        for flaw in counted_flaws(server)
    )


def _categories_per_tool(
    tools_per_flaw: Iterable[tuple[FlawRecord, frozenset[str]]],
) -> dict[str, frozenset[JudgeCategory]]:
    categories: dict[str, set[JudgeCategory]] = defaultdict(set)
    for flaw, names in tools_per_flaw:
        if flaw.effect_class is None:
            continue
        for name in names:
            categories[name] |= VALID_CATEGORIES[flaw.effect_class]
    return {name: frozenset(cats) for name, cats in categories.items()}


def flaw_counted_tools(flaw: FlawRecord) -> frozenset[str]:
    return _reachable_tools(flaw, declared_function_is_effect=False)


def _reachable_tools(flaw: FlawRecord, *, declared_function_is_effect: bool) -> frozenset[str]:
    if flaw.effect_class is None or flaw.backend_need == "external":
        return frozenset()
    selected = {
        tool.patched_name
        for tool in flaw.tools
        if (tool.real_software is None or tool.real_software.answers)
        and _declared_function_is_effect(tool, flaw) == declared_function_is_effect
    }
    return flaw_tools(flaw) & selected


def _declared_function_is_effect(tool: ToolRecord, flaw: FlawRecord) -> bool:
    if tool.declared_function_is_effect is not None:
        return tool.declared_function_is_effect
    return flaw.declared_function_is_effect


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
