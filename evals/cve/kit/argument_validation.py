"""The exploits a patched version's MCP SDK rejects at argument validation, before any of its code
runs, read from the version's own tools/list and the SDKs' error wordings. The calibration check,
the kit driver and the kit fix check share it, free of mcp_auditor so the kits carry it."""

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class AnsweredCall(Protocol):
    @property
    def content(self) -> str: ...
    @property
    def is_error(self) -> bool: ...


type CallExchange = tuple[str, Mapping[str, Any], AnsweredCall]


@dataclass(frozen=True)
class PatchedExploits:
    """The exploits played on one patched version, with the arguments its own tools/list marks
    required, per tool it lists."""

    version: str
    exploits: Sequence[Sequence[CallExchange]]
    required: Mapping[str, frozenset[str]]


def unreached_reasons(patched: PatchedExploits, surfacing: Collection[int]) -> list[str]:
    """The exploits that surfaced the nonce or witness on the vulnerable version and reach none of
    the patched version's code: a nonce or witness that does not surface after them shows nothing
    about the fix. A call is rejected only when it lacks an argument the schema lists as required
    and the SDK answers with its argument-validation error: a server that fills in a default runs
    the call. A value the schema refuses (a pattern, an enum) can be the fix itself, and a tool the
    version no longer lists can be the fix removing it. An exploit with one call that runs is no
    reason."""
    reasons: list[str] = []
    for index in sorted(surfacing):
        calls = patched.exploits[index] if index < len(patched.exploits) else ()
        rejections = [_rejected_for(call, patched.required) for call in calls]
        if calls and all(rejections):
            tools = ", ".join(dict.fromkeys(tool for tool, _, _ in calls))
            reasons.append(
                f"{patched.version}: exploit {index} ({tools}) lacks {_names(rejections)}, which"
                " the schema requires, and the SDK rejects every call of it at argument"
                " validation, so it never reaches the patched code"
            )
    return reasons


def unreached_notes(patched: PatchedExploits) -> list[str]:
    """What the pass condition does not read but a reader should: a call to a tool the version
    does not list, and a call lacking a required argument that errors without the SDK's
    argument-validation wording."""
    notes: list[str] = []
    for index, exploit in enumerate(patched.exploits):
        for tool, arguments, response in exploit:
            if tool not in patched.required:
                notes.append(
                    f"{patched.version}: exploit {index} calls {tool}, which this"
                    " version does not list"
                )
                continue
            missing = patched.required[tool] - arguments.keys()
            if missing and response.is_error and not is_argument_validation_error(response):
                notes.append(
                    f"{patched.version}: exploit {index} calls {tool} without"
                    f" {', '.join(sorted(missing))}, which its schema requires, and errors"
                    " without the SDK's argument-validation wording"
                )
    return notes


def _rejected_for(call: CallExchange, required: Mapping[str, frozenset[str]]) -> frozenset[str]:
    tool, arguments, response = call
    missing = frozenset(required.get(tool, frozenset()) - arguments.keys())
    return missing if missing and is_argument_validation_error(response) else frozenset()


def _names(rejections: Sequence[frozenset[str]]) -> str:
    return ", ".join(sorted(frozenset().union(*rejections)))


# The argument-validation errors of the MCP SDKs, each tuple one wording whose every marker it
# carries. The Python SDK's FastMCP answers with pydantic's error ("1 validation error for
# process_natural_languageArguments ... Field required", as patched versions answered on
# 2026-11-27), its low-level server with jsonschema's ("Input validation error: 'url' is a
# required property", mcp/server/lowlevel/server.py in mcp 1.30.0), and the TypeScript SDK with
# its invalid-params error ("MCP error -32602: Input validation error: Invalid arguments for tool
# git_clone: ... received undefined at url", as a patched version answered on 2026-11-27; up to
# 1.20.0 the same error has no "Input validation error: " prefix).
SDK_ARGUMENT_VALIDATION_MARKERS: tuple[tuple[re.Pattern[str], ...], ...] = (
    (re.compile(r"validation errors? for \w+Arguments"), re.compile(r"Field required")),
    (re.compile(r"Input validation error: "), re.compile(r"'[^']+' is a required property")),
    (re.compile(r"-32602"), re.compile(r"Invalid arguments for tool")),
)


def is_argument_validation_error(response: AnsweredCall) -> bool:
    return response.is_error and any(
        all(marker.search(response.content) for marker in markers)
        for markers in SDK_ARGUMENT_VALIDATION_MARKERS
    )


class DeclaredTool(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def input_schema(self) -> Mapping[str, Any]: ...


def required_arguments(tools: Sequence[DeclaredTool]) -> dict[str, frozenset[str]]:
    """Each listed tool's arguments that its inputSchema marks required."""
    # A schema may spell "required": null, as one server does for its argument-less tools.
    return {tool.name: frozenset(tool.input_schema.get("required") or ()) for tool in tools}
