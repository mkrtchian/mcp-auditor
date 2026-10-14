"""The discovery-route check (ADR 031 condition 2).

Per target and per kept layout place, whether the anchor the place hangs off is revealed by the
server's own outputs under the run conditions: the scope the layout dictates, a response or an
error that names the place's path, or a location relation the place's plant kind documents from
the scope. Never by a planted file and never by a path the route procedure itself fills into the
arguments (rule v5: the scope and a documented default count as route, a path the procedure sent
does not, since the grammar does not credit a proof copied from the arguments, ADR 029).

`minimal_calls` fixes the route procedure (holdout-rule.md:157): every tool the target exposes,
in the order `tools/list` returns, called once with the minimal arguments its schema requires,
the filling policy the same for every target. `route_observations` is the Docker collector that
runs it, exercised by the maintainer like calibration.

A catalogue place carries no anchor and is on the route by construction (ADR 029 chose it as a
place an attacker probes), so `route_admits` admits it unconditionally. A layout place is admitted
only when its anchor path is among the paths the observations reveal. `route_admits` is a pure
function over the collected observations, pinned by a golden master, so a typo cannot silently
open a version.
"""

import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

from evals.cve_environments import Launch
from evals.cve_layout import ANCHOR_PATHS
from evals.cve_places import Place, PlantKind
from evals.cve_targets import CVETarget
from mcp_auditor.domain.models import ToolDefinition
from mcp_auditor.domain.ports import MCPClientPort

# An absolute path mentioned in a server output (a listing, an error, the clone's origin record).
_ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9._][A-Za-z0-9._/-]*")
# A string property whose name denotes a filesystem path (path, repo_path, directory, file_name).
_PATH_NAME = re.compile(r"path|dir|file", re.IGNORECASE)
_MINIMAL_STRING = ""  # the minimal filler for a required non-path string (command, url, revision)


@dataclass(frozen=True)
class RouteObservations:
    launch_command: tuple[str, ...]  # the full launch argv, recorded for the fixture fingerprint
    scope: str | None  # the scope the layout dictates, read from Launch.scope, not scanned here
    tool_names: tuple[str, ...]  # tools/list, in order
    responses: tuple[str, ...]  # the body of each tool called at minimal arguments (error or not)
    call_errored: tuple[bool, ...]  # per call, whether it returned an error
    tools_list_succeeded: bool  # whether tools/list itself returned


def route_admits(place: Place, observations: RouteObservations) -> bool:
    anchor = place.coordinates.anchor
    if anchor is None:
        return True  # a catalogue place is on the route by construction (ADR 029)
    return ANCHOR_PATHS[anchor] in _revealed_paths(place, observations)


def _revealed_paths(place: Place, observations: RouteObservations) -> set[str]:
    revealed: set[str] = set()
    if observations.scope:
        revealed.add(_normalise(observations.scope))
    for body in observations.responses:
        revealed.update(_normalise(match) for match in _ABSOLUTE_PATH.findall(body))
    revealed |= _documented_default(place, observations.scope)
    return revealed


def _documented_default(place: Place, scope: str | None) -> set[str]:
    """A location the place's plant kind documents relative to the scope. Only the dotenv kind
    carries one: find_dotenv searches increasingly higher folders, so the parent of the working
    directory is the documented default for a workspace .env (holdout-rule.md:171). No other kind
    documents a relation, so the bare's <project>.git sibling placement, a convention of our
    layout rather than a location the git documentation fixes relative to a checkout, is never
    derived."""
    if place.kind is PlantKind.DOTENV and scope:
        parent = posixpath.dirname(_normalise(scope))
        if parent not in ("", "/"):
            return {parent}
    return set()


def _normalise(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


async def route_observations(
    target: CVETarget, client: MCPClientPort, launch: Launch
) -> RouteObservations:
    tools = await client.list_tools()
    responses: list[str] = []
    errored: list[bool] = []
    for name, args in minimal_calls(tools, target.tools_filter, launch.scope):
        response = await client.call_tool(name, args)
        responses.append(response.content)
        errored.append(response.is_error)
    return RouteObservations(
        launch_command=tuple(launch.args),
        scope=launch.scope,
        tool_names=tuple(tool.name for tool in tools),
        responses=tuple(responses),
        call_errored=tuple(errored),
        tools_list_succeeded=True,
    )


def minimal_calls(
    tools: Sequence[ToolDefinition],
    tools_filter: frozenset[str] | None,
    scope: str | None,
) -> list[tuple[str, dict[str, Any]]]:
    """The rule's route procedure (holdout-rule.md:157): every tool the target exposes, in the
    order tools/list returns, called once with the minimal arguments its schema requires. The
    exposed tools are those under the target's filter, or all of them when it sets none (the
    holdout sets no filter, holdout-rule.md:192). Arguments are filled by JSON type and `required`,
    the same policy for every target, never by tool name."""
    selected = (tool for tool in tools if tools_filter is None or tool.name in tools_filter)
    return [(tool.name, _minimal_arguments(tool, scope)) for tool in selected]


def _minimal_arguments(tool: ToolDefinition, scope: str | None) -> dict[str, Any]:
    schema = tool.input_schema
    properties = cast(dict[str, Any], schema.get("properties", {}))
    required = cast(list[str], schema.get("required", []))
    return {
        name: _filler(name, cast(dict[str, Any], properties.get(name, {})), scope)
        for name in required
    }


def _filler(name: str, spec: dict[str, Any], scope: str | None) -> Any:
    json_type = spec.get("type")
    if json_type == "array":
        return []
    if json_type == "object":
        return {}
    if json_type in ("integer", "number"):
        return 0
    if json_type == "boolean":
        return False
    if json_type == "string" and _PATH_NAME.search(name):
        return _in_scope_probe(scope)
    return _MINIMAL_STRING


def _in_scope_probe(scope: str | None) -> str:
    # The in-scope checkout's VCS config, the first in-scope artifact an attacker reads (ADR 029):
    # it names the bare as origin, which is what reveals the bare for a filesystem server. Always
    # in scope, never a planted place. With no scope, a minimal relative placeholder.
    return f"{_normalise(scope)}/.git/config" if scope else "."
