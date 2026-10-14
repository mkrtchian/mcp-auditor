"""The discovery-route check (ADR 031 condition 2).

Per target and per kept layout place, whether the anchor the place hangs off is revealed by the
server's own outputs under the run conditions: its scope, a listing, an error, the clone's record
of its origin, or a documented default path relative to a location the server revealed. Never by a
planted file and never by a path the audit procedure itself puts in the arguments (rule v5 W2: the
scope argument and a documented default count as route, an option the agent itself sets does not).

A catalogue place carries no anchor and is on the route by construction (ADR 029 chose it as a
place an attacker probes), so `route_admits` admits it unconditionally. A layout place is admitted
only when its anchor path is among the paths the observations reveal. `route_admits` is a pure
function over the collected observations, pinned by a golden master, so a typo cannot silently open
a version. `route_observations` is the Docker collector, exercised by the maintainer like
calibration.
"""

import posixpath
import re
from dataclasses import dataclass
from typing import Any

from evals.cve_environments import Launch
from evals.cve_layout import ANCHOR_PATHS, PROJECT
from evals.cve_places import Place
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# An absolute path mentioned in a server output (a listing, an error, the clone's origin record).
_ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9._][A-Za-z0-9._/-]*")


@dataclass(frozen=True)
class RouteObservations:
    launch_command: tuple[str, ...]  # the scope argument and documented defaults count as route
    tool_names: tuple[str, ...]  # tools/list
    responses: tuple[str, ...]  # the bodies of the tools called at minimal arguments


def route_admits(place: Place, observations: RouteObservations) -> bool:
    anchor = place.coordinates.anchor
    if anchor is None:
        return True  # a catalogue place is on the route by construction (ADR 029)
    return ANCHOR_PATHS[anchor] in _revealed_paths(observations)


def _revealed_paths(observations: RouteObservations) -> set[str]:
    revealed: set[str] = set()
    for token in observations.launch_command:
        if token.startswith("/"):
            scope = _normalise(token)
            revealed.add(scope)
            parent = posixpath.dirname(
                scope
            )  # the workspace the scope sits in, a documented default
            if parent not in ("", "/"):
                revealed.add(parent)
    for body in observations.responses:
        revealed.update(_normalise(match) for match in _ABSOLUTE_PATH.findall(body))
    return revealed


def _normalise(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


async def route_observations(
    target: CVETarget, client: MCPClientPort, launch: Launch
) -> RouteObservations:
    tool_names = tuple(tool.name for tool in await client.list_tools())
    responses: list[str] = []
    for name, args in minimal_calls(target):
        responses.append((await client.call_tool(name, args)).content)
    return RouteObservations(tuple(launch.args), tool_names, tuple(responses))


def minimal_calls(target: CVETarget) -> list[tuple[str, dict[str, Any]]]:
    """The in-scope, non-mutating calls that reveal the routes: a listing of the checkout, the
    clone's origin record (a documented default relative to the revealed scope), a git log of the
    in-scope repo, a kubectl version or a public fetch. Keyed off the target's filtered tools so
    one helper feeds both the route observations and the layout surface."""
    tools = target.tools_filter or frozenset()
    calls: list[tuple[str, dict[str, Any]]] = []
    if "list_directory" in tools:
        calls.append(("list_directory", {"path": PROJECT}))
    if "read_file" in tools:
        calls.append(("read_file", {"path": f"{PROJECT}/.git/config"}))
    if "git_log" in tools:
        calls.append(("git_log", {"repo_path": PROJECT}))
    if "kubectl_generic" in tools:
        calls.append(("kubectl_generic", {"command": "version"}))
    if "fetch_txt" in tools:
        calls.append(("fetch_txt", {"url": "http://example.invalid/"}))
    return calls
