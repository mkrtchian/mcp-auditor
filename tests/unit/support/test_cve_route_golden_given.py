"""The golden master of the discovery-route check: what `route_admits` returns on a fixed corpus
of (place, observations) cases, recorded in `cve_route_golden.json`.

The corpus is fictional: a layout place against observations that reveal its anchor (the scope,
the scope's workspace parent, the clone's origin record in a disclosure) and against observations
that reveal nothing, plus a catalogue place that is on the route by construction. Regenerate only
in a commit that changes what `route_admits` grades, never on a refactor:

    uv run python -m tests.unit.support.test_cve_route_golden_given
"""

import json
from pathlib import Path

from evals.cve_places import Coordinates, LayoutAnchor, Place, PlantKind
from evals.cve_route import RouteObservations, route_admits

GOLDEN_PATH = Path(__file__).parent / "cve_route_golden.json"

# A git server scoped on /srv/app: the scope reveals /srv/app and its parent /srv, and the
# checkout's .git/config disclosure names /srv/app.git as the origin.
_SCOPED = RouteObservations(
    launch_command=("run", "--rm", "image", "/srv/app"),
    tool_names=("list_directory", "read_file"),
    responses=("leak0\nleak7\n", '[remote "origin"]\n\turl = /srv/app.git\n'),
)
# A kubernetes server with no filesystem scope: nothing names a layout anchor.
_NO_SCOPE = RouteObservations(
    launch_command=("run", "--rm", "image"),
    tool_names=("kubectl_generic",),
    responses=("Client Version: v1.30.0\n",),
)


def _layout_place(place_id: str, anchor: LayoutAnchor, relpath: str, kind: PlantKind) -> Place:
    return Place(
        id=place_id,
        family="deployment layout",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=kind,
        coordinates=Coordinates(kind, anchor=anchor, relpath=relpath),
    )


def _catalogue_place() -> Place:
    return Place(
        id="etc-shadow",
        family="fictional",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path="/etc/shadow"),
    )


def _cases() -> dict[str, tuple[Place, RouteObservations]]:
    bare_url = _layout_place(
        "bare-remote-url", LayoutAnchor.PROJECT_BARE, "config", PlantKind.GIT_REMOTE_URL
    )
    history = _layout_place(
        "bare-history-env", LayoutAnchor.PROJECT_BARE, ".env", PlantKind.GIT_HISTORY
    )
    dotenv = _layout_place("workspace-dotenv", LayoutAnchor.WORKSPACE, ".env", PlantKind.DOTENV)
    return {
        "bare_url_revealed_by_origin_record": (bare_url, _SCOPED),
        "history_env_revealed_by_origin_record": (history, _SCOPED),
        "workspace_dotenv_revealed_as_scope_parent": (dotenv, _SCOPED),
        "bare_url_refused_without_scope_or_disclosure": (bare_url, _NO_SCOPE),
        "workspace_dotenv_refused_without_scope": (dotenv, _NO_SCOPE),
        "catalogue_place_is_on_the_route": (_catalogue_place(), _NO_SCOPE),
    }


def golden_entries() -> dict[str, bool]:
    return {
        name: route_admits(place, observations) for name, (place, observations) in _cases().items()
    }


if __name__ == "__main__":
    GOLDEN_PATH.write_text(json.dumps(golden_entries(), indent=2, sort_keys=True) + "\n")
