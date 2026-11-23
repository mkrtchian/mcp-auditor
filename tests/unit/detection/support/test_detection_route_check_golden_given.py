"""The golden master of the discovery-route check: what `has_route` returns on a fixed corpus
of (place, observations) cases, recorded in `detection_route_check_golden.json`.

The corpus is fictional: a layout place against observations that reveal its anchor (the scope,
the scope's workspace parent, the clone's origin record in a disclosure) and against observations
that reveal nothing, plus a catalogue place that is on the route by construction. Regenerate only
in a commit that changes what `has_route` grades, never on a refactor:

    uv run python -m tests.unit.detection.support.test_detection_route_check_golden_given
"""

import json
from pathlib import Path

from evals.cve.detection.route_check import RouteObservations, has_route
from evals.cve.places import LayoutAnchor, Place, PlaceKind
from tests.unit.detection.support.fictional_places import a_catalogue_place, a_layout_place

GOLDEN_PATH = Path(__file__).parent / "detection_route_check_golden.json"

# A filesystem server scoped on /srv/app: the scope names /srv/app, the dotenv kind documents its
# parent /srv, and the checkout's .git/config disclosure names /srv/app.git as the origin.
_SCOPED = RouteObservations(
    scope="/srv/app",
    responses=("archive0\narchive7\n", '[remote "origin"]\n\turl = /srv/app.git\n'),
    call_errored=(False, False),
    tools_list_succeeded=True,
)
# A kubernetes server with no filesystem scope: nothing names a layout anchor.
_NO_SCOPE = RouteObservations(
    scope=None,
    responses=("Client Version: v1.30.0\n",),
    call_errored=(False,),
    tools_list_succeeded=True,
)


def golden_entries() -> dict[str, bool]:
    return {
        name: has_route(place, observations) for name, (place, observations) in _cases().items()
    }


def _cases() -> dict[str, tuple[Place, RouteObservations]]:
    bare_url = a_layout_place(
        "bare-remote-url", LayoutAnchor.PROJECT_BARE, PlaceKind.GIT_REMOTE_URL
    )
    history = a_layout_place(
        "bare-history-env", LayoutAnchor.PROJECT_BARE, PlaceKind.GIT_HISTORY, relpath=".env"
    )
    dotenv = a_layout_place(
        "workspace-dotenv", LayoutAnchor.WORKSPACE, PlaceKind.DOTENV, relpath=".env"
    )
    return {
        "bare_url_revealed_by_origin_record": (bare_url, _SCOPED),
        "history_env_revealed_by_origin_record": (history, _SCOPED),
        "workspace_dotenv_revealed_as_scope_parent": (dotenv, _SCOPED),
        "bare_url_refused_without_scope_or_disclosure": (bare_url, _NO_SCOPE),
        "workspace_dotenv_refused_without_scope": (dotenv, _NO_SCOPE),
        "catalogue_place_is_on_the_route": (a_catalogue_place(), _NO_SCOPE),
    }


if __name__ == "__main__":
    GOLDEN_PATH.write_text(json.dumps(golden_entries(), indent=2, sort_keys=True) + "\n")
