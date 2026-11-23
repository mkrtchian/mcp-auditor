from evals.cve.places import Coordinates, LayoutAnchor, Place, PlaceKind, Places


def a_fictional_places() -> Places:
    """One place per catalogue reach the sweeping exploits read: a command-execution file and
    env for the kubernetes sweep, an internal-fetch endpoint for the SSRF sweep. The layout
    exploits read the frozen /srv constants, not these records."""
    return {
        "fict-file": Place(
            id="fict-file",
            family="fictional",
            reaches=frozenset({"arbitrary_read", "command_execution"}),
            kind=PlaceKind.FILE,
            coordinates=Coordinates(PlaceKind.FILE, path="/etc/fict-secret"),
        ),
        "fict-env": Place(
            id="fict-env",
            family="fictional",
            reaches=frozenset({"command_execution"}),
            kind=PlaceKind.ENV,
            coordinates=Coordinates(PlaceKind.ENV, name="FICT_SECRET"),
        ),
        "fict-endpoint": Place(
            id="fict-endpoint",
            family="fictional",
            reaches=frozenset({"internal_fetch"}),
            kind=PlaceKind.HTTP_ENDPOINT,
            coordinates=Coordinates(PlaceKind.HTTP_ENDPOINT, host="169.254.169.254", path="/fict"),
        ),
    }


def a_layout_place(
    place_id: str, anchor: LayoutAnchor, kind: PlaceKind, relpath: str = "config"
) -> Place:
    return Place(
        id=place_id,
        family="deployment layout",
        reaches=frozenset({"arbitrary_read"}),
        kind=kind,
        coordinates=Coordinates(kind, anchor=anchor, relpath=relpath),
    )


def a_catalogue_place() -> Place:
    return Place(
        id="etc-shadow",
        family="fictional",
        reaches=frozenset({"arbitrary_read"}),
        kind=PlaceKind.FILE,
        coordinates=Coordinates(PlaceKind.FILE, path="/etc/shadow"),
    )
