# The one filesystem probe of the confined path: the mount policy decides which
# spellings matter, this resolves them.
from collections.abc import Iterable
from pathlib import Path


def existing_paths(spellings: Iterable[str]) -> dict[str, Path]:
    """Each spelling that exists on the host, mapped to its absolute resolved path.

    Relative spellings resolve against the working directory, and a missing one is
    omitted rather than reported.
    """
    resolved = {spelling: Path(spelling).resolve() for spelling in spellings}
    return {spelling: path for spelling, path in resolved.items() if path.exists()}
