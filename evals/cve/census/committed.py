from pathlib import Path

from evals.cve.census.census import Census, load_census
from evals.eval_session import Refused


def committed_census(path: Path) -> Census:
    """Only the census load reads a ValueError as a refusal: a malformed census must not read as
    success, and a ValueError raised later is a crash."""
    try:
        return load_census(path)
    except ValueError as error:
        raise Refused("Refused: the census is malformed.", [str(error)]) from error
