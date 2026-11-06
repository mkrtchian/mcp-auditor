import re
from pathlib import Path

from evals.holdout_census import load_census
from evals.run_census import CENSUS_PATH


def the_census_drawn_identifiers() -> set[str]:
    draw = load_census(CENSUS_PATH).draw
    assert draw is not None, "the committed census carries no draw"
    return set(draw.drawn)


_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----\n", re.DOTALL)


def the_authority_inlined_in(dockerfile: Path) -> str:
    certificates = _CERTIFICATE.findall(dockerfile.read_text())
    assert len(certificates) == 1, f"{dockerfile.name} inlines {len(certificates)} certificates"
    return certificates[0]
