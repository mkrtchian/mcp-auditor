"""The draw-time schema of the holdout census.

Step 1 holds only the side of a flaw on the draw cutoff; the draw record and the calibration
cards follow. This module imports nothing from holdout_draw or holdout_census, so both can
import Side from it with no cycle.
"""

from datetime import date
from enum import StrEnum


class Side(StrEnum):
    PRE_CUTOFF = "pre_cutoff"
    POST_CUTOFF = "post_cutoff"


def side_of(disclosure_date: date, cutoff: date) -> Side:
    return Side.PRE_CUTOFF if disclosure_date <= cutoff else Side.POST_CUTOFF
