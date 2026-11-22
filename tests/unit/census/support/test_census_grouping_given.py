from typing import Any

from evals.cve.census.classification import Classification, Criterion
from tests.unit.census.support import classifier_pairs
from tests.unit.support.censuses import OUTSIDE_THE_GRAMMAR

NO_CONTAINER: dict[str, Any] = {"runs_in_container": False}
NOT_PINNABLE: dict[str, Any] = {"pinnable": False, "first_failed_criterion": Criterion.PINNABLE}


def classified(
    *pairs: tuple[Classification, Classification],
) -> dict[str, list[Classification]]:
    return classifier_pairs.census_parts(*pairs).classifications


def outside_the_grammar(flaw: str, **fields: Any) -> tuple[Classification, Classification]:
    return classifier_pairs.agreed(flaw, **(OUTSIDE_THE_GRAMMAR | fields))
