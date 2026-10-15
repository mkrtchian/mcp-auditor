from typing import Any

import tests.unit.support.test_census_figures_given as figures
from evals.census_classification import Classification, Criterion
from evals.census_grouping import NO_PROOF_GROUP, ProofJudgment

OUTSIDE_THE_GRAMMAR: dict[str, Any] = {
    "effect_class": "authorization_bypass",
    "first_failed_criterion": Criterion.GRAMMAR_CLASS,
}
NO_CONTAINER: dict[str, Any] = {"runs_in_container": False}
NOT_PINNABLE: dict[str, Any] = {"pinnable": False, "first_failed_criterion": Criterion.PINNABLE}


def classified(
    *pairs: tuple[Classification, Classification],
) -> dict[str, list[Classification]]:
    return figures.a_census(*pairs).classifications


def outside_the_grammar(flaw: str, **fields: Any) -> tuple[Classification, Classification]:
    return figures.agreed(flaw, **(OUTSIDE_THE_GRAMMAR | fields))


def a_judgment(flaw: str, group: str = "authorization_bypass") -> ProofJudgment:
    return ProofJudgment(
        flaw=flaw,
        group=group,
        proof="A nonce planted in a record only the bypass returns.",
        reason="The tool returns the record it reads.",
    )


def no_proof(flaw: str) -> ProofJudgment:
    return a_judgment(flaw, group=NO_PROOF_GROUP)
