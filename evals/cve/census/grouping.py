"""The grouping by proof of the census, and the known gap it gives.

Two readers judge, each on its own, how the effect of each flaw the rule gives them could be
proven in a tool response, and group the flaws by that proof. The flaws a reader places in
`NO_PROOF_GROUP` are the known gap as that reader finds it (ADR 029). A flaw
meets a criterion when either classifier finds that it does, so it falls outside the grammar
only when both place it there.
"""

from collections import defaultdict
from collections.abc import Sequence

from pydantic import BaseModel

from evals.cve.census.classification import Classification, Criterion, met_by_either_classifier
from evals.cve.census.exclusions import ACCEPTANCE_TARGET_FLAWS, EXCLUDED_SERVERS
from evals.cve.census.figures import Share

READERS = ("reader_1", "reader_2")
NO_PROOF_GROUP = "no_proof_in_tool_output"

# The criteria of eligibility an advisory can check (detection suite rule, Eligibility).
# Criterion.GRAMMAR_CLASS left them with detection suite rule v4.
DRAW_ORDER_CRITERIA = (
    Criterion.MCP_SERVER,
    Criterion.STDIO_TOOLS_CALL,
    Criterion.EFFECT_IN_TOOL_RESPONSE,
    Criterion.PINNABLE,
)


class ProofJudgment(BaseModel):
    flaw: str
    group: str
    proof: str
    reason: str


def grouped_flaws(
    classifications: dict[str, list[Classification]], candidates: set[str]
) -> set[str]:
    seen = _by_flaw(classifications)
    return {
        flaw
        for flaw in gap_population(classifications, candidates)
        if not met_by_either_classifier(seen[flaw], Criterion.GRAMMAR_CLASS)
    }


def gap_population(
    classifications: dict[str, list[Classification]], candidates: set[str]
) -> set[str]:
    """The flaws of `candidates` that meet the criteria of the draw order and whose server
    either classifier finds able to run in a container: the denominator of the known gap."""
    seen = _by_flaw(classifications)
    return {
        flaw
        for flaw in draw_order_flaws(classifications, candidates)
        if any(classification.runs_in_container for classification in seen[flaw])
    }


def draw_order_flaws(
    classifications: dict[str, list[Classification]], candidates: set[str]
) -> set[str]:
    """The flaws of `candidates` that meet the draw-order criteria, the runs-in-container
    criterion aside: a flaw of a server judged unable to run in a container is still drawn and
    calibrated."""
    return {
        flaw
        for flaw, seen in _by_flaw(classifications).items()
        if flaw in candidates and _in_draw_order(flaw, seen)
    }


def known_gap(groupings: dict[str, list[ProofJudgment]], population: set[str]) -> dict[str, Share]:
    """A flaw either classifier places in the grammar counts outside the gap without being
    read, so each share is a lower bound."""
    return {
        reader: Share(
            count=sum(
                judgment.group == NO_PROOF_GROUP and judgment.flaw in population for judgment in own
            ),
            denominator=len(population),
        )
        for reader, own in groupings.items()
    }


def _by_flaw(classifications: dict[str, list[Classification]]) -> dict[str, list[Classification]]:
    seen: defaultdict[str, list[Classification]] = defaultdict(list)
    for own in classifications.values():
        for classification in own:
            seen[classification.flaw].append(classification)
    return seen


def _in_draw_order(flaw: str, seen: Sequence[Classification]) -> bool:
    return (
        flaw not in ACCEPTANCE_TARGET_FLAWS
        and all(met_by_either_classifier(seen, criterion) for criterion in DRAW_ORDER_CRITERIA)
        and any(classification.server_package not in EXCLUDED_SERVERS for classification in seen)
    )
