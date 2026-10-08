"""Figures of the holdout census, recomputed from its classifications.

A flaw meets a criterion under the rule when either classifier finds that it does, so it
falls outside the grammar only when both place it there. The breakdowns are never merged:
each classifier's are taken over the flaws that classifier finds to be MCP server flaws.
Withdrawn flaws count in the agreement only.
"""

from collections import Counter
from collections.abc import Callable, Iterable
from datetime import date

from pydantic import BaseModel

from evals.census_classification import (
    Classification,
    Criterion,
    criteria_met,
    in_grammar,
    normalized_class,
)

type Pair = tuple[Classification, Classification]

_COMPARED_FIELDS = [name for name in Classification.model_fields if name != "flaw"]


class Share(BaseModel):
    count: int
    denominator: int


class Breakdown(BaseModel):
    by_transport: dict[str, Share]
    by_primitive: dict[str, Share]
    by_effect_class: dict[str, Share]
    effect_not_in_tool_response: Share


class CensusFigures(BaseModel):
    agreement: dict[str, Share]
    effect_class_name_agreement: Share
    effect_class_membership_agreement: Share
    reachable: Share
    grammar_covered: Share
    breakdowns: dict[str, Breakdown]
    monthly_counts: dict[str, int]


def compute_figures(
    classifications: dict[str, list[Classification]],
    disclosure_dates: dict[str, date],
    withdrawn: set[str],
) -> CensusFigures:
    pairs = _pairs(classifications)
    published = [pair for pair in pairs if pair[0].flaw not in withdrawn]
    servers = [pair for pair in published if _met_under_rule(pair, Criterion.MCP_SERVER)]
    reachable = [pair for pair in servers if _reachable(pair)]
    return CensusFigures(
        agreement={field: _agreement(pairs, _field(field)) for field in _COMPARED_FIELDS},
        effect_class_name_agreement=_agreement(pairs, _class_name),
        effect_class_membership_agreement=_agreement(pairs, _grammar_membership),
        reachable=_share(len(reachable), len(servers)),
        grammar_covered=_share(
            sum(_met_under_rule(pair, Criterion.GRAMMAR_CLASS) for pair in reachable),
            len(reachable),
        ),
        breakdowns={
            classifier: _breakdown(own, withdrawn) for classifier, own in classifications.items()
        },
        monthly_counts=_monthly_counts(servers, disclosure_dates),
    )


def _pairs(classifications: dict[str, list[Classification]]) -> list[Pair]:
    first, second = classifications.values()
    second_by_flaw = {classification.flaw: classification for classification in second}
    return [(classification, second_by_flaw[classification.flaw]) for classification in first]


def _met_under_rule(pair: Pair, criterion: Criterion) -> bool:
    return any(criteria_met(classification)[criterion] for classification in pair)


def _reachable(pair: Pair) -> bool:
    return _met_under_rule(pair, Criterion.STDIO_TOOLS_CALL) and _met_under_rule(
        pair, Criterion.EFFECT_IN_TOOL_RESPONSE
    )


def _agreement(pairs: list[Pair], value: Callable[[Classification], object]) -> Share:
    return _share(sum(value(first) == value(second) for first, second in pairs), len(pairs))


def _field(name: str) -> Callable[[Classification], object]:
    return lambda classification: getattr(classification, name)


def _class_name(classification: Classification) -> str:
    return normalized_class(classification.effect_class)


def _grammar_membership(classification: Classification) -> str | None:
    name = classification.effect_class
    return normalized_class(name) if in_grammar(name) else None


def _breakdown(classifications: list[Classification], withdrawn: set[str]) -> Breakdown:
    servers = [
        classification
        for classification in classifications
        if classification.flaw not in withdrawn
        and criteria_met(classification)[Criterion.MCP_SERVER]
    ]
    return Breakdown(
        by_transport=_shares_by(str(server.transport) for server in servers),
        by_primitive=_shares_by(str(server.primitive) for server in servers),
        by_effect_class=_shares_by(server.effect_class for server in servers),
        effect_not_in_tool_response=_share(
            sum(not server.effect_in_tool_response for server in servers), len(servers)
        ),
    )


def _shares_by(values: Iterable[str]) -> dict[str, Share]:
    counts = Counter(values)
    total = counts.total()
    return {value: _share(count, total) for value, count in sorted(counts.items())}


def _monthly_counts(servers: list[Pair], disclosure_dates: dict[str, date]) -> dict[str, int]:
    months = Counter(disclosure_dates[first.flaw].strftime("%Y-%m") for first, _ in servers)
    return dict(sorted(months.items()))


def _share(count: int, denominator: int) -> Share:
    return Share(count=count, denominator=denominator)
