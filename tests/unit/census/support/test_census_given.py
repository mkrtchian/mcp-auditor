from collections.abc import Callable
from datetime import timedelta
from typing import Any

from evals.cve.census.census import BOUND, CLASSIFIERS, Census, CensusFlaw
from evals.cve.census.classification import Classification, Criterion
from evals.cve.census.figures import Share
from evals.cve.census.grouping import READERS, ProofJudgment
from tests.unit.support.censuses import (
    FLAW_WITH_A_CVE,
    GHSA_ONLY_FLAW,
    ITS_GHSA,
    OSV_ONLY_FLAW,
    a_classification,
    a_judgment,
    recomputed,
)

SHARED_ID = "GO-2025-0001"


# Each defect below breaks one rule of `load_census` and keeps every derived part
# (figures, date mismatches) recomputed, so the census carries that defect alone.


def with_a_non_canonical_identifier(census: Census) -> Census:
    def renamed(own: list[Classification]) -> list[Classification]:
        return [
            each.model_copy(update={"flaw": ITS_GHSA}) if each.flaw == FLAW_WITH_A_CVE else each
            for each in own
        ]

    census = _with_flaw(census, FLAW_WITH_A_CVE, identifier=ITS_GHSA)
    for classifier in CLASSIFIERS:
        census = _with_classifications(census, classifier, renamed)
    return recomputed(census)


def with_a_wrong_disclosure_date(census: Census) -> Census:
    flaw = _flaw(census, GHSA_ONLY_FLAW)
    return recomputed(
        _with_flaw(census, GHSA_ONLY_FLAW, disclosure_date=flaw.disclosure_date + timedelta(days=1))
    )


def with_a_duplicate_identifier(census: Census) -> Census:
    duplicate = _flaw(census, OSV_ONLY_FLAW).model_copy(update={"ids": ["PYSEC-2025-2"]})
    return census.model_copy(update={"flaws": [*census.flaws, duplicate]})


def with_two_flaws_sharing_an_id(census: Census) -> Census:
    for identifier in (OSV_ONLY_FLAW, GHSA_ONLY_FLAW):
        census = _with_flaw(census, identifier, ids=[*_flaw(census, identifier).ids, SHARED_ID])
    return census


def with_a_hit_decision_without_reason(census: Census) -> Census:
    hits = [census.hits[0].model_copy(update={"reason": "  "}), *census.hits[1:]]
    return census.model_copy(update={"hits": hits})


def with_a_flaw_missing_from_one_classifier(census: Census) -> Census:
    return _with_classifications(
        census, CLASSIFIERS[1], lambda own: [each for each in own if each.flaw != OSV_ONLY_FLAW]
    )


def with_a_flaw_classified_twice(census: Census) -> Census:
    return _with_classifications(census, CLASSIFIERS[0], lambda own: [*own, own[0]])


def with_a_classification_of_an_unknown_flaw(census: Census) -> Census:
    unknown = a_classification(flaw="CVE-2099-0001")
    return _with_classifications(census, CLASSIFIERS[0], lambda own: [*own, unknown])


def with_three_classifiers(census: Census) -> Census:
    third = {"classifier_3": census.classifications[CLASSIFIERS[0]]}
    return census.model_copy(update={"classifications": census.classifications | third})


def with_an_inconsistent_first_failed_criterion(census: Census) -> Census:
    def stdio_tools_call_marked_failed(own: list[Classification]) -> list[Classification]:
        failed = {"first_failed_criterion": Criterion.STDIO_TOOLS_CALL}
        return [own[0].model_copy(update=failed), *own[1:]]

    return recomputed(_with_classifications(census, CLASSIFIERS[0], stdio_tools_call_marked_failed))


def with_a_flaw_disclosed_after_the_bound(census: Census) -> Census:
    late = BOUND + timedelta(days=1)
    flaw = _flaw(census, GHSA_ONLY_FLAW)
    records = [record.model_copy(update={"published": late}) for record in flaw.records]
    moved = _with_flaw(census, GHSA_ONLY_FLAW, records=records, disclosure_date=late)
    return recomputed(moved)


def with_stale_figures(census: Census) -> Census:
    stale = census.figures.model_copy(update={"reachable": Share(count=0, denominator=3)})
    return census.model_copy(update={"figures": stale})


def with_a_reader_missing_a_grouped_flaw(census: Census) -> Census:
    return recomputed(_with_groupings(census, READERS[1], lambda own: []))


def with_a_reader_grouping_a_flaw_outside_the_population(census: Census) -> Census:
    extra = a_judgment(FLAW_WITH_A_CVE)
    return recomputed(_with_groupings(census, READERS[0], lambda own: [*own, extra]))


def with_a_flaw_grouped_twice(census: Census) -> Census:
    return recomputed(_with_groupings(census, READERS[0], lambda own: [*own, own[0]]))


def with_a_judgment_without_a_reason(census: Census) -> Census:
    return _with_groupings(
        census, READERS[0], lambda own: [own[0].model_copy(update={"reason": " "}), *own[1:]]
    )


def with_three_readers(census: Census) -> Census:
    third = {"reader_3": census.groupings[READERS[0]]}
    return recomputed(census.model_copy(update={"groupings": census.groupings | third}))


def with_a_reader_without_an_agent_record(census: Census) -> Census:
    agents = [agent for agent in census.agents if agent.scope != READERS[1]]
    return census.model_copy(update={"agents": agents})


def with_a_stale_known_gap(census: Census) -> Census:
    stale = {reader: Share(count=0, denominator=1) for reader in READERS}
    return census.model_copy(update={"known_gap": stale})


def with_stale_date_mismatches(census: Census) -> Census:
    return with_a_classifier_date_differing_from_the_computed_one(census).model_copy(
        update={"date_mismatches": []}
    )


def with_a_classifier_date_differing_from_the_computed_one(
    census: Census,
) -> Census:
    def one_day_late(own: list[Classification]) -> list[Classification]:
        late = own[0].disclosure_date + timedelta(days=1)
        return [own[0].model_copy(update={"disclosure_date": late}), *own[1:]]

    return recomputed(_with_classifications(census, CLASSIFIERS[1], one_day_late))


def _flaw(census: Census, identifier: str) -> CensusFlaw:
    return next(flaw for flaw in census.flaws if flaw.identifier == identifier)


def _with_flaw(census: Census, changed: str, **changes: Any) -> Census:
    flaws = [
        flaw.model_copy(update=changes) if flaw.identifier == changed else flaw
        for flaw in census.flaws
    ]
    return census.model_copy(update={"flaws": flaws})


def _with_classifications(
    census: Census,
    classifier: str,
    change: Callable[[list[Classification]], list[Classification]],
) -> Census:
    classifications = census.classifications | {
        classifier: change(census.classifications[classifier])
    }
    return census.model_copy(update={"classifications": classifications})


def _with_groupings(
    census: Census,
    reader: str,
    change: Callable[[list[ProofJudgment]], list[ProofJudgment]],
) -> Census:
    groupings = census.groupings | {reader: change(census.groupings[reader])}
    return census.model_copy(update={"groupings": groupings})
