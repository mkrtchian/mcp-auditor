from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_census_identity_given as identity
from evals.census_classification import Classification, Criterion
from evals.census_figures import Share, compute_figures
from evals.census_identity import merge
from evals.census_prefilter import INITIAL_TERMS
from evals.census_sources import AdvisoryRecord, SourceFile, SourceName, SourceProvenance
from evals.census_work import AgentRecord, AgentRole, HitDecision, VulnerableMcpEntry
from evals.holdout_census import (
    BOUND,
    CLASSIFIERS,
    CensusFlaw,
    Discovery,
    HoldoutCensus,
    TermHits,
    census_flaw,
    date_mismatches,
)

FLAW_WITH_A_CVE = "CVE-2025-0001"
ITS_GHSA = "GHSA-aaaa-bbbb-cccc"
GHSA_ONLY_FLAW = "GHSA-dddd-eeee-ffff"
OSV_ONLY_FLAW = "PYSEC-2025-1"
SHARED_ID = "GO-2025-0001"


def a_census() -> HoldoutCensus:
    flaws = [
        census_flaw(flaw, [Discovery.PREFILTER])
        for flaw in merge(
            [
                identity.a_ghsa(ITS_GHSA, FLAW_WITH_A_CVE),
                identity.an_nvd(FLAW_WITH_A_CVE),
                identity.a_ghsa(GHSA_ONLY_FLAW),
                identity.an_osv(OSV_ONLY_FLAW),
            ],
            recorded={},
        )
    ]
    dates = {flaw.identifier: flaw.disclosure_date for flaw in flaws}
    classifications = {
        classifier: [
            figures.a_classification(flaw=flaw, disclosure_date=disclosed)
            for flaw, disclosed in dates.items()
        ]
        for classifier in CLASSIFIERS
    }
    return HoldoutCensus(
        sources=_provenance(),
        agents=[AgentRecord(role=AgentRole.COLLECTOR, scope="ghsa", model="claude-opus-5-5")],
        prefilter=[TermHits(term=term, hit_count=2) for term in INITIAL_TERMS],
        hits=[_a_hit(ITS_GHSA), _a_hit(GHSA_ONLY_FLAW)],
        flaws=flaws,
        vulnerablemcp=[
            VulnerableMcpEntry(cve_id=FLAW_WITH_A_CVE, listed=date(2025, 7, 3), found=True)
        ],
        classifications=classifications,
        date_mismatches=[],
        figures=compute_figures(classifications, dates, withdrawn=set()),
    )


def written(tmp_path: Path, census: HoldoutCensus) -> Path:
    path = tmp_path / "holdout_census.json"
    path.write_text(census.model_dump_json(indent=2))
    return path


def a_flaw_with_records(*records: AdvisoryRecord) -> CensusFlaw:
    [flaw] = merge(records, recorded={})
    return census_flaw(flaw, [Discovery.PREFILTER])


# Each defect below breaks one rule of `load_census` and keeps every derived part
# (figures, date mismatches) recomputed, so the census carries that defect alone.


def with_a_non_canonical_identifier(census: HoldoutCensus) -> HoldoutCensus:
    def renamed(own: list[Classification]) -> list[Classification]:
        return [
            each.model_copy(update={"flaw": ITS_GHSA}) if each.flaw == FLAW_WITH_A_CVE else each
            for each in own
        ]

    census = _with_flaw(census, FLAW_WITH_A_CVE, identifier=ITS_GHSA)
    for classifier in CLASSIFIERS:
        census = _with_classifications(census, classifier, renamed)
    return _recomputed(census)


def with_a_wrong_disclosure_date(census: HoldoutCensus) -> HoldoutCensus:
    flaw = _flaw(census, GHSA_ONLY_FLAW)
    return _with_flaw(
        census, GHSA_ONLY_FLAW, disclosure_date=flaw.disclosure_date + timedelta(days=1)
    )


def with_a_duplicate_identifier(census: HoldoutCensus) -> HoldoutCensus:
    duplicate = _flaw(census, OSV_ONLY_FLAW).model_copy(update={"ids": ["PYSEC-2025-2"]})
    return census.model_copy(update={"flaws": [*census.flaws, duplicate]})


def with_two_flaws_sharing_an_id(census: HoldoutCensus) -> HoldoutCensus:
    for identifier in (OSV_ONLY_FLAW, GHSA_ONLY_FLAW):
        census = _with_flaw(census, identifier, ids=[*_flaw(census, identifier).ids, SHARED_ID])
    return census


def with_a_hit_decision_without_reason(census: HoldoutCensus) -> HoldoutCensus:
    hits = [census.hits[0].model_copy(update={"reason": "  "}), *census.hits[1:]]
    return census.model_copy(update={"hits": hits})


def with_a_flaw_missing_from_one_classifier(census: HoldoutCensus) -> HoldoutCensus:
    return _with_classifications(
        census, CLASSIFIERS[1], lambda own: [each for each in own if each.flaw != OSV_ONLY_FLAW]
    )


def with_a_flaw_classified_twice(census: HoldoutCensus) -> HoldoutCensus:
    return _with_classifications(census, CLASSIFIERS[0], lambda own: [*own, own[0]])


def with_a_classification_of_an_unknown_flaw(census: HoldoutCensus) -> HoldoutCensus:
    unknown = figures.a_classification(flaw="CVE-2099-0001")
    return _with_classifications(census, CLASSIFIERS[0], lambda own: [*own, unknown])


def with_three_classifiers(census: HoldoutCensus) -> HoldoutCensus:
    third = {"classifier_3": census.classifications[CLASSIFIERS[0]]}
    return census.model_copy(update={"classifications": census.classifications | third})


def with_an_inconsistent_first_failed_criterion(census: HoldoutCensus) -> HoldoutCensus:
    def stdio_tools_call_marked_failed(own: list[Classification]) -> list[Classification]:
        failed = {"first_failed_criterion": Criterion.STDIO_TOOLS_CALL}
        return [own[0].model_copy(update=failed), *own[1:]]

    return _recomputed(
        _with_classifications(census, CLASSIFIERS[0], stdio_tools_call_marked_failed)
    )


def with_a_flaw_disclosed_after_the_bound(census: HoldoutCensus) -> HoldoutCensus:
    late = BOUND + timedelta(days=1)
    flaw = _flaw(census, GHSA_ONLY_FLAW)
    records = [record.model_copy(update={"published": late}) for record in flaw.records]
    moved = _with_flaw(census, GHSA_ONLY_FLAW, records=records, disclosure_date=late)
    return _recomputed(moved)


def with_stale_figures(census: HoldoutCensus) -> HoldoutCensus:
    stale = census.figures.model_copy(update={"reachable": Share(count=0, denominator=3)})
    return census.model_copy(update={"figures": stale})


def with_a_classifier_date_differing_from_the_computed_one(
    census: HoldoutCensus,
) -> HoldoutCensus:
    def one_day_late(own: list[Classification]) -> list[Classification]:
        late = own[0].disclosure_date + timedelta(days=1)
        return [own[0].model_copy(update={"disclosure_date": late}), *own[1:]]

    return _recomputed(_with_classifications(census, CLASSIFIERS[1], one_day_late))


def with_stale_date_mismatches(census: HoldoutCensus) -> HoldoutCensus:
    return with_a_classifier_date_differing_from_the_computed_one(census).model_copy(
        update={"date_mismatches": []}
    )


def _recomputed(census: HoldoutCensus) -> HoldoutCensus:
    dates = {flaw.identifier: flaw.disclosure_date for flaw in census.flaws}
    withdrawn = {flaw.identifier for flaw in census.flaws if flaw.withdrawn}
    return census.model_copy(
        update={
            "figures": compute_figures(census.classifications, dates, withdrawn),
            "date_mismatches": date_mismatches(census.classifications, dates),
        }
    )


def _flaw(census: HoldoutCensus, identifier: str) -> CensusFlaw:
    return next(flaw for flaw in census.flaws if flaw.identifier == identifier)


def _with_flaw(census: HoldoutCensus, changed: str, **changes: Any) -> HoldoutCensus:
    flaws = [
        flaw.model_copy(update=changes) if flaw.identifier == changed else flaw
        for flaw in census.flaws
    ]
    return census.model_copy(update={"flaws": flaws})


def _with_classifications(
    census: HoldoutCensus,
    classifier: str,
    change: Callable[[list[Classification]], list[Classification]],
) -> HoldoutCensus:
    classifications = census.classifications | {
        classifier: change(census.classifications[classifier])
    }
    return census.model_copy(update={"classifications": classifications})


def _a_hit(source_id: str) -> HitDecision:
    return HitDecision(
        source=SourceName.GHSA,
        source_id=source_id,
        decision="keep",
        software_kind=figures.a_classification().software_kind,
        reason="A filesystem MCP server.",
        agent="ghsa collector",
    )


def _provenance() -> SourceProvenance:
    a_file = SourceFile(name="all.zip", downloaded=date(2026, 10, 8), sha256="0" * 64)
    return SourceProvenance(
        ghsa_commit="1" * 40,
        nvd_feeds=[a_file.model_copy(update={"name": "nvdcve-2.0-2025.json.gz"})],
        osv_export=a_file,
    )
