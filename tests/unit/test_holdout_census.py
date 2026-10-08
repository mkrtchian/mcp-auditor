import re
from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest

import tests.unit.support.test_census_identity_given as identity
import tests.unit.support.test_holdout_census_given as given
from evals.census_work import HitDecision, read_jsonl
from evals.holdout_census import DateMismatch, HoldoutCensus, load_census


def test_a_well_formed_census_loads(tmp_path: Path):
    census = given.a_census()

    loaded = load_census(given.written(tmp_path, census))

    assert loaded == census


DEFECTS: list[tuple[Callable[[HoldoutCensus], HoldoutCensus], str]] = [
    (
        given.with_a_non_canonical_identifier,
        "flaw GHSA-aaaa-bbbb-cccc: its canonical identifier is CVE-2025-0001",
    ),
    (
        given.with_a_wrong_disclosure_date,
        "flaw GHSA-dddd-eeee-ffff: disclosure date 2025-06-11 is not the earliest published, "
        "2025-06-10",
    ),
    (given.with_a_duplicate_identifier, "identifier PYSEC-2025-1 appears 2 times"),
    (
        given.with_two_flaws_sharing_an_id,
        "ID GO-2025-0001 is shared by flaws GHSA-dddd-eeee-ffff, PYSEC-2025-1",
    ),
    (given.with_a_hit_decision_without_reason, "hit ghsa GHSA-aaaa-bbbb-cccc has no reason"),
    (
        given.with_a_flaw_missing_from_one_classifier,
        "classifier_2 does not classify flaw PYSEC-2025-1",
    ),
    (given.with_a_flaw_classified_twice, "classifier_1 classifies flaw CVE-2025-0001 2 times"),
    (
        given.with_a_classification_of_an_unknown_flaw,
        "classifier_1 classifies CVE-2099-0001, which is not in the census",
    ),
    (given.with_three_classifiers, "classifiers must be classifier_1, classifier_2"),
    (
        given.with_an_inconsistent_first_failed_criterion,
        "classifier_1: the first_failed_criterion of flaw CVE-2025-0001 is inconsistent "
        "with its fields",
    ),
    (
        given.with_a_flaw_disclosed_after_the_bound,
        "flaw GHSA-dddd-eeee-ffff is disclosed on 2026-10-08, after the bound 2026-10-07",
    ),
    (given.with_stale_figures, "figures differ from their computation"),
    (given.with_stale_date_mismatches, "date mismatches differ from their computation"),
]


@pytest.mark.parametrize(
    ("defect", "refusal"), DEFECTS, ids=[defect.__name__ for defect, _ in DEFECTS]
)
def test_a_census_with_one_defect_is_refused(
    tmp_path: Path, defect: Callable[[HoldoutCensus], HoldoutCensus], refusal: str
):
    path = given.written(tmp_path, defect(given.a_census()))

    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(path)


def test_a_classifier_date_differing_from_the_computed_one_is_listed_not_refused(
    tmp_path: Path,
):
    census = given.with_a_classifier_date_differing_from_the_computed_one(given.a_census())

    loaded = load_census(given.written(tmp_path, census))

    assert loaded.date_mismatches == [
        DateMismatch(
            flaw="CVE-2025-0001",
            classifier="classifier_2",
            classifier_date=date(2025, 6, 11),
            computed_date=date(2025, 6, 10),
        )
    ]


def test_a_flaw_is_withdrawn_only_when_every_record_is_withdrawn_or_rejected():
    withdrawn = identity.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-0001").model_copy(
        update={"withdrawn": date(2025, 8, 1)}
    )
    rejected = identity.an_nvd("CVE-2025-0001", rejected=True)
    live = identity.an_osv("PYSEC-2025-1", "CVE-2025-0001")

    assert given.a_flaw_with_records(withdrawn, rejected).withdrawn
    assert not given.a_flaw_with_records(withdrawn, rejected, live).withdrawn


def test_a_malformed_work_file_line_is_refused_with_its_file_and_line_number(tmp_path: Path):
    decisions = tmp_path / "decisions_ghsa.jsonl"
    decisions.write_text(
        '{"source": "ghsa", "source_id": "GHSA-aaaa-bbbb-cccc", "decision": "keep",'
        ' "software_kind": "server", "reason": "A server.", "agent": "ghsa collector"}\n'
        '{"source": "ghsa", "source_id": "GHSA-dddd-eeee-ffff", "decision": "maybe"}\n'
    )

    with pytest.raises(ValueError, match=re.escape(f"{decisions}, line 2")):
        read_jsonl(decisions, HitDecision)
