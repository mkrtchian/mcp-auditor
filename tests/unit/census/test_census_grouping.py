import tests.unit.census.support.test_census_grouping_given as given
from evals.cve.census.figures import Share
from evals.cve.census.grouping import gap_population, grouped_flaws, known_gap
from tests.unit.census.support import classifier_pairs
from tests.unit.support import censuses

EXCLUDED_SERVER = "npm:mcp-fetch-server"
AN_ACCEPTANCE_TARGET_FLAW = "CVE-2025-65513"


def test_a_flaw_both_classifiers_place_outside_the_grammar_is_grouped():
    classifications = given.classified(given.outside_the_grammar("CVE-2026-0001"))

    assert grouped_flaws(classifications, {"CVE-2026-0001"}) == {"CVE-2026-0001"}


def test_a_flaw_either_classifier_places_in_the_grammar_is_not_grouped():
    classifications = given.classified(
        classifier_pairs.the_same_flaw_seen_as("CVE-2026-0001", censuses.OUTSIDE_THE_GRAMMAR, {})
    )

    assert grouped_flaws(classifications, {"CVE-2026-0001"}) == set()


def test_a_server_counts_able_to_run_in_a_container_when_either_classifier_finds_it_so():
    classifications = given.classified(
        classifier_pairs.the_same_flaw_seen_as(
            "CVE-2026-0001",
            censuses.OUTSIDE_THE_GRAMMAR | given.NO_CONTAINER,
            censuses.OUTSIDE_THE_GRAMMAR,
        ),
        given.outside_the_grammar("CVE-2026-0002", **given.NO_CONTAINER),
    )

    grouped = grouped_flaws(classifications, {"CVE-2026-0001", "CVE-2026-0002"})

    assert grouped == {"CVE-2026-0001"}


def test_a_flaw_meets_a_criterion_of_the_draw_order_when_either_classifier_finds_it_does():
    classifications = given.classified(
        classifier_pairs.the_same_flaw_seen_as("CVE-2026-0001", given.NOT_PINNABLE, {}),
        classifier_pairs.agreed("CVE-2026-0002", **given.NOT_PINNABLE),
    )

    population = gap_population(classifications, {"CVE-2026-0001", "CVE-2026-0002"})

    assert population == {"CVE-2026-0001"}


def test_a_flaw_is_left_out_as_an_excluded_server_only_when_both_classifiers_name_one():
    classifications = given.classified(
        classifier_pairs.the_same_flaw_seen_as(
            "CVE-2026-0001", {"server_package": EXCLUDED_SERVER}, {}
        ),
        classifier_pairs.agreed("CVE-2026-0002", server_package=EXCLUDED_SERVER),
    )

    population = gap_population(classifications, {"CVE-2026-0001", "CVE-2026-0002"})

    assert population == {"CVE-2026-0001"}


def test_a_flaw_that_is_or_was_an_acceptance_target_is_left_out():
    classifications = given.classified(classifier_pairs.agreed(AN_ACCEPTANCE_TARGET_FLAW))

    assert gap_population(classifications, {AN_ACCEPTANCE_TARGET_FLAW}) == set()


def test_a_flaw_outside_the_candidates_is_left_out():
    classifications = given.classified(given.outside_the_grammar("PYSEC-2026-1"))

    assert gap_population(classifications, set()) == set()


def test_the_known_gap_of_a_reader_is_its_no_proof_share_of_the_gap_population():
    population = {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}
    groupings = {
        "reader_1": [censuses.no_proof("CVE-2026-0001"), censuses.a_judgment("CVE-2026-0002")],
        "reader_2": [censuses.no_proof("CVE-2026-0001"), censuses.no_proof("CVE-2026-0002")],
    }

    gap = known_gap(groupings, population)

    assert gap == {
        "reader_1": Share(count=1, denominator=4),
        "reader_2": Share(count=2, denominator=4),
    }
