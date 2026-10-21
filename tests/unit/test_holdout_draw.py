from datetime import date

import tests.unit.support.test_holdout_draw_given as given
from evals.holdout_draw import DRAW_SALT, draw_digest, draw_order
from tests.unit.support.test_holdout_draw_given import A_BENCHMARK_FLAW, AN_EXCLUDED_SERVER


def test_draw_digest_is_the_known_sha256_of_a_fixed_identifier():
    assert DRAW_SALT == "mcp-auditor-holdout:"
    assert (
        draw_digest("CVE-2026-0001")
        == "67fc3923d5883e0917c22e27d5b5dbb948f25abde818ba7278544b1b356fd514"
    )


def test_draw_order_sorts_entries_by_digest_with_each_disclosure_date():
    flaws = [
        given.a_flaw("CVE-2026-0001", disclosure=date(2025, 6, 10)),
        given.a_flaw("CVE-2026-0002", disclosure=date(2026, 7, 1)),
    ]
    census = given.a_census(
        flaws, given.agreed_classifications({"CVE-2026-0001": {}, "CVE-2026-0002": {}})
    )

    entries = draw_order(census)

    assert [entry.digest for entry in entries] == sorted(
        draw_digest(flaw.identifier) for flaw in flaws
    )
    by_identifier = {entry.identifier: entry for entry in entries}
    assert by_identifier["CVE-2026-0001"].disclosure_date == date(2025, 6, 10)
    assert by_identifier["CVE-2026-0002"].disclosure_date == date(2026, 7, 1)


def test_draw_order_keeps_only_the_draw_order_candidates():
    flaws = [
        given.a_flaw("CVE-2026-0001"),
        given.a_flaw("CVE-2026-0002"),  # a server that does not run in a container is still drawn
        given.a_flaw("CVE-2026-0003", withdrawn=True),
        given.a_flaw("CVE-2026-0004", no_census_identifier=True),
        given.a_flaw("CVE-2026-0005"),
        given.a_flaw(A_BENCHMARK_FLAW),
        given.a_flaw("CVE-2026-0007"),
    ]
    classifications = given.agreed_classifications(
        {
            "CVE-2026-0001": {},
            "CVE-2026-0002": {"runs_in_container": False},
            "CVE-2026-0003": {},
            "CVE-2026-0004": {},
            "CVE-2026-0005": {"server_package": AN_EXCLUDED_SERVER},
            A_BENCHMARK_FLAW: {},
            "CVE-2026-0007": {"pinnable": False, "first_failed_criterion": "pinnable"},
        }
    )
    census = given.a_census(flaws, classifications)

    drawn = {entry.identifier for entry in draw_order(census)}

    assert drawn == {"CVE-2026-0001", "CVE-2026-0002"}
