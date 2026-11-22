from evals.cve.census.prefilter import INITIAL_TERMS, PrefilterTerm, matches, prefilter
from evals.cve.census.sources import SourceName
from tests.unit.census.support import advisory_sources

UNRELATED = {"summary": "Overflow in an image codec", "details": "A crafted PNG crashes it."}


def test_mcp_in_the_summary_matches_without_regard_to_case():
    record = advisory_sources.a_record(summary="Path traversal in the MCP filesystem server")

    assert matches(record, INITIAL_TERMS)


def test_model_context_protocol_in_the_details_matches():
    record = advisory_sources.a_record(
        summary="", details="A Model Context Protocol server leaks files."
    )

    assert matches(record, INITIAL_TERMS)


def test_mcp_inside_a_package_name_matches():
    record = advisory_sources.a_record(**UNRELATED, packages=["npm:@acme/mcp-server-git"])

    assert matches(record, INITIAL_TERMS)


def test_a_record_with_neither_term_does_not_match():
    record = advisory_sources.a_record(**UNRELATED, packages=["npm:png-codec"])

    assert not matches(record, INITIAL_TERMS)


def test_a_package_term_matches_the_name_after_the_ecosystem():
    record = advisory_sources.a_record(**UNRELATED, packages=["npm:@scope/name"])

    assert matches(record, [a_package_term("@Scope/Name")])


def a_package_term(text: str) -> PrefilterTerm:
    return PrefilterTerm(text=text, kind="package", added_for="GHSA-gap", reason="a missed server")


def test_a_package_term_matches_a_whole_cpe_product():
    record = advisory_sources.a_record(**UNRELATED, source=SourceName.NVD, packages=["file_server"])

    assert matches(record, [a_package_term("file_server")])


def test_a_package_term_does_not_match_by_substring():
    record = advisory_sources.a_record(**UNRELATED, packages=["npm:@scope/name-extra"])

    assert not matches(record, [a_package_term("@scope/name")])


def test_a_package_term_does_not_match_the_text():
    record = advisory_sources.a_record(summary="A flaw in @scope/name", packages=[])

    assert not matches(record, [a_package_term("@scope/name")])


def test_the_prefilter_keeps_the_matching_records_in_order():
    first = advisory_sources.a_record(id="GHSA-1", summary="An MCP server flaw")
    unrelated = advisory_sources.a_record(id="GHSA-2", **UNRELATED, packages=[])
    second = advisory_sources.a_record(id="GHSA-3", details="model context protocol")

    hits = prefilter([first, unrelated, second], INITIAL_TERMS)

    assert [hit.id for hit in hits] == ["GHSA-1", "GHSA-3"]
