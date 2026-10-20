from pathlib import Path

import pytest

import tests.unit.support.test_fixture_contamination_given as given
import tests.unit.support.test_fixture_contamination_then as then

SERVER_CORPUS = {"Adds file contents to the staging area"}


class TestShippedConstantsNameNoHoneypotLiteral:
    def test_the_honeypots_plant_discriminating_literals(self):
        literals = given.discriminating_literals()

        assert {"Invalid category", "Alice"} <= literals

    def test_no_constant_of_src_contains_a_honeypot_literal(self):
        constants = given.shipped_constants()
        literals = given.discriminating_literals()

        then.no_constant_contains_any_of(constants, literals)


class TestShippedConstantsNameNoLayoutLiteral:
    def test_no_constant_of_src_contains_a_layout_literal(self):
        constants = given.shipped_constants()
        literals = given.layout_literals()

        then.no_constant_contains_any_substring(constants, literals)


class TestShippedConstantsNameNoExcludedServerText:
    def test_the_corpus_is_not_vacuous(self):
        corpus = given.excluded_server_corpus()

        assert corpus

    def test_no_constant_of_src_contains_excluded_server_text(self):
        constants = given.shipped_constants()
        corpus = given.excluded_server_corpus()

        then.no_constant_contains_any_server_text(constants, corpus)

    def test_a_five_word_run_of_server_text_in_a_constant_leaks(self):
        constant = [(Path("src/leak.py"), "qqq contents to the staging area qqq")]

        with pytest.raises(AssertionError):
            then.no_constant_contains_any_server_text(constant, SERVER_CORPUS)

    def test_a_four_word_run_of_server_text_does_not_leak(self):
        constant = [(Path("src/benign.py"), "qqq to the staging area qqq")]

        then.no_constant_contains_any_server_text(constant, SERVER_CORPUS)

    def test_an_echoed_auditor_marker_is_dropped_from_the_corpus(self):
        payload = "/work/sandbox/;echo mcp-auditor-probe"
        case = given.a_cve_case(
            "CVE-2025-53109",
            error=f"Error: ENOENT: no such file or directory, scandir '{payload}'",
            arguments={"path": payload},
        )

        corpus = given.server_corpus_of([case], given.servers_by_cve())

        assert all("mcp-auditor-probe" not in text and payload not in text for text in corpus)

    def test_an_unclassified_cve_case_fails(self):
        case = given.a_cve_case("CVE-0000-0000", tool_description="x")

        with pytest.raises(LookupError):
            given.server_corpus_of([case], given.servers_by_cve())

    def test_a_non_excluded_server_case_is_absent_from_the_corpus(self):
        case = given.a_cve_case("CVE-0000-0001", tool_description="distinctive server prose here")
        servers = {"CVE-0000-0001": "npm:some-unrelated-server"}

        assert given.server_corpus_of([case], servers) == set()
