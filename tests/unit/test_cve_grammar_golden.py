import json

import tests.unit.support.test_cve_grammar_golden_given as given


def test_the_grammar_grades_the_corpus_as_recorded():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())
