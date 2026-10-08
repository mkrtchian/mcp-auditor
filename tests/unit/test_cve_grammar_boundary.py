from types import ModuleType

import pytest

import tests.unit.support.test_cve_grammar_boundary_given as given
from evals import cve_grammar, cve_units
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


def test_every_valid_category_names_an_audit_category():
    audit_categories = {category.value for category in AuditCategory}

    names = {name for names in cve_grammar.VALID_CATEGORIES.values() for name in names}

    assert names <= audit_categories


@pytest.mark.parametrize("verdict", list(EvalVerdict))
def test_every_eval_verdict_translates_to_a_grammar_verdict_of_the_same_value(
    verdict: EvalVerdict,
):
    assert cve_units.Verdict(verdict.value).value == verdict.value


@pytest.mark.parametrize("module", [cve_grammar, cve_units], ids=lambda module: module.__name__)
def test_the_grammar_imports_nothing_of_the_auditor(module: ModuleType):
    imported = given.modules_imported_by(module)

    assert not {name for name in imported if name.split(".")[0] == "mcp_auditor"}
