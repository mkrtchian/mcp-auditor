import pytest

from mcp_auditor.domain.models import AuditCategory
from mcp_auditor.domain.owasp import category_with_owasp_id, category_with_owasp_label


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        (AuditCategory.INJECTION, "injection / MCP-05"),
        (AuditCategory.INFO_LEAKAGE, "info_leakage / MCP-10"),
        (AuditCategory.INPUT_VALIDATION, "input_validation"),
        (AuditCategory.ERROR_HANDLING, "error_handling"),
        (AuditCategory.RESOURCE_ABUSE, "resource_abuse"),
    ],
)
def test_category_with_owasp_id(category: AuditCategory, expected: str):
    assert category_with_owasp_id(category) == expected


def test_a_mapped_category_carries_its_owasp_label():
    assert (
        category_with_owasp_label(AuditCategory.INJECTION)
        == "injection / MCP-05: Command Injection & Execution"
    )


def test_an_unmapped_category_stays_bare_with_the_label():
    assert category_with_owasp_label(AuditCategory.INPUT_VALIDATION) == "input_validation"
