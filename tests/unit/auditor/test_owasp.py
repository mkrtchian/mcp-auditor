from mcp_auditor.domain.models import AuditCategory
from mcp_auditor.domain.owasp import owasp_id_for, owasp_label_for


def test_owasp_id_for_injection():
    assert owasp_id_for(AuditCategory.INJECTION) == "MCP-05"


def test_owasp_id_for_info_leakage():
    assert owasp_id_for(AuditCategory.INFO_LEAKAGE) == "MCP-10"


def test_owasp_id_for_input_validation_is_none():
    assert owasp_id_for(AuditCategory.INPUT_VALIDATION) is None


def test_owasp_id_for_error_handling_is_none():
    assert owasp_id_for(AuditCategory.ERROR_HANDLING) is None


def test_owasp_id_for_resource_abuse_is_none():
    assert owasp_id_for(AuditCategory.RESOURCE_ABUSE) is None


def test_owasp_label_for_mapped_category():
    assert owasp_label_for(AuditCategory.INJECTION) == "MCP-05: Command Injection & Execution"


def test_owasp_label_for_unmapped_category():
    assert owasp_label_for(AuditCategory.INPUT_VALIDATION) is None
