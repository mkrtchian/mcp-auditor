from mcp_auditor.adapters.mcp_client import SessionBounds


def test_the_default_session_bounds_are_those_every_audit_runs_under():
    assert SessionBounds() == SessionBounds(initialize=120, ping=10, teardown=30)
