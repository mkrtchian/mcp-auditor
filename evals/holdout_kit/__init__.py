"""The isolated calibration kit (holdout rule, Calibration): a self-contained path the
calibration agent runs, importing nothing from mcp_auditor so the agent that develops a fixture
cannot read the auditor. Every module here is pinned free of mcp_auditor by
tests/unit/test_holdout_kit_isolation.py.
"""
