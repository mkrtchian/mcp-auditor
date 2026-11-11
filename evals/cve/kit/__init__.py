"""The kit (the detection suite rule, Calibration): a self-contained path the calibration agent
and the admission agents run, importing nothing from mcp_auditor so the agent that develops a
fixture cannot read the auditor. Every module here is pinned free of mcp_auditor by
tests/unit/test_kit_isolation.py.
"""
