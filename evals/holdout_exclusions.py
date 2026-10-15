"""The exclusions of the holdout that docs/holdout-log.md records, as the census code reads them.

Each change here is a line of that log. The packages are written as the classifiers write
`server_package`. Forks and copied code are checked by the maintainer at the draw, and the
siblings of a target are found at its calibration, so neither is listed here.
"""

EXCLUDED_SERVERS = frozenset(
    {
        "npm:@modelcontextprotocol/server-filesystem",
        "PyPI:mcp-server-git",
        "npm:mcp-server-kubernetes",
        "npm:mcp-fetch-server",
    }
)

# Every flaw that is or was a target of the CVE benchmark, dropped targets included.
BENCHMARK_FLAWS = frozenset(
    {
        "CVE-2025-53109",
        "CVE-2025-53110",
        "CVE-2025-53355",
        "CVE-2025-65513",
        "CVE-2025-68143",
        "CVE-2025-68144",
        "CVE-2025-68145",
        "CVE-2026-0755",
    }
)
