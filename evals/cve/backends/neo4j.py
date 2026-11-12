"""The Neo4j database image the mcp-neo4j-cypher CVE-2026-35402 fix check
(`evals/cve/nuisance/fix_checks/cve_2026_35402_neo4j_cypher.py`) stands beside its sentinel.

The run no longer drives this module: Neo4j runs in the server's own run image. What stays is the
tag the fix check builds from `Dockerfile.neo4j-backend` when absent, the digest pin living in that
file.
"""

from evals.cve.docker_paths import DOCKER_DIRECTORY

NEO4J_IMAGE = "mcp-auditor-cve-neo4j-backend:local"
NEO4J_BACKEND_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.neo4j-backend"
