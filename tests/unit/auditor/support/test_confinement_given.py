from pathlib import Path

from mcp_auditor.domain.confinement import MountPolicy, parse_mount_option, refused_roots

HOME = Path("/home/alice")


def a_policy(*declared: str) -> MountPolicy:
    return MountPolicy(
        declared=tuple(parse_mount_option(raw) for raw in declared),
        refused=refused_roots(HOME),
    )
