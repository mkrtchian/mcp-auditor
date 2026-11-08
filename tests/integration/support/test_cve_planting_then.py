import subprocess

from tests.integration.support.test_cve_planting_given import RecordingPlanting


def nothing_it_made_outlives(docker: RecordingPlanting) -> None:
    assert docker.networks and docker.containers
    assert not [name for name in docker.containers if _exists("container", name)]
    assert not [name for name in docker.networks if _exists("network", name)]


def no_container_it_started_outlives(docker: RecordingPlanting) -> None:
    """For a launch with no network of its own: its holder and stand-ins only."""
    assert docker.containers
    assert not [name for name in docker.containers if _exists("container", name)]


def no_container_carries(label: str) -> None:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label={label}", "-q"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert result.stdout.split() == []


def _exists(kind: str, name: str) -> bool:
    result = subprocess.run(["docker", kind, "inspect", name], capture_output=True, text=True)
    return result.returncode == 0


def no_search_domain_nor_audit_name(identity: dict[str, str]) -> None:
    named = {
        name: content
        for name, content in identity.items()
        if "mcp-auditor" in content or "mcpaudit" in content.lower()
    }
    assert named == {}, f"the target reads a name of the audit: {named}"
    resolv_conf = identity["/etc/resolv.conf"]
    search_lines = [line for line in resolv_conf.splitlines() if line.startswith("search")]
    assert search_lines == [], f"the target reads a search domain:\n{resolv_conf}"
