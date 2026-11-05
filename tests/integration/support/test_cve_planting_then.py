import subprocess
from collections.abc import Sequence

from tests.integration.support.test_cve_planting_given import Fetched, RecordingPlanting


def nothing_it_made_outlives(docker: RecordingPlanting) -> None:
    assert docker.networks and docker.containers
    assert not [name for name in docker.containers if _exists("container", name)]
    assert not [name for name in docker.networks if _exists("network", name)]


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


def answered_without_its_body(fetched: Fetched, status: int, body: str) -> None:
    assert (fetched.status, fetched.body) == (status, "")
    assert fetched.headers.get("content-length") == str(len(body.encode()))


def redirects_to(fetched: Fetched, location: str) -> None:
    assert fetched.status == 301
    assert fetched.headers.get("location") == location


def logged_its_default_for(log: str, host: str, misses: list[str]) -> None:
    prefix = f"stand-in for {host} answered with its default for: miss "
    assert all(prefix + miss in log for miss in misses), log


def answered_with(fetched: Fetched, status: int, body: str) -> None:
    assert (fetched.status, fetched.body) == (status, body)
    assert fetched.headers.get("content-length") == str(len(body.encode()))


def carries(fetched: Fetched, headers: Sequence[tuple[str, str]], length: int | None) -> None:
    computed = [] if length is None else [("Content-Length", str(length))]
    assert fetched.header_list == [*headers, *computed]


def answered_by_its_route(fetched: Fetched, headers: Sequence[tuple[str, str]], body: str) -> None:
    assert (fetched.status, fetched.body) == (200, body)
    carries(fetched, headers, len(body.encode()))
