import subprocess


def no_container_carries(label: str) -> None:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label={label}", "-q"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert result.stdout.split() == []


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
