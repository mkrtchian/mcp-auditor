import re
from pathlib import Path

from evals.cve.backends.mcp_ssh_sshd import StoodSshd
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.nuisance.fix_checks import mcp_ssh_fix_check as fix_check


def an_sshd_on(network: str) -> StoodSshd:
    return StoodSshd(network, Path("/tmp/known_hosts"))


def the_cve_2025_9654_fixture() -> FixCheckFixture:
    return fix_check.target(
        flaw="CVE-2025-9654",
        aim=re.compile(r'";'),
        injection=fix_check.shell_injection,
        vulnerable_service="mcp-ssh-flaw-1.0.3",
        patched_service="mcp-ssh-flaw-1.0.4",
        server_patched_service="mcp-ssh",
    )
