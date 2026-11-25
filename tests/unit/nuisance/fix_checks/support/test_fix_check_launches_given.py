from collections.abc import Callable
from pathlib import Path

from evals.cve.backends.mcp_ssh_sshd import StoodSshd
from evals.cve.nuisance.fix_checks import (
    cve_2026_10276_jenkins,
    cve_2026_11720_googleapis,
    cve_2026_19956_facebook_ads,
    cve_2026_35402_neo4j_cypher,
    cve_2026_41041_gravitino,
    cve_2026_46341_apify,
    cve_2026_61462_gitlab,
    cve_2026_77252_atlassian,
    mcp_ssh_fix_check,
)

_ADDRESS = "10.0.0.100"

SERVER_LAUNCHES: dict[str, Callable[[], list[str]]] = {
    "atlassian-server": lambda: cve_2026_77252_atlassian.server_args("image", _ADDRESS),
    "apify-server": lambda: cve_2026_46341_apify.server_args("image", _ADDRESS),
    "jenkins-server": lambda: cve_2026_10276_jenkins.server_args("image", _ADDRESS),
    "facebook-ads-server": lambda: cve_2026_19956_facebook_ads.server_args(
        "image", _ADDRESS, Path("/bundle.pem")
    ),
    "gitlab-server": lambda: cve_2026_61462_gitlab.server_args("image", _ADDRESS),
    "googleapis-server": lambda: cve_2026_11720_googleapis.server_args("image", 100),
    "gravitino-server": lambda: cve_2026_41041_gravitino.server_args("image", "n"),
    "mcp-ssh-server": lambda: mcp_ssh_fix_check.server_args(
        "image", StoodSshd("n", Path("/known_hosts")), "/witness"
    ),
    "neo4j-server": lambda: cve_2026_35402_neo4j_cypher.server_args("image"),
}

PART_LAUNCHES: dict[str, Callable[[], list[str]]] = {
    "gravitino-part": lambda: cve_2026_41041_gravitino.part_args("p", "n", "postgresql", "image"),
}

BACKEND_LAUNCHES: dict[str, Callable[[], list[str]]] = {
    "atlassian-responder": lambda: cve_2026_77252_atlassian.responder_args("r", "n", _ADDRESS),
    "apify-responder": lambda: cve_2026_46341_apify.responder_args("r", "n", _ADDRESS),
    "jenkins-controller": lambda: cve_2026_10276_jenkins.controller_args("c", _ADDRESS),
    "facebook-ads-sentinel": lambda: cve_2026_19956_facebook_ads.sentinel_args("r", "n", _ADDRESS),
    "gitlab-responder": lambda: cve_2026_61462_gitlab.responder_args("r", "n", _ADDRESS),
    "googleapis-responder": lambda: cve_2026_11720_googleapis.responder_args("r", "n", 100),
    "neo4j-sentinel": lambda: cve_2026_35402_neo4j_cypher.sentinel_args("s", "n"),
}

# The neo4j database runs unconfined, which test_neo4j_fix_check_builder.py pins.
UNCONFINED_LAUNCHES: dict[str, Callable[[], list[str]]] = {
    "neo4j-database": lambda: cve_2026_35402_neo4j_cypher.neo4j_container_args("d"),
}

CONFINED_LAUNCHES: dict[str, Callable[[], list[str]]] = {
    **SERVER_LAUNCHES,
    **PART_LAUNCHES,
    **BACKEND_LAUNCHES,
}

HAND_BUILT_LAUNCHES: dict[str, Callable[[], list[str]]] = {
    **CONFINED_LAUNCHES,
    **UNCONFINED_LAUNCHES,
}
