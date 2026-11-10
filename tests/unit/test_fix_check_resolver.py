from collections.abc import Callable

import pytest

from evals.cve_planting_base import PlantedArgs, resolver_args
from evals.nuisance_fix_checks import (
    cve_2026_10276_jenkins,
    cve_2026_11720_googleapis,
    cve_2026_19956_facebook_ads,
    cve_2026_35402_neo4j_cypher,
    cve_2026_46341_apify,
    cve_2026_61462_gitlab,
    cve_2026_77252_atlassian,
)

_ADDRESS = "10.0.0.100"
_NO_PLANTING = PlantedArgs(
    user=(), working_directory=(), env=(), mounts=(), hostname=(), network=()
)

_BUILDERS: dict[str, Callable[[], list[str]]] = {
    "atlassian-responder": lambda: cve_2026_77252_atlassian.responder_args("r", "n", _ADDRESS),
    "atlassian-server": lambda: cve_2026_77252_atlassian.server_args("image", _ADDRESS),
    "apify-responder": lambda: cve_2026_46341_apify.responder_args("r", "n", _ADDRESS),
    "apify-server": lambda: cve_2026_46341_apify.server_args("image", _ADDRESS),
    "jenkins-responder": lambda: cve_2026_10276_jenkins.responder_args("r", "n", _ADDRESS),
    "jenkins-server": lambda: cve_2026_10276_jenkins.server_args("image", _ADDRESS),
    "facebook-ads-sentinel": lambda: cve_2026_19956_facebook_ads.sentinel_args("r", "n", _ADDRESS),
    "facebook-ads-server": lambda: cve_2026_19956_facebook_ads.server_args("image", _ADDRESS),
    "gitlab-responder": lambda: cve_2026_61462_gitlab.responder_args("r", "n", _ADDRESS),
    "gitlab-server": lambda: cve_2026_61462_gitlab.server_args("image", _ADDRESS),
    "googleapis-responder": lambda: cve_2026_11720_googleapis.responder_args("r", "n", 100),
    "googleapis-server": lambda: cve_2026_11720_googleapis.server_args("image", 100),
    "neo4j-sentinel": lambda: cve_2026_35402_neo4j_cypher.sentinel_args("s", "n"),
    "neo4j-database": lambda: cve_2026_35402_neo4j_cypher.neo4j_container_args("d"),
    "neo4j-server": lambda: cve_2026_35402_neo4j_cypher.server_args("image"),
}


@pytest.mark.parametrize("builder", list(_BUILDERS.values()), ids=list(_BUILDERS))
def test_a_fix_check_container_with_its_own_network_carries_the_resolver_option_once(
    builder: Callable[[], list[str]],
):
    argv = builder()
    option = resolver_args()

    occurrences = sum(argv[i : i + len(option)] == option for i in range(len(argv)))

    assert occurrences == 1
