"""The registry of the backends a nuisance fixture can provision, each a named lifecycle the
holdout already drives.

A server records a `BackendFixture` naming one of these keys; the provisioner ensures the
backend is up and query-ready and yields the server `Launch` wired to it, as `doris_db_env`
does for the holdout. `backend_problems` is the load check that a recorded fixture matches the
backend its key defines. The provisioners live in `nuisance_provisioners`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from evals.apify_backend import APIFY_BRIDGE, APIFY_RESPONDER_IMAGE
from evals.atlassian_backend import ATLASSIAN_BRIDGE, ATLASSIAN_RESPONDER_IMAGE
from evals.ckan_backend import CKAN_BRIDGE, CKAN_RESPONDER_IMAGE
from evals.contextforge_backend import CONTEXTFORGE_BRIDGE, CONTEXTFORGE_RESPONDER_IMAGE
from evals.cve_environments import Launch
from evals.cve_targets import image_tag
from evals.doris_backend import DORIS_BRIDGE, DORIS_IMAGE
from evals.facebook_ads_backend import FACEBOOK_ADS_BRIDGE, FACEBOOK_ADS_RESPONDER_IMAGE
from evals.figma_backend import FIGMA_BRIDGE, FIGMA_RESPONDER_IMAGE
from evals.gitlab_backend import GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE
from evals.googleapis_backend import GOOGLEAPIS_BRIDGE, GOOGLEAPIS_RESPONDER_IMAGE
from evals.jenkins_backend import JENKINS_BRIDGE, JENKINS_RESPONDER_IMAGE
from evals.mysql_backend import MYSQL_BRIDGE, MYSQL_IMAGE
from evals.n8n_backend import N8N_BRIDGE, N8N_RESPONDER_IMAGE
from evals.neo4j_backend import NEO4J_BRIDGE, NEO4J_IMAGE
from evals.nuisance_provisioners import (
    apify_provisioner,
    atlassian_provisioner,
    ckan_provisioner,
    contextforge_provisioner,
    doris_provisioner,
    facebook_ads_provisioner,
    figma_provisioner,
    gitlab_provisioner,
    googleapis_provisioner,
    jenkins_provisioner,
    mysql_provisioner,
    n8n_provisioner,
    neo4j_provisioner,
)

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer

type BackendProvisioner = Callable[[AdmittedServer], AbstractContextManager[Launch]]


@dataclass(frozen=True)
class RegisteredBackend:
    provisioner: BackendProvisioner
    network: str
    image: str
    built_service: str | None  # the compose service that builds the image, None when pulled


BACKENDS: dict[str, RegisteredBackend] = {
    "doris": RegisteredBackend(doris_provisioner, DORIS_BRIDGE, DORIS_IMAGE, None),
    "mysql": RegisteredBackend(mysql_provisioner, MYSQL_BRIDGE, MYSQL_IMAGE, None),
    "ckan": RegisteredBackend(
        ckan_provisioner, CKAN_BRIDGE, CKAN_RESPONDER_IMAGE, "ckan-responder"
    ),
    "contextforge": RegisteredBackend(
        contextforge_provisioner,
        CONTEXTFORGE_BRIDGE,
        CONTEXTFORGE_RESPONDER_IMAGE,
        "contextforge-responder",
    ),
    "n8n": RegisteredBackend(n8n_provisioner, N8N_BRIDGE, N8N_RESPONDER_IMAGE, "n8n-responder"),
    "atlassian": RegisteredBackend(
        atlassian_provisioner, ATLASSIAN_BRIDGE, ATLASSIAN_RESPONDER_IMAGE, "atlassian-responder"
    ),
    "apify": RegisteredBackend(
        apify_provisioner, APIFY_BRIDGE, APIFY_RESPONDER_IMAGE, "apify-responder"
    ),
    "jenkins": RegisteredBackend(
        jenkins_provisioner, JENKINS_BRIDGE, JENKINS_RESPONDER_IMAGE, "jenkins-responder"
    ),
    "gitlab": RegisteredBackend(
        gitlab_provisioner, GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE, "gitlab-responder"
    ),
    "googleapis": RegisteredBackend(
        googleapis_provisioner,
        GOOGLEAPIS_BRIDGE,
        GOOGLEAPIS_RESPONDER_IMAGE,
        "googleapis-responder",
    ),
    "neo4j": RegisteredBackend(neo4j_provisioner, NEO4J_BRIDGE, NEO4J_IMAGE, "neo4j-backend"),
    "facebook_ads": RegisteredBackend(
        facebook_ads_provisioner,
        FACEBOOK_ADS_BRIDGE,
        FACEBOOK_ADS_RESPONDER_IMAGE,
        "facebook-ads-responder",
    ),
    "figma": RegisteredBackend(
        figma_provisioner, FIGMA_BRIDGE, FIGMA_RESPONDER_IMAGE, "figma-responder"
    ),
}


def built_backend_services(servers: Sequence[AdmittedServer]) -> list[str]:
    services = (
        BACKENDS[server.backend.provisioner].built_service
        for server in servers
        if server.backend is not None
    )
    return list(dict.fromkeys(service for service in services if service is not None))


def built_backend_tags(servers: Sequence[AdmittedServer]) -> list[str]:
    return [image_tag(service) for service in built_backend_services(servers)]


def backend_problems(
    server: AdmittedServer, backends: Mapping[str, RegisteredBackend]
) -> list[str]:
    if server.backend is None:
        return []
    key = server.backend.provisioner
    entry = backends.get(key)
    if entry is None:
        return [f"{server.server_package}: backend provisioner {key!r} is not registered"]
    expected = {"provisioner": key, "image": entry.image, "network": entry.network}
    if server.backend.model_dump() != expected:
        return [
            f"{server.server_package}: backend fixture {server.backend.model_dump()} "
            f"is not the registered {expected}"
        ]
    return []
