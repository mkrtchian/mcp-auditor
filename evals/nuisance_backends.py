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
from pathlib import Path
from typing import TYPE_CHECKING

from evals import (
    apify_backend,
    atlassian_backend,
    ckan_backend,
    closed_network,
    contextforge_backend,
    doris_backend,
    facebook_ads_backend,
    figma_backend,
    gitlab_backend,
    googleapis_backend,
    jenkins_backend,
    mysql_backend,
    n8n_backend,
    neo4j_backend,
    responder_backend,
)
from evals.apify_backend import API_HOST, APIFY_BRIDGE, APIFY_RESPONDER_IMAGE
from evals.atlassian_backend import ATLASSIAN_BRIDGE, ATLASSIAN_RESPONDER_IMAGE
from evals.ckan_backend import CKAN_BRIDGE, CKAN_RESPONDER_IMAGE
from evals.contextforge_backend import CONTEXTFORGE_BRIDGE, CONTEXTFORGE_RESPONDER_IMAGE
from evals.cve_environments import Launch
from evals.cve_planting_base import STAND_IN_SERVICE
from evals.cve_targets import image_dockerfile, image_tag
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
from evals.public_stand_ins import stand_in_files

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer

type BackendProvisioner = Callable[[AdmittedServer], AbstractContextManager[Launch]]


@dataclass(frozen=True)
class RegisteredBackend:
    provisioner: BackendProvisioner
    network: str
    image: str
    built_services: tuple[str, ...]  # the compose services building its images, empty when pulled
    served: tuple[Path, ...]  # what it serves and how it joins the server, read by the fingerprint


def _served(backend_module: str, *built_services: str) -> tuple[Path, ...]:
    dockerfiles = (image_dockerfile(service) for service in built_services)
    return (Path(backend_module), Path(closed_network.__file__), *dockerfiles)


def _responder(
    provisioner: BackendProvisioner, backend_module: str, network: str, image: str, service: str
) -> RegisteredBackend:
    served = (*_served(backend_module, service), Path(responder_backend.__file__))
    return RegisteredBackend(provisioner, network, image, (service,), served)


_API_STAND_IN_FILES = stand_in_files(API_HOST)

BACKENDS: dict[str, RegisteredBackend] = {
    "doris": RegisteredBackend(
        doris_provisioner, DORIS_BRIDGE, DORIS_IMAGE, (), _served(doris_backend.__file__)
    ),
    "mysql": RegisteredBackend(
        mysql_provisioner, MYSQL_BRIDGE, MYSQL_IMAGE, (), _served(mysql_backend.__file__)
    ),
    "ckan": _responder(
        ckan_provisioner, ckan_backend.__file__, CKAN_BRIDGE, CKAN_RESPONDER_IMAGE, "ckan-responder"
    ),
    "contextforge": _responder(
        contextforge_provisioner,
        contextforge_backend.__file__,
        CONTEXTFORGE_BRIDGE,
        CONTEXTFORGE_RESPONDER_IMAGE,
        "contextforge-responder",
    ),
    "n8n": _responder(
        n8n_provisioner, n8n_backend.__file__, N8N_BRIDGE, N8N_RESPONDER_IMAGE, "n8n-responder"
    ),
    "atlassian": _responder(
        atlassian_provisioner,
        atlassian_backend.__file__,
        ATLASSIAN_BRIDGE,
        ATLASSIAN_RESPONDER_IMAGE,
        "atlassian-responder",
    ),
    "apify": RegisteredBackend(
        apify_provisioner,
        APIFY_BRIDGE,
        APIFY_RESPONDER_IMAGE,
        ("apify-responder", STAND_IN_SERVICE),
        (
            *_served(apify_backend.__file__, "apify-responder", STAND_IN_SERVICE),
            Path(responder_backend.__file__),
            _API_STAND_IN_FILES.capture,
            _API_STAND_IN_FILES.certificate,
        ),
    ),
    "jenkins": _responder(
        jenkins_provisioner,
        jenkins_backend.__file__,
        JENKINS_BRIDGE,
        JENKINS_RESPONDER_IMAGE,
        "jenkins-responder",
    ),
    "gitlab": _responder(
        gitlab_provisioner,
        gitlab_backend.__file__,
        GITLAB_BRIDGE,
        GITLAB_RESPONDER_IMAGE,
        "gitlab-responder",
    ),
    "googleapis": _responder(
        googleapis_provisioner,
        googleapis_backend.__file__,
        GOOGLEAPIS_BRIDGE,
        GOOGLEAPIS_RESPONDER_IMAGE,
        "googleapis-responder",
    ),
    "neo4j": RegisteredBackend(
        neo4j_provisioner,
        NEO4J_BRIDGE,
        NEO4J_IMAGE,
        ("neo4j-backend",),
        _served(neo4j_backend.__file__, "neo4j-backend"),
    ),
    "facebook_ads": _responder(
        facebook_ads_provisioner,
        facebook_ads_backend.__file__,
        FACEBOOK_ADS_BRIDGE,
        FACEBOOK_ADS_RESPONDER_IMAGE,
        "facebook-ads-responder",
    ),
    "figma": _responder(
        figma_provisioner,
        figma_backend.__file__,
        FIGMA_BRIDGE,
        FIGMA_RESPONDER_IMAGE,
        "figma-responder",
    ),
}


def built_backend_services(servers: Sequence[AdmittedServer]) -> list[str]:
    services = (
        service
        for server in servers
        if server.backend is not None
        for service in BACKENDS[server.backend.provisioner].built_services
    )
    return list(dict.fromkeys(services))


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
