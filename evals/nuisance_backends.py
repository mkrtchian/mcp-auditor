"""The registry of the backends a nuisance fixture can provision, each a named lifecycle the
holdout already drives.

A server records a `BackendFixture` naming one of these keys; the provisioner built from the
key's lifecycle (`nuisance_provisioners.provisioner_of`) ensures the backend is up and
query-ready and yields the server `Launch` wired to it, as `holdout_environments.doris_db_env`
does for the holdout. `backend_problems` is the load check that a recorded fixture matches the
backend its key defines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from evals import (
    atlassian_backend,
    ckan_backend,
    closed_network,
    doris_backend,
    facebook_ads_backend,
    gitlab_backend,
    googleapis_backend,
    gravitino_backend,
    jenkins_backend,
    n8n_backend,
    responder_backend,
)
from evals.atlassian_backend import ATLASSIAN_BRIDGE, ATLASSIAN_RESPONDER_IMAGE
from evals.backend_lifecycle import BackendLifecycle
from evals.ckan_backend import CKAN_BRIDGE, CKAN_IMAGE, CKAN_PARTS, MOUNTED_FILES
from evals.cve_targets import image_tag
from evals.docker_paths import image_dockerfile
from evals.doris_backend import DORIS_BRIDGE, DORIS_IMAGE
from evals.facebook_ads_backend import FACEBOOK_ADS_BRIDGE, FACEBOOK_ADS_RESPONDER_IMAGE
from evals.gitlab_backend import GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE
from evals.googleapis_backend import GOOGLEAPIS_BRIDGE, GOOGLEAPIS_RESPONDER_IMAGE
from evals.gravitino_backend import GRAVITINO_BRIDGE, GRAVITINO_IMAGE, GRAVITINO_SERVICES
from evals.jenkins_backend import JENKINS_BRIDGE, JENKINS_RESPONDER_IMAGE
from evals.n8n_backend import N8N_BRIDGE, N8N_IMAGE, N8N_SERVICE

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer


@dataclass(frozen=True)
class RegisteredBackend:
    lifecycle: BackendLifecycle
    network: str
    image: str
    built_services: tuple[str, ...]  # the compose services building its images, empty when pulled
    served: tuple[Path, ...]  # what it serves and how it joins the server, read by the fingerprint


def _served(backend_module: str, *built_services: str) -> tuple[Path, ...]:
    dockerfiles = (image_dockerfile(service) for service in built_services)
    return (Path(backend_module), Path(closed_network.__file__), *dockerfiles)


def _responder(
    lifecycle: BackendLifecycle, backend_module: str, network: str, image: str, service: str
) -> RegisteredBackend:
    served = (*_served(backend_module, service), Path(responder_backend.__file__))
    return RegisteredBackend(lifecycle, network, image, (service,), served)


_CKAN_SERVICES = tuple(part.service for part in CKAN_PARTS)

BACKENDS: dict[str, RegisteredBackend] = {
    "doris": RegisteredBackend(
        doris_backend.LIFECYCLE, DORIS_BRIDGE, DORIS_IMAGE, (), _served(doris_backend.__file__)
    ),
    "ckan": RegisteredBackend(
        ckan_backend.LIFECYCLE,
        CKAN_BRIDGE,
        CKAN_IMAGE,
        _CKAN_SERVICES,
        (*_served(ckan_backend.__file__, *_CKAN_SERVICES), *MOUNTED_FILES),
    ),
    "n8n": RegisteredBackend(
        n8n_backend.LIFECYCLE,
        N8N_BRIDGE,
        N8N_IMAGE,
        (N8N_SERVICE,),
        _served(n8n_backend.__file__, N8N_SERVICE),
    ),
    "gravitino": RegisteredBackend(
        gravitino_backend.LIFECYCLE,
        GRAVITINO_BRIDGE,
        GRAVITINO_IMAGE,
        GRAVITINO_SERVICES,
        _served(gravitino_backend.__file__, *GRAVITINO_SERVICES),
    ),
    "atlassian": _responder(
        atlassian_backend.LIFECYCLE,
        atlassian_backend.__file__,
        ATLASSIAN_BRIDGE,
        ATLASSIAN_RESPONDER_IMAGE,
        "atlassian-responder",
    ),
    "jenkins": _responder(
        jenkins_backend.LIFECYCLE,
        jenkins_backend.__file__,
        JENKINS_BRIDGE,
        JENKINS_RESPONDER_IMAGE,
        "jenkins-responder",
    ),
    "gitlab": _responder(
        gitlab_backend.LIFECYCLE,
        gitlab_backend.__file__,
        GITLAB_BRIDGE,
        GITLAB_RESPONDER_IMAGE,
        "gitlab-responder",
    ),
    "googleapis": _responder(
        googleapis_backend.LIFECYCLE,
        googleapis_backend.__file__,
        GOOGLEAPIS_BRIDGE,
        GOOGLEAPIS_RESPONDER_IMAGE,
        "googleapis-responder",
    ),
    "facebook_ads": _responder(
        facebook_ads_backend.LIFECYCLE,
        facebook_ads_backend.__file__,
        FACEBOOK_ADS_BRIDGE,
        FACEBOOK_ADS_RESPONDER_IMAGE,
        "facebook-ads-responder",
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
