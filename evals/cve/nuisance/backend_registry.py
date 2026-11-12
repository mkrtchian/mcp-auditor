"""The registry of the backends a nuisance fixture can provision, each a named lifecycle the
detection holdout layer already drives.

A server records a `BackendFixture` naming one of these keys; the provisioner built from the key's
lifecycle (`provisioners.provisioner_of`) ensures the backend is up and query-ready and yields the
server `Launch` wired to it, as `holdout_environments.doris_db_env` does for the holdout target of
CVE-2025-66335. `backend_problems` is the load check that a recorded fixture matches the backend its
key defines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from evals.cve import closed_network
from evals.cve.backends import (
    atlassian,
    ckan,
    doris,
    facebook_ads,
    gitlab,
    googleapis,
    gravitino,
    jenkins,
    mcp_ssh_sshd,
    n8n,
    responder,
)
from evals.cve.backends.atlassian import ATLASSIAN_BRIDGE, ATLASSIAN_RESPONDER_IMAGE
from evals.cve.backends.ckan import CKAN_BRIDGE, CKAN_IMAGE, CKAN_PARTS, MOUNTED_FILES
from evals.cve.backends.doris import DORIS_BRIDGE, DORIS_CONTAINER, DORIS_IMAGE
from evals.cve.backends.facebook_ads import FACEBOOK_ADS_BRIDGE, FACEBOOK_ADS_RESPONDER_IMAGE
from evals.cve.backends.gitlab import GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE
from evals.cve.backends.googleapis import GOOGLEAPIS_BRIDGE, GOOGLEAPIS_RESPONDER_IMAGE
from evals.cve.backends.gravitino import GRAVITINO_BRIDGE, GRAVITINO_IMAGE, GRAVITINO_SERVICES
from evals.cve.backends.jenkins import JENKINS_BRIDGE, JENKINS_RESPONDER_IMAGE, JENKINS_SERVICE
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.backends.mcp_ssh_sshd import SSHD_BRIDGE, SSHD_IMAGE, SSHD_SERVICE
from evals.cve.backends.n8n import N8N_BRIDGE, N8N_IMAGE, N8N_SERVICE
from evals.cve.detection.targets import image_tag
from evals.cve.docker_paths import image_dockerfile

if TYPE_CHECKING:
    from evals.cve.nuisance.admission import AdmittedServer


@dataclass(frozen=True)
class RegisteredBackend:
    lifecycle: BackendLifecycle
    network: str
    image: str
    built_services: tuple[str, ...]  # the compose services building its images, empty when pulled
    served: tuple[Path, ...]  # what it serves and how it joins the server, read by the fingerprint
    # The persistent containers a nuisance command removes at its start, so the backend stands
    # again from its image and its seed: empty for a built backend, which is removed by its tag.
    reset_containers: tuple[str, ...] = ()


def _served(backend_module: str, *built_services: str) -> tuple[Path, ...]:
    dockerfiles = (image_dockerfile(service) for service in built_services)
    return (Path(backend_module), Path(closed_network.__file__), *dockerfiles)


def _responder(
    lifecycle: BackendLifecycle, backend_module: str, network: str, image: str, service: str
) -> RegisteredBackend:
    served = (*_served(backend_module, service), Path(responder.__file__))
    return RegisteredBackend(lifecycle, network, image, (service,), served)


_CKAN_SERVICES = tuple(part.service for part in CKAN_PARTS)

BACKENDS: dict[str, RegisteredBackend] = {
    "doris": RegisteredBackend(
        doris.LIFECYCLE,
        DORIS_BRIDGE,
        DORIS_IMAGE,
        (),
        _served(doris.__file__),
        (DORIS_CONTAINER,),
    ),
    "ckan": RegisteredBackend(
        ckan.LIFECYCLE,
        CKAN_BRIDGE,
        CKAN_IMAGE,
        _CKAN_SERVICES,
        (*_served(ckan.__file__, *_CKAN_SERVICES), *MOUNTED_FILES),
    ),
    "n8n": RegisteredBackend(
        n8n.LIFECYCLE,
        N8N_BRIDGE,
        N8N_IMAGE,
        (N8N_SERVICE,),
        _served(n8n.__file__, N8N_SERVICE),
    ),
    "gravitino": RegisteredBackend(
        gravitino.LIFECYCLE,
        GRAVITINO_BRIDGE,
        GRAVITINO_IMAGE,
        GRAVITINO_SERVICES,
        _served(gravitino.__file__, *GRAVITINO_SERVICES),
    ),
    "mcp_ssh_sshd": RegisteredBackend(
        mcp_ssh_sshd.LIFECYCLE,
        SSHD_BRIDGE,
        SSHD_IMAGE,
        (SSHD_SERVICE,),
        _served(mcp_ssh_sshd.__file__, SSHD_SERVICE),
    ),
    "jenkins": RegisteredBackend(
        jenkins.LIFECYCLE,
        JENKINS_BRIDGE,
        JENKINS_RESPONDER_IMAGE,
        (JENKINS_SERVICE,),
        _served(jenkins.__file__, JENKINS_SERVICE),
    ),
    "atlassian": _responder(
        atlassian.LIFECYCLE,
        atlassian.__file__,
        ATLASSIAN_BRIDGE,
        ATLASSIAN_RESPONDER_IMAGE,
        "atlassian-responder",
    ),
    "gitlab": _responder(
        gitlab.LIFECYCLE,
        gitlab.__file__,
        GITLAB_BRIDGE,
        GITLAB_RESPONDER_IMAGE,
        "gitlab-responder",
    ),
    "googleapis": _responder(
        googleapis.LIFECYCLE,
        googleapis.__file__,
        GOOGLEAPIS_BRIDGE,
        GOOGLEAPIS_RESPONDER_IMAGE,
        "googleapis-responder",
    ),
    "facebook_ads": _responder(
        facebook_ads.LIFECYCLE,
        facebook_ads.__file__,
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


def backend_reset_containers(servers: Sequence[AdmittedServer]) -> list[str]:
    names = (
        name
        for server in servers
        if server.backend is not None
        for name in BACKENDS[server.backend.provisioner].reset_containers
    )
    return list(dict.fromkeys(names))


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
