"""The provisioners of the registered nuisance backends.

Each ensures its backend is up and query-ready, yields the server `Launch` wired to it, and reaps
the server when the launch ends. `nuisance_backends` registers them under their fixture keys.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING
from uuid import uuid4

from evals.apify_backend import (
    APIFY_LAUNCH_LOCK,
    apify_rm,
    apify_server_args,
    ensure_apify_responder,
)
from evals.atlassian_backend import (
    ATLASSIAN_LAUNCH_LOCK,
    atlassian_rm,
    atlassian_server_args,
    ensure_atlassian_responder,
)
from evals.ckan_backend import (
    CKAN_LAUNCH_LOCK,
    ckan_rm,
    ckan_server_args,
    ensure_ckan_responder,
)
from evals.contextforge_backend import (
    CONTEXTFORGE_LAUNCH_LOCK,
    contextforge_rm,
    contextforge_server_args,
    ensure_contextforge_responder,
)
from evals.cve_environments import Launch
from evals.cve_planting_base import LABEL
from evals.doris_backend import DORIS_LAUNCH_LOCK, doris_rm, doris_server_args, ensure_doris
from evals.googleapis_backend import (
    GOOGLEAPIS_LAUNCH_LOCK,
    ensure_googleapis_responder,
    googleapis_rm,
    googleapis_server_args,
)
from evals.jenkins_backend import (
    JENKINS_LAUNCH_LOCK,
    ensure_jenkins_responder,
    jenkins_rm,
    jenkins_server_args,
)
from evals.mysql_backend import MYSQL_LAUNCH_LOCK, ensure_mysql, mysql_rm, mysql_server_args
from evals.n8n_backend import N8N_LAUNCH_LOCK, ensure_n8n_responder, n8n_rm, n8n_server_args
from evals.neo4j_backend import NEO4J_LAUNCH_LOCK, ensure_neo4j, neo4j_rm, neo4j_server_args
from evals.nuisance_images import image_tag

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer


@contextmanager
def doris_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock is not held across the yield: a server's
    # concurrent runs share the one cluster that serves them all.
    with DORIS_LAUNCH_LOCK:
        ensure_doris()
    name = f"{LABEL}-doris-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=doris_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        doris_rm(name)


@contextmanager
def ckan_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with CKAN_LAUNCH_LOCK:
        ensure_ckan_responder()
    name = f"{LABEL}-ckan-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=ckan_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        ckan_rm(name)


@contextmanager
def atlassian_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no witness, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with ATLASSIAN_LAUNCH_LOCK:
        ensure_atlassian_responder()
    name = f"{LABEL}-atlassian-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=atlassian_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        atlassian_rm(name)


@contextmanager
def apify_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no witness, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with APIFY_LAUNCH_LOCK:
        ensure_apify_responder()
    name = f"{LABEL}-apify-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=apify_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        apify_rm(name)


@contextmanager
def contextforge_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with CONTEXTFORGE_LAUNCH_LOCK:
        ensure_contextforge_responder()
    name = f"{LABEL}-contextforge-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=contextforge_server_args(
                name, image_tag(server.service), server.host, server.launch
            ),
        )
    finally:
        contextforge_rm(name)


@contextmanager
def n8n_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with N8N_LAUNCH_LOCK:
        ensure_n8n_responder()
    name = f"{LABEL}-n8n-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=n8n_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        n8n_rm(name)


@contextmanager
def mysql_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run plants nothing, so the lock serialises only the stand-up of the pair, not
    # the yield: a server's concurrent runs share the one pair that serves them all.
    with MYSQL_LAUNCH_LOCK:
        ensure_mysql()
    name = f"{LABEL}-mysql-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=mysql_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        mysql_rm(name)


@contextmanager
def jenkins_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no witness, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with JENKINS_LAUNCH_LOCK:
        ensure_jenkins_responder()
    name = f"{LABEL}-jenkins-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=jenkins_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        jenkins_rm(name)


@contextmanager
def googleapis_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no witness, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with GOOGLEAPIS_LAUNCH_LOCK:
        ensure_googleapis_responder()
    name = f"{LABEL}-googleapis-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=googleapis_server_args(
                name, image_tag(server.service), server.host, server.launch
            ),
        )
    finally:
        googleapis_rm(name)


@contextmanager
def neo4j_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run plants nothing, so the lock serialises only the stand-up of the database,
    # not the yield: a server's concurrent runs share the one database that serves them all.
    with NEO4J_LAUNCH_LOCK:
        ensure_neo4j()
    name = f"{LABEL}-neo4j-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=neo4j_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        neo4j_rm(name)
