"""The servers the nuisance commands play alone: after every other server's calls are done, one
call at a time, so no other server's audit or benign call is in flight beside theirs. The vet,
the run and the gate share this one list."""

import asyncio
from collections.abc import Awaitable, Callable, Sequence

from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.run_interruption import first_failure

# Two reasons put a server here. First, magento2-dev-mcp bounds each magerun2 command at 30 s,
# and magerun2 exits 0 when that bound stops it, so a command cut short answers its partial
# output as a success. Magento's own work behind a call (rebuilding its config cache, compiling
# its dependency injection, upgrading its schema) stays under 30 s alone and passes it under the
# contention of other servers and their backends running beside it. Second, a server whose
# backend is bounded at 4 GiB and holds most of it, so that two such backends beside the rest of
# a command would press the host's memory. The Doris all-in-one cluster (one container, front end
# and back end together) holds about 2.1 GiB resident through its benign calls, 2.4 GiB at its
# cgroup's peak, and it stays up through the rest of the command once its server has played.
# GitLab CE with its Runner holds about 3.35 GiB anonymous memory, 3.8 GiB at its cgroup's peak.
# The other multi-container backends hold far less through their benign calls and play together:
# CKAN about 1.25 GiB, Gravitino about 1.1 GiB, n8n about 0.85 GiB, Jenkins about 0.53 GiB.
SOLO_SERVERS = frozenset(
    {"npm:@elgentos/magento2-dev-mcp", "PyPI:doris-mcp-server", "npm:@zereight/mcp-gitlab"}
)


def played_alone(server: AdmittedServer) -> bool:
    return server.server_package in SOLO_SERVERS


async def gathered_then_alone[R](
    servers: Sequence[AdmittedServer], play: Callable[[AdmittedServer], Awaitable[R]]
) -> list[R]:
    """Each server's outcome, in the servers' order: the other servers played together, then
    each solo server on its own."""
    together = [server for server in servers if not played_alone(server)]
    outcomes = dict(
        zip(
            [server.server_package for server in together],
            await asyncio.gather(*(play(server) for server in together)),
            strict=True,
        )
    )
    for server in servers:
        if played_alone(server):
            outcomes[server.server_package] = await play(server)
    return [outcomes[server.server_package] for server in servers]


async def first_failure_then_alone[R](
    servers: Sequence[AdmittedServer], play: Callable[[AdmittedServer], Awaitable[R]]
) -> tuple[list[tuple[AdmittedServer, R]], BaseException | None]:
    """`first_failure` over the other servers together, then over each solo server on its own
    while nothing has failed, the finished servers kept in the servers' order."""
    finished, failure = await first_failure(
        [server for server in servers if not played_alone(server)], play
    )
    for server in servers:
        if played_alone(server) and failure is None:
            alone, failure = await first_failure([server], play)
            finished.extend(alone)
    order = [server.server_package for server in servers]
    return sorted(finished, key=lambda pair: order.index(pair[0].server_package)), failure
