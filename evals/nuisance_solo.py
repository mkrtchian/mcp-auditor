"""The servers the nuisance commands play alone: after every other server's calls are done, one
call at a time, so no other server's audit or benign call is in flight beside theirs. The vet,
the run and the gate share this one list."""

import asyncio
from collections.abc import Awaitable, Callable, Sequence

from evals.nuisance_admission import AdmittedServer
from evals.run_interruption import first_failure

# magento2-dev-mcp bounds each magerun2 command at 30 s, and magerun2 exits 0 when that bound
# stops it, so a command cut short answers its partial output as a success. Magento's own work
# behind a call (rebuilding its config cache, compiling its dependency injection, upgrading its
# schema) stays under 30 s alone and passes it under the contention of other servers and their
# backends running beside it.
SOLO_SERVERS = frozenset({"npm:@elgentos/magento2-dev-mcp"})


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
