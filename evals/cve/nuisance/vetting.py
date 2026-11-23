"""The vet of a nuisance holdout run: drop from the run, before any audit, a server whose benign
call fails on its patched image. A server whose first pass fails gets a second pass, alone and on a
fresh launch once every first pass has finished, and is dropped only when that pass fails too: a
fixture whose real software is slow or nondeterministic, or whose backend sets a state in the
background, can fail one pass while sound, and a broken fixture fails both. Before its second
pass, the server's backend containers are removed, so its provisioner stands the backend again
from its image and its seed, since a first pass can change a backend's state."""

import os
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field

from evals.concurrency import entered_in_thread
from evals.cve.environments import Launch, connect
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.launch_audit import Connect, named
from evals.cve.launch_retry import PRE_RUN_LAUNCH_ATTEMPTS
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.audit import nuisance_environment
from evals.cve.nuisance.benign_call import benign_call_failure
from evals.cve.nuisance.containers import remove_backend_containers, run_images
from evals.cve.nuisance.results import NotRunCause, NotRunServer
from evals.cve.nuisance.solo import gathered_then_alone
from evals.cve.run_images import ContainerSweep

type BenignCall = Callable[[AdmittedServer], Awaitable[str | None]]


@dataclass(frozen=True)
class VetResult:
    not_run: list[NotRunServer]
    surviving: list[AdmittedServer]
    # The servers run only after a clean second pass, to the first pass's reason: unlike the
    # detection's list of targets, it keeps the reason, the lever to repair an intermittent fixture.
    second_pass: dict[str, str]


async def drop_failing_servers(
    servers: Sequence[AdmittedServer], benign_call: BenignCall, sweep: ContainerSweep
) -> VetResult:
    first_reasons = await gathered_then_alone(servers, benign_call)
    final_reasons = [  # one second pass at a time, in the servers' order
        None if first is None else await _second_pass(server, benign_call, sweep)
        for server, first in zip(servers, first_reasons, strict=True)
    ]
    passes = list(zip(servers, first_reasons, final_reasons, strict=True))
    return VetResult(
        not_run=[
            NotRunServer(server.server_package, final, NotRunCause.BENIGN_CALL_FAILED)
            for server, _, final in passes
            if final is not None
        ],
        surviving=[server for server, _, final in passes if final is None],
        second_pass={
            server.server_package: first
            for server, first, final in passes
            if first is not None and final is None
        },
    )


async def _second_pass(
    server: AdmittedServer, benign_call: BenignCall, sweep: ContainerSweep
) -> str | None:
    remove_backend_containers(sweep, run_images([server]))
    return await benign_call(server)


@dataclass(frozen=True)
class ServerLauncher:
    environment: Callable[[AdmittedServer], AbstractContextManager[Launch]] = nuisance_environment
    connect: Connect = connect


@dataclass(frozen=True)
class LaunchedBenignCall:
    """The benign call's failure reason, or None when it answers. A launch or connection that
    fails is retried up to `PRE_RUN_LAUNCH_ATTEMPTS` launches and keeps the last reason. An answer
    that errors is an observation of a launch that ran, returned at once: retrying it would keep
    the best of several tries, and so is a failure once connected, a teardown's included. The
    vet's second pass (`drop_failing_servers`) is the one further try, made on a fresh launch after
    every first pass.
    `on_ping`, when given, gets whether the server answers a ping sent right after the handshake,
    and a server that never connects never calls it."""

    timeout: int
    on_ping: Callable[[AdmittedServer, bool], None] | None = None
    launcher: ServerLauncher = field(default_factory=ServerLauncher)

    async def __call__(self, server: AdmittedServer) -> str | None:
        reason = ""
        for _ in range(PRE_RUN_LAUNCH_ATTEMPTS):
            connected = False
            try:
                with open(os.devnull, "w") as devnull:
                    async with (
                        entered_in_thread(self.launcher.environment(server)) as launch,
                        self.launcher.connect(
                            named(launch), devnull, tool_call_timeout=self.timeout
                        ) as client,
                    ):
                        connected = True
                        if self.on_ping is not None:
                            self.on_ping(server, await client.ping())
                        return await benign_call_failure(server, client)
            except Exception as exc:
                reason = f"failed to connect for the benign call: {TYPES_ONLY.describe(exc)}"
                if connected:
                    return reason
        return reason
