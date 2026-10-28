"""The nuisance pre-run check: drop from the run, before any audit, a server whose benign call
fails on its patched image."""

import asyncio
import os
from collections.abc import Awaitable, Callable, Sequence

from evals.concurrency import entered_in_thread
from evals.cve_calibration import PRE_RUN_LAUNCH_ATTEMPTS
from evals.cve_environments import connect
from evals.failure_text import TYPES_ONLY
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_audit import benign_call_failure, nuisance_environment
from evals.nuisance_results import NotRunCause, NotRunServer


async def vet_all(
    servers: Sequence[AdmittedServer],
    benign_call: Callable[[AdmittedServer], Awaitable[str | None]],
) -> tuple[list[NotRunServer], list[AdmittedServer]]:
    reasons = await asyncio.gather(*(benign_call(server) for server in servers))
    paired = list(zip(servers, reasons, strict=True))
    not_run = [
        NotRunServer(server.server_package, reason, NotRunCause.BENIGN_CALL_FAILED)
        for server, reason in paired
        if reason is not None
    ]
    return not_run, [server for server, reason in paired if reason is None]


async def benign_call(server: AdmittedServer, timeout: int) -> str | None:
    """The benign call's failure reason, or None when it answers. A launch or connection that
    fails is retried up to `PRE_RUN_LAUNCH_ATTEMPTS` launches and keeps the last reason. An answer
    that errors is an observation of a launch that ran, returned at once: retrying it would keep
    the best of several tries, and so is a failure once connected, a teardown's included."""
    reason = ""
    for _ in range(PRE_RUN_LAUNCH_ATTEMPTS):
        connected = False
        try:
            with open(os.devnull, "w") as devnull:
                async with (
                    entered_in_thread(nuisance_environment(server)) as launch,
                    connect(launch, devnull, tool_call_timeout=timeout) as client,
                ):
                    connected = True
                    return await benign_call_failure(server, client)
        except Exception as exc:
            reason = f"failed to connect for the benign call: {TYPES_ONLY.describe(exc)}"
            if connected:
                return reason
    return reason
