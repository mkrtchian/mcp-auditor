"""The live wiring of the `gate` subcommand."""

import functools
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from evals.concurrency import bounded
from evals.cve.closed_network import check_closed_network_support
from evals.cve.holdout_conditions import HoldoutConditions, committed_conditions
from evals.cve.images import backend_image_ids, image_ids
from evals.cve.launch_audit import RunOverrides, SessionAuditor, build_auditor
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.audit import audit_once, nuisance_audit
from evals.cve.nuisance.gate.gate_audit import GateRun, gate_run
from evals.cve.nuisance.gate.gate_baseline import (
    NUISANCE_GATE_BASELINE_DIRECTORY,
    NuisanceGateConditions,
)
from evals.cve.nuisance.gate.gate_session import run_gate
from evals.cve.nuisance.gate.gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
)
from evals.cve.nuisance.images import image_tag
from evals.cve.nuisance.vetting import LaunchedBenignCall
from evals.cve.run_images import DOCKER_SWEEP, rebuild_images
from evals.eval_session import read_tree
from evals.session_usage import SessionThrottles
from mcp_auditor.config import Settings, load_settings

type GateSessionRunner = Callable[
    [NuisanceGateOptions, NuisanceGateHarness], Coroutine[Any, Any, NuisanceGateSession]
]


def default_harness(conditions: NuisanceGateConditions, concurrency: int) -> NuisanceGateHarness:
    overrides = RunOverrides(
        conditions.chain_budget, conditions.max_chain_steps, conditions.tool_call_timeout
    )
    throttles = SessionThrottles()
    auditor = SessionAuditor(build_auditor(conditions.budget), overrides, throttles)

    async def audit(server: AdmittedServer) -> GateRun | None:
        return await gate_run(
            server, lambda: nuisance_audit(server, lambda: audit_once(server, auditor))
        )

    return NuisanceGateHarness(
        audit=bounded(audit, concurrency),
        benign_call=bounded(LaunchedBenignCall(conditions.tool_call_timeout), concurrency),
        announce_audits=lambda _: None,
        throttled_requests=lambda: throttles.requests,
        rebuild=rebuild_images,
        image_ids=functools.partial(image_ids, tag=image_tag),
        backend_image_ids=backend_image_ids,
        read_tree=read_tree,
        clock=lambda: datetime.now(UTC).isoformat(),
        baselines=NUISANCE_GATE_BASELINE_DIRECTORY,
        check_networks=check_closed_network_support,
        sweep=DOCKER_SWEEP,
    )


@dataclass(frozen=True)
class GateCommandDeps:
    conditions: Callable[[], HoldoutConditions] = committed_conditions
    settings: Callable[[], Settings] = load_settings
    harness: Callable[[NuisanceGateConditions, int], NuisanceGateHarness] = default_harness
    run_gate: GateSessionRunner = run_gate
