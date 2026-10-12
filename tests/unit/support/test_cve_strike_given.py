import re
from collections.abc import Mapping

from evals.cve_grammar import MechanismClass, PlantedTarget
from evals.cve_units import Unit, unit_of_exchanges

NONCE_A = "MCPAUDIT-aaaaaaaa11112222"
NONCE_B = "MCPAUDIT-bbbbbbbb33334444"
FRESH_A = "MCPAUDIT-aaaaffff55556666"
FRESH_B = "MCPAUDIT-bbbbffff77778888"
PLACE_A = "alpha"
PLACE_B = "beta"
AIM = re.compile(r"^/outside/")


def a_target(
    nonces: Mapping[str, str], mechanism: MechanismClass | None = MechanismClass.READ_OUTSIDE_SCOPE
) -> PlantedTarget:
    return PlantedTarget(mechanism, AIM, nonces)


def leaking_unit(*nonces: str) -> Unit:
    output = " ".join(f"leaked {nonce}" for nonce in nonces) if nonces else "nothing"
    return unit_of_exchanges([({"path": "/x"}, output)])


def echoing_unit(nonce: str) -> Unit:
    return unit_of_exchanges([({"path": nonce}, f"echo {nonce}")])
