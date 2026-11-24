from collections.abc import Mapping

import tests.unit.support.grammar_inputs as grammar
from evals.cve.grammar import FlawClass, PlantedTarget
from evals.cve.units import Unit, unit_of_exchanges

NONCE_A = "MCPAUDIT-aaaaaaaa11112222"
NONCE_B = "MCPAUDIT-bbbbbbbb33334444"
FRESH_A = "MCPAUDIT-aaaaffff55556666"
FRESH_B = "MCPAUDIT-bbbbffff77778888"
PLACE_A = "alpha"
PLACE_B = "beta"


def a_target(nonces: Mapping[str, str]) -> PlantedTarget:
    return PlantedTarget(frozenset({FlawClass.READ_OUTSIDE_SCOPE}), grammar.READ_AIM, nonces)


def leaking_unit(*nonces: str) -> Unit:
    output = " ".join(f"leaked {nonce}" for nonce in nonces) if nonces else "nothing"
    return unit_of_exchanges([({"path": "/x"}, output)])


def echoing_unit(nonce: str) -> Unit:
    return unit_of_exchanges([({"path": nonce}, f"echo {nonce}")])
