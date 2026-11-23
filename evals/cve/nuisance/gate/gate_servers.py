from dataclasses import dataclass

from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.admission.admission_walk import standing_exit
from evals.cve.nuisance.results import ServerExit


@dataclass(frozen=True)
class GateServers:
    audited: list[AdmittedServer]
    outside_gate: list[ServerExit]
    not_admitted: list[str]


def gate_servers(admission: NuisanceAdmission | None, current: set[str]) -> GateServers:
    """A nuisance acceptance server that cannot launch would keep the gate not comparable for a
    standing reason, so it stays out of the gate set."""
    admitted: list[AdmittedServer] = [] if admission is None else admission.servers
    in_gate = [server for server in admitted if server.server_package in current]
    return GateServers(
        audited=[server for server in in_gate if standing_exit(server) is None],
        outside_gate=[
            ServerExit(server.server_package, reason)
            for server in in_gate
            if (reason := standing_exit(server)) is not None
        ],
        not_admitted=sorted(current - {server.server_package for server in admitted}),
    )
