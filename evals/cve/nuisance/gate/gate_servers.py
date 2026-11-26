import sys
from dataclasses import dataclass

from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.gate.gate_report import outside_gate_line
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
        audited=[server for server in in_gate if server.standing_exit is None],
        outside_gate=[
            ServerExit(server.server_package, reason)
            for server in in_gate
            if (reason := server.standing_exit) is not None
        ],
        not_admitted=sorted(current - {server.server_package for server in admitted}),
    )


def print_empty_gate(outside: list[ServerExit]) -> None:
    if not outside:
        print("no nuisance acceptance server is admitted")
        return
    print("no admitted nuisance acceptance server can run in the gate")
    for server in outside:
        print(f"- {outside_gate_line(server)}")


def print_unknown_gate_servers(unknown: list[str], gate_set: list[str]) -> None:
    print(
        f"unknown gate server: {', '.join(unknown)} (gate set: {', '.join(gate_set)})",
        file=sys.stderr,
    )
