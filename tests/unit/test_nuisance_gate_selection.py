"""Which admitted servers the nuisance gate audits, and which it names as left out."""

import tests.unit.support.test_nuisance_gate_selection_given as given
from evals.cve.nuisance.gate_session import gate_servers, not_admitted, outside_gate
from evals.cve.nuisance.results import ServerExit
from tests.unit.support.test_nuisance_admission_edits_given import without_stdio
from tests.unit.support.test_nuisance_gate_session_given import FILESYSTEM, KUBERNETES

CURRENT = {FILESYSTEM.server_package, KUBERNETES.server_package}


def test_the_gate_servers_are_the_current_ones_that_run_over_stdio_in_admission_order():
    other = given.a_server_outside_the_census("npm:not-current")
    admitted = given.admitting(KUBERNETES, other, FILESYSTEM)
    no_stdio = without_stdio(given.admitting(KUBERNETES, FILESYSTEM), KUBERNETES.server_package)

    assert gate_servers(admitted, CURRENT) == [KUBERNETES, FILESYSTEM]
    assert gate_servers(no_stdio, CURRENT) == [FILESYSTEM]


def test_a_current_server_that_does_not_run_over_stdio_is_outside_the_gate_naming_why():
    no_stdio = without_stdio(given.admitting(KUBERNETES, FILESYSTEM), KUBERNETES.server_package)

    assert outside_gate(no_stdio, CURRENT) == [
        ServerExit(KUBERNETES.server_package, "does not run over stdio")
    ]


def test_a_current_package_no_admitted_server_carries_is_not_admitted():
    current = {*CURRENT, "PyPI:mcp-server-git"}

    assert not_admitted(given.admitting(FILESYSTEM), current) == [
        "PyPI:mcp-server-git",
        KUBERNETES.server_package,
    ]
