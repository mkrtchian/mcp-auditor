from evals.cve.backends.n8n import N8N_IP, n8n_server_args, singleton_run_args
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.unit.support.docker_argv import environment, value_after

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)


def test_the_n8n_server_reaches_the_instance_on_its_default_port_with_its_issued_key():
    args = n8n_server_args("server-name", "image", HOST, ["serve"])

    assert environment(args)["N8N_API_URL"] == f"http://{N8N_IP}:5678/"
    assert "N8N_API_KEY" in environment(args)


def test_the_n8n_server_leaves_telemetry_at_its_documented_default():
    args = n8n_server_args("server-name", "image", HOST, ["serve"])

    assert "N8N_MCP_TELEMETRY_DISABLED" not in environment(args)


def test_the_n8n_instance_stands_at_the_address_the_server_reaches_on_its_bridge():
    args = singleton_run_args()

    assert value_after(args, "--network") == BACKENDS["n8n"].network
    assert value_after(args, "--ip") == N8N_IP
    assert (args[-1],) == BACKENDS["n8n"].images
