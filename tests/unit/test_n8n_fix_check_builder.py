from evals.nuisance_fix_checks import cve_2026_44694_n8n as n8n


def test_server_env_points_the_api_url_at_the_stand_in():
    args = n8n.n8n_server_env_args()

    assert f"N8N_API_URL=http://{n8n.STAND_IN_IP}/" in args
    assert "N8N_API_KEY=calib-key" in args


def test_server_env_turns_telemetry_off():
    assert "N8N_MCP_TELEMETRY_DISABLED=true" in n8n.n8n_server_env_args()
