"""The code standards violations the tree still carries, each keyed by path, standard and symbol.

An entry is added only for a violation blocked by a fingerprinted file (one an eval fingerprint
hashes, which cannot change without moving that fingerprint) or by a third-party package, and it
names that blocker. It is paid when the blocker changes for its own reason. The violations blocked
by nothing, grouped by file, are still to clear: the list only shrinks.
"""

from dataclasses import dataclass

from tests.unit.project.support.code_standards_scan import CodeStandard


@dataclass(frozen=True)
class FingerprintedFile:
    path: str


@dataclass(frozen=True)
class ThirdParty:
    distribution: str
    reason: str


@dataclass(frozen=True)
class Debt:
    path: str
    standard: CodeStandard
    symbol: str
    blocked_by: FingerprintedFile | ThirdParty | None  # None: not blocked, to be cleared


NEWSPAPER = CodeStandard.NEWSPAPER_ORDER
FOREIGN = CodeStandard.FOREIGN_GIVEN_THEN
SETATTR = CodeStandard.MONKEYPATCH_SETATTR

_FIREWORKS_RETRY = ThirdParty(
    "langchain-core",
    "langchain_fireworks retries through langchain_core's create_base_retry_decorator, whose "
    "tenacity wait_exponential(min=4) is hard-coded",
)
_GOOGLE_RETRY = ThirdParty(
    "google-genai",
    "the throttled call is retried by google-genai's own retry loop, which waits between attempts",
)

_UNBLOCKED: dict[str, tuple[tuple[CodeStandard, str], ...]] = {
    "evals/baseline.py": (
        (NEWSPAPER, "fingerprint_ground_truth"),
        (NEWSPAPER, "fingerprint_source"),
    ),
    "evals/capture_stand_in.py": (
        (NEWSPAPER, "capture_record"),
        (NEWSPAPER, "parse_request"),
    ),
    "evals/cve/backends/apify.py": ((NEWSPAPER, "_read_only_mounts"),),
    "evals/cve/census/census.py": (
        (NEWSPAPER, "date_mismatches"),
        (NEWSPAPER, "draw_candidates"),
    ),
    "evals/cve/census/classification.py": (
        (NEWSPAPER, "in_grammar"),
        (NEWSPAPER, "normalized_class"),
    ),
    "evals/cve/census/draw_order.py": ((NEWSPAPER, "draw_digest"),),
    "evals/cve/census/grouping.py": ((NEWSPAPER, "gap_population"),),
    "evals/cve/census/identity.py": ((NEWSPAPER, "flaw_id_of"),),
    "evals/cve/detection/audit.py": ((NEWSPAPER, "build_auditor"),),
    "evals/cve/detection/calibration_check.py": (
        (NEWSPAPER, "check_target"),
        (NEWSPAPER, "not_fixed_reasons"),
        (NEWSPAPER, "not_live_reasons"),
    ),
    "evals/cve/detection/calibration_dossier.py": (
        (NEWSPAPER, "acceptance_services"),
        (NEWSPAPER, "copy_kit_sources"),
    ),
    "evals/cve/detection/costs.py": ((NEWSPAPER, "target_costs"),),
    "evals/cve/detection/draw_record.py": ((NEWSPAPER, "governing_steps"),),
    "evals/cve/detection/holdout_fixtures/cve_2025_11489_desktop_commander.py": (
        (NEWSPAPER, "_coordinate_paths"),
        (NEWSPAPER, "_link_indices"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2025_53818_github_kanban.py": (
        (NEWSPAPER, "_cmd_for"),
        (NEWSPAPER, "_payload"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2025_58358_markdownify.py": ((NEWSPAPER, "_reader"),),
    "evals/cve/detection/holdout_fixtures/cve_2025_65719_kubectl.py": ((NEWSPAPER, "_cmd_for"),),
    "evals/cve/detection/holdout_fixtures/cve_2025_66335_doris.py": ((NEWSPAPER, "_inject_call"),),
    "evals/cve/detection/holdout_fixtures/cve_2025_9654_mcp_ssh.py": (
        (NEWSPAPER, "_injection"),
        (NEWSPAPER, "_snippet_for"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_15415_healthomics.py": (
        (NEWSPAPER, "_bundle_args"),
        (NEWSPAPER, "_read_target"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_19978_android.py": (
        (NEWSPAPER, "_injection"),
        (NEWSPAPER, "_read_cmd"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_2130_maigret.py": (
        (NEWSPAPER, "_file_paths"),
        (NEWSPAPER, "injection_command"),
        (NEWSPAPER, "payload"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_25546_godot_mcp.py": ((NEWSPAPER, "_payload"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_26029_sf_mcp.py": (
        (NEWSPAPER, "_call"),
        (NEWSPAPER, "_read_command"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_33060_ckan.py": ((NEWSPAPER, "_ssrf_base_url"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_35402_neo4j_cypher.py": (
        (NEWSPAPER, "_exploit_query"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_3680_biome.py": ((NEWSPAPER, "_payload_for"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_42260_open_websearch.py": (
        (NEWSPAPER, "_mapped_url"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_4270_aws_api_mcp.py": (
        (NEWSPAPER, "_read_command"),
        (NEWSPAPER, "_readable_path"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_44717_calculate.py": (
        (NEWSPAPER, "_file_payload"),
        (NEWSPAPER, "_payload"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_46514_frogman.py": (
        (NEWSPAPER, "_inject_args"),
        (NEWSPAPER, "_read_command"),
        (NEWSPAPER, "_readback_args"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_47394_praisonai.py": (
        (NEWSPAPER, "_read_paths"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_5323_a11y.py": ((NEWSPAPER, "_url"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_53710_python_sandbox.py": (
        (NEWSPAPER, "_argv_for"),
        (NEWSPAPER, "_escape"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_55157_token_optimizer.py": (
        (NEWSPAPER, "_call"),
        (NEWSPAPER, "_payload"),
        (NEWSPAPER, "_read_command"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_55581_mcp_shell.py": (
        (NEWSPAPER, "_command_for"),
        (NEWSPAPER, "_file_command"),
        (NEWSPAPER, "_http_command"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_55787_flyto.py": ((NEWSPAPER, "_mapped_url"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_5603_magento2.py": ((NEWSPAPER, "_payload"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_5833_taskwarrior.py": ((NEWSPAPER, "_payload"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_58485_searxng.py": ((NEWSPAPER, "_ssrf_url"),),
    "evals/cve/detection/holdout_fixtures/cve_2026_65831_arcadedb.py": (
        (NEWSPAPER, "_command_for"),
        (NEWSPAPER, "_fetch_url_js"),
        (NEWSPAPER, "_read_file_js"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_7785_wireshark.py": (
        (NEWSPAPER, "_breakout"),
        (NEWSPAPER, "_file_read_cmd"),
        (NEWSPAPER, "_http_payload"),
        (NEWSPAPER, "_payload_for"),
        (NEWSPAPER, "_quick_capture"),
        (NEWSPAPER, "_shell_read_payload"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_81562_claude_in_mobile.py": (
        (NEWSPAPER, "_inject"),
        (NEWSPAPER, "_shell"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_82112_houtini_lm.py": (
        (NEWSPAPER, "_code_task_files"),
        (NEWSPAPER, "_read_path"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_85787_postgres.py": (
        (NEWSPAPER, "_connect"),
        (NEWSPAPER, "_first_path"),
        (NEWSPAPER, "_run_query"),
    ),
    "evals/cve/detection/holdout_fixtures/cve_2026_85788_mysql.py": (
        (NEWSPAPER, "_connect"),
        (NEWSPAPER, "_read_targets"),
    ),
    "evals/cve/detection/holdout_fixtures/ghsa_8g7g_hmwm_6rv2_n8n.py": ((NEWSPAPER, "_trigger"),),
    "evals/cve/detection/layout_check.py": (
        (NEWSPAPER, "layout_breaks"),
        (NEWSPAPER, "layout_breaks_any"),
        (NEWSPAPER, "layout_check"),
        (NEWSPAPER, "layout_check_gave_up"),
        (NEWSPAPER, "layout_failure"),
        (NEWSPAPER, "layout_routes"),
        (NEWSPAPER, "leaking_places"),
        (NEWSPAPER, "nonce_in_surface"),
        (NEWSPAPER, "unrouted_kept_places"),
    ),
    "evals/cve/detection/measurement.py": (
        (NEWSPAPER, "measurement_from"),
        (NEWSPAPER, "missing_price"),
    ),
    "evals/cve/detection/session_recording.py": ((NEWSPAPER, "load_checked"),),
    "evals/cve/detection/survey.py": (
        (NEWSPAPER, "candidates_for"),
        (NEWSPAPER, "survey_groups"),
        (NEWSPAPER, "survey_lines"),
    ),
    "evals/cve/detection/targets.py": ((NEWSPAPER, "image_tag"),),
    "evals/cve/dossier_closure.py": ((NEWSPAPER, "import_closure"),),
    "evals/cve/holdout_intervals.py": ((NEWSPAPER, "wilson"),),
    "evals/cve/images.py": ((NEWSPAPER, "compose_build"),),
    "evals/cve/kit/benign_probe.py": (
        (NEWSPAPER, "record_host"),
        (NEWSPAPER, "single_container_launch"),
    ),
    "evals/cve/kit/driver.py": (
        (NEWSPAPER, "launch_user_condition"),
        (NEWSPAPER, "options_before_image"),
    ),
    "evals/cve/kit/fix_check.py": ((NEWSPAPER, "benign_transcript"),),
    "evals/cve/kit/launch.py": ((NEWSPAPER, "image_tag"),),
    "evals/cve/nuisance/admission/unrecorded.py": ((NEWSPAPER, "unrecorded_fields"),),
    "evals/cve/nuisance/admission/walk.py": (
        (NEWSPAPER, "acceptance_target_servers"),
        (NEWSPAPER, "candidate_counted_flaws"),
        (NEWSPAPER, "census_flaws_of"),
        (NEWSPAPER, "server_of"),
    ),
    "evals/cve/nuisance/admission/walk_record.py": ((NEWSPAPER, "reached_identifiers"),),
    "evals/cve/nuisance/audit.py": ((NEWSPAPER, "nuisance_environment"),),
    "evals/cve/nuisance/backend_registry.py": ((NEWSPAPER, "built_backend_services"),),
    "evals/cve/nuisance/fix_checks/cve_2025_15061_figma.py": ((NEWSPAPER, "server_args"),),
    "evals/cve/nuisance/fix_checks/cve_2026_10276_jenkins.py": (
        (NEWSPAPER, "controller_args"),
        (NEWSPAPER, "plant_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_11720_googleapis.py": (
        (NEWSPAPER, "responder_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_18905_contextforge.py": ((NEWSPAPER, "_find_tool"),),
    "evals/cve/nuisance/fix_checks/cve_2026_19956_facebook_ads.py": (
        (NEWSPAPER, "sentinel_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_35402_neo4j_cypher.py": (
        (NEWSPAPER, "neo4j_container_args"),
        (NEWSPAPER, "sentinel_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_40576_excel.py": ((NEWSPAPER, "excel_env"),),
    "evals/cve/nuisance/fix_checks/cve_2026_41041_gravitino.py": (
        (NEWSPAPER, "part_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_46341_apify.py": (
        (NEWSPAPER, "responder_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_54561_memory_keeper.py": (
        (NEWSPAPER, "_import_then_get"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_55787_flyto.py": (
        (NEWSPAPER, "_ensure_redirector_image"),
        (NEWSPAPER, "_remove"),
        (NEWSPAPER, "_run_detached"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_57496_netlicensing.py": ((NEWSPAPER, "_token_route"),),
    "evals/cve/nuisance/fix_checks/cve_2026_61462_gitlab.py": (
        (NEWSPAPER, "responder_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_73845_ckan.py": ((NEWSPAPER, "_bypass_url"),),
    "evals/cve/nuisance/fix_checks/cve_2026_77252_atlassian.py": (
        (NEWSPAPER, "responder_args"),
        (NEWSPAPER, "server_args"),
    ),
    "evals/cve/nuisance/fix_checks/cve_2026_82112_houtini.py": ((NEWSPAPER, "_code_task_files"),),
    "evals/cve/nuisance/fix_checks/mcp_ssh_fix_check.py": (
        (NEWSPAPER, "_exploit"),
        (NEWSPAPER, "_exploits"),
        (NEWSPAPER, "server_args"),
        (NEWSPAPER, "ssh_env"),
    ),
    "evals/cve/nuisance/fix_checks/n8n_redirect_stand_in.py": ((NEWSPAPER, "n8n_server_env_args"),),
    "evals/cve/nuisance/gate/gate_baseline.py": ((NEWSPAPER, "baseline_file_name"),),
    "evals/cve/nuisance/gate/gate_session_recording.py": ((NEWSPAPER, "load_checked"),),
    "evals/cve/nuisance/solo.py": ((NEWSPAPER, "played_alone"),),
    "evals/cve/provider_errors.py": ((NEWSPAPER, "classify"),),
    "evals/cve/run_files.py": ((NEWSPAPER, "write_result"),),
    "evals/detection_preflight.py": ((NEWSPAPER, "expected_services"),),
    "evals/draw_judge_cases.py": (
        (NEWSPAPER, "candidates_from_detection"),
        (NEWSPAPER, "candidates_from_honeypot"),
        (NEWSPAPER, "complement"),
        (NEWSPAPER, "complement_refusals"),
        (NEWSPAPER, "draw"),
        (NEWSPAPER, "draw_fixture"),
    ),
    "evals/export.py": (
        (NEWSPAPER, "detection_export_path"),
        (NEWSPAPER, "nuisance_gate_export_path"),
    ),
    "evals/gate.py": ((NEWSPAPER, "recall_floor_breached"),),
    "evals/judge/fixture.py": ((NEWSPAPER, "case_id"),),
    "evals/judge/gate.py": ((NEWSPAPER, "compare_cases"),),
    "evals/judge/metrics.py": ((NEWSPAPER, "compute_judge_metrics"),),
    "evals/judge/recording.py": ((NEWSPAPER, "judge_unconfirmed_commit_refusal"),),
    "evals/metrics.py": (
        (NEWSPAPER, "blocked_reasons"),
        (NEWSPAPER, "compute_distribution_coverage"),
        (NEWSPAPER, "compute_precision"),
        (NEWSPAPER, "compute_recall"),
        (NEWSPAPER, "missed_model_calls"),
    ),
    "evals/recording.py": (
        (NEWSPAPER, "condition_refusals"),
        (NEWSPAPER, "unconfirmed_commit_refusal"),
    ),
    "evals/run_detection_holdout.py": ((NEWSPAPER, "_census"),),
    "src/mcp_auditor/domain/owasp.py": (
        (NEWSPAPER, "owasp_id_for"),
        (NEWSPAPER, "owasp_label_for"),
    ),
    "src/mcp_auditor/domain/relaunch_rendering.py": ((NEWSPAPER, "describe_relaunch"),),
    "src/mcp_auditor/domain/rendering.py": (
        (NEWSPAPER, "describe_coverage_gap"),
        (NEWSPAPER, "describe_missed_model_call"),
        (NEWSPAPER, "format_severity_breakdown"),
    ),
    "src/mcp_auditor/domain/server_watch.py": (
        (NEWSPAPER, "is_lost_connection"),
        (NEWSPAPER, "is_timeout"),
    ),
    "src/mcp_auditor/domain/shown_response.py": ((NEWSPAPER, "rendered_response"),),
    "src/mcp_auditor/graph/nodes.py": ((NEWSPAPER, "route_test_cases"),),
    "src/mcp_auditor/graph/prompts.py": ((NEWSPAPER, "format_tool_header"),),
    "tests/conftest.py": (
        (SETATTR, "_no_dotenv_in_tests:'mcp_auditor.config.load_dotenv'"),
        (NEWSPAPER, "_noop_load_dotenv"),
    ),
    "tests/fakes/scripted_docker.py": ((SETATTR, "ScriptedDocker:subprocess.run"),),
    "tests/integration/committed/cve/backends/support/test_backend_hostnames_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
        (NEWSPAPER, "admitted_servers"),
        (NEWSPAPER, "part_dockerfile_env"),
        (NEWSPAPER, "the_admitted_server"),
    ),
    "tests/integration/committed/cve/backends/support/test_mcp_ssh_sshd_backend_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/cve/support/test_committed_stand_ins_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
        (NEWSPAPER, "is_ip_literal"),
    ),
    "tests/integration/committed/nuisance/admission/test_nuisance_admission_loads.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/nuisance/admission/test_nuisance_re_admission_dossier.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/nuisance/fix_checks/support/test_nuisance_fix_checks_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/nuisance/fix_checks/test_nuisance_fix_checks.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/nuisance/test_nuisance_backend_registry_built.py": (
        (FOREIGN, "test_backend_lifecycle_given"),
        (NEWSPAPER, "_is_built"),
    ),
    "tests/integration/committed/nuisance/test_nuisance_compose.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/nuisance/test_nuisance_fixture_sources.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/project/support/test_workflow_path_filters_given.py": (
        (NEWSPAPER, "path_filters"),
    ),
    "tests/integration/support/docker_prerequisites.py": (
        (FOREIGN, "test_cve_planting_given"),
        (NEWSPAPER, "skip_or_require"),
    ),
    "tests/integration/support/stalling_server.py": (
        (NEWSPAPER, "_answered_with_an_error"),
        (NEWSPAPER, "_log_shutdown_once_stdin_closes"),
        (NEWSPAPER, "_never_answered"),
        (NEWSPAPER, "_served_before"),
    ),
    "tests/integration/support/test_cve_closed_networks_given.py": (
        (FOREIGN, "test_cve_planting_given"),
        (NEWSPAPER, "a_network_name"),
        (NEWSPAPER, "routes"),
    ),
    "tests/integration/support/test_cve_keyed_stand_in_routes_given.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
    ),
    "tests/integration/support/test_cve_layout_mount_given.py": (
        (FOREIGN, "test_cve_planting_given"),
    ),
    "tests/integration/support/test_cve_planting_given.py": ((NEWSPAPER, "spec_of"),),
    "tests/integration/support/test_cve_planting_stand_ins_given.py": (
        (FOREIGN, "test_cve_planting_given"),
    ),
    "tests/integration/support/test_cve_planting_stand_ins_then.py": ((NEWSPAPER, "carries"),),
    "tests/integration/support/test_detection_replay_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (NEWSPAPER, "a_places_mapping"),
    ),
    "tests/integration/support/unconfined_audit.py": ((NEWSPAPER, "an_unconfined_audit"),),
    "tests/integration/test_audit_server_failures.py": (
        (
            SETATTR,
            "test_a_local_failure_before_the_session_opens_is_not_blamed_on_the_server:audit.checkpoint_db_path",
        ),
    ),
    "tests/integration/test_cve_keyed_stand_in_routes.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
        (FOREIGN, "test_cve_planting_stand_ins_then"),
    ),
    "tests/integration/test_cve_planting_stand_ins.py": (
        (FOREIGN, "test_cve_planting_given"),
        (FOREIGN, "test_cve_planting_then"),
    ),
    "tests/integration/test_detection_calibration_check.py": (
        (NEWSPAPER, "_check"),
        (NEWSPAPER, "_survey"),
    ),
    "tests/integration/test_detection_replay.py": (
        (
            SETATTR,
            "test_a_patched_server_that_stops_answering_leaves_the_credit_unchecked:mcp_client.PING_TIMEOUT_SECONDS",
        ),
    ),
    "tests/integration/test_kit.py": ((NEWSPAPER, "_missing_prerequisite"),),
    "tests/integration/test_kit_client.py": ((FOREIGN, "test_mcp_client_given"),),
    "tests/integration/test_mcp_client_relaunch.py": (
        (
            SETATTR,
            "test_a_teardown_past_its_bound_returns_false:mcp_client.TEARDOWN_TIMEOUT_SECONDS",
        ),
    ),
    "tests/integration/test_nuisance_doris_backend.py": ((NEWSPAPER, "_missing_prerequisite"),),
    "tests/integration/test_nuisance_public_names.py": (
        (FOREIGN, "test_cve_planting_given"),
        (FOREIGN, "test_cve_planting_stand_ins_given"),
        (FOREIGN, "test_cve_planting_then"),
    ),
    "tests/integration/test_subtle_server.py": ((NEWSPAPER, "connected_subtle_server"),),
    "tests/unit/auditor/support/chain_states.py": (
        (NEWSPAPER, "a_payload"),
        (NEWSPAPER, "a_tool"),
    ),
    "tests/unit/auditor/support/report_builders.py": ((NEWSPAPER, "a_two_tool_report"),),
    "tests/unit/auditor/support/test_attack_context_given.py": (
        (NEWSPAPER, "a_text_of"),
        (NEWSPAPER, "items"),
    ),
    "tests/unit/auditor/support/test_chain_nodes_given.py": ((NEWSPAPER, "a_fail_judge_result"),),
    "tests/unit/auditor/support/test_cli_given.py": (
        (FOREIGN, "test_models_given"),
        (NEWSPAPER, "a_report_with_a_missed_call"),
    ),
    "tests/unit/auditor/support/test_console_given.py": (
        (NEWSPAPER, "a_refused_chain_planning_on_list_items"),
        (NEWSPAPER, "a_report_with_two_tools"),
    ),
    "tests/unit/auditor/support/test_context_extraction_prompt_given.py": (
        (NEWSPAPER, "a_tool_report"),
    ),
    "tests/unit/auditor/support/test_generate_test_cases_given.py": ((NEWSPAPER, "a_payload"),),
    "tests/unit/auditor/support/test_graph_throttling_given.py": (
        (FOREIGN, "test_llm_throttling_given"),
        (NEWSPAPER, "no_wait"),
    ),
    "tests/unit/auditor/support/test_llm_adapter_given.py": ((NEWSPAPER, "a_completion"),),
    "tests/unit/auditor/support/test_llm_patience_given.py": (
        (FOREIGN, "test_llm_adapter_given"),
        (FOREIGN, "test_llm_refusals_given"),
        (FOREIGN, "test_llm_throttling_given"),
        (NEWSPAPER, "a_throttle"),
    ),
    "tests/unit/auditor/support/test_llm_refusals_given.py": ((FOREIGN, "test_llm_adapter_given"),),
    "tests/unit/auditor/support/test_llm_throttling_given.py": (
        (NEWSPAPER, "an_openai_rate_limit"),
    ),
    "tests/unit/auditor/support/test_model_inputs_golden_given.py": (
        (FOREIGN, "test_llm_adapter_given"),
    ),
    "tests/unit/auditor/support/test_models_given.py": (
        (NEWSPAPER, "a_judge_result"),
        (NEWSPAPER, "a_payload"),
        (NEWSPAPER, "a_tool"),
    ),
    "tests/unit/auditor/support/test_nodes_given.py": (
        (NEWSPAPER, "a_judge_result"),
        (NEWSPAPER, "a_judged_case"),
        (NEWSPAPER, "a_payload"),
        (NEWSPAPER, "a_test_case"),
        (NEWSPAPER, "a_tool"),
    ),
    "tests/unit/auditor/support/test_server_watch_given.py": ((NEWSPAPER, "a_relaunch_from"),),
    "tests/unit/auditor/support/test_throttling_given.py": (
        (NEWSPAPER, "an_httpx_client_answering"),
    ),
    "tests/unit/auditor/support/test_unsent_calls_given.py": (
        (NEWSPAPER, "a_chain_goal"),
        (NEWSPAPER, "a_tool"),
    ),
    "tests/unit/auditor/test_anthropic_structured_output.py": ((NEWSPAPER, "_wire_payload"),),
    "tests/unit/auditor/test_audited_server.py": ((NEWSPAPER, "_a_payload"),),
    "tests/unit/auditor/test_chain_models.py": ((FOREIGN, "test_chain_nodes_given"),),
    "tests/unit/auditor/test_chain_prompts.py": (
        (FOREIGN, "test_chain_nodes_given"),
        (FOREIGN, "test_shown_response_given"),
        (FOREIGN, "test_shown_response_then"),
    ),
    "tests/unit/auditor/test_chat_model_factory.py": ((NEWSPAPER, "_transport_of"),),
    "tests/unit/auditor/test_config.py": ((NEWSPAPER, "_settings"),),
    "tests/unit/auditor/test_console_display.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/auditor/test_console_findings.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/auditor/test_context_extraction_prompt.py": (
        (FOREIGN, "test_shown_response_given"),
        (FOREIGN, "test_shown_response_then"),
    ),
    "tests/unit/auditor/test_openrouter_models.py": (
        (NEWSPAPER, "_catalog"),
        (NEWSPAPER, "_warnings"),
    ),
    "tests/unit/auditor/test_progress.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/auditor/test_prompts.py": (
        (FOREIGN, "test_shown_response_given"),
        (FOREIGN, "test_shown_response_then"),
    ),
    "tests/unit/auditor/test_relaunch_rendering.py": ((FOREIGN, "test_rendering_then"),),
    "tests/unit/auditor/test_relayed_environment.py": ((NEWSPAPER, "_resolved"),),
    "tests/unit/auditor/test_stream_handler.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/census/support/test_census_draw_order_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_given"),
    ),
    "tests/unit/census/support/test_census_figures_given.py": (
        (NEWSPAPER, "a_classification"),
        (NEWSPAPER, "the_same_flaw_seen_as"),
    ),
    "tests/unit/census/support/test_census_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_grouping_given"),
        (FOREIGN, "test_census_identity_given"),
        (NEWSPAPER, "a_flaw_with_records"),
        (NEWSPAPER, "with_a_classifier_date_differing_from_the_computed_one"),
    ),
    "tests/unit/census/support/test_census_grouping_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (NEWSPAPER, "a_judgment"),
    ),
    "tests/unit/census/support/test_census_identity_given.py": (
        (FOREIGN, "test_census_sources_given"),
    ),
    "tests/unit/census/support/test_run_census_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_sources_given"),
    ),
    "tests/unit/census/test_census.py": ((FOREIGN, "test_census_identity_given"),),
    "tests/unit/census/test_census_classification.py": ((FOREIGN, "test_census_figures_given"),),
    "tests/unit/census/test_census_grouping.py": ((FOREIGN, "test_census_figures_given"),),
    "tests/unit/census/test_census_identity.py": ((FOREIGN, "test_census_sources_given"),),
    "tests/unit/census/test_census_prefilter.py": (
        (FOREIGN, "test_census_sources_given"),
        (NEWSPAPER, "a_package_term"),
    ),
    "tests/unit/census/test_run_census.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_census_sources_given"),
    ),
    "tests/unit/cve/backends/support/test_backend_lifecycle_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (NEWSPAPER, "_a_control_plane_with_no_container"),
        (NEWSPAPER, "_a_gitlab_with_no_container"),
        (NEWSPAPER, "_a_socket_with_no_engine"),
        (NEWSPAPER, "a_host"),
    ),
    "tests/unit/cve/backends/support/test_ckan_holdout_builder_given.py": (
        (NEWSPAPER, "the_targets_spec"),
    ),
    "tests/unit/cve/backends/support/test_node_sandbox_engine_given.py": (
        (SETATTR, "a_docker_whose_engine_opens_its_socket:subprocess.run"),
    ),
    "tests/unit/cve/backends/support/test_searxng_backend_given.py": (
        (NEWSPAPER, "the_targets_spec"),
    ),
    "tests/unit/cve/backends/test_backend_lifecycle.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (
            SETATTR,
            "test_a_backend_module_whose_lifecycle_is_neither_kind_is_refused_by_name:importlib.import_module",
        ),
    ),
    "tests/unit/cve/backends/test_facebook_ads_backend.py": ((NEWSPAPER, "run_launch"),),
    "tests/unit/cve/support/cve_grammar_golden_corpus.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/cve/support/test_capture_stand_in_given.py": ((NEWSPAPER, "a_not_found_answer"),),
    "tests/unit/cve/support/test_cve_grammar_golden_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_strike_given"),
    ),
    "tests/unit/cve/support/test_cve_keyed_stand_in_routes_given.py": (
        (NEWSPAPER, "a_keyed_route"),
    ),
    "tests/unit/cve/support/test_cve_launch_audit_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (NEWSPAPER, "graph_reporting"),
    ),
    "tests/unit/cve/support/test_cve_places_given.py": ((NEWSPAPER, "written"),),
    "tests/unit/cve/support/test_cve_server_health_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
    "tests/unit/cve/support/test_kit_benign_probe_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (SETATTR, "a_fake_lifecycle_resolved_by_key:benign_probe.lifecycle_of"),
        (SETATTR, "a_probe_answering:benign_probe.probe"),
        (NEWSPAPER, "a_call"),
        (NEWSPAPER, "a_record_with_benign_calls"),
        (NEWSPAPER, "a_server"),
        (NEWSPAPER, "the_record_of"),
    ),
    "tests/unit/cve/support/test_kit_fix_check_given.py": ((NEWSPAPER, "a_witness"),),
    "tests/unit/cve/test_capture_kept_default.py": ((NEWSPAPER, "_capture_keeping"),),
    "tests/unit/cve/test_cve_audit_progress.py": (
        (NEWSPAPER, "_descriptions"),
        (NEWSPAPER, "_task"),
    ),
    "tests/unit/cve/test_cve_closed_network_refusal.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_vet_given"),
    ),
    "tests/unit/cve/test_cve_fixture_provenance.py": (
        (NEWSPAPER, "_a_stand_in"),
        (NEWSPAPER, "_an_output"),
    ),
    "tests/unit/cve/test_cve_holdout_conditions.py": (
        (NEWSPAPER, "_complete_payload"),
        (NEWSPAPER, "_payload_with_luna_cutoff"),
        (NEWSPAPER, "_refusal_reasons"),
        (NEWSPAPER, "_write"),
    ),
    "tests/unit/cve/test_cve_holdout_intervals.py": ((NEWSPAPER, "_close"),),
    "tests/unit/cve/test_cve_holdout_statistic.py": (
        (NEWSPAPER, "_result"),
        (NEWSPAPER, "_split_sides"),
    ),
    "tests/unit/cve/test_cve_launch_audit.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/cve/test_cve_launches.py": ((NEWSPAPER, "_root"),),
    "tests/unit/cve/test_cve_layout.py": ((NEWSPAPER, "_git_log_patch"),),
    "tests/unit/cve/test_cve_planting.py": ((NEWSPAPER, "_args_in"),),
    "tests/unit/cve/test_cve_provider_errors.py": ((FOREIGN, "test_llm_throttling_given"),),
    "tests/unit/cve/test_cve_strike.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/cve/test_kit_isolation.py": ((FOREIGN, "test_census_given"),),
    "tests/unit/detection/support/detection_audits.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_launch_audit_given"),
        (FOREIGN, "test_eval_display_given"),
    ),
    "tests/unit/detection/support/detection_sessions.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_detection_gate_given"),
        (FOREIGN, "test_detection_oracle_given"),
    ),
    "tests/unit/detection/support/holdout_report_runs.py": ((NEWSPAPER, "a_target_result"),),
    "tests/unit/detection/support/run_detection_cli.py": (
        (SETATTR, "a_session_under_priced_models:run_detection.audit_target"),
        (SETATTR, "a_session_under_priced_models:run_detection.preflight_ok"),
        (SETATTR, "a_session_under_priced_models:run_detection.read_tree"),
        (SETATTR, "a_session_under_priced_models:run_detection.run_gated"),
        (SETATTR, "a_sweep_finding:run_detection.DOCKER_SWEEP"),
        (SETATTR, "exit_code_of:'sys.argv'"),
    ),
    "tests/unit/detection/support/test_detection_audit_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_launch_audit_given"),
        (NEWSPAPER, "a_run"),
    ),
    "tests/unit/detection/support/test_detection_audit_holdout_given.py": (
        (FOREIGN, "test_cve_launch_audit_given"),
    ),
    "tests/unit/detection/support/test_detection_baseline_given.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
        (NEWSPAPER, "_a_file_record"),
        (NEWSPAPER, "_an_endpoint_record"),
        (NEWSPAPER, "a_baseline"),
        (NEWSPAPER, "a_layout_record"),
        (NEWSPAPER, "a_target_keeping_a_file"),
        (NEWSPAPER, "conditions"),
    ),
    "tests/unit/detection/support/test_detection_calibration_check_given.py": (
        (SETATTR, "launches:calibration_check.connect"),
    ),
    "tests/unit/detection/support/test_detection_calibration_dossier_given.py": (
        (FOREIGN, "test_census_given"),
    ),
    "tests/unit/detection/support/test_detection_census_work_given.py": (
        (FOREIGN, "test_detection_draw_record_given"),
    ),
    "tests/unit/detection/support/test_detection_console_given.py": (
        (FOREIGN, "test_detection_oracle_given"),
        (FOREIGN, "test_eval_display_given"),
        (NEWSPAPER, "a_gated_report"),
        (NEWSPAPER, "a_no_baseline_report"),
        (NEWSPAPER, "a_not_run_result"),
    ),
    "tests/unit/detection/support/test_detection_draw_record_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_given"),
        (NEWSPAPER, "a_draw"),
        (NEWSPAPER, "a_draw_carrying"),
    ),
    "tests/unit/detection/support/test_detection_gate_given.py": ((NEWSPAPER, "conditions"),),
    "tests/unit/detection/support/test_detection_holdout_run_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
    "tests/unit/detection/support/test_detection_layout_check_golden_given.py": (
        (NEWSPAPER, "_any_cases"),
        (NEWSPAPER, "_break_cases"),
        (NEWSPAPER, "_leak_cases"),
    ),
    "tests/unit/detection/support/test_detection_oracle_given.py": (
        (NEWSPAPER, "a_detection_report"),
    ),
    "tests/unit/detection/support/test_detection_recording_given.py": (
        (FOREIGN, "test_detection_gate_given"),
    ),
    "tests/unit/detection/support/test_detection_replay_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
    "tests/unit/detection/support/test_detection_route_check_golden_given.py": (
        (NEWSPAPER, "_cases"),
        (NEWSPAPER, "_catalogue_place"),
        (NEWSPAPER, "_layout_place"),
    ),
    "tests/unit/detection/support/test_detection_session_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_detection_gate_given"),
        (FOREIGN, "test_detection_oracle_given"),
    ),
    "tests/unit/detection/support/test_run_detection_given.py": (
        (FOREIGN, "test_detection_calibration_check_exit_given"),
        (SETATTR, "a_calibration:no_llm_modes.default_calibration_check_deps"),
        (SETATTR, "a_calibration:run_detection.preflight_ok"),
        (SETATTR, "a_session_recording_options:run_detection.run_gated"),
        (SETATTR, "a_survey:no_llm_modes.survey_all"),
        (SETATTR, "a_survey:run_detection.preflight_ok"),
    ),
    "tests/unit/detection/support/test_run_detection_holdout_run_given.py": (
        (SETATTR, "a_drawn_run_ending_in:run_detection_holdout.default_deps"),
        (SETATTR, "a_drawn_run_ending_in:run_detection_holdout.run_holdout_targets"),
        (SETATTR, "a_drawn_target_with_a_ready_card:run_detection_holdout.HOLDOUT_TARGETS"),
        (SETATTR, "a_run_reaching_nothing:run_detection_holdout.default_deps"),
        (SETATTR, "a_run_reaching_nothing:run_detection_holdout.load_conditions"),
        (SETATTR, "a_run_reaching_nothing:run_detection_holdout.run_holdout_targets"),
        (SETATTR, "cards_reporting:run_detection_holdout.unready_cards"),
    ),
    "tests/unit/detection/support/test_run_detection_recording_given.py": (
        (FOREIGN, "test_eval_display_given"),
        (SETATTR, "a_recording_session_writing:run_detection.run_gated"),
    ),
    "tests/unit/detection/test_detection_audit.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_launch_audit_given"),
        (FOREIGN, "test_detection_oracle_given"),
    ),
    "tests/unit/detection/test_detection_audit_holdout.py": (
        (FOREIGN, "test_cve_launch_audit_given"),
    ),
    "tests/unit/detection/test_detection_draw_record.py": ((FOREIGN, "test_census_given"),),
    "tests/unit/detection/test_detection_holdout_audit.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_detection_oracle_given"),
        (FOREIGN, "test_eval_display_given"),
    ),
    "tests/unit/detection/test_detection_holdout_card_readiness.py": (
        (FOREIGN, "test_detection_draw_record_given"),
    ),
    "tests/unit/detection/test_detection_holdout_run_pre_run.py": (
        (FOREIGN, "test_detection_holdout_pre_run_check_given"),
    ),
    "tests/unit/detection/test_detection_layout_check.py": (
        (FOREIGN, "test_detection_layout_check_golden_given"),
        (NEWSPAPER, "_catalogue_place"),
        (NEWSPAPER, "_layout_place"),
        (NEWSPAPER, "_observed"),
    ),
    "tests/unit/detection/test_detection_preflight.py": (
        (NEWSPAPER, "_a_daemon_that_cannot_close_a_network"),
        (NEWSPAPER, "_a_docker"),
        (NEWSPAPER, "_a_store_with_one_stale"),
    ),
    "tests/unit/detection/test_detection_replay.py": ((NEWSPAPER, "_agree"),),
    "tests/unit/detection/test_detection_route_check.py": (
        (FOREIGN, "test_detection_route_check_golden_given"),
        (NEWSPAPER, "_git_scope_naming_no_bare"),
        (NEWSPAPER, "_git_tool"),
        (NEWSPAPER, "_layout_place"),
        (NEWSPAPER, "_path_tool"),
    ),
    "tests/unit/detection/test_detection_targets.py": ((NEWSPAPER, "_an_env_place"),),
    "tests/unit/detection/test_run_detection.py": (
        (
            SETATTR,
            "test_a_graded_run_that_crashes_still_removes_the_containers_left_running:run_detection.run_gated",
        ),
        (
            SETATTR,
            "test_a_measurement_run_with_an_unpriced_model_is_refused_before_any_audit:run_detection.run_gated",
        ),
    ),
    "tests/unit/detection/test_run_detection_holdout.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_calibration_check_exit_given"),
        (FOREIGN, "test_run_detection_holdout_run_given"),
        (SETATTR, "_a_calibration_check:run_detection_holdout.default_calibration_check_deps"),
        (SETATTR, "_drawn_targets:run_detection_holdout.HOLDOUT_TARGETS"),
        (SETATTR, "_drawn_targets:run_detection_holdout.IMAGE_STORE"),
        (SETATTR, "_drawn_targets:run_detection_holdout.check_closed_network_support"),
        (SETATTR, "_leftovers:run_detection_holdout.DOCKER_SWEEP"),
        (
            SETATTR,
            "test_run_refuses_an_acceptance_target_for_its_tools_filter:run_detection_holdout.HOLDOUT_TARGETS",
        ),
        (
            SETATTR,
            "test_run_without_a_drawn_target_exits_zero_and_says_so:run_detection_holdout.HOLDOUT_TARGETS",
        ),
        (
            SETATTR,
            "test_the_calibration_check_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network:run_detection_holdout.check_closed_network_support",
        ),
        (
            SETATTR,
            "test_the_calibration_check_refuses_with_exit_three_on_a_stale_or_absent_image:run_detection_holdout.IMAGE_STORE",
        ),
        (
            SETATTR,
            "test_the_calibration_check_without_a_drawn_target_exits_zero_and_says_so:run_detection_holdout.HOLDOUT_TARGETS",
        ),
    ),
    "tests/unit/detection/test_run_detection_holdout_run.py": (
        (
            SETATTR,
            "test_run_writes_its_result_before_the_report:run_detection_holdout.build_report",
        ),
    ),
    "tests/unit/evals/support/test_declared_flips_given.py": ((NEWSPAPER, "an_entry"),),
    "tests/unit/evals/support/test_draw_judge_cases_given.py": (
        (NEWSPAPER, "a_detection_line"),
        (NEWSPAPER, "a_honeypot_line"),
        (NEWSPAPER, "lines_for"),
        (NEWSPAPER, "some_cases"),
        (NEWSPAPER, "some_detection_cases"),
    ),
    "tests/unit/evals/support/test_eval_baseline_given.py": (
        (FOREIGN, "test_eval_gate_given"),
        (NEWSPAPER, "a_baseline"),
        (NEWSPAPER, "conditions"),
    ),
    "tests/unit/evals/support/test_eval_cell_grid_given.py": ((NEWSPAPER, "baseline_runs"),),
    "tests/unit/evals/support/test_eval_cell_grid_then.py": ((NEWSPAPER, "box_of"),),
    "tests/unit/evals/support/test_eval_display_given.py": (
        (FOREIGN, "test_eval_baseline_given"),
        (SETATTR, "a_captured_console:module.console"),
    ),
    "tests/unit/evals/support/test_eval_gate_given.py": ((NEWSPAPER, "a_ground_truth"),),
    "tests/unit/evals/support/test_eval_gate_outcome_given.py": (
        (FOREIGN, "test_eval_gate_given"),
    ),
    "tests/unit/evals/support/test_eval_recording_given.py": (
        (FOREIGN, "test_eval_baseline_given"),
        (FOREIGN, "test_eval_gate_given"),
    ),
    "tests/unit/evals/support/test_eval_session_given.py": (
        (FOREIGN, "test_eval_baseline_given"),
        (NEWSPAPER, "a_git_that_must_not_run"),
        (NEWSPAPER, "ci_conditions"),
    ),
    "tests/unit/evals/support/test_export_given.py": (
        (NEWSPAPER, "a_chain_with_leakage_verdict"),
        (NEWSPAPER, "a_judged_case"),
        (NEWSPAPER, "a_report"),
        (NEWSPAPER, "an_unjudged_case"),
    ),
    "tests/unit/evals/support/test_honeypot_decision_given.py": (
        (FOREIGN, "test_eval_session_given"),
        (FOREIGN, "test_honeypot_retest_given"),
        (NEWSPAPER, "a_baseline_all_correct"),
    ),
    "tests/unit/evals/support/test_honeypot_fault_fakes_given.py": ((NEWSPAPER, "the_fixture"),),
    "tests/unit/evals/support/test_honeypot_fault_harness_given.py": (
        (FOREIGN, "test_honeypot_fault_injection_given"),
    ),
    "tests/unit/evals/support/test_honeypot_fault_injection_given.py": (
        (NEWSPAPER, "the_fault_injection_baseline"),
    ),
    "tests/unit/evals/support/test_judge_baseline_given.py": (
        (FOREIGN, "test_judge_fixture_given"),
        (NEWSPAPER, "a_baseline"),
        (NEWSPAPER, "a_ground_truth"),
        (NEWSPAPER, "a_judge_fixture"),
        (NEWSPAPER, "conditions"),
        (NEWSPAPER, "correct_runs"),
    ),
    "tests/unit/evals/support/test_judge_display_given.py": (
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_judge_outcomes_given"),
    ),
    "tests/unit/evals/support/test_judge_fixture_given.py": (
        (NEWSPAPER, "a_fixture"),
        (NEWSPAPER, "some_inputs"),
    ),
    "tests/unit/evals/support/test_judge_gate_given.py": ((FOREIGN, "test_judge_baseline_given"),),
    "tests/unit/evals/support/test_judge_outcomes_given.py": (
        (FOREIGN, "test_judge_baseline_given"),
        (FOREIGN, "test_judge_fixture_given"),
    ),
    "tests/unit/evals/support/test_judge_recording_given.py": (
        (FOREIGN, "test_judge_baseline_given"),
    ),
    "tests/unit/evals/support/test_judge_session_given.py": (
        (FOREIGN, "test_judge_baseline_given"),
        (NEWSPAPER, "a_baseline_file"),
    ),
    "tests/unit/evals/support/test_probe_corpus_given.py": ((NEWSPAPER, "a_capture"),),
    "tests/unit/evals/support/test_probe_subset_given.py": (
        (FOREIGN, "test_probe_analysis_given"),
    ),
    "tests/unit/evals/support/test_run_judge_eval_given.py": (
        (FOREIGN, "test_judge_baseline_given"),
    ),
    "tests/unit/evals/test_draw_judge_cases.py": (
        (SETATTR, "test_the_detection_export_is_read_from_its_flag:'sys.argv'"),
    ),
    "tests/unit/evals/test_judge_baseline.py": ((FOREIGN, "test_judge_fixture_given"),),
    "tests/unit/evals/test_judge_metrics.py": (
        (NEWSPAPER, "_fn"),
        (NEWSPAPER, "_fp"),
        (NEWSPAPER, "_tn"),
        (NEWSPAPER, "_tp"),
    ),
    "tests/unit/evals/test_judge_session.py": (
        (NEWSPAPER, "_refused"),
        (NEWSPAPER, "_throttle_mismatch"),
    ),
    "tests/unit/evals/test_run_honeypot_suite.py": (
        (FOREIGN, "test_honeypot_retest_given"),
        (SETATTR, "test_the_no_baseline_flag_is_read:'sys.argv'"),
    ),
    "tests/unit/evals/test_run_judge_eval.py": (
        (SETATTR, "test_the_no_baseline_flag_is_read:'sys.argv'"),
    ),
    "tests/unit/evals/test_run_probe.py": ((NEWSPAPER, "_models_raising"),),
    "tests/unit/nuisance/admission/support/test_nuisance_admission_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_walk_given"),
        (NEWSPAPER, "a_backend_registry"),
        (NEWSPAPER, "a_census"),
        (NEWSPAPER, "a_fake_lifecycle"),
        (NEWSPAPER, "a_server"),
        (NEWSPAPER, "admitting_the_server_of"),
        (NEWSPAPER, "an_admission"),
        (NEWSPAPER, "walk_inputs_of"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_admission_records_given.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_admission_walk_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
        (NEWSPAPER, "the_queue_packages"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_dossier_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_nuisance_committed_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_holdout_calibration_copies_given.py": (
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_re_admission_dossier_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_committed_admission_given"),
        (NEWSPAPER, "a_drawn_target_and_its_sibling"),
        (NEWSPAPER, "the_copy_resolution"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_unrecorded_given.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_admission_records_given"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_walk_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_census_grouping_given"),
        (NEWSPAPER, "a_census_walking"),
        (NEWSPAPER, "with_a_record_settlement"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_walk_record_given.py": (
        (FOREIGN, "test_nuisance_walk_given"),
        (NEWSPAPER, "a_census"),
    ),
    "tests/unit/nuisance/admission/test_nuisance_admission_records.py": (
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/admission/test_nuisance_admission_walk.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/admission/test_nuisance_dossier.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_nuisance_unrecorded_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/admission/test_nuisance_re_admission_dossier.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_committed_admission_given"),
        (FOREIGN, "test_nuisance_dossier_given"),
        (FOREIGN, "test_nuisance_dossier_then"),
        (
            SETATTR,
            "test_a_closure_reaching_the_auditor_is_refused_before_writing:re_admission.closure_roots",
        ),
    ),
    "tests/unit/nuisance/fix_checks/support/recorded_exchanges.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/unit/nuisance/fix_checks/support/test_nuisance_fix_check_command_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
        (SETATTR, "a_fix_check_ready:fix_check_command.DOCKER_SWEEP"),
        (SETATTR, "a_fix_check_ready:fix_check_command.FIX_CHECK_FIXTURES"),
        (SETATTR, "a_fix_check_ready:fix_check_command.check_closed_network_support"),
        (SETATTR, "a_fix_check_ready:fix_check_command.default_fix_check_deps"),
    ),
    "tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py": (
        (FOREIGN, "test_kit_fix_check_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (
            SETATTR,
            "test_a_fix_check_with_no_fixture_says_no_server_is_admitted:fix_check_command.FIX_CHECK_FIXTURES",
        ),
    ),
    "tests/unit/nuisance/fix_checks/test_nuisance_fix_checks.py": (
        (NEWSPAPER, "_cve_environments_imports"),
    ),
    "tests/unit/nuisance/gate/support/nuisance_gate_sessions.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (NEWSPAPER, "a_gate_run"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_baseline_given.py": (
        (NEWSPAPER, "conditions"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_console_given.py": (
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_nuisance_gate_report_given"),
        (NEWSPAPER, "a_red_report"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_given.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_recording_given.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
        (FOREIGN, "test_nuisance_gate_given"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_selection_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_session_given.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
    ),
    "tests/unit/nuisance/gate/support/test_run_nuisance_gate_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_admission_records_given"),
        (FOREIGN, "test_nuisance_gate_baseline_given"),
        (FOREIGN, "test_nuisance_walk_given"),
        (SETATTR, "a_green_recording_writing:nuisance_gate_command.default_harness"),
        (SETATTR, "a_green_recording_writing:nuisance_gate_command.gate_conditions"),
        (SETATTR, "a_green_recording_writing:nuisance_gate_command.run_gate"),
        (NEWSPAPER, "gate_arguments"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_baseline.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_benign_calls.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_console.py": (
        (FOREIGN, "test_nuisance_gate_report_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_report.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_selection.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_session.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
    ),
    "tests/unit/nuisance/gate/test_nuisance_gate_sweep.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
    ),
    "tests/unit/nuisance/gate/test_run_nuisance_gate.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_admission_records_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_assembly_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_audit_once_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_launch_audit_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (NEWSPAPER, "an_auditor"),
    ),
    "tests/unit/nuisance/support/test_nuisance_benign_call_given.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_confinement_given.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_counting_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_fingerprint_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (SETATTR, "a_confinement_copy:nuisance_fingerprint.CONFINEMENT_SOURCE"),
    ),
    "tests/unit/nuisance/support/test_nuisance_holdout_run_backends_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_holdout_run_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (NEWSPAPER, "a_report"),
        (NEWSPAPER, "an_audit"),
        (NEWSPAPER, "conditions"),
        (NEWSPAPER, "draw_entries"),
    ),
    "tests/unit/nuisance/support/test_nuisance_holdout_servers_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_report_given.py": (
        (FOREIGN, "test_nuisance_statistic_given"),
        (NEWSPAPER, "with_incidents"),
    ),
    "tests/unit/nuisance/support/test_nuisance_solo_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_vet_given"),
        (NEWSPAPER, "_answering"),
    ),
    "tests/unit/nuisance/support/test_nuisance_statistic_given.py": (
        (NEWSPAPER, "a_server_result"),
    ),
    "tests/unit/nuisance/support/test_nuisance_vet_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_walk_given"),
        (SETATTR, "VetHarness:nuisance_vet_command.default_vet_deps"),
        (SETATTR, "VetHarness:nuisance_vet_command.load_conditions"),
    ),
    "tests/unit/nuisance/support/test_nuisance_vetting_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (SETATTR, "launches_failing:nuisance_vetting.connect"),
        (SETATTR, "launches_failing:nuisance_vetting.nuisance_environment"),
    ),
    "tests/unit/nuisance/support/test_run_nuisance_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_admission_records_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/support/test_run_nuisance_holdout_run_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_statistic_given"),
        (FOREIGN, "test_nuisance_walk_given"),
        (SETATTR, "a_run_reaching_nothing:run_nuisance"),
        (SETATTR, "a_run_refused_before_its_settings:run_nuisance"),
        (SETATTR, "an_admitted_run_ending_in:run_nuisance.default_deps"),
        (SETATTR, "an_admitted_run_ending_in:run_nuisance.last_commit"),
        (SETATTR, "an_admitted_run_ending_in:run_nuisance.run_nuisance"),
        (SETATTR, "an_admitted_run_keeping_its_provenance:run_nuisance.run_nuisance"),
        (NEWSPAPER, "a_run_result"),
        (NEWSPAPER, "an_admitted_run_ending_in"),
    ),
    "tests/unit/nuisance/test_nuisance_assembly.py": ((FOREIGN, "test_nuisance_admission_given"),),
    "tests/unit/nuisance/test_nuisance_audit_once.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_launch_audit_given"),
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_backend_registry.py": (
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/test_nuisance_backend_registry_built.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_benign_call.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
    ),
    "tests/unit/nuisance/test_nuisance_confinement.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
    ),
    "tests/unit/nuisance/test_nuisance_containers.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_counter.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/nuisance/test_nuisance_counting.py": ((FOREIGN, "test_nuisance_admission_given"),),
    "tests/unit/nuisance/test_nuisance_fingerprint.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (
            SETATTR,
            "test_the_fingerprint_moves_when_the_confinement_options_change:planting_base.confinement_args",
        ),
        (
            SETATTR,
            "test_the_fingerprint_moves_when_the_resolver_option_changes:planting_base.resolver_args",
        ),
    ),
    "tests/unit/nuisance/test_nuisance_holdout_run_backends.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_holdout_run_interrupted.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_holdout_run_status.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_holdout_run_sweep.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_holdout_servers.py": (
        (FOREIGN, "test_nuisance_admission_walk_given"),
    ),
    "tests/unit/nuisance/test_nuisance_images.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/test_nuisance_report.py": ((FOREIGN, "test_nuisance_statistic_given"),),
    "tests/unit/nuisance/test_nuisance_report_sections.py": (
        (FOREIGN, "test_nuisance_statistic_given"),
    ),
    "tests/unit/nuisance/test_nuisance_retry_policy.py": (
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/test_nuisance_solo.py": ((FOREIGN, "test_nuisance_holdout_run_given"),),
    "tests/unit/nuisance/test_nuisance_vet.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_run_nuisance_given"),
    ),
    "tests/unit/nuisance/test_nuisance_vetting.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
    ),
    "tests/unit/nuisance/test_run_nuisance.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/test_run_nuisance_dossier.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_re_admission_dossier_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/test_run_nuisance_holdout_run.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_admission_records_given"),
        (FOREIGN, "test_nuisance_holdout_calibration_copies_given"),
        (FOREIGN, "test_run_detection_holdout_run_given"),
        (SETATTR, "test_run_writes_its_result_before_the_report:run_nuisance.build_report"),
    ),
    "tests/unit/nuisance/test_run_nuisance_vet.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_vet_given"),
        (FOREIGN, "test_nuisance_vetting_given"),
        (FOREIGN, "test_run_nuisance_given"),
    ),
    "tests/unit/support/admission_mutations.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (NEWSPAPER, "with_a_backend"),
        (NEWSPAPER, "with_host"),
    ),
    "tests/unit/support/audited_launch_builders.py": (
        (FOREIGN, "test_ckan_holdout_builder_given"),
        (FOREIGN, "test_cve_planting_stand_ins_given"),
        (FOREIGN, "test_kubernetes_backend_given"),
        (FOREIGN, "test_searxng_backend_given"),
        (NEWSPAPER, "an_empty_spec"),
    ),
    "tests/unit/support/detection_holdout_runs.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (NEWSPAPER, "a_report"),
        (NEWSPAPER, "graded"),
    ),
    "tests/unit/support/docker_argv.py": ((NEWSPAPER, "values_after"),),
    "tests/unit/support/kit_isolation.py": ((NEWSPAPER, "mcp_auditor_imports"),),
    "tests/unit/support/recorded_subprocess.py": ((SETATTR, "recorded_commands:subprocess.run"),),
    "tests/unit/support/test_nuisance_admission_edits_given.py": (
        (NEWSPAPER, "with_the_first_flaw"),
        (NEWSPAPER, "with_the_registered_backend"),
    ),
    "tests/unit/support/test_nuisance_committed_admission_given.py": (
        (NEWSPAPER, "the_committed_walk_inputs"),
    ),
}

DEBTS: tuple[Debt, ...] = (
    Debt(
        "evals/cve/backends/jenkins.py",
        NEWSPAPER,
        "singleton_run_args",
        FingerprintedFile("evals/cve/backends/jenkins.py"),
    ),
    Debt(
        "evals/cve/backends/mcp_ssh_sshd.py",
        NEWSPAPER,
        "singleton_run_args",
        FingerprintedFile("evals/cve/backends/mcp_ssh_sshd.py"),
    ),
    Debt(
        "evals/cve/backends/n8n.py",
        NEWSPAPER,
        "singleton_run_args",
        FingerprintedFile("evals/cve/backends/n8n.py"),
    ),
    Debt(
        "evals/cve/closed_network.py",
        NEWSPAPER,
        "create_closed_network",
        FingerprintedFile("evals/cve/closed_network.py"),
    ),
    Debt(
        "evals/cve/closed_network.py",
        NEWSPAPER,
        "is_closed",
        FingerprintedFile("evals/cve/closed_network.py"),
    ),
    Debt(
        "evals/cve/closed_network.py",
        NEWSPAPER,
        "network_facts",
        FingerprintedFile("evals/cve/closed_network.py"),
    ),
    Debt(
        "evals/cve/environments.py",
        NEWSPAPER,
        "materialise",
        FingerprintedFile("evals/cve/environments.py"),
    ),
    Debt("evals/cve/grammar.py", NEWSPAPER, "grade_run", FingerprintedFile("evals/cve/grammar.py")),
    Debt(
        "evals/cve/nuisance/confinement.py",
        NEWSPAPER,
        "user_args",
        FingerprintedFile("evals/cve/nuisance/confinement.py"),
    ),
    Debt(
        "evals/cve/nuisance/counter.py",
        NEWSPAPER,
        "tool_verdicts",
        FingerprintedFile("evals/cve/nuisance/counter.py"),
    ),
    Debt(
        "evals/cve/nuisance/counting.py",
        NEWSPAPER,
        "counted_flaws",
        FingerprintedFile("evals/cve/nuisance/counting.py"),
    ),
    Debt(
        "evals/cve/planting_docker.py",
        NEWSPAPER,
        "_best_effort",
        FingerprintedFile("evals/cve/planting_docker.py"),
    ),
    Debt(
        "evals/cve/planting_spec.py",
        NEWSPAPER,
        "request_target",
        FingerprintedFile("evals/cve/planting_spec.py"),
    ),
    Debt(
        "evals/cve/planting_spec.py",
        NEWSPAPER,
        "served_file",
        FingerprintedFile("evals/cve/planting_spec.py"),
    ),
    Debt("evals/cve/proofs.py", NEWSPAPER, "proofs_in", FingerprintedFile("evals/cve/proofs.py")),
    Debt(
        "tests/integration/test_cve_planting.py",
        SETATTR,
        "test_a_file_place_over_etc_hosts_beside_a_name_host_fails_the_probe:'evals.cve.planting_docker._SENTINEL_PROBE_BUDGET'",
        FingerprintedFile("evals/cve/planting_docker.py"),
    ),
    Debt(
        "tests/integration/test_cve_planting.py",
        SETATTR,
        "test_a_file_place_over_resolv_conf_beside_a_bridge_alias_fails_the_probe:'evals.cve.planting_docker._SENTINEL_PROBE_BUDGET'",
        FingerprintedFile("evals/cve/planting_docker.py"),
    ),
    Debt(
        "tests/integration/test_cve_planting.py",
        SETATTR,
        "test_a_probe_killed_past_its_run_timeout_leaves_no_container:planting_docker._PROBE_RUN_TIMEOUT",
        FingerprintedFile("evals/cve/planting_docker.py"),
    ),
    Debt(
        "tests/unit/auditor/test_throttling.py",
        SETATTR,
        "test_a_fireworks_retry_counts_the_throttled_response_once:asyncio.sleep",
        _FIREWORKS_RETRY,
    ),
    Debt(
        "tests/unit/auditor/test_throttling.py",
        SETATTR,
        "test_a_google_retry_counts_the_throttled_response:asyncio.sleep",
        _GOOGLE_RETRY,
    ),
    Debt(
        "tests/unit/cve/backends/support/doris_launch.py",
        SETATTR,
        "doris_helpers_faked:holdout_environments.doris_rm",
        FingerprintedFile("evals/cve/detection/holdout_environments.py"),
    ),
    Debt(
        "tests/unit/cve/backends/support/doris_launch.py",
        SETATTR,
        "doris_helpers_faked:holdout_environments.ensure_doris",
        FingerprintedFile("evals/cve/detection/holdout_environments.py"),
    ),
    Debt(
        "tests/unit/cve/backends/support/doris_launch.py",
        SETATTR,
        "doris_helpers_faked:holdout_environments.start_doris_sentinel",
        FingerprintedFile("evals/cve/detection/holdout_environments.py"),
    ),
    Debt(
        "tests/unit/cve/backends/support/doris_launch.py",
        SETATTR,
        "doris_helpers_faked:holdout_environments.time",
        FingerprintedFile("evals/cve/detection/holdout_environments.py"),
    ),
    Debt(
        "tests/unit/cve/backends/support/test_doris_seed_given.py",
        SETATTR,
        "a_cluster_whose_sample_table_holds:doris.time",
        FingerprintedFile("evals/cve/backends/doris.py"),
    ),
    Debt(
        "tests/unit/cve/backends/support/test_doris_seed_given.py",
        SETATTR,
        "a_cluster_whose_sample_table_holds:subprocess.run",
        FingerprintedFile("evals/cve/backends/doris.py"),
    ),
    Debt(
        "tests/unit/cve/test_cve_planting_host_files.py",
        SETATTR,
        "test_write_host_file_removes_the_temp_file_when_the_content_cannot_be_encoded:tempfile.tempdir",
        FingerprintedFile("evals/cve/planting_docker.py"),
    ),
    *(
        Debt(path, standard, symbol, None)
        for path, unblocked in _UNBLOCKED.items()
        for standard, symbol in unblocked
    ),
)
