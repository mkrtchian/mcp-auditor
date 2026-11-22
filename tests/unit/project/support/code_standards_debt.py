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
    "tests/conftest.py": ((SETATTR, "_no_dotenv_in_tests:'mcp_auditor.config.load_dotenv'"),),
    "tests/fakes/scripted_docker.py": ((SETATTR, "ScriptedDocker:subprocess.run"),),
    "tests/integration/committed/cve/backends/support/test_backend_hostnames_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/cve/backends/support/test_mcp_ssh_sshd_backend_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/cve/support/test_committed_stand_ins_given.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
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
    ),
    "tests/integration/committed/nuisance/test_nuisance_compose.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/committed/nuisance/test_nuisance_fixture_sources.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/integration/support/docker_prerequisites.py": ((FOREIGN, "test_cve_planting_given"),),
    "tests/integration/support/test_cve_closed_networks_given.py": (
        (FOREIGN, "test_cve_planting_given"),
    ),
    "tests/integration/support/test_cve_keyed_stand_in_routes_given.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
    ),
    "tests/integration/support/test_cve_layout_mount_given.py": (
        (FOREIGN, "test_cve_planting_given"),
    ),
    "tests/integration/support/test_cve_planting_stand_ins_given.py": (
        (FOREIGN, "test_cve_planting_given"),
    ),
    "tests/integration/support/test_detection_replay_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
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
    "tests/integration/test_kit_client.py": ((FOREIGN, "test_mcp_client_given"),),
    "tests/integration/test_nuisance_public_names.py": (
        (FOREIGN, "test_cve_planting_given"),
        (FOREIGN, "test_cve_planting_stand_ins_given"),
        (FOREIGN, "test_cve_planting_then"),
    ),
    "tests/unit/auditor/support/test_cli_given.py": ((FOREIGN, "test_models_given"),),
    "tests/unit/auditor/support/test_graph_throttling_given.py": (
        (FOREIGN, "test_llm_throttling_given"),
    ),
    "tests/unit/auditor/support/test_llm_patience_given.py": (
        (FOREIGN, "test_llm_adapter_given"),
        (FOREIGN, "test_llm_refusals_given"),
        (FOREIGN, "test_llm_throttling_given"),
    ),
    "tests/unit/auditor/support/test_llm_refusals_given.py": ((FOREIGN, "test_llm_adapter_given"),),
    "tests/unit/auditor/support/test_model_inputs_golden_given.py": (
        (FOREIGN, "test_llm_adapter_given"),
    ),
    "tests/unit/auditor/test_chain_models.py": ((FOREIGN, "test_chain_nodes_given"),),
    "tests/unit/auditor/test_chain_prompts.py": (
        (FOREIGN, "test_chain_nodes_given"),
        (FOREIGN, "test_shown_response_given"),
        (FOREIGN, "test_shown_response_then"),
    ),
    "tests/unit/auditor/test_console_display.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/auditor/test_console_findings.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/auditor/test_context_extraction_prompt.py": (
        (FOREIGN, "test_shown_response_given"),
        (FOREIGN, "test_shown_response_then"),
    ),
    "tests/unit/auditor/test_progress.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/auditor/test_prompts.py": (
        (FOREIGN, "test_shown_response_given"),
        (FOREIGN, "test_shown_response_then"),
    ),
    "tests/unit/auditor/test_relaunch_rendering.py": ((FOREIGN, "test_rendering_then"),),
    "tests/unit/auditor/test_stream_handler.py": ((FOREIGN, "test_console_given"),),
    "tests/unit/census/support/test_census_draw_order_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_given"),
    ),
    "tests/unit/census/support/test_census_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_grouping_given"),
        (FOREIGN, "test_census_identity_given"),
    ),
    "tests/unit/census/support/test_census_grouping_given.py": (
        (FOREIGN, "test_census_figures_given"),
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
    "tests/unit/census/test_census_prefilter.py": ((FOREIGN, "test_census_sources_given"),),
    "tests/unit/census/test_run_census.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_census_sources_given"),
    ),
    "tests/unit/cve/backends/support/test_backend_lifecycle_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/cve/backends/support/test_node_sandbox_engine_given.py": (
        (SETATTR, "a_docker_whose_engine_opens_its_socket:subprocess.run"),
    ),
    "tests/unit/cve/backends/test_backend_lifecycle.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (
            SETATTR,
            "test_a_backend_module_whose_lifecycle_is_neither_kind_is_refused_by_name:importlib.import_module",
        ),
    ),
    "tests/unit/cve/support/cve_grammar_golden_corpus.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/cve/support/test_cve_grammar_golden_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_strike_given"),
    ),
    "tests/unit/cve/support/test_cve_launch_audit_given.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/cve/support/test_cve_server_health_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
    "tests/unit/cve/support/test_kit_benign_probe_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (SETATTR, "a_fake_lifecycle_resolved_by_key:benign_probe.lifecycle_of"),
        (SETATTR, "a_probe_answering:benign_probe.probe"),
    ),
    "tests/unit/cve/test_cve_closed_network_refusal.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_vet_given"),
    ),
    "tests/unit/cve/test_cve_launch_audit.py": ((FOREIGN, "test_cve_grammar_given"),),
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
    "tests/unit/detection/support/test_detection_audit_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_cve_launch_audit_given"),
    ),
    "tests/unit/detection/support/test_detection_audit_holdout_given.py": (
        (FOREIGN, "test_cve_launch_audit_given"),
    ),
    "tests/unit/detection/support/test_detection_baseline_given.py": (
        (FOREIGN, "test_cve_planting_stand_ins_given"),
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
    ),
    "tests/unit/detection/support/test_detection_draw_record_given.py": (
        (FOREIGN, "test_census_figures_given"),
        (FOREIGN, "test_census_given"),
    ),
    "tests/unit/detection/support/test_detection_holdout_run_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
    "tests/unit/detection/support/test_detection_recording_given.py": (
        (FOREIGN, "test_detection_gate_given"),
    ),
    "tests/unit/detection/support/test_detection_replay_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
    ),
    "tests/unit/detection/support/test_detection_session_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_detection_gate_given"),
        (FOREIGN, "test_detection_oracle_given"),
    ),
    "tests/unit/detection/support/test_run_detection_given.py": (
        (FOREIGN, "test_detection_calibration_check_exit_given"),
    ),
    "tests/unit/detection/support/test_run_detection_holdout_run_given.py": (
        (FOREIGN, "test_detection_draw_record_given"),
    ),
    "tests/unit/detection/support/test_run_detection_recording_given.py": (
        (FOREIGN, "test_eval_display_given"),
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
    ),
    "tests/unit/detection/test_detection_route_check.py": (
        (FOREIGN, "test_detection_route_check_golden_given"),
    ),
    "tests/unit/detection/test_run_detection_holdout.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_calibration_check_exit_given"),
        (FOREIGN, "test_run_detection_holdout_run_given"),
    ),
    "tests/unit/evals/support/test_eval_baseline_given.py": ((FOREIGN, "test_eval_gate_given"),),
    "tests/unit/evals/support/test_eval_display_given.py": (
        (FOREIGN, "test_eval_baseline_given"),
        (SETATTR, "a_captured_console:module.console"),
    ),
    "tests/unit/evals/support/test_eval_gate_outcome_given.py": (
        (FOREIGN, "test_eval_gate_given"),
    ),
    "tests/unit/evals/support/test_eval_recording_given.py": (
        (FOREIGN, "test_eval_baseline_given"),
        (FOREIGN, "test_eval_gate_given"),
    ),
    "tests/unit/evals/support/test_eval_session_given.py": ((FOREIGN, "test_eval_baseline_given"),),
    "tests/unit/evals/support/test_honeypot_decision_given.py": (
        (FOREIGN, "test_eval_session_given"),
        (FOREIGN, "test_honeypot_retest_given"),
    ),
    "tests/unit/evals/support/test_honeypot_fault_harness_given.py": (
        (FOREIGN, "test_honeypot_fault_injection_given"),
    ),
    "tests/unit/evals/support/test_judge_baseline_given.py": (
        (FOREIGN, "test_judge_fixture_given"),
    ),
    "tests/unit/evals/support/test_judge_display_given.py": (
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_judge_outcomes_given"),
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
    ),
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
    "tests/unit/evals/test_run_honeypot_suite.py": (
        (FOREIGN, "test_honeypot_retest_given"),
        (SETATTR, "test_the_no_baseline_flag_is_read:'sys.argv'"),
    ),
    "tests/unit/evals/test_run_judge_eval.py": (
        (SETATTR, "test_the_no_baseline_flag_is_read:'sys.argv'"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_admission_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_admission_records_given.py": (
        (FOREIGN, "test_nuisance_admission_edits_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_admission_walk_given.py": (
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
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
    ),
    "tests/unit/nuisance/admission/support/test_nuisance_walk_record_given.py": (
        (FOREIGN, "test_nuisance_walk_given"),
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
    ),
    "tests/unit/nuisance/fix_checks/support/recorded_exchanges.py": (
        (FOREIGN, "test_nuisance_committed_admission_given"),
    ),
    "tests/unit/nuisance/fix_checks/support/test_nuisance_fix_check_command_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_detection_draw_record_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/fix_checks/test_nuisance_fix_check_command.py": (
        (FOREIGN, "test_kit_fix_check_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/gate/support/nuisance_gate_sessions.py": (
        (FOREIGN, "test_nuisance_gate_baseline_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/gate/support/test_nuisance_gate_console_given.py": (
        (FOREIGN, "test_eval_display_given"),
        (FOREIGN, "test_nuisance_gate_report_given"),
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
        (FOREIGN, "test_nuisance_walk_given"),
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
    ),
    "tests/unit/nuisance/support/test_nuisance_holdout_run_backends_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_holdout_run_given.py": (
        (FOREIGN, "test_cve_grammar_given"),
        (FOREIGN, "test_nuisance_admission_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_holdout_servers_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_report_given.py": (
        (FOREIGN, "test_nuisance_statistic_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_solo_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_vet_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_vet_given.py": (
        (FOREIGN, "test_census_given"),
        (FOREIGN, "test_nuisance_admission_given"),
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
        (FOREIGN, "test_nuisance_walk_given"),
    ),
    "tests/unit/nuisance/support/test_nuisance_vetting_given.py": (
        (FOREIGN, "test_nuisance_holdout_run_backends_given"),
        (FOREIGN, "test_nuisance_holdout_run_given"),
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
    ),
    "tests/unit/support/audited_launch_builders.py": (
        (FOREIGN, "test_ckan_holdout_builder_given"),
        (FOREIGN, "test_cve_planting_stand_ins_given"),
        (FOREIGN, "test_kubernetes_backend_given"),
        (FOREIGN, "test_searxng_backend_given"),
    ),
    "tests/unit/support/detection_holdout_runs.py": ((FOREIGN, "test_cve_grammar_given"),),
    "tests/unit/support/recorded_subprocess.py": ((SETATTR, "recorded_commands:subprocess.run"),),
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
