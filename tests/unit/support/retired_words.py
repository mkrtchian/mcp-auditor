"""The words the living text of the repository may no longer say, one pattern each."""

import re

from tests.unit.support.retired_word_scan import RetiredWord

_OLD_TEST_STEMS = (
    "cve_layout_check_golden",
    "cve_replay_stub_server",
    "cve_route_golden",
    "cve_stub_server",
    "cve_stub_target",
    "holdout_kit_isolation",
    "test_admission_calibration",
    "test_admission_calibration_given",
    "test_audit_launch",
    "test_audit_launch_given",
    "test_audit_progress",
    "test_audit_progress_given",
    "test_benign_probe",
    "test_benign_probe_given",
    "test_calibration_dossier",
    "test_calibration_dossier_given",
    "test_census_draw",
    "test_census_draw_given",
    "test_closed_network",
    "test_closed_network_given",
    "test_closed_network_refusal",
    "test_closed_network_refusal_given",
    "test_closed_network_refusal_then",
    "test_closed_network_then",
    "test_closed_networks",
    "test_closed_networks_given",
    "test_closed_networks_then",
    "test_cve_audit",
    "test_cve_audit_given",
    "test_cve_baseline",
    "test_cve_baseline_given",
    "test_cve_calibration",
    "test_cve_calibration_given",
    "test_cve_console",
    "test_cve_console_given",
    "test_cve_costs",
    "test_cve_costs_given",
    "test_cve_gate",
    "test_cve_gate_given",
    "test_cve_layout_check",
    "test_cve_layout_check_golden_given",
    "test_cve_oracle",
    "test_cve_oracle_given",
    "test_cve_preflight",
    "test_cve_recording",
    "test_cve_recording_client",
    "test_cve_recording_given",
    "test_cve_replay",
    "test_cve_replay_given",
    "test_cve_replay_then",
    "test_cve_route",
    "test_cve_route_golden_given",
    "test_cve_session",
    "test_cve_session_given",
    "test_cve_session_then",
    "test_cve_survey",
    "test_cve_targets",
    "test_dossier_closure",
    "test_eval_fault_fakes",
    "test_eval_fault_fakes_given",
    "test_eval_fault_harness",
    "test_eval_fault_harness_given",
    "test_eval_fault_harness_then",
    "test_eval_fault_injection",
    "test_eval_fault_injection_given",
    "test_eval_fault_injection_then",
    "test_eval_gate_verdict",
    "test_eval_gate_verdict_given",
    "test_eval_judging",
    "test_eval_judging_given",
    "test_eval_replay",
    "test_eval_replay_given",
    "test_failure_text",
    "test_fix_check",
    "test_fix_check_given",
    "test_fixture_provenance",
    "test_fixture_sources",
    "test_holdout_audit",
    "test_holdout_card_readiness",
    "test_holdout_census",
    "test_holdout_census_given",
    "test_holdout_conditions",
    "test_holdout_draw",
    "test_holdout_draw_given",
    "test_holdout_fixture_sources",
    "test_holdout_fixture_sources_then",
    "test_holdout_hierarchical",
    "test_holdout_intervals",
    "test_holdout_kit",
    "test_holdout_kit_client",
    "test_holdout_kit_isolation",
    "test_holdout_report",
    "test_holdout_run",
    "test_holdout_run_given",
    "test_holdout_run_interrupted",
    "test_holdout_statistic",
    "test_holdout_targets",
    "test_holdout_targets_given",
    "test_holdout_vetting",
    "test_holdout_vetting_given",
    "test_holdout_vetting_then",
    "test_missed_steps",
    "test_nuisance_backends",
    "test_nuisance_backends_built",
    "test_nuisance_calibrate_command",
    "test_nuisance_calibrate_command_given",
    "test_nuisance_holdout_copies",
    "test_nuisance_holdout_copies_given",
    "test_nuisance_population",
    "test_nuisance_readmission_dossier",
    "test_nuisance_readmission_dossier_given",
    "test_probe",
    "test_probe_given",
    "test_probe_then",
    "test_provider_errors",
    "test_provider_errors_given",
    "test_public_stand_ins",
    "test_public_stand_ins_given",
    "test_run_cve_benchmark",
    "test_run_cve_benchmark_given",
    "test_run_evals",
    "test_run_evals_given",
    "test_run_holdout",
    "test_run_holdout_run",
    "test_run_holdout_run_given",
    "test_run_images",
    "test_run_images_given",
    "test_server_health",
    "test_target_execution",
    "test_target_execution_given",
)

RETIRED_WORDS = (
    RetiredWord("acceptance-gate", r"\bacceptance gates?\b", re.IGNORECASE, "5"),
    RetiredWord("acceptance-test", r"\bacceptance tests?\b", re.IGNORECASE, "2"),
    RetiredWord(
        "bare-acceptance-server", r"(?<!nuisance )\bacceptance[ -]servers?\b", re.IGNORECASE, "5"
    ),
    RetiredWord("twin", r"twins?\b|_twin|Twin", re.NOFLAG, "5"),
    RetiredWord(
        "admission-cve",
        r"admission_calibration|confirm_admission|AdmissionCalibration|admission (bars?|probe)",
        re.IGNORECASE,
        "4",
    ),
    RetiredWord(
        "alarm-tag", r'CellTag\.ALARM\b|\bALARM = "alarm"|PASS cell always flagged', re.NOFLAG, "3"
    ),
    RetiredWord(
        "audit-step",
        (
            r"\bAuditStep\b|\bMissedStep\b|\bJUDGE_STEPS\b|\bCHAIN_STEPS\b|is_(judge|chain)_step\b|"
            r"describe_missed_step|print_missed_steps"
        ),
        re.NOFLAG,
        "2",
    ),
    RetiredWord(
        "missed-steps",
        (
            r"missed_steps?\b|\bmissed steps?\b|\brefused[ _](chain )?steps?\b|"
            r"step (was|is) missed|chain_step_missed"
        ),
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "calibrate-cmd",
        (
            r"--calibrate\b|\b(run_holdout|run_nuisance) calibrate\b|nuisance_calibrate|"
            r"calibrate_command"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord("calibration-gate", r"\bcalibration gate\b|\bCI gates?\b", re.IGNORECASE, "5"),
    RetiredWord("workshop", r"\bworkshops?\b", re.IGNORECASE, "5"),
    RetiredWord(
        "capability",
        (
            r"\bcapability (figure|number|rate)s?\b|\bholdout figures?\b|capability_(number|figure|"
            r"rate)"
        ),
        re.IGNORECASE,
        "5",
    ),
    RetiredWord("challenger", r"\bchallengers?\b", re.IGNORECASE, "5"),
    RetiredWord("cve-family", r"\bCVE family\b", re.NOFLAG, "4"),
    RetiredWord(
        "cve-x",
        (
            r"\bCVE (gates?|oracles?|grammars?|baselines?|fixtures?|runs?|targets?|holdout|"
            r"validation benchmark|acceptance)\b"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord(
        "cve-ident",
        (
            r"\bCVE(?:Targets?|Status|Result|BenchmarkReport|GateResult|GateVerdict|RunConditions|"
            r"TargetBaseline|SessionResult|Options|Harness|Audit)\b|\bCVE_(?:TARGETS|RUNS|"
            r"TEST_BUDGET|CONCURRENCY)\b|\bOutOfScopeCVE\b|\bOUT_OF_SCOPE_CVES\b"
        ),
        re.NOFLAG,
        "4",
    ),
    RetiredWord("cve-flag", r"--cve(?![-\w])", re.NOFLAG, "5"),
    RetiredWord(
        "dead",
        (
            r"dead[ _]conditions?|patched_dead|calibrat\w* dead|\breads? dead\b|\bdead fixtures?\b|"
            r"\bdead on (a|its|the|both)\b|\blive (or|and|/) dead\b|\[red\]dead|_report_dead|"
            r"\btargets? dead\b|\bdead targets?\b|\bdead:"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord("dfie", r"\bdfie\b", re.IGNORECASE, "2"),
    RetiredWord("distribution-label", r'"Distribution"', re.NOFLAG, "3"),
    RetiredWord("e2e", r"\be2e\b|end-to-end evals?\b|honeypot_e2e", re.IGNORECASE, "5"),
    RetiredWord("eval-result", r"\beval_results?\b|\bEvalResults?\b", re.NOFLAG, "4"),
    RetiredWord("baselines-cve", r"baselines/cve\b", re.NOFLAG, "5"),
    RetiredWord(
        "holdout-census",
        r"holdout_census|HoldoutCensus|\bholdout census\b|holdout's census|HOLDOUT_CENSUS",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord("holdout-kit", r"holdout_kit|holdout kit\b", re.IGNORECASE, "5"),
    RetiredWord("holdout-places", r"holdout_places|HOLDOUT_PLACES", re.NOFLAG, "4"),
    RetiredWord("run-cve-benchmark", r"run_cve_benchmark", re.NOFLAG, "5"),
    RetiredWord("run-evals", r"\brun_evals\b", re.NOFLAG, "5"),
    RetiredWord("run-holdout", r"\brun_holdout(\b|_run)", re.NOFLAG, "5"),
    RetiredWord("execution-config", r"\bExecutionConfig\b", re.NOFLAG, "2"),
    RetiredWord(
        "exploratory-baseline",
        (
            r"BaselineStatus\.EXPLORATORY|EXPLORATORY = |\bexploratory baselines?\b|"
            r"\(exploratory, then confirmed\)|exploratory recording|recorded exploratory|"
            r"first recording is exploratory|exploratory_commit_refusal"
        ),
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "figure",
        (
            r"(?i:\b(the|nuisance|holdout|a server's) figure\b|figure: at most)|FigureExit\w*|"
            r"outside_figure|\bdef figure\b|figure=figure|\bfigure\("
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord("fixed-tag", r'CellTag\.FIXED|FIXED = "fixed"', re.NOFLAG, "3"),
    RetiredWord(
        "version-setting",
        r"version-setting|\bsets? (the|its) version\b(?! of its server)",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord("fresh-targets", r"\bfresh targets?\b", re.IGNORECASE, "5"),
    RetiredWord(
        "gate-verdict",
        r"\bGateVerdict|\bgate_verdict|\bgate verdicts?\b|verdict of the gate",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "holdout-calibration",
        r"(?<!detection_)holdout_calibration(?!_cop)|\bholdout calibration\b(?! cop(?:y|ies)\b)",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "holdout-rule-log",
        r"holdout-(rule|log)|\bholdout (rule|log)\b|HOLDOUT_(RULE|LOG)\b",
        re.IGNORECASE,
        "after this plan",
    ),
    RetiredWord(
        "bare-holdout-server",
        r"(?<!detection )(?<!nuisance )\bholdout[ -]servers?\b",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "holdout-walk", r"\bholdout walk\b|holdout's draw order|holdout_walk", re.IGNORECASE, "5"
    ),
    RetiredWord(
        "holdout-vetting", r"holdout_vetting|pre-run vetting|\bvet_all\b", re.IGNORECASE, "4"
    ),
    RetiredWord("judge-isolation", r"judge[ _]isolation", re.IGNORECASE, "5"),
    RetiredWord("judged-cases", r"\bjudged_cases\b(?!\.jsonl)", re.NOFLAG, "2"),
    RetiredWord("known-gap-holdout", r"known gap of the holdout", re.IGNORECASE, "4"),
    RetiredWord("location-id", r"\blocation[ _]ids?\b", re.IGNORECASE, "4"),
    RetiredWord("openrouter-hosts", r"OPENROUTER_HOSTS|openrouter_hosts", re.IGNORECASE, "5"),
    RetiredWord("not-run-conditions", r"not_run_conditions", re.NOFLAG, "4"),
    RetiredWord(
        "nuisance-rule-log",
        r"nuisance-(rule|log)\b|\bnuisance (rule|log)\b|NUISANCE_(RULE|LOG)\b",
        re.IGNORECASE,
        "after this plan",
    ),
    RetiredWord("oracle-version", r"\boracle versions?\b", re.IGNORECASE, "2"),
    RetiredWord(
        "payload-label",
        (
            r"\*\*Payload\*\*|\bpayload=case\.payload\.arguments|payload=last_payload\.arguments|"
            r"result\.payload\b"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord(
        "replay-retest",
        r"pending_replay|replay_observations|\breplay_rule\b|\bReplayRule\b|\breplay rules?\b",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "replay-retest-ident",
        (
            r"\bReplayer\b|\b_?replayer\b|a_replayer|ReplayAudit|replay_audit|ReplayContext|"
            r"replay_flips|decide_replays|on_replays|replay_fraction|judge_replay|evals/replay\.py|"
            r"evals\.replay\b|\bReplays\b|\bReplaying\b|_replaying|replays alike|runs and replays"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord("planting-layer", r"\bplanting layer\b", re.IGNORECASE, "5"),
    RetiredWord("readmission", r"readmission", re.IGNORECASE, "5"),
    RetiredWord(
        "refused-credit",
        r"\brefused (and the unchecked )?credits?\b|credits? the replay refused|the replay refused",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord("relayed-variables", r"relayed_variables", re.NOFLAG, "2"),
    RetiredWord(
        "replay-capture",
        (
            r"\b(stand-in|it) replays\b|replay(s|ed|ing)? (a|the|its|each|every) (dated )?(capture|"
            r"answer|captured)|unreplayed_captures|replays? .{0,20}captured|_replay_the_seed"
        ),
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "replay-corpus",
        r"replay(s|ed|ing)? (the|its|a|frozen) (frozen )?corpus|replay the corpus",
        re.IGNORECASE,
        "5",
    ),
    RetiredWord("replayed-walk", r"\breplayed walks?\b", re.IGNORECASE, "2"),
    RetiredWord(
        "replays-exploits",
        (
            r"replay(s|ed|ing)? (its|the|each target's|every fixture's|hand-written|"
            r"every) ?(hand-written )?(exploits?|fixture)"
        ),
        re.IGNORECASE,
        "5",
    ),
    RetiredWord(
        "report-only-set", r"report-only (population|servers?|set|layer)", re.IGNORECASE, "2"
    ),
    RetiredWord(
        "rubric-judge", r"judge'?s? rubric|rubric of the judge|judging rubric", re.IGNORECASE, "2"
    ),
    RetiredWord("selection-rule", r"\bselection rule\b", re.IGNORECASE, "2"),
    RetiredWord(
        "sentinel-value",
        (
            r"(?i:sentinel (nonce|value|convention|string)s?|planted sentinels?|plants? a sentinel|"
            r"sentinels? (surfaces?|leaks?|appears?)\b)|\bSENTINEL\b"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord("sentinel-route", r"\bsentinel routes?\b", re.IGNORECASE, "4"),
    RetiredWord("server-under-audit", r"\bservers? under audit\b", re.IGNORECASE, "5"),
    RetiredWord("stub", r"\bstubs?\b|_stub\b|stub_", re.IGNORECASE, "4"),
    RetiredWord(
        "target-product",
        r'\bTargetExecution\b|target_execution|launch\.target\b|report\.target\b|"target": ',
        re.NOFLAG,
        "4",
    ),
    RetiredWord("target-route", r"route\.target\b", re.NOFLAG, "2"),
    RetiredWord("ungated", r"\bungated\b", re.IGNORECASE, "5"),
    RetiredWord("unread-targets", r"\bunread targets?\b", re.IGNORECASE, "2"),
    RetiredWord(
        "mechanism-class",
        r"\bMechanismClass\b|\.mechanisms\b|\bmechanisms=|\bmechanism_labels\b",
        re.NOFLAG,
        "5",
    ),
    RetiredWord("plant-kind", r"\bPlantKind\b", re.NOFLAG, "4"),
    RetiredWord("miss-class", r"\bMissClass\b|\bmiss_class\b", re.NOFLAG, "4"),
    RetiredWord(
        "reachable-by",
        r"\bREACHABLE_BY\b|\.reachable_by\b|\breachable_by=|\b_reachable_by\b",
        re.NOFLAG,
        "4",
    ),
    RetiredWord("entry-id", r"\bentry_id\b", re.NOFLAG, "4"),
    RetiredWord("cve-id", r"\bcve_ids?\b", re.NOFLAG, "4"),
    RetiredWord(
        "census-names",
        (
            r"\bNuisanceCensus\b|\bnuisance_census\b|\bcensus_identifier\b|\bBENCHMARK_FLAWS\b|"
            r"\bDrawWalkStep\b"
        ),
        re.NOFLAG,
        "4",
    ),
    RetiredWord("fix-check-target", r"\bFixCheckTarget\b|\bFIX_CHECK_TARGETS\b", re.NOFLAG, "4"),
    RetiredWord(
        "recording-names",
        r"\bRecordingClient\b|\bKitRecorder\b|\bRecordingLLM\b|cve_recording_client",
        re.NOFLAG,
        "4",
    ),
    RetiredWord(
        "verdict-names", r"\bConclusionVerdict\b|\bprint_verdict\b|_VERDICT_STYLES", re.NOFLAG, "4"
    ),
    RetiredWord(
        "acceptance-mark",
        r"ServerMark\.ACCEPTANCE\b|\bcurrent_acceptance_servers\b|\bacceptance_servers\(",
        re.NOFLAG,
        "4",
    ),
    RetiredWord("version-setting-ident", r"\bversion_setting\w*|\b_sets_version\b", re.NOFLAG, "4"),
    RetiredWord("primary-number", r"\bprimary_number\b|\bprimary_controls\b", re.NOFLAG, "4"),
    RetiredWord("miss-causes", r"\bmiss_causes\b|describe_miss_causes", re.NOFLAG, "5"),
    RetiredWord(
        "stand-in-target",
        r"\bprobed_target\b|\bStandInRoute\.target\b|r\['target'\]",
        re.NOFLAG,
        "4",
    ),
    RetiredWord(
        "calibrate-ident",
        (
            r"\badmission_gave_up\b|\broute_admits\b|\bcalibrate_admitted\b|\bcalibrate_all\b|"
            r"\bcalibrate_one\b|\bCalibrationDeps\b|\bdefault_calibration_deps\b|"
            r"\bcalibrate_fixtures\b|\bFixCheckCalibrationDeps\b"
        ),
        re.NOFLAG,
        "4",
    ),
    RetiredWord(
        "eval-names", r"\bEval(?:Report|RunResult|Options|Session|Metrics)\b", re.NOFLAG, "3"
    ),
    RetiredWord("phase-usage", r"\bPhaseUsage\b", re.NOFLAG, "3"),
    RetiredWord(
        "suite-enum", r"\bSuite\.(?:HONEYPOT|JUDGE)\b|\bdeclared_flips\.Suite\b", re.NOFLAG, "3"
    ),
    RetiredWord("settle-gate", r"\bsettle\(|\b_settled\b", re.NOFLAG, "4"),
    RetiredWord(
        "moved-module",
        r"evals[./](?:cve|holdout|nuisance|census)_[a-z_]+(?:\.py)?\b(?!\.(?:json|md))",
        re.NOFLAG,
        "5",
    ),
    RetiredWord(
        "moved-module-other",
        (
            r"evals[./](?:replay|judging|gate_verdict|eval_report|eval_runs|fault_(?:catalog|"
            r"harness|injection)|judge_[a-z_]+|[a-z0-9_]+_backend|backend_lifecycle|"
            r"public_stand_ins|closed_network|docker_paths|dossier_closure|launch_audit|"
            r"audit_(?:attempts|progress)|failure_text|provider_errors|server_health|run_(?:files|"
            r"images|interruption)|fixture_(?:provenance|sources)|calibration_dossier|"
            r"admission_calibration)\b(?!\.(?:json|md))|evals[./]probe(?:_candidates|_corpus|"
            r"_subset)?(?:\.py\b|(?= import\b))"
        ),
        re.NOFLAG,
        "5",
    ),
    RetiredWord(
        "moved-test",
        r"\b(?:" + "|".join(sorted(_OLD_TEST_STEMS, key=len, reverse=True)) + r")\b",
        re.NOFLAG,
        "5",
    ),
)
