# Glossary log

ADRs and plans keep the words of their date. This file maps those words to the current terms of [`glossary.md`](glossary.md). Search it for the word you met.

The table has one line per change of vocabulary, sorted by the older word. A rename keeps the concept and changes its word. A moved meaning keeps the word for another concept, so in an older text the word means something else. Its line ends with what the word means now. A retired word has no successor of its own, so its line says what it meant and a current text writes that out. A changed decision is not listed here: the ADR that supersedes it records it. The date is the day the older word stopped being the current one, and most lines date from the adoption of this glossary.

The words whose meaning moved are the ones to watch, since a reader who thinks they know the word will not look it up: acceptance layer, acceptance server, admission, alarm, calibration, CVE benchmark, exploratory, fixed, holdout, holdout server, oracle, payload, replay, report-only, rubric, sentinel, target and vet. In an ADR or a plan, read them through their line below.

| Older word | Current term | Kind | Date |
|---|---|---|---|
| acceptance gate (ADR 006, the end-to-end eval as the gate of the whole system) | no successor: a role ADR 015 took away from the honeypot suite, which is now a regression guard gated by the honeypot gate | retired | 2026-09-21 |
| acceptance gate (ADR 024, ADR 030, the detection rule, CONTRIBUTING) | detection gate | rename | 2026-11-11 |
| acceptance gate (nuisance plans: the nuisance suite's gate) | nuisance gate | rename | 2026-11-11 |
| acceptance layer (ADR 015, ADR 024, plans: the detection acceptance layer alone) | detection acceptance layer. "Acceptance layer" now names a role of both suites. | moved meaning | 2026-11-11 |
| acceptance layer, acceptance test (plans of 2026-07: the manual check of a plan step against the real images) | no successor: a manual verification step, not a layer of a suite | retired | 2026-11-11 |
| acceptance server (nuisance rule, ADR 033: the server of a current or past acceptance target) | nuisance acceptance server for a current target, the server of a dropped acceptance target for a past one. "Acceptance server" is now always qualified by its suite. | moved meaning | 2026-11-11 |
| acceptance twin, in-repo twin (kit docstrings, plans) | no successor: the module of the repository that a kit module copies | retired | 2026-11-11 |
| admission (plans of 2026-10-14 and 2026-10-15, holdout log, `admission_calibration.py`: a target admitted through its calibration and its layout and route checks) | calibration check, layout check, route check. "Admission" now names the nuisance admission. | moved meaning | 2026-11-11 |
| admission, admission bars, admission probe (ADR 019, plans of 2026-09-24 and 2026-09-25: a candidate model clearing the probe's bars) | no successor: ADR 021 chooses a model on a written judgment, and the model probe reports defects | retired | 2026-09-26 |
| alarm, false alarm (honeypot grid tag, judge plans: a FAIL on a honeypot PASS cell) | `false_positive`. "Alarm" now names a nuisance alarm. | moved meaning | 2026-11-11 |
| `AuditStep` | model call kind | rename | 2026-11-11 |
| calibrate, calibration (`--calibrate`, `run_holdout calibrate`, the no-LLM check) | calibration check (`--calibration-check`, `run_detection_holdout calibration-check`). "Calibration" now names writing or repairing a fixture. | moved meaning | 2026-11-11 |
| calibrate (`run_nuisance calibrate`) | fix check (`run_nuisance fix-check`). "Calibration" now names writing or repairing a detection fixture. | moved meaning | 2026-11-11 |
| calibration gate | calibration check | rename | 2026-11-11 |
| calibration workshop | kit | rename | 2026-11-11 |
| capability figure, holdout figure (plans) | holdout detection rate, or a holdout number of either suite | rename | 2026-11-11 |
| capability number, capability rate (ADR 015) | holdout detection rate | rename | 2026-11-11 |
| challenger (ADR 019) | candidate model | rename | 2026-09-26 |
| CI gate (the calibration job) | calibration check | rename | 2026-11-11 |
| CVE acceptance gate (ADR 024) | detection gate | rename | 2026-11-11 |
| CVE benchmark (the detection suite alone) | detection suite. "CVE benchmark" now names both suites and what they share. | moved meaning | 2026-11-11 |
| CVE family (CLAUDE.md, labeling log, nuisance log: the detection suite's targets, set against the nuisance fix checks) | detection suite | rename | 2026-11-11 |
| CVE gate, CVE oracle, CVE grammar, CVE baseline, CVE fixture, CVE run (ADRs, rules, logs, plans) | detection gate, oracle, grammar, detection baseline, detection fixture, detection suite run | rename | 2026-11-11 |
| CVE holdout (ADR 028) | detection holdout layer | rename | 2026-11-11 |
| CVE target | target (acceptance target, holdout target) | rename | 2026-11-11 |
| CVE validation benchmark | detection suite | rename | 2026-11-11 |
| `--cve ID` | `--flaw ID` | rename | 2026-11-11 |
| `--cve-export` (`draw_judge_cases`) | `--detection-export` | rename | 2026-11-11 |
| dead, calibrated dead (a target that fails its calibration check), `dead_conditions` | out of calibration, out-of-calibration reasons | rename | 2026-11-11 |
| dead (a patched version where no exploit works) | fixed | rename | 2026-11-11 |
| dfie (plans) | declared function is the effect | rename | 2026-11-11 |
| Distribution (ADR 003, ADR 005, the honeypot report's label) | distribution coverage | rename | 2026-11-11 |
| e2e eval, E2E evals, end-to-end eval, honeypot e2e suite (ADR 003, ADR 006, ADR 007, ADR 015, ADR 034, CONTRIBUTING) | honeypot suite | rename | 2026-11-11 |
| `e2e-eval` (the honeypot CI job) | `honeypot-suite` | rename | 2026-11-11 |
| `eval_result`, `EvalResult` | judge result (`judge_result`) | rename | 2026-11-11 |
| `evals/baselines/cve/` | `evals/baselines/detection/` | rename | 2026-11-11 |
| `evals/baselines/honeypot_e2e.json` | `evals/baselines/honeypot.json` | rename | 2026-11-11 |
| `evals/baselines/judge_isolation.json` | `evals/baselines/judge.json` | rename | 2026-11-11 |
| `evals/holdout_census.json` | `evals/census.json` | rename | 2026-11-11 |
| `evals/holdout_kit/` | kit | rename | 2026-11-11 |
| `evals/holdout_places.json` | `evals/detection_places.json` | rename | 2026-11-11 |
| `evals.run_cve_benchmark` | `evals.run_detection` | rename | 2026-11-11 |
| `evals.run_evals` | `evals.run_honeypot_suite` | rename | 2026-11-11 |
| `evals.run_holdout` | `evals.run_detection_holdout`, its `draw-order` moved to `evals.run_census` | rename | 2026-11-11 |
| `ExecutionConfig` | audit run options | rename | 2026-11-11 |
| exploratory (status of a baseline) | unconfirmed. "Exploratory" now names only the status of a number. | moved meaning | 2026-11-11 |
| figure (the set of servers counted) | nuisance holdout layer | rename | 2026-11-11 |
| figure (the number) | holdout nuisance rate | rename | 2026-11-11 |
| fixed (honeypot grid tag) | `improved`. "Fixed" now names a patched version where no exploit surfaces. | moved meaning | 2026-11-11 |
| flaw that sets the version, version-setting flaw | counted flaw | rename | 2026-11-11 |
| fresh targets (ADR 015, ADR 028, README) | holdout targets | rename | 2026-11-11 |
| `GateVerdict`, gate verdict, verdict of the gate (ADR 020, labeling log, plans) | gate outcome | rename | 2026-11-11 |
| holdout (the detection holdout layer alone) | detection holdout layer. "Holdout" now names a role of both suites. | moved meaning | 2026-11-11 |
| holdout calibration (fix-check source) | holdout calibration copy (`detection_holdout_calibration`) | rename | 2026-11-11 |
| holdout calibration (CLAUDE.md, plans: `run_holdout calibrate`) | calibration check of the holdout targets | rename | 2026-11-11 |
| holdout census | census | rename | 2026-11-11 |
| holdout log (`docs/holdout-log.md`) | detection suite log (`docs/detection-suite-log.md`) | rename | 2026-11-11 |
| holdout rule (`docs/holdout-rule.md`) | detection suite rule (`docs/detection-suite-rule.md`) | rename | 2026-11-11 |
| holdout server (the server of a holdout target) | detection holdout server. "Holdout server" is now always qualified by its suite. | moved meaning | 2026-11-11 |
| holdout twin, drawn twin (nuisance rule, nuisance log, plans) | no successor: the holdout target of a nuisance server ("its holdout twin's calibration"), or that server itself, a detection holdout server ("the first admissions of holdout twins") | retired | 2026-11-11 |
| holdout walk, holdout's draw order | detection walk, draw order | rename | 2026-11-11 |
| `holdout_vetting`, vet, pre-run vetting (holdout plans, `holdout_vetting` docstring) | pre-run check. "Vet" now names only the nuisance check of benign calls. | moved meaning | 2026-11-11 |
| judge isolation eval | judge eval | rename | 2026-11-11 |
| `judged_cases` (the audit's state channel) | processed cases | rename | 2026-11-11 |
| known gap of the holdout | known gap | rename | 2026-11-11 |
| location id | place id | rename | 2026-11-11 |
| `MCP_AUDITOR_OPENROUTER_HOSTS` | `MCP_AUDITOR_OPENROUTER_PROVIDERS` | rename | 2026-11-11 |
| missed step, refused step, `missed_steps` | missed model call (`missed_model_calls`) | rename | 2026-11-11 |
| `not_run_conditions` | `not_run_reasons` | rename | 2026-11-11 |
| nuisance rule (`docs/nuisance-rule.md`), nuisance log (`docs/nuisance-log.md`) | nuisance suite rule (`docs/nuisance-suite-rule.md`), nuisance suite log (`docs/nuisance-suite-log.md`) | rename | 2026-11-11 |
| oracle (ADR 015, CLAUDE.md: the grader of any instrument, the ground truth on the honeypot suite) | grader: the ground truth, the labels. "Oracle" now names only the detection suite's grader. | moved meaning | 2026-11-11 |
| oracle version (ADR 016, ADR 020: on the honeypot suite) | ground truth fingerprint | rename | 2026-09-25 |
| oracle version (plans: on the CVE benchmark) | grammar fingerprint | rename | 2026-09-28 |
| `output/eval_report.json` | `output/honeypot_report.json` | rename | 2026-11-11 |
| patched twin, vulnerable twin, git twin (ADR 030, ADR 031, labeling log, plans) | patched image, vulnerable image | rename | 2026-11-11 |
| `payload` (the key of a judge result in the JSON report, the "Payload" line of the Markdown report: the arguments only) | arguments (`arguments`). "Payload" now names the whole generated test input. | moved meaning | 2026-11-11 |
| `pending_replay`, `replay_observations`, `replay_rule` | `pending_retest`, `retest_observations`, `retest_rule`, the two committed baselines keeping `replay_rule` until their next re-recording | rename | 2026-11-11 |
| planting layer | planting code | rename | 2026-11-11 |
| readmission | re-admission | rename | 2026-11-11 |
| refused credit | struck credit | rename | 2026-11-11 |
| `relayed_variables` | redacted variables (`redacted_variables`) | rename | 2026-11-11 |
| replay (re-auditing a gated cell, case, target or server that flipped, missed or raised an alarm: ADR 016, ADR 024, nuisance rule v1 to v4) | retest. "Replay" now names only the resend of ADR 030. | moved meaning | 2026-11-11 |
| replay a capture (stand-ins, CLAUDE.md, plans) | serve a capture | rename | 2026-11-11 |
| replay rule (ADR 024, nuisance rule, `ReplayRule`) | retest rule | rename | 2026-11-11 |
| replay the corpus (ADR 019, the model probe, `evals/probe_method.md`) | send the corpus | rename | 2026-11-11 |
| replayed walk | re-walk | rename | 2026-11-11 |
| replays its exploits (the calibration in CI) | runs its exploits | rename | 2026-11-11 |
| report-only (ADR 033, nuisance rule, nuisance log: said of a server outside the nuisance acceptance layer) | nuisance holdout server. "Report-only" now qualifies only a count that is reported and never compared. | moved meaning | 2026-11-11 |
| report-only population | nuisance holdout layer | rename | 2026-11-11 |
| report-only server | nuisance holdout server | rename | 2026-11-11 |
| rubric (ADR 014: the judge's criteria) | judge criteria. "Rubric" now names only the labeling rubric, the sense of ADR 016 and ADR 027. | moved meaning | 2026-11-11 |
| selection rule (ADR 015, ADR 028, ADR 029, ADR 031) | detection suite rule | rename | 2026-11-11 |
| sentinel (the planted value, ADR 014 to ADR 024, plans before 2026-10-11, and the witness in nuisance plans: "sentinel nonce") | nonce, or witness in a fix check. "Sentinel" now names only the sidecar container. | moved meaning | 2026-10-11 |
| sentinel route | no successor: the responder route that serves a witness | retired | 2026-11-11 |
| server under audit | audited server | rename | 2026-11-11 |
| stub | stand-in, or the real software | rename | 2026-11-02 |
| target (the audited server, its command) | audited server, server command. "Target" now names the unit of the detection suite. | moved meaning | 2026-11-11 |
| target (an HTTP request's target in a stand-in route, the `target` key of `evals/stand_ins/*.json`) | request target (`request_target`) | moved meaning | 2026-11-11 |
| twin (bare twin, replayed twins, nuisance twin) | no successor: the bare repository, the units a replay pairs, the nuisance counterpart of a module or a test | retired | 2026-11-11 |
| `--ungated` | `--no-baseline` | rename | 2026-11-11 |
| unread targets (ADR 015, three targets not yet read in 2026-09) | no successor: acceptance targets not yet read. They were never the holdout layer. | retired | 2026-11-11 |
