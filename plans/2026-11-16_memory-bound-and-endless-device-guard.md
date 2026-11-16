# Memory bound on the CVE benchmark's containers, and endless devices in the destructive-payload guard

## Context

On 2026-11-16, a measurement run of the detection acceptance layer, under the settings of a holdout run, audited the kubernetes target (CVE-2025-53355). The auditor sent `kubectl_patch` a patch file named `/dev/zero`. The server ran `kubectl patch deployments web -n default --type strategic --patch-file /dev/zero`, kubectl read the device without end and reached 26.6 GiB of resident memory inside the target's container, and the host ran out of memory.

Two things let that happen, and this plan changes both, as two separate changes that do not justify each other (ADR 016).

1. **The detection suite's confinement bounds no memory.** `confinement_args()` in `evals/cve/planting_base.py` drops the capabilities, forbids privilege escalation and bounds the process count, and stops there. The nuisance suite adds `--memory 4g --memory-swap 4g` on top of it (`evals/cve/nuisance/confinement.py`), and the product's confined regime bounds the audited server at `2g` (ADR 018). Of the detection suite's containers, only three backends of holdout targets carry the bound today, the two the nuisance suite shares (the Doris cluster, the CKAN stack) and SearXNG, which sets it beside its own options. The docstring of `evals/cve/environments.py` says why the detection suite held back: a server killed on memory mid-audit counts as a missed detection, since the client turns a closed connection into an error response and nothing reads the container's kill state. A holdout run audits 37 targets for hours with nobody watching, under that same profile.
2. **The destructive-payload guard lets a read of an endless device through.** ADR 013 scopes the policy to destruction of state and to host availability, and its table already lists the fork bomb. A device that never ends, named as an input, is the same class: consumption that cannot finish, through memory where the fork bomb goes through processes. Under the `unconfined` and `declared_container` execution regimes nothing bounds the server's memory, so the payload takes down the machine of whoever runs the audit.

The first is an instrument change. The second changes the system under test. Each goes in its own commits, with its own justification.

## Decisions taken with the maintainer

- **A target the bound kills mid-audit counts as it does today for any server the auditor brings down: missed in that run, when no nonce surfaced before.** No reader of the kill state is built. The reasons: the kill comes from the auditor's own payload and not from the harness, the rule retries only an audit that ends on an error (detection suite rule, Run conditions and statistic) and such an audit ends normally on error responses, the confined regime of the product gives a user the same outcome (ADR 018 reads a memory kill as a resource-abuse signal), and the kernel most often kills the process that grew, a child of the server, which then answers an error and goes on. The kernel kills the largest process of the container, so on a server that itself holds a large share of the bound (arcadedb and its 2 GiB heap) the server can be the one killed. Retrying such an audit or leaving the target out of N would change the count the rule sets, and would take out of N the targets the auditor brings down.
- **The bound is the nuisance suite's, `--memory 4g --memory-swap 4g`, on every container the CVE benchmark starts under the confinement**: target, namespace holder, sentinels, stand-ins, per-launch and shared backends, and the fix checks' containers. `2g` does not start arcadedb, whose image sets a 2 GiB heap (nuisance suite log, 2026-11-03), and arcadedb is a holdout target (CVE-2026-65831). One value on both suites keeps a holdout run and a nuisance run under the same launch.
- **No rule version and no ADR.** The detection suite rule names no memory bound, the nuisance suite rule already names one, and ADR 013 already covers host availability with a table meant to grow. One entry in each suite's log records the instrument change.
- **Consequences accepted**: the fixture fingerprint of every detection target moves (no detection baseline exists since the reset of 2026-11-02, so nothing is reset), every nuisance fixture fingerprint moves (no nuisance run or baseline exists), and the 17 holdout calibration copies of `evals/nuisance_admission.json` are recorded again after a green calibration check.

## Part 1: endless devices in the destructive-payload guard (system under test)

### Change

`src/mcp_auditor/domain/payload_safety.py`: `DESTRUCTIVE_CONSTRUCTS` gains one construct, placed after the fork bomb:

```python
DestructiveConstruct(
    reason="read of an endless device",
    patterns=("/dev/zero", "/dev/urandom", "/dev/random", "/dev/full"),
),
```

Nothing else in the module changes. `/dev/random` does not match inside `/dev/urandom`, so both are listed. `/dev/full` is listed with them: a read of it returns zero bytes without end, as `/dev/zero` does (`full(4)`). `_HARMLESS_SINKS` (`/dev/null`, `/dev/stdout`, `/dev/stderr`) is untouched and still stripped before matching. A raw-device write that also reads `/dev/zero` (`dd if=/dev/zero of=/dev/sda`) keeps its earlier reason, `destructive disk operation`, since the table is read in order.

`src/mcp_auditor/graph/prompts.py`: `NON_DESTRUCTIVE_CONSTRAINT` is aligned by hand (ADR 013). Its first bullet gains one item, after the fork bomb: `..., no fork bomb, no read of a device that never ends (/dev/zero, /dev/urandom, /dev/random, /dev/full).` The three other bullets do not change.

### Accepted false blocks and what still passes

A bounded read of one of these devices is blocked too (`head -c 16 /dev/urandom`, `dd if=/dev/zero of=out bs=1M count=1`): matching is literal and ADR 013 accepts false blocks over a false allow. A large finite value probes resource abuse as well. A value that names `/dev/full` as an output is blocked under this reason too, when no redirect pattern caught it first. What still passes: `yes`, a watch or follow flag, a huge finite count. The table is aimed at what the generator writes and is not a security boundary (ADR 013).

### Tests (written first, red before the change)

`tests/unit/auditor/test_payload_safety.py`:
- a read of each of the four devices is blocked with the reason `read of an endless device: <pattern>`, once as a bare path value (`{"path": "/dev/zero"}`) and once inside a command (`{"cmd": "cat /dev/urandom"}`);
- a bounded read is blocked too (`{"cmd": "head -c 16 /dev/urandom"}`), the accepted false block;
- the existing tests on the harmless sinks and on `test_every_pattern_is_lowercase_and_not_a_bare_word` stay green unchanged.

`tests/unit/auditor/test_prompts.py`: the test that lists what the constraint names gains `/dev/zero`.

`tests/unit/auditor/support/model_inputs_golden.json` is regenerated in the same commit (`uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given`). Its diff must touch only the keys whose text embeds the constraint, 14 today: `constant/non_destructive`, the three `generation/*` keys, `chain_planning/empty`, `chain_planning/summary`, `step_planning/first`, `step_planning/history_and_hint`, and the six `audit/plain/*` and `audit/redacted/*` captures that hold a generation prompt (`00`, `02`, `04` of each). Any other key that moves is a defect.

### Living docs

- `README.md`, the sentence on the guard: the examples become "(`rm -rf`, `DROP TABLE`, a fork bomb, a read of `/dev/zero`, and a handful more)".
- `CHANGELOG.md`, `[Unreleased]`, under Changed: the guard also refuses a payload that names `/dev/zero`, `/dev/urandom`, `/dev/random` or `/dev/full`, reported as blocked like the others.

### Commit message and declared flips

The commit that changes `src/` answers the four questions of ADR 016. Question 1: the change lands in the system under test. Its justification holds with no mention of any measurement: under the `unconfined` and `declared_container` regimes nothing bounds the audited server's memory, a device that never ends named as an input exhausts the host the way the fork bomb the table already lists does, and a blocked payload of this kind carries no detection value, since it returns no content and a large finite value probes resource abuse as well. Questions 2 to 4 are about a label revision: no label, rubric or instrument is revised, so they do not apply.

`evals/declared_flips.json` stays empty: no planted flaw of the honeypots is reached through one of these devices, so no gated cell is expected to flip.

## Part 2: the memory bound in the CVE benchmark's confinement (instrument)

### Change

`evals/cve/planting_base.py`:
- gains `MEMORY_BOUND = "4g"`, with the comment that sets the value (arcadedb's fixed 2 GiB heap plus an audit's load, the product's regime uses `2g`, ADR 018), and `memory_bound_args()`, both moved from `evals/cve/nuisance/confinement.py` with the comment on `--memory-swap`, `memory_bound_args()` placed right below `confinement_args()`, its caller (newspaper rule, `CLAUDE.md`);
- `confinement_args()` returns the options it returns today followed by `*memory_bound_args()`. This is the order `nuisance_confinement_args()` returns today, so the launch digest of a persistent backend that carried the nuisance confinement does not move and none of those is recreated;
- the comment of `confinement_args()` keeps what it says of the process bound and says of the memory bound that it does not fail gracefully: the kernel kills a process of the container, and how that is counted is in the docstring of `evals/cve/environments.py`.

`evals/cve/nuisance/confinement.py`: `MEMORY_BOUND`, `memory_bound_args` and `nuisance_confinement_args` are removed, with no alias left behind. Its module docstring is rewritten: the nuisance suite runs its servers under the confinement of the CVE benchmark, memory bound included, and this module holds what is the nuisance suite's own (the launch digest of a persistent backend, the user arguments, the single-container launch).

Every caller follows (`grep -rn 'nuisance_confinement_args\|memory_bound_args\|MEMORY_BOUND' evals tests`): a site that took `nuisance_confinement_args()` takes `confinement_args()`, and a site that took `memory_bound_args()` alone (a backend that runs its real software outside the full profile: the Doris cluster, GitLab CE, SearXNG) imports it from `evals.cve.planting_base`. A site that would now carry the bound twice (`confinement_args()` and `memory_bound_args()` in one argv) keeps `confinement_args()` alone.

The one such site is the Kubernetes control plane (`evals/cve/backends/kubernetes.py`): `control_plane_run_args` already takes `*confinement_args()` and appends a `memory_bound` parameter, which the nuisance launch (`control_plane_launch`) and the kubectl fix check (`cve_2025_69902_kubectl.kubectl_env`) fill with `memory_bound_args()` and the detection builder (`kubernetes_detection.kubernetes_injection_env`) with `()`. Once the profile carries the bound, the parameter carries nothing: it is removed from `control_plane_run_args`, `stood_control_plane` and the `ControlPlaneStand` type (`Callable[[str], AbstractContextManager[StoodControlPlane]]`, its comment `# control plane name -> the stood control plane`), and the three callers call `stand(name)`. The fakes that take it follow: `FakeControlPlane.stand` and its `memory_bounds` record (`tests/unit/cve/backends/support/test_kubernetes_backend_given.py`), `_a_control_plane_with_no_container` (`tests/unit/cve/backends/support/test_backend_lifecycle_given.py`) and `_a_stood_control_plane` (`tests/unit/detection/support/test_detection_targets_given.py`). `kubernetes.py` then imports only `user_args` from `evals.cve.nuisance.confinement`, and its module docstring drops "As a nuisance backend it also takes the memory bound": the control plane runs under the confinement, memory bound included, on both suites. `evals/cve/nuisance/fingerprint.py` reads `planting_base.confinement_args()` where it read `confinement.nuisance_confinement_args()`, by attribute access at call time, and its docstring follows. `evals/cve/nuisance/admission/re_admission_docs.py` reads `confinement_args()` and `memory_bound_args()` from `evals.cve.planting_base`, the text of `confinement.md` unchanged.

Nothing is added at a detection call site: every detection launch already takes `confinement_args()` (the builders of `evals/cve/environments.py` and `evals/cve/detection/holdout_environments.py`, the holder, sentinels, stand-ins and the address-setup container in `evals/cve/planting.py`, `planting_docker.py` and `planting_stand_ins.py`, the holdout backends in `evals/cve/backends/`), so each gains the bound through the profile. The calibration kit imports the planting modules in the repository and gains it the same way.

### Comments and docstrings that become false

Each is corrected in the same change:
- `evals/cve/environments.py`, module docstring: the paragraph "The profile carries no memory bound yet..." is replaced. It says: the profile bounds memory, swap included, because the auditor sends resource-abuse payloads by design and one of them can make a server or a child of it grow without end. When a container reaches the bound the kernel kills its largest process, most often the one that grew, and the server itself when it holds a large share of the bound. When that process is the server, the client turns the closed connection into error responses, the audit goes on, and the target counts as missed in that run unless a nonce surfaced before: this is what the confined regime of the product gives a user (ADR 018). Nothing reads the container's kill state: a report counts the calls answered with a lost connection (`lost_connection_responses`, report-only) and does not say what ended the server.
- `evals/cve/kit/launch.py`, the landmine note that says the detection suite's and the kit's launch set no memory bound.
- `evals/cve/detection/holdout_environments.py`, the comment on the two Doris launches ("takes the nuisance memory bound").
- The fix-check modules and backends that say a fix-check server or a per-launch fix-check backend keeps the suite's confinement "without the memory bound" (`evals/cve/nuisance/fix_checks/cve_2025_53372_node_sandbox.py`, `cve_2025_69902_kubectl.py`, `cve_2026_10276_jenkins.py`), and the backend docstrings that speak of "the nuisance confinement, memory bound included" (`evals/cve/backends/n8n.py`, `responder.py`, `jenkins.py`, `gitlab.py`, `node_sandbox_engine.py`, `kubernetes.py`): the confinement is now one, and it includes the bound. Find the rest with `grep -rn -i 'memory bound' evals`.

### Tests (written first, red before the change)

- `tests/unit/cve/test_cve_planting.py`: the confinement carries `--memory` and `--memory-swap` with the same value (the bound bites only when they are equal), and the holder's, a sentinel's and a stand-in's run arguments carry them (through the fake planting docker the file already uses, which records each). `PlantedArgs.run_args()` carries no confinement (each builder prepends `confinement_args()` itself), so the target's argv is covered by the builder tests below, not here.
- One builder of each module: the `Launch.args` of an acceptance builder (`evals/cve/environments.py`) and of a holdout builder (`evals/cve/detection/holdout_environments.py`) carry the bound, in the test files that already cover those builders.
- `tests/integration/test_cve_planting.py`: on a started launch, `docker inspect -f '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}'` reads `4294967296 4294967296` on the holder. The file's target is a one-shot `docker run --rm` (`run_as_target` in its given), gone before an inspect, so the target's bound is read from inside it: `cat /sys/fs/cgroup/memory.max` prints `4294967296` (cgroup v2, the layout of the machine that runs the suite). Docker and network as the file's other tests, skipped without Docker.
- `tests/unit/nuisance/test_nuisance_confinement.py`: `test_the_nuisance_confinement_is_the_acceptance_one_then_the_memory_bound` is deleted with the function it tested. The tests on the single-container launch read `confinement_args()`.
- `tests/unit/cve/backends/test_doris_backend.py`: the pin becomes "the helper and the holdout env differ only by the layout". The test is renamed and no longer strips the bound from the helper.
- `tests/unit/nuisance/test_nuisance_fingerprint.py`: `test_the_fingerprint_moves_when_the_confinement_code_changes` edits a literal the confinement module still holds, and `test_the_fingerprint_moves_when_the_confinement_options_change` patches `planting_base.confinement_args`. A change of the bound's value is already covered: it changes the options that second test pins.
- The tests that pin the absence of the bound now assert that the container carries it, and drop "without the memory bound" from their names:
  - `tests/unit/nuisance/fix_checks/test_jenkins_fix_check_builder.py`, `test_the_per_launch_controller_keeps_the_holdout_confinement_without_the_memory_bound`;
  - `tests/unit/nuisance/fix_checks/test_gravitino_fix_check_builder.py`, `test_the_server_runs_under_the_holdout_confinement_without_the_memory_bound` and `test_each_part_joins_the_per_launch_network_under_its_alias_without_the_memory_bound`;
  - `tests/unit/nuisance/fix_checks/test_mcp_ssh_fix_check_builder.py`, `test_the_per_launch_sshd_runs_hardened_without_the_memory_bound`, and the `"--memory" not in args` line of `test_the_server_joins_the_per_launch_network_not_the_singleton_bridge`;
  - `tests/unit/cve/backends/test_mcp_ssh_holdout_builder.py`, the `"--memory" not in args` line on the detection holdout's per-launch sshd (`sshd_args`) is deleted, nothing replacing it: `carries(args, confinement_args())` just above it now covers the bound.
- Kubernetes: `the_control_plane_was_stood_within_the_memory_bound` (`tests/unit/cve/backends/support/test_kubernetes_backend_then.py`) reads the `memory_bounds` the fake no longer records. It is deleted with its call: the parameter that could double the bound is gone, and `test_the_nuisance_control_plane_carries_the_memory_bound` keeps its assertion and still covers the bound on the control plane.
- Every other test that imports `memory_bound_args`, `nuisance_confinement_args` or `MEMORY_BOUND` from `evals.cve.nuisance.confinement` follows the move, its assertion unchanged.

The grammar golden master is not regenerated: nothing the grammar grades changes.

### The holdout calibration copies

`tests/unit/nuisance/admission/test_nuisance_admission_loads.py` pins that each holdout calibration copy of the committed admission is recorded at its target's current fixture fingerprint. The fixture fingerprint hashes `planting_base.py`, so the 17 `holdout_fingerprint` values of `evals/nuisance_admission.json` go stale with the change, that test turns red, and `run_nuisance run` would refuse.

They are recorded again in the commit that changes the profile, in this order:
1. with the change in the working tree, `uv run python -m evals.run_detection_holdout calibration-check` runs on the 37 holdout targets and exits 0 (Docker, no LLM). It proves each target is live on its vulnerable version and fixed on its patched one under the bound, with its routes and no new layout break or leak;
2. each of the 17 values is replaced by the current fixture fingerprint of the target its copy resolves to (what `current_copy_fingerprints()` in `tests/unit/support/test_nuisance_committed_admission_given.py` computes). No other value of the admission changes.

If a target fails its calibration check under the bound, the step stops there and reports the target and the reason: no fingerprint is recorded, the bound is not raised and no fixture is touched. That decision is the maintainer's.

### The calibration cards

Ten calibration cards of `evals/census.json` list the confinement's options among the items their fixture seeds outside the layout (`seeded_outside_layout`), in eleven items, for instance "Container confinement on the target and the sentinels: --cap-drop ALL, --security-opt no-new-privileges, --pids-limit 256 (confinement_args) ...": one item each on the cards of CVE-2026-33060, CVE-2026-55157, CVE-2026-55787, CVE-2026-104120, CVE-2026-58485, CVE-2026-2130, CVE-2025-11489, CVE-2025-9654 (the per-launch sshd) and CVE-2025-65719 (the control plane), and two on the card of CVE-2026-5323 (its launch command and its confinement profile). `grep -c 'pids-limit 256' evals/census.json` counts 13 lines: the two others are not such items and stay as they are, a `reason` on the card of CVE-2026-35402, which says what its Neo4j settings were sized for, and a gap the card checker reported on CVE-2026-55787 (`draw.card_checks`), which is the record of that check. After the change the eleven items no longer describe the profile in force. They are corrected in the commit that changes the profile, as a correction of the record by the maintainer under version 13 of the detection suite rule, which touches no fixture (the fixture fingerprint hashes no card) and sends no card back to the card checker, since no limit is added or tightened:
- in each of the eleven items, the bound follows `--pids-limit 256` in the item's own form: `, --memory 4g --memory-swap 4g` in the eight that separate the options with commas, ` --memory 4g --memory-swap 4g` in the three written as a command line (CVE-2026-55787, CVE-2026-104120 and the launch command of CVE-2026-5323). Nothing else of the item, its reason or its card changes;
- the card of CVE-2026-33060 names `nuisance_confinement_args`, which this plan removes. Its sentence on the CKAN stack reads: "The CKAN stack's parts run under the same confinement (confinement_args), as they do for the nuisance suite."

`load_census` must still load the file, and a test or a log line that pins the content of the census follows if one does. The diff of `evals/census.json` holds these eleven items and nothing else.

### Mechanical proof, without an LLM

All four run on the changed tree, one after the other and never at the same time (a fix check or a calibration check must not overlap a nuisance command on one machine), and their outcome goes in the log entries:
- `uv run python -m evals.run_detection --calibration-check` (the 4 acceptance targets), exit 0;
- `uv run python -m evals.run_detection_holdout calibration-check` (the 37 holdout targets), exit 0;
- `uv run python -m evals.run_nuisance fix-check`, exit 0: the fix-check servers and per-launch backends now run under the bound, and every recorded fix check must still match;
- `uv run python -m evals.run_nuisance vet`, exit 0, `65 of 65 servers answer their benign calls`. No persistent backend's launch digest moves (see Edge cases), so nothing is recreated beyond the built backend containers and the Doris cluster `vet` replaces on every invocation.

No Dockerfile changes, so no image is rebuilt for this plan beyond what these commands rebuild by themselves. The step must not grow the machine's Docker disk usage: it pulls and builds nothing these commands do not need, and it leaves the cleanup of existing images to the maintainer.

### Log entries

All three are dated 2026-11-16 and written in the commit of the change, with the measured outcomes in place of the bracketed parts.

`docs/labeling-log.md` (every instrument change has an entry there, fixtures included, and the log records the changes to the detection and nuisance fixtures, `CLAUDE.md` and the log's preamble), in the form of the entries of 2026-11-13, headed `### 2026-11-16, the confinement of the CVE benchmark carries the memory bound`:
- **State.** No detection or nuisance baseline is stored, so none is deleted and nothing resets. No holdout run, nuisance run or gate run exists. The honeypot ground truth is unchanged, and no label moves.
- **What changes.** `confinement_args()` (`evals/cve/planting_base.py`) carries the memory bound, `--memory 4g --memory-swap 4g`, moved from the nuisance confinement with its value unchanged, so every container of the CVE benchmark started under the confinement carries it, on both suites and both layers, the fix checks' containers included.
- **Fingerprint.** No grammar, counter, ground truth or judge inputs fingerprint moves. Every detection fixture fingerprint, on both layers, and every nuisance fixture fingerprint move, and the 17 holdout calibration copies are recorded again. The values the copies take are in the nuisance suite log, same day.
- **The four questions of ADR 016.** (1) The change lands in the instrument: the confinement every CVE benchmark container runs under. No prompt, guard or default of the system under test moves in this commit, and the change to the destructive-payload guard, in a commit of its own, does not license it. (2) It was raised by the host running out of memory during a measurement run, a failure of the harness, not by a measured detection or alarm: no baseline of either suite exists. (3) An unbounded container lets one payload exhaust the host and every audit beside it. The value is the nuisance suite's, set by arcadedb's 2 GiB heap, and reads no outcome. (4) It applies to every container started under the confinement, on both suites and both layers, no target or server exempted.

`docs/detection-suite-log.md`:

> 2026-11-16: the confinement of the CVE benchmark gains a memory bound, `--memory 4g --memory-swap 4g`, on every container a detection launch starts under it: the target, the namespace holder, the sentinels, the stand-ins and the backends. The short-lived helpers that take no profile (the layout's busybox, the mcp-ssh `known_hosts` hand-over, the Doris `mysql` client) stay as they were. Until now only the nuisance suite's confinement carried it (nuisance suite log, 2026-11-03), and of the detection suite's containers only three backends of holdout targets: the Doris cluster and the CKAN stack, which the nuisance suite shares, and SearXNG (for the last two, entries of 2026-11-13). On a measurement run of the acceptance layer, a payload that named `/dev/zero` as an input file made a child process of the kubernetes target (CVE-2025-53355) grow to 26.6 GiB and exhausted the host's memory, and a holdout run would have run its 37 targets under the same profile. The value is the nuisance suite's, the smallest under which every server starts as its documentation prescribes (arcadedb sets a 2 GiB heap), so both suites launch a server under one confinement. The bound belongs to the suite's confinement, which no fixture chooses: no exploit, kept place, aim, benign call or image changes. Ten calibration cards list the confinement's options among what their fixture seeds, in eleven items, and each of those items now names the bound, a correction of the record under version 13 that touches no fixture and reopens no card check. The card of CVE-2026-33060 names the profile of the CKAN stack by its current function. When a container reaches the bound the kernel kills its largest process: most often the child that grew, after which the server answers an error and goes on, and the server itself when it holds a large share of the bound, as arcadedb does. A target whose server the bound kills during an audit is counted as any server the auditor brings down: the client turns the closed connection into error responses, the audit ends normally, and the target is missed in that run unless a nonce surfaced before. Only an audit that ends on an error is retried (Run conditions and statistic), and a kill the auditor's own payload causes is not a failure of the fixture. Nothing reads the container's kill state: a report counts the calls answered with a lost connection and does not say what ended the server. The fixture fingerprint hashes the planting code, so the fingerprint of every target moves, on both layers. The acceptance layer has had no baseline since the reset of 2026-11-02, so none is reset. On the tree of this entry's commit, `run_detection --calibration-check` [exit, targets] and `run_detection_holdout calibration-check` [exit, targets]. The break the entry of 2026-11-14 keeps on CVE-2026-19978 (android-mcp-server), its device stand-in closing every stream, rests on a reason the bound removes: the adb client that loops without end on `push . .` is now killed inside the target's container at the bound, as in a nuisance launch (nuisance suite log, 2026-11-14), instead of exhausting the host. The repair is tried again in a change of its own. No holdout run has taken place.

`docs/nuisance-suite-log.md`:

> 2026-11-16: the memory bound moves from the nuisance confinement into the confinement of the CVE benchmark (`confinement_args()`), with its value unchanged, `--memory 4g --memory-swap 4g` (detection suite log, same day). The run's server and backend containers carry what they carried. The fix checks' server containers and per-launch backends now carry the bound too: the entry of 2026-11-03 left them without it because the bound checks nothing there, not because it would harm them, and one profile for every confined container leaves no confined launch unbounded. `run_nuisance fix-check` [exit, every recorded fix check matched]. The 17 holdout calibration copies are recorded again, their targets' fixture fingerprints having moved with the planting code, after `run_detection_holdout calibration-check` exited 0 on the tree of this entry's commit: [flaw, old fingerprint, new fingerprint, one per copy]. The nuisance fixture fingerprint covers the confinement module and its options, so all 65 fingerprints move, before any run. No persistent backend's launch changes, so none is recreated. `run_nuisance vet` [outcome]. No admission value other than the 17 fingerprints changes. No nuisance run or gate run has taken place.

### Living docs

- `CLAUDE.md`, Landmines: the Doris entry says the two launches differ "only by the layout mount" (the nuisance memory bound is no longer a difference). The Commands list keeps what it says of the nuisance run's `4g` bound, which stays true.
- `README.md`, the detection suite's **Safety** paragraph: "all capabilities dropped, no privilege escalation, a process bound," gains "a memory bound (`--memory 4g --memory-swap 4g`),".
- `CHANGELOG.md`, `[Unreleased]`, under Changed: every container of the CVE benchmark's detection suite started under the confinement runs under the memory bound the nuisance suite already set, `--memory 4g --memory-swap 4g`, and so do the nuisance fix checks' containers. The existing bullet of that section on the nuisance run's memory bound loses its last sentence, "The fix checks' server and per-launch responder containers stay unbounded.", which the change makes false.
- `docs/glossary.md`: no term is added or moved. The entry "confinement" already lists the memory bound.

## What stays unchanged

- The two rules (detection suite rule v13, nuisance suite rule v6) and every ADR. `plans/` and `docs/adr/` are not edited.
- The grammar, the counter, their fingerprints and the grammar golden master.
- Every Dockerfile, exploit, kept place, aim, benign call and admission value, apart from the 17 `holdout_fingerprint` values, and every card, apart from the eleven items that list the confinement's options.
- The product's confined regime and its `2g` bound (`src/mcp_auditor/adapters/server_launch.py`, ADR 018). Part 2 touches nothing under `src/`.
- `evals/holdout_conditions.json`, the census, the draw record and every other part of `evals/census.json`, the honeypot and judge baselines, `evals/declared_flips.json`.
- The honeypot servers.
- The corpus of the model probe (`evals/fixtures/probe_corpus.json`). Part 1 changes the generation prompt, so the corpus is captured again before the next model probe (`evals/probe_method.md`), which this plan does not run.

## Edge cases

- A container that joins a namespace holder takes its own memory bound: `--memory` is per container and has no joiner restriction, unlike the resolver option.
- The one-shot address-setup container (`NET_ADMIN`) takes the bound through the profile and exits before the target starts.
- No persistent backend gets a new launch digest. Every container started through `labelled_run_args` (the CKAN, Gravitino and httpbin parts, the responders, the Jenkins controller, the n8n responder, the mcp-ssh sshd singleton) took `nuisance_confinement_args()`, whose argv `confinement_args()` now returns unchanged, and the Doris cluster takes `memory_bound_args()` alone, also unchanged. The detection holdout CKAN builder reuses that same stack (`ensure_ckan_backend`). The containers that took `confinement_args()` alone and now gain the bound (the n8n instance of GHSA-8g7g-hmwm-6rv2, the per-launch sshd, the Doris sentinels, the targets) are all per-launch, so nothing persistent is recreated.
- Containers outside the confinement stay as they are: the short-lived helpers (the layout busybox, the mcp-ssh `known_hosts` chown, the Doris `mysql` client) and the neo4j fix check's database container (`cve_2026_35402_neo4j_cypher.neo4j_container_args`), which takes no profile today. The plan changes the profile, not which containers take it.
- The host holds 31 GB: eight audits whose containers all reach the bound at once would ask for 32 GiB. The concurrency of a run is the maintainer's choice at launch and is no part of this plan.

## Verification

Per step, the short loop of `CLAUDE.md`, then at the close of each part:

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
```

After Part 1, the golden diff is read key by key. After Part 2, the four no-LLM commands of "Mechanical proof" exit 0 and `git diff --stat evals/nuisance_admission.json` shows 17 insertions and 17 deletions, and the diff of `evals/census.json` holds the eleven card items alone.

After the last step, run by the maintainer and not by an implementation step, since they call a model: `uv run python -m evals.run_honeypot_suite` (the honeypot gate, under the baseline's model), then the measurement run of the detection acceptance layer under the settings of a holdout run. The judge gate is not rerun: nothing the judge reads changes.

## Due diligence record

What the due-diligence pass concluded, on 2026-11-16, about the external facts this plan cites or defers. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `--memory 4g --memory-swap 4g` gives the container no swap, the same value on both flags being what makes the bound bite (verified against docs.docker.com, Resource constraints: "If `--memory` and `--memory-swap` are set to the same value, this prevents containers from using any swap").
- SETTLED: inside such a container `/sys/fs/cgroup/memory.max` reads `4294967296` and `/sys/fs/cgroup/memory.swap.max` reads `0` (verified against the runc cgroups code, `ConvertMemorySwapToCgroupV2Value` returns `memorySwap - memory`, and dockerd's reference, `--default-cgroupns-mode` defaults to `private`; the host runs cgroup v2, Docker 29.9.3, swap limit support on, no daemon.json override of the cgroup namespace mode).
- OPEN (unverified): `docker inspect -f '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}'` printing `4294967296 4294967296` on the holder; follows from `--memory-swap` being the memory-plus-swap total (docker run reference), but no live source shows the inspect field, and the integration test itself settles it on its first run.
- SETTLED: a container joining `--network container:<holder>` keeps its own memory bound; the memory flags are not among the options Docker refuses in that mode (verified against docs.docker.com, Networking overview, the list of flags unsupported with `container:`), and the cgroup is per container, not per network namespace.
- SETTLED: at the bound the kernel's OOM killer kills one task of the container's cgroup, chosen by `oom_score`, whose basis is the memory the process uses, and never a task outside the cgroup; `memory.oom.group` defaults to `0` and Docker leaves it at `0` (verified against the kernel's cgroup v2 admin guide, proc_pid_oom_score(5), and the `memory.oom.group` of the containers running on this host, all `0`).
- SETTLED: a read of `/dev/zero`, `/dev/urandom` or `/dev/random` never reaches end of file, and `/dev/random` blocks only during early boot since Linux 5.6 (verified against null(4) and random(4); the host kernel is 7.0).
- SETTLED: a read of `/dev/full` returns `\0` bytes without end, as `/dev/zero` does (verified against full(4)).
- OPEN (unverified): arcadedb's image sets a fixed 2 GiB heap, the reason `2g` is too small; taken from the nuisance suite log of 2026-11-03, not re-checked against the image in this pass (no image pulled or inspected).

## Implementation steps

Two steps, one per part, one commit each. Part 1 changes the system under test and Part 2 the instrument, so they never share a commit (ADR 016). Part 2 cannot be cut further: any change to the AST of `evals/cve/planting_base.py` (or of a backend module a holdout fixture lists in its `backend_sources`: `kubernetes.py`, `doris.py`, `ckan.py`, `searxng.py`, `mcp_ssh_sshd.py`, all touched by the import move) moves the fixture fingerprint the 17 holdout calibration copies pin, `tests/unit/nuisance/admission/test_nuisance_admission_loads.py` turns red, and re-recording them is licensed only by a green `run_detection_holdout calibration-check` on that tree. A preliminary refactoring commit or a follow-up cleanup commit would each need their own re-recording and their own 37-target calibration check. Most of Step 2's edits are mechanical (import moves, test renames, docstrings), which keeps it within one session despite its file count.

### Step 1: endless devices in the destructive-payload guard (system under test)

**Files**
- `tests/unit/auditor/test_payload_safety.py`
- `tests/unit/auditor/test_prompts.py`
- `src/mcp_auditor/domain/payload_safety.py`
- `src/mcp_auditor/graph/prompts.py`
- `tests/unit/auditor/support/model_inputs_golden.json` (regenerated)
- `README.md`, `CHANGELOG.md`

**Do**
1. Tests first (see Test), run them with `uv run pytest tests/unit/auditor/test_payload_safety.py tests/unit/auditor/test_prompts.py -n 0` and confirm the new ones fail.
2. `payload_safety.py`: append to `DESTRUCTIVE_CONSTRUCTS`, right after the `fork bomb` construct (last today), `DestructiveConstruct(reason="read of an endless device", patterns=("/dev/zero", "/dev/urandom", "/dev/random", "/dev/full"))`. Nothing else in the module changes (`_HARMLESS_SINKS` untouched).
3. `prompts.py`: in `NON_DESTRUCTIVE_CONSTRAINT`, the first bullet ends `..., no fork bomb, no read of a device that never ends (/dev/zero, /dev/urandom, /dev/random, /dev/full).` The three other bullets do not change.
4. Regenerate the golden: `uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given`. Read its diff key by key: only the 14 keys whose text embeds the constraint may move (`constant/non_destructive`, the three `generation/*`, `chain_planning/empty`, `chain_planning/summary`, `step_planning/first`, `step_planning/history_and_hint`, and `audit/plain/00`, `02`, `04` and `audit/redacted/00`, `02`, `04`). Any other key that moves is a defect to fix before going on.
5. Living docs: `README.md`, the guard sentence (line ~56) reads "(`rm -rf`, `DROP TABLE`, a fork bomb, a read of `/dev/zero`, and a handful more)". `CHANGELOG.md`, `[Unreleased]`, `### Changed`: one bullet saying the guard also refuses a payload that names `/dev/zero`, `/dev/urandom`, `/dev/random` or `/dev/full`, reported as blocked like the others.
6. `evals/declared_flips.json` stays empty.
7. Commit message (prepared for the commit, `feat(domain): ...`): answers the four questions of ADR 016 as written in "Commit message and declared flips" of Part 1 (Q1: lands in the system under test, justification with no mention of a measurement, the unbounded `unconfined` and `declared_container` regimes, same class as the fork bomb, no detection value. Q2 to Q4: no label, rubric or instrument revised, so they do not apply). Nothing under `evals/` changes in this commit.

**Test**
- `test_payload_safety.py` (plain functions in the file's style, no given/then needed): for each of the four devices, `destructive_reason({"path": "<device>"}) == "read of an endless device: <device>"` and `destructive_reason({"cmd": "cat <device>"})` returns the same (a parametrized test over the four devices is fine). `destructive_reason({"cmd": "head -c 16 /dev/urandom"}) == "read of an endless device: /dev/urandom"` (the accepted false block). `destructive_reason({"cmd": "dd if=/dev/zero of=/dev/sda"})` keeps the reason it returns today (`destructive disk operation: ...`, read the exact pattern from the table), since the table is read in order. The harmless-sink tests and `test_every_pattern_is_lowercase_and_not_a_bare_word` stay unchanged and green.
- `test_prompts.py`, `test_forbids_destruction_and_names_benign_markers`: gains `assert "/dev/zero" in NON_DESTRUCTIVE_CONSTRAINT`.

**Verify**
- Short loop: `uv run pytest tests/unit -n auto --maxprocesses 6` green, `uv run pyright <changed files>`.
- Closing: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`, all green. The golden diff touches the 14 keys alone.

### Step 2: the memory bound in the CVE benchmark's confinement (instrument)

Read Part 2 of this plan whole before starting: it lists every site and the exact wording of the log entries. Docker disk clause: pull or build nothing the commands below do not need by themselves, never pass `--no-cache`, and leave the cleanup of existing images to the maintainer.

**Files** (find the full set with `grep -rn 'nuisance_confinement_args\|memory_bound_args\|MEMORY_BOUND' evals tests` and `grep -rn -i 'memory bound' evals --include=*.py`; Dockerfile comments that mention "the memory bound" stay as they are, they remain true)
- Tests: `tests/unit/cve/test_cve_planting.py`, `tests/unit/cve/test_cve_launches.py` (or the file that already covers an acceptance builder of `evals/cve/environments.py`), a holdout builder's test file (`tests/unit/cve/backends/test_doris_backend.py` covers `holdout_environments.doris_db_env`), `tests/integration/test_cve_planting.py` and its given, `tests/unit/nuisance/test_nuisance_confinement.py`, `tests/unit/nuisance/test_nuisance_fingerprint.py`, `tests/unit/nuisance/fix_checks/test_jenkins_fix_check_builder.py`, `test_gravitino_fix_check_builder.py`, `test_mcp_ssh_fix_check_builder.py`, `tests/unit/cve/backends/test_mcp_ssh_holdout_builder.py`, `tests/unit/cve/backends/test_kubernetes_backend.py` with `support/test_kubernetes_backend_given.py` and `support/test_kubernetes_backend_then.py`, `tests/unit/cve/backends/support/test_backend_lifecycle_given.py`, `tests/unit/detection/support/test_detection_targets_given.py`, and every other test importing the three moved names (`test_backend_lifecycle.py`, `test_searxng_backend.py`, `test_nuisance_backend_registry.py`, `test_nuisance_re_admission_dossier.py`, the `support/*_then.py` of gitlab, httpbin, node sandbox engine)
- Production: `evals/cve/planting_base.py`, `evals/cve/nuisance/confinement.py`, `evals/cve/nuisance/fingerprint.py`, `evals/cve/nuisance/admission/re_admission_docs.py`, `evals/cve/backends/{kubernetes,kubernetes_detection,ckan,doris,gitlab,gravitino,httpbin,jenkins,mcp_ssh_sshd,n8n,node_sandbox_engine,responder,searxng}.py`, `evals/cve/nuisance/fix_checks/{cve_2025_69902_kubectl,cve_2025_53372_node_sandbox,cve_2026_10276_jenkins,cve_2025_59834_adb_mcp}.py` (the last only if its sentence becomes false), `evals/cve/environments.py`, `evals/cve/kit/launch.py`, `evals/cve/detection/holdout_environments.py`
- Records: `evals/nuisance_admission.json` (17 values), `evals/census.json` (eleven card items)
- Logs and docs: `docs/labeling-log.md`, `docs/detection-suite-log.md`, `docs/nuisance-suite-log.md`, `CLAUDE.md`, `README.md`, `CHANGELOG.md`

**Do**

A. Tests first, red before the change (see Test). Run only the files you change, `-n 0`.

B. The profile (Part 2, "Change"):
- `planting_base.py`: add `MEMORY_BOUND = "4g"` with its comment (arcadedb's fixed 2 GiB heap plus an audit's load, the product's regime uses `2g`, ADR 018), and `memory_bound_args()` with its `--memory-swap` comment, both moved verbatim from `evals/cve/nuisance/confinement.py`, `memory_bound_args()` right below `confinement_args()`. `confinement_args()` returns its current options followed by `*memory_bound_args()` (this exact order keeps every persistent backend's launch digest). Its comment keeps the process-bound sentence and says the memory bound does not fail gracefully: the kernel kills a process of the container, and how that is counted is in the docstring of `evals/cve/environments.py`.
- `nuisance/confinement.py`: remove `MEMORY_BOUND`, `memory_bound_args`, `nuisance_confinement_args` (no alias). `single_container_launch_args` and `single_container_run_args` take `confinement_args()`. Rewrite the module docstring as Part 2 says (the nuisance suite runs its servers under the CVE benchmark's confinement, memory bound included; this module holds the launch digest of a persistent backend, the user arguments and the single-container launch; keep the paragraph on servers with public names).
- Every caller: `nuisance_confinement_args()` becomes `confinement_args()` (imported from `evals.cve.planting_base`), `memory_bound_args` alone (Doris cluster, GitLab CE, SearXNG) is imported from `evals.cve.planting_base`. No argv may carry the bound twice.
- Kubernetes: remove the `memory_bound` parameter from `control_plane_run_args`, `stood_control_plane` and `ControlPlaneStand` (becomes `Callable[[str], AbstractContextManager[StoodControlPlane]]` with the comment `# control plane name -> the stood control plane`). `control_plane_launch` (`kubernetes.py`), `kubectl_env` (`cve_2025_69902_kubectl.py`) and `kubernetes_injection_env` (`kubernetes_detection.py`, today `control_plane.stand(name, ())`) call `stand(name)`. `kubernetes.py` imports only `user_args` from `evals.cve.nuisance.confinement`, and its docstring drops "As a nuisance backend it also takes the memory bound". The fakes follow: `FakeControlPlane.stand` loses the parameter and its `memory_bounds` record, `_a_control_plane_with_no_container` and `_a_stood_control_plane` lose it too.
- `nuisance/fingerprint.py`: reads `planting_base.confinement_args()` (attribute access at call time) where it read `confinement.nuisance_confinement_args()`, docstring follows. `re_admission_docs.py` reads the two functions from their new place, `confinement.md`'s text unchanged.

C. Comments and docstrings that become false (Part 2, "Comments and docstrings that become false"): the `environments.py` paragraph "The profile carries no memory bound yet..." is replaced by the text the plan gives, the `kit/launch.py` landmine note, the Doris comment in `holdout_environments.py` (~line 272), the fix-check and backend docstrings ("without the memory bound", "the nuisance confinement, memory bound included"). Re-run `grep -rn -i 'memory bound\|nuisance confinement' evals --include=*.py` and read each hit. A comment and a module docstring do not move a fingerprint (`fingerprint_source` in `evals/baseline.py` leaves both out), but the docstring of a function or a class is hashed with the code: an edit to one in a module a fixture fingerprint reads is made here, before E, never after F.

D. Short loop green except `tests/unit/nuisance/admission/test_nuisance_admission_loads.py`, which is expected red until F. Then run `uv run pytest tests/integration/test_cve_planting.py -n 0` (Docker) and confirm the new integration test passes (it settles the OPEN line of the due diligence record on the holder's inspect values).

E. Mechanical proof (Docker, no LLM). Run the four commands one after the other, never at the same time and never while an integration test run is in progress, each in the background with its output redirected to a file outside the repository, and read only the summary lines and exit code:
1. `uv run python -m evals.run_detection --calibration-check`, exit 0 (the 4 acceptance targets);
2. `uv run python -m evals.run_detection_holdout calibration-check`, exit 0 (the 37 holdout targets);
3. `uv run python -m evals.run_nuisance fix-check`, exit 0, every recorded fix check matched;
4. `uv run python -m evals.run_nuisance vet`, exit 0, `65 of 65 servers answer their benign calls`.

Stop and report to the maintainer, with the target or server and the reason, on any other outcome: a target out of calibration under the bound, a fix-check mismatch, a vet failure, or an exit 3 on an absent or stale image (do not build it). In that case no fingerprint is recorded, the bound is not raised, no fixture is touched and nothing is committed.

F. Records, only after E is green:
- `evals/nuisance_admission.json`: compute the new values with `current_copy_fingerprints()` (`tests/unit/support/test_nuisance_committed_admission_given.py`) in a one-off script, keep a flaw -> (old, new) table for the nuisance suite log, and replace each of the 17 `holdout_fingerprint` hex values textually so the file's formatting is kept (two copies resolve to one target and carry the same value). `git diff --stat evals/nuisance_admission.json` shows 17 insertions and 17 deletions and nothing else.
- `evals/census.json`: in each of the eleven `seeded_outside_layout` items "The calibration cards" lists, insert the bound right after `--pids-limit 256`, as `, --memory 4g --memory-swap 4g` where the item separates its options with commas and as ` --memory 4g --memory-swap 4g` in the three written as a command line. The two other lines holding `pids-limit 256` (the `reason` on the card of CVE-2026-35402 and the reported gap of the card check of CVE-2026-55787) are not edited. The card of CVE-2026-33060: the same item (one of the eleven) also holds the sentence "The CKAN stack's parts run under the nuisance suite's confinement (nuisance_confinement_args), as they do for the nuisance suite.", which becomes "The CKAN stack's parts run under the same confinement (confinement_args), as they do for the nuisance suite." `load_census` still loads the file (`uv run pytest tests/unit -k census -n 0` at least), and the diff holds those items alone.

G. Logs and living docs, with the measured outcomes of E and F in place of the bracketed parts of Part 2's "Log entries":
- `docs/labeling-log.md`: the entry `### 2026-11-16, the confinement of the CVE benchmark carries the memory bound`, at the end of the log, after the 2026-11-14 entry, in the form of the 2026-11-13 entries (Commit, State, What changes, Fingerprint, the four questions of ADR 016).
- `docs/detection-suite-log.md` and `docs/nuisance-suite-log.md`: the two entries of the plan, appended in date order.
- `CLAUDE.md`, the Doris landmine: "differ only by the layout mount and the nuisance memory bound" becomes "differ only by the layout mount". `README.md`, the detection suite's **Safety** paragraph: "a process bound," becomes "a process bound, a memory bound (`--memory 4g --memory-swap 4g`),". `CHANGELOG.md`, `[Unreleased]`, `### Changed`: one bullet saying every container of the detection suite started under the confinement now runs under the memory bound the nuisance suite already set, `--memory 4g --memory-swap 4g`, and so do the nuisance fix checks' containers, and the existing bullet on the nuisance run's memory bound loses its last sentence ("The fix checks' server and per-launch responder containers stay unbounded.").

H. Commit (`chore(evals): ...` or the type the repo uses for instrument changes): one commit holding the code, the tests, the 17 fingerprints, the eleven card items, the three log entries and the living docs. Nothing under `src/` changes.

**Test**
- `test_cve_planting.py` (unit): `confinement_args()` carries `--memory` and `--memory-swap` with equal values (`"4g"`), and through the fake planting docker the file already uses, the holder's, a sentinel's and a stand-in's run arguments each carry them.
- An acceptance builder of `evals/cve/environments.py` and a holdout builder of `evals/cve/detection/holdout_environments.py`: their `Launch.args` carry `--memory 4g` and `--memory-swap 4g`, in the test files that already cover those builders.
- `tests/integration/test_cve_planting.py`: on a started launch with a holder, `docker inspect -f '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}' <holder>` reads `4294967296 4294967296`, and inside the one-shot target `cat /sys/fs/cgroup/memory.max` prints `4294967296`. Skipped without Docker like the file's other tests.
- `test_nuisance_confinement.py`: delete `test_the_nuisance_confinement_is_the_acceptance_one_then_the_memory_bound`. The single-container tests read `confinement_args()`.
- `test_doris_backend.py`: `test_the_helper_and_the_holdout_env_differ_only_by_the_layout_and_the_memory_bound` is renamed `..._differ_only_by_the_layout` and no longer strips the bound from the helper.
- `test_nuisance_fingerprint.py`: `test_the_fingerprint_moves_when_the_confinement_code_changes` edits a literal the confinement module still holds (for instance `LAUNCH_LABEL = f"{LABEL}-launch"`). `test_the_fingerprint_moves_when_the_confinement_options_change` patches `planting_base.confinement_args`.
- Absence pins turned into presence assertions, "without the memory bound" dropped from the names: `test_the_per_launch_controller_keeps_the_holdout_confinement_without_the_memory_bound` (jenkins), `test_the_server_runs_under_the_holdout_confinement_without_the_memory_bound` and `test_each_part_joins_the_per_launch_network_under_its_alias_without_the_memory_bound` (gravitino), `test_the_per_launch_sshd_runs_hardened_without_the_memory_bound` and the `"--memory" not in args` line of `test_the_server_joins_the_per_launch_network_not_the_singleton_bridge` (mcp-ssh fix check), the `"--memory" not in args` line of `test_mcp_ssh_holdout_builder.py`.
- Kubernetes: `the_control_plane_was_stood_within_the_memory_bound` is deleted with its call. `test_the_nuisance_control_plane_carries_the_memory_bound` keeps its assertion.
- Every other test importing a moved name follows the move, assertion unchanged. The grammar golden master is not regenerated.

**Verify**
- Short loop `uv run pytest tests/unit -n auto --maxprocesses 6` green after F (the admission-loads test included), `uv run pyright <changed files>` in the loop.
- The four commands of E exit 0, as listed.
- `git diff --stat evals/nuisance_admission.json` shows 17 insertions and 17 deletions, the diff of `evals/census.json` holds the eleven card items alone, nothing under `src/` or `evals/docker/` changes.
- After F, a change to the code of a module a detection fixture fingerprint reads (a later pass's fix included) makes the 17 values stale again: `test_nuisance_admission_loads.py` turns red, and E.2 and F are done again on that tree.
- Closing: `uv run pytest -n auto` (not concurrently with any command of E), `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`, all green.
- Left to the maintainer after this step, since they call a model: the honeypot gate (`uv run python -m evals.run_honeypot_suite`), then the measurement run of the detection acceptance layer under the settings of a holdout run.
