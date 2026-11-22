"""The code standards violations the tree still carries, each keyed by path, standard and symbol.

An entry is added only for a violation blocked by a fingerprinted file (one an eval fingerprint
hashes, which cannot change without moving that fingerprint) or by a third-party package, and it
names that blocker. It is paid when the blocker changes for its own reason.
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
    blocked_by: FingerprintedFile | ThirdParty


NEWSPAPER = CodeStandard.NEWSPAPER_ORDER
SETATTR = CodeStandard.MONKEYPATCH_SETATTR

_FIREWORKS_RETRY = ThirdParty(
    "langchain-core",
    "langchain_fireworks retries through langchain_core's create_base_retry_decorator, whose "
    "tenacity wait_exponential(min=4) is hard-coded",
)

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
)
