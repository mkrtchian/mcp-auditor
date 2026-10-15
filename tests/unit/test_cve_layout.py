import subprocess
from pathlib import Path

from evals.cve_layout import ANCHOR_PATHS, NEUTRAL_TOKEN, build_empty_layout, build_layout
from evals.cve_places import LayoutAnchor
from evals.cve_planting_base import LayoutNode


def test_the_empty_reference_arm_builds_a_valid_repository_at_each_repo_anchor(tmp_path: Path):
    build_empty_layout(tmp_path)

    checkout = _git(["-C", str(tmp_path / "app"), "rev-parse", "--git-dir"])
    bare = _git(["--git-dir", str(tmp_path / "app.git"), "rev-parse", "--is-bare-repository"])

    assert checkout.returncode == 0
    assert bare.stdout.strip() == "true"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["app", "app.git"]


def test_the_empty_reference_arm_carries_none_of_the_normal_tree(tmp_path: Path):
    build_empty_layout(tmp_path)

    config = (tmp_path / "app.git" / "config").read_text()
    checkout_log = _git(["-C", str(tmp_path / "app"), "log", "--all"])
    bare_log = _git(["--git-dir", str(tmp_path / "app.git"), "log", "--all"])

    assert NEUTRAL_TOKEN not in config
    assert "origin" not in config  # no remote.origin.url
    assert not (tmp_path / ".env").exists()
    assert not checkout_log.stdout.strip()  # no commit in the checkout
    assert not bare_log.stdout.strip()  # no commit in the bare


def _git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def _git_log_patch(bare: Path) -> str:
    return subprocess.run(
        ["git", "--git-dir", str(bare), "log", "--all", "-p"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def test_an_empty_node_set_still_materialises_the_full_tree_with_neutral_content(tmp_path: Path):
    build_layout(tmp_path, [])

    assert (tmp_path / "app.git").is_dir()
    assert (tmp_path / "app" / ".git").is_dir()
    assert (tmp_path / ".env").is_file()
    assert NEUTRAL_TOKEN in (tmp_path / ".env").read_text()
    assert NEUTRAL_TOKEN in (tmp_path / "app.git" / "config").read_text()
    assert NEUTRAL_TOKEN in _git_log_patch(tmp_path / "app.git")


def test_the_checkout_config_names_the_bare_as_its_origin(tmp_path: Path):
    build_layout(tmp_path, [])

    checkout_config = (tmp_path / "app" / ".git" / "config").read_text()
    assert ANCHOR_PATHS[LayoutAnchor.PROJECT_BARE] in checkout_config


def test_a_kept_workspace_dotenv_carries_its_nonce_while_the_other_nodes_stay_neutral(
    tmp_path: Path,
):
    build_layout(tmp_path, [LayoutNode(LayoutAnchor.WORKSPACE, ".env", "NONCE-WORKSPACE")])

    assert "NONCE-WORKSPACE" in (tmp_path / ".env").read_text()
    assert NEUTRAL_TOKEN in (tmp_path / "app.git" / "config").read_text()
    assert NEUTRAL_TOKEN in _git_log_patch(tmp_path / "app.git")


def test_a_kept_remote_url_nonce_lands_in_the_bare_config_as_a_url_userinfo(tmp_path: Path):
    build_layout(tmp_path, [LayoutNode(LayoutAnchor.PROJECT_BARE, "config", "NONCE-REMOTE")])

    config = (tmp_path / "app.git" / "config").read_text()
    assert "NONCE-REMOTE" in config
    assert "@" in config  # the nonce sits in a remote URL userinfo
    assert NEUTRAL_TOKEN in (tmp_path / ".env").read_text()


def test_the_checkout_lacks_the_history_env_while_the_bare_history_carries_the_nonce(
    tmp_path: Path,
):
    build_layout(tmp_path, [LayoutNode(LayoutAnchor.PROJECT_BARE, ".env", "NONCE-HISTORY")])

    assert not (tmp_path / "app" / ".env").exists()
    assert (tmp_path / "app" / ".git" / "shallow").is_file()
    assert "NONCE-HISTORY" in _git_log_patch(tmp_path / "app.git")


def test_only_the_kept_node_carries_a_nonce_when_a_single_place_is_kept(tmp_path: Path):
    build_layout(tmp_path, [LayoutNode(LayoutAnchor.WORKSPACE, ".env", "NONCE-ONLY")])

    config = (tmp_path / "app.git" / "config").read_text()
    assert "NONCE-ONLY" not in config
    assert "NONCE-ONLY" not in _git_log_patch(tmp_path / "app.git")
