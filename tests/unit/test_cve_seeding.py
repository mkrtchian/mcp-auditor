import subprocess
from pathlib import Path

from evals.cve_seeding import init_git_repo_with_commit, make_dir_with_file, plant_symlink

SENTINEL = "s3nt1nel_ab12cd34ef56"


def test_make_dir_with_file_writes_content(tmp_path: Path):
    file_path = make_dir_with_file(tmp_path / "outside", "flag.txt", SENTINEL)

    assert file_path.read_text() == SENTINEL


def test_plant_symlink_resolves_to_target(tmp_path: Path):
    target = make_dir_with_file(tmp_path / "outside", "flag.txt", SENTINEL)
    link = tmp_path / "sandbox" / "report"

    plant_symlink(link, target)

    assert link.is_symlink()
    assert link.resolve() == target.resolve()
    assert link.read_text() == SENTINEL


def test_init_git_repo_carries_commit_message(tmp_path: Path):
    repo = tmp_path / "other"

    init_git_repo_with_commit(repo, SENTINEL)

    log = subprocess.run(
        ["git", "log", "--format=%s"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    assert SENTINEL in log.stdout
