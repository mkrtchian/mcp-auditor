import os
import subprocess
from pathlib import Path


def make_dir_with_file(dir_path: Path, filename: str, content: str) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    file_path = dir_path / filename
    file_path.write_text(content)
    return file_path


def plant_symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)


def init_git_repo_with_commit(repo: Path, commit_message: str) -> None:
    make_dir_with_file(repo, "seed.txt", "seed")
    _git(repo, "init")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", commit_message)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, env=_git_env(), check=True, capture_output=True)


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_AUTHOR_NAME": "mcp-auditor",
        "GIT_AUTHOR_EMAIL": "bench@mcp-auditor.local",
        "GIT_COMMITTER_NAME": "mcp-auditor",
        "GIT_COMMITTER_EMAIL": "bench@mcp-auditor.local",
    }
