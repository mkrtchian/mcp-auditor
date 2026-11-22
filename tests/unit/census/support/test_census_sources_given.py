import subprocess
from pathlib import Path
from typing import Any


def cpe_configurations(*criteria: str) -> list[dict[str, Any]]:
    matches = [{"vulnerable": True, "criteria": each} for each in criteria]
    return [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}]


def a_committed_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "README").write_text("advisories")
    git = ["git", "-C", str(repository), "-c", "user.name=a", "-c", "user.email=a@example.org"]
    subprocess.run([*git, "init", "--quiet"], check=True)
    subprocess.run([*git, "add", "README"], check=True)
    subprocess.run([*git, "commit", "--quiet", "--message", "init"], check=True)
    head = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    return repository, head.stdout.strip()
