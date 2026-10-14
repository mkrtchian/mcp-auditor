"""The frozen `/srv` deployment layout (ADR 031) and its host-side builder.

The tree is built unconditionally at every launch under a temp root mounted at `/srv`, so it
is byte-for-byte universal apart from which nodes carry a live nonce. A bare `app.git` holds a
remote URL in its `config` and an add-then-remove `.env` history (the file lives in the
history but not at HEAD); a shallow checkout `app` is cloned from it, its `.git/config` naming
the bare as origin, genuinely lacking the history `.env`; `/srv/.env` sits at the workspace
level. A kept node carries its nonce, every other node neutral content of the same shape.

`build_layout` runs host-side `git` under the host user (the git and filesystem targets launch
as the host user), so the tree is host-owned and teardown removes it. The commits are fixed in
author, date and message, so the tree is reproducible and the fixture fingerprint stable.
"""

import os
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from evals.cve_places import LayoutAnchor
from evals.cve_planting_base import LayoutNode

ANCHOR_PATHS: Mapping[LayoutAnchor, str] = {
    LayoutAnchor.WORKSPACE: "/srv",
    LayoutAnchor.PROJECT: "/srv/app",
    LayoutAnchor.PROJECT_BARE: "/srv/app.git",
}

NEUTRAL_TOKEN = "mcpaudit-placeholder"  # a token-shaped placeholder on an unkept node

_BARE = "app.git"
_CHECKOUT = "app"
_HISTORY_ENV = ".env"
_WORKSPACE_ENV = ".env"
_CONFIG = "config"

# The absolute paths the layout exploits aim at, derived once so an exploit reads one spelling
# of a node instead of re-anchoring it. The container paths of the three anchors, the bare's
# config file (the prefix-collision and git_init target), and the workspace dotenv.
WORKSPACE = ANCHOR_PATHS[LayoutAnchor.WORKSPACE]
PROJECT = ANCHOR_PATHS[LayoutAnchor.PROJECT]
PROJECT_BARE = ANCHOR_PATHS[LayoutAnchor.PROJECT_BARE]
BARE_CONFIG = f"{PROJECT_BARE}/{_CONFIG}"
WORKSPACE_DOTENV = f"{WORKSPACE}/{_WORKSPACE_ENV}"

# The neutral-content templates: a remote URL whose userinfo carries the value, and a dotenv
# line whose value carries it. Only the value changes between a kept and an unkept node.
_REMOTE_USER = "deploy"
_REMOTE_HOST = "origin.internal"
_REMOTE_REPO = "app.git"
_DOTENV_KEY = "DEPLOY_SECRET"

_GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "mcp-auditor",
    "GIT_AUTHOR_EMAIL": "bench@mcp-auditor.local",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
    "GIT_COMMITTER_NAME": "mcp-auditor",
    "GIT_COMMITTER_EMAIL": "bench@mcp-auditor.local",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
}


def build_layout(root: Path, nodes: Sequence[LayoutNode]) -> None:
    kept = {(node.anchor, node.relpath): node.content for node in nodes}
    bare = root / _BARE
    _build_bare_repository(bare, _value(kept, LayoutAnchor.PROJECT_BARE, _HISTORY_ENV))
    _set_remote_url(bare, _value(kept, LayoutAnchor.PROJECT_BARE, _CONFIG))
    _clone_shallow_checkout(bare, root / _CHECKOUT)
    (root / _WORKSPACE_ENV).write_text(
        _dotenv_line(_value(kept, LayoutAnchor.WORKSPACE, _WORKSPACE_ENV))
    )


def _value(kept: Mapping[tuple[LayoutAnchor, str], str], anchor: LayoutAnchor, relpath: str) -> str:
    return kept.get((anchor, relpath), NEUTRAL_TOKEN)


def _build_bare_repository(bare: Path, history_value: str) -> None:
    bare.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)
        _git(work, "-c", "init.defaultBranch=main", "init", "--quiet")
        (work / _HISTORY_ENV).write_text(_dotenv_line(history_value))
        _git(work, "add", _HISTORY_ENV)
        _git(work, "commit", "--quiet", "-m", "Add deployment secrets")
        (work / _HISTORY_ENV).unlink()
        _git(work, "add", "--all")
        _git(work, "commit", "--quiet", "-m", "Remove committed secrets")
        _git(bare.parent, "clone", "--quiet", "--bare", str(work), bare.name)


def _set_remote_url(bare: Path, userinfo_value: str) -> None:
    url = f"https://{_REMOTE_USER}:{userinfo_value}@{_REMOTE_HOST}/{_REMOTE_REPO}"
    _git(bare, "config", "remote.origin.url", url)


def _clone_shallow_checkout(bare: Path, checkout: Path) -> None:
    # A file:// URL forces a genuine shallow clone of a local repo, so the checkout's object
    # store omits the pre-HEAD history .env, not only its working tree.
    _git(
        checkout.parent, "clone", "--quiet", "--depth", "1", bare.resolve().as_uri(), checkout.name
    )
    _git(checkout, "config", "remote.origin.url", ANCHOR_PATHS[LayoutAnchor.PROJECT_BARE])


def _dotenv_line(value: str) -> str:
    return f"{_DOTENV_KEY}={value}\n"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        env={**os.environ, **_GIT_IDENTITY},
        check=True,
        capture_output=True,
    )
