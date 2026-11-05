"""The frozen `/srv` deployment layout (ADR 031), its host-side builder and its owner.

The tree is built unconditionally at every launch under a temp root mounted at `/srv`, so it
is byte-for-byte universal apart from which nodes carry a live nonce. A bare `app.git` holds a
remote URL in its `config` and an add-then-remove `.env` history (the file lives in the
history but not at HEAD); a shallow checkout `app` is cloned from it, its `.git/config` naming
the bare as origin, genuinely lacking the history `.env`; `/srv/.env` sits at the workspace
level. A kept node carries its nonce, every other node neutral content of the same shape.

The tree belongs to the unprivileged account, uid and gid 65534, on every target and both
versions, as version 11 of the holdout rule's Deployment layout asks: a server under that
account owns the checkout it runs git in and writes to a layout mounted read-write. The host
user cannot chown, so `owned_layout` builds the tree on the host (`build_layout` runs host-side
`git` at a fixed umask, author, date and message, so the tree is reproducible and the fixture
fingerprint stable), then hands it over once complete through the `PlantingDocker` port, a
short-lived container running `chown -hR`. The host user cannot delete what the account owns
either, so the root sits under a host-owned outer directory carrying `LAYOUT_PREFIX`, and a
second container removes the root before the outer directory is cleaned up. The root is
traversable and the tree readable by any account, whatever the host's umask, so a server under
any account resolves `/srv` and `..` as a deployed one does.

The mount mode is the target's, declared on its host (`PlantingHost.layout_mount`), so its two
versions and its layout check share it: read-only, or read-write on a target whose exploits,
written from the published mechanism, write to the layout. Every builder mounts the tree through
`layout_mount_args`, and none decides the mode itself. `WORK` is the working directory of a
target that cannot write to the checkout while a tool its flaw is reached through writes to the
working directory first: a per-launch tmpfs the planting layer emits, never a place.
"""

import os
import subprocess
import tempfile
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

from evals.cve_places import LayoutAnchor
from evals.cve_planting_base import (
    LAYOUT_PREFIX,
    LAYOUT_ROOT,
    LayoutMount,
    LayoutNode,
    PlantingDocker,
)

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
WORK = "/work"

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


@contextmanager
def owned_layout(docker: PlantingDocker, build: Callable[[Path], None]) -> Generator[Path]:
    with tempfile.TemporaryDirectory(prefix=LAYOUT_PREFIX, ignore_cleanup_errors=True) as name:
        # The try covers the build and the hand-over: a chown that fails midway leaves entries
        # the host user cannot remove.
        try:
            root = Path(name) / LAYOUT_ROOT
            build(root)
            docker.hand_over_layout(str(root))
            yield root
        finally:
            docker.remove_layout(name)


def layout_mount_args(root: Path, mount: LayoutMount) -> list[str]:
    if mount is LayoutMount.READ_WRITE:
        return ["-v", f"{root}:{WORKSPACE}"]
    return ["-v", f"{root}:{WORKSPACE}:ro"]


def build_layout(root: Path, nodes: Sequence[LayoutNode]) -> None:
    _traversable_root(root)
    kept = {(node.anchor, node.relpath): node.content for node in nodes}
    bare = root / _BARE
    _build_bare_repository(bare, _value(kept, LayoutAnchor.PROJECT_BARE, _HISTORY_ENV))
    _set_remote_url(bare, _value(kept, LayoutAnchor.PROJECT_BARE, _CONFIG))
    _clone_shallow_checkout(bare, root / _CHECKOUT)
    workspace_env = root / _WORKSPACE_ENV
    workspace_env.write_text(_dotenv_line(_value(kept, LayoutAnchor.WORKSPACE, _WORKSPACE_ENV)))
    workspace_env.chmod(0o644)


def build_empty_layout(root: Path) -> None:
    """The rule's reference arm (holdout-rule.md:159): a minimal valid empty node at each layout
    path, by the node's type, so the break detector can compare the server launched with and
    without the layout even when the server requires its scope to be a valid repository (a bare
    empty directory kills such a server before tools/list). The workspace anchor (/srv) is an empty
    directory, the checkout anchor (/srv/app) an empty initialised repository, the bare anchor
    (/srv/app.git) an empty bare repository. None carries the normal tree's content: no remote, no
    history, no workspace dotenv, only a valid empty instance of each node's type. Host-side only,
    the built tree need not be byte-reproducible."""
    _traversable_root(root)
    _git(root, "-c", "init.defaultBranch=main", "init", "--quiet", _CHECKOUT)
    _git(root, "init", "--bare", "--quiet", _BARE)


def _traversable_root(root: Path) -> None:
    # A temp root is 0700, which an unprivileged server cannot traverse to the checkout or up
    # from it.
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)


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
        umask=0o022,
    )
