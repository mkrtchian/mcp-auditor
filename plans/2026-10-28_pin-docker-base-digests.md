# Pin the base image digest of every eval Docker image

## Context

Before each holdout run, every vulnerable and patched image is built again from its committed Dockerfile, with the build cache (`docs/holdout-rule.md`, Run conditions). The nuisance run does the same (`docs/nuisance-rule.md`, Images), whose text already says that "an image pins the server's patched version and the digest of its base image, as the CVE Dockerfiles do". The acceptance Dockerfiles pin their base by digest. Most of the holdout and nuisance Dockerfiles do not: 65 `FROM` lines name a tag only (`node:22-bookworm-slim`, `python:3.12-slim-bookworm`, `python:3.12-slim`, `node:20-alpine`, `node:20-bookworm`, `node:22-bookworm`, `node:24-bookworm-slim`, `node:20.18-bookworm-slim`, `node:18-alpine`, `node:20`, `python:3.11-slim`, `golang:1.25-alpine`, `mcr.microsoft.com/dotnet/sdk:10.0`, `mysql:8.0`, `arcadedata/arcadedb:26.6.1` and `26.7.1`). When the base tag is not in the local store or the cache, BuildKit resolves it on the registry, and a tag that moved since the last build rebuilds the target from a new base, with its system packages and every dependency resolved again. The pre-run check catches a target that breaks, not one that drifts.

Two fix-checks of the nuisance suite also build a stand-in image from a Dockerfile held inline in Python, `FROM python:3.12-slim`, piped to `docker build -t <tag> -`: `_STAND_IN_DOCKERFILE` (`evals/nuisance_fix_checks/cve_2026_44694_n8n.py`) and `_REDIRECTOR_DOCKERFILE` (`evals/nuisance_fix_checks/cve_2026_55787_flyto.py`). They float the same way under `run_nuisance calibrate`.

Three images are pulled by tag at run time, outside any Dockerfile: `apache/doris:all-in-one-4.1.3` (`DORIS_IMAGE`, `evals/doris_backend.py`), `mysql:8.0.46` (`MYSQL_CLIENT_IMAGE`, same file, reused as `MYSQL_IMAGE` in `evals/mysql_backend.py`) and `motoserver/moto:5.2.5` (`_MOTO_IMAGE`, `evals/mysql_backend.py`). A tag can be rewritten on its registry, so they carry the same risk.

## Decisions taken with the maintainer

- Pin to the digest the registry serves for each tag today, then rebuild and recalibrate every target without an LLM. The digest each current local image was built from is not recoverable in general (most bases are not in the local store, and the BuildKit cache already holds at least one newer digest), and the transitive dependencies float anyway, so the exact identity of the current images is not worth reconstructing. The images change once, now, before any holdout or nuisance run.
- The three images pulled at run time are pinned by digest in the same plan.
- No "never prune" rule. The transitive npm, pip and apt dependencies keep floating, a limit the rules already name.
- A unit test refuses any `FROM` without a digest under `evals/docker/`, acceptance included, so a Dockerfile added later by the holdout, the nuisance admission or the acceptance layer cannot land unpinned.
- Out of scope: the nuisance run's compose services and the run Dockerfiles not written yet, another workstream, which will follow the convention through the test.

## Approach

1. Add the test first, red on the 65 unpinned lines.
2. Pin each `FROM` to `image:tag@sha256:<index digest>`, keeping the tag for the reader, and update the fingerprint label of every changed service in `evals/docker/compose.yml` (the existing label test prints each value). Pin the two inline stand-in Dockerfiles the same way.
3. Pin the three run-time images the same way, and remove the persistent backend containers so they restart from the pinned images.
4. Clear what would keep the old images in use, then rebuild and recalibrate. Before the build: remove the leftover containers of the eval images (anonymous holdout containers such as android and desktop-commander, and `Created` ones, found with `docker ps -a --filter ancestor=<image>` over the compose and fix-check images), the persistent backends (Doris, MySQL, moto) and any running responder container, and remove the five fix-check images that are built only when their tag is missing (`mcp-auditor-kit-n8n-standin:local`, `mcp-auditor-kit-flyto-redirector:local`, `mcp-auditor-cve-ckan-responder:local`, `mcp-auditor-cve-contextforge-responder:local`, `mcp-auditor-cve-n8n-responder:local`: `Responder._ensure_image` in `evals/responder_backend.py` and the stand-in and redirector builders inspect the tag and skip the build when it exists). Then rebuild (`docker compose -f evals/docker/compose.yml build` for the compose services, the other fix-check images being rebuilt by `run_nuisance calibrate`, `kit_launch.build_images` always, the five above because their tag is now missing) and recalibrate every layer without an LLM: `run_cve_benchmark --calibrate`, `run_holdout calibrate`, `run_nuisance calibrate`. A target that no longer calibrates is a fixture repair, done before any run.
5. Log entries and living docs.

## Files

### `tests/unit/test_cve_compose_labels.py`

It already parametrizes over `DOCKER_DIRECTORY.glob("Dockerfile.*")` for `test_no_dockerfile_copies_from_the_build_context`. Add beside it:

```python
@pytest.mark.parametrize(
    "dockerfile", sorted(DOCKER_DIRECTORY.glob("Dockerfile.*")), ids=lambda path: path.name
)
def test_every_base_image_is_pinned_by_digest(dockerfile: Path):
    unpinned = unpinned_bases(dockerfile_instructions(dockerfile))

    assert not unpinned, f"{dockerfile.name}: pin {unpinned} to image:tag@sha256:<digest>"
```

`unpinned_bases` lives in `evals/cve_images.py` beside `dockerfile_instructions`, a pure function over the instruction lines, so it is unit-tested on its own:

```python
def unpinned_bases(instructions: Sequence[str]) -> list[str]:
    """A FROM naming an earlier stage of the same Dockerfile, or `scratch`, pulls nothing and
    needs no digest."""
```

Its logic: walk the instructions in order. For each line whose first word is `FROM` (case-insensitive), drop leading `--flag=value` options (`--platform=...`), take the next word as the reference and the word after `AS` (case-insensitive) as a stage name to remember. A reference is pinned when it matches `@sha256:[0-9a-f]{64}$`. It is exempt when it is `scratch` or a stage name seen earlier. Return the references that are neither. Build args in a `FROM` (`FROM ${BASE}`) are not used by any Dockerfile today: the function reports such a reference as unpinned, which is the safe reading (a test case pins this).

Test cases for `unpinned_bases`, in `tests/unit/test_cve_images.py` (it already tests this module):
- `FROM node:22-bookworm-slim` is reported.
- `FROM node:22-bookworm-slim@sha256:<64 hex>` is not.
- `FROM node@sha256:<64 hex>` (digest without tag, the form some current Dockerfiles use) is not.
- `FROM --platform=linux/amd64 python:3.12-slim AS build` reports `python:3.12-slim`.
- A multi-stage file: `FROM golang:1.25-alpine@sha256:<hex> AS build` then `FROM build` reports nothing, and `FROM alpine:3.20` as the second stage is reported.
- `from node:20` (lower case) is reported.
- `FROM scratch` is not.
- `FROM ${BASE}` is reported.
- A digest of the wrong length (`@sha256:abc`) is reported.

### `evals/docker/Dockerfile.*` (the 65 unpinned lines)

Of the 65 lines, 52 are in Dockerfiles that are `evals/docker/compose.yml` services. The other 13 are in nuisance fix-check Dockerfiles that are not compose services (`Dockerfile.arcadedb`, `-vuln`, `Dockerfile.ckan-responder`, `Dockerfile.claude-in-mobile`, `-vuln`, `Dockerfile.contextforge`, `-responder`, `-vuln`, `Dockerfile.doris`, `Dockerfile.kanban`, `-vuln`, `Dockerfile.token-optimizer`, `-vuln`): they carry no fingerprint label, are built by plain `docker build` (`evals/holdout_kit/kit_launch.py`, `evals/responder_backend.py`), and are exercised by `run_nuisance calibrate` only. The new test covers them too, since it globs every `Dockerfile.*`.

Each `FROM image:tag` becomes `FROM image:tag@sha256:<digest>`, where the digest is the one the registry serves for the tag at implementation time, read without pulling (the disk is near full): `docker buildx imagetools inspect image:tag --format '{{json .Manifest}}'` gives the index digest under `digest`. Pin the index (manifest list) digest, not a platform manifest, so the reference stays the one the tag names. Every line naming a tag gets the digest the tag serves today, read once, so one tag has one digest in the tree. A line already pinned to an older digest of a tag that other lines now pin moves to today's digest too: this is the case of the seven lines pinned to `node:22-bookworm-slim@sha256:c3de60bf...` while the tag serves `4b150b48...` today, `Dockerfile.n8n-responder`, the three compose services of the n8n holdout target (`Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n`, `-patched`, `-redirect`, whose fingerprint labels move) and the three nuisance n8n fix-check Dockerfiles (`Dockerfile.n8n`, `Dockerfile.n8n-vuln`, `Dockerfile.n8n-flaw-2.50.1`). Their images are rebuilt and the n8n holdout target and nuisance fix-checks recalibrated with the rest. No other already pinned line names a tag an unpinned line names (`node:20-bookworm-slim` is already pinned to today's digest).
A pinned line whose tag no unpinned line names keeps its digest, so the acceptance Dockerfiles and the sentinel do not move.

### Inline stand-in Dockerfiles

`_STAND_IN_DOCKERFILE` in `evals/nuisance_fix_checks/cve_2026_44694_n8n.py` and `_REDIRECTOR_DOCKERFILE` in `evals/nuisance_fix_checks/cve_2026_55787_flyto.py`: `FROM python:3.12-slim` becomes `FROM python:3.12-slim@sha256:<digest>`, the same digest as the Dockerfiles naming that tag. The new test globs `evals/docker/` only and does not see them, so they are pinned by hand here (a module-level constant is private, and a test reaching into it would be fragile for two lines).

### `evals/docker/compose.yml`

Every compose service whose Dockerfile changed gets its `org.mcp-auditor.dockerfile-fingerprint` label set to the value `test_each_compose_service_is_labeled_with_its_dockerfile_fingerprint` prints. No service is added or removed.

### Run-time images

- `evals/doris_backend.py`: `DORIS_IMAGE = "apache/doris:all-in-one-4.1.3@sha256:<digest>"` and `MYSQL_CLIENT_IMAGE = "mysql:8.0.46@sha256:<digest>"`.
- `evals/mysql_backend.py`: `_MOTO_IMAGE = "motoserver/moto:5.2.5@sha256:<digest>"`.

What consumes them, to check under the new form:
- `docker run` and `docker pull` accept `name:tag@sha256:...` (the digest wins).
- `backend_image_ids` (`evals/cve_baseline.py`) and the nuisance backend provenance call `docker image inspect <ref>`. Inspect by `name:tag@digest` resolves only when the local image carries that repo digest, which it does once pulled by that reference. The implementer verifies it on the local daemon after the pull; if inspect does not resolve, the lookup stays tolerant (`check=False`) and the provenance would read empty, which must be fixed rather than accepted.
- `CVETarget.backend_images` of the Doris holdout target (`evals/holdout_fixtures/cve_2025_66335_doris.py`) feeds the per-target fixture fingerprint, so CVE-2025-66335's fingerprint moves.
- `RegisteredBackend.image` in `evals/nuisance_backends.py` and the admission's `BackendFixture.image`: `backend_problems` refuses any difference between the two, so `evals/nuisance_admission.json` gets the new strings for every server with a `doris` or `mysql` backend, in the same commit. `load_admission` must stay green.
- `tests/unit/test_mysql_backend.py` asserts `MYSQL_IMAGE == "mysql:8.0.46"` (line 37): it goes red. Update the literal to the pinned string. The other unit tests that name `apache/doris:all-in-one-4.1.3` (`test_holdout_run.py`, `test_nuisance_run.py`, `test_nuisance_gate_session.py`, `support/test_cve_baseline_given.py`) use it as free test data with their own fakes and stay as they are.
- Persistent containers: `ensure_doris` keeps a running `mcp-auditor-cve-doris` (one runs today, from `apache/doris:all-in-one-4.1.3`), and `_ensure_container` in `evals/mysql_backend.py` keeps a running MySQL or moto container, neither checking the image. Left in place, the calibrations would run against the container started from the tag while the provenance records the pinned image's id. Remove them (`docker rm -f` of the Doris, MySQL and moto containers, names in `DORIS_CONTAINER`, `MYSQL_CONTAINER`, `MOTO_CONTAINER`) before step 4, so the backends start again from the pinned references.
- The opt-in Doris test (`tests/integration/test_nuisance_doris_backend.py`, `NUISANCE_DORIS=1`, docstring and skip message), CONTRIBUTING.md and the `CLAUDE.md` Commands entry for `tests/integration` name the two Doris images by tag in prose: update the prose to say they are pinned by digest.

### Logs and living docs

- `docs/holdout-log.md`: one entry. Every holdout image's base is pinned by digest and the Doris backend images too, the images were rebuilt and every target recalibrated without an LLM (result stated), and the fixture fingerprints of the targets move, before any holdout run. No rule version: the rule fixes what calibration and the pre-run check pass, and this changes neither.
- `docs/nuisance-log.md`: one entry. The Dockerfiles now meet the Images clause of the rule ("pins ... the digest of its base image"), the backend images are pinned by digest, the admission records the new backend image strings, and `run_nuisance calibrate` is green (result stated). No rule version.
- `docs/labeling-log.md`: no entry. No label, fixture of the honeypots or judge, or scoring code moves, and the acceptance Dockerfiles are already pinned.
- `CONTRIBUTING.md`: beside the sentence on the fingerprint label, a sentence that every `FROM` under `evals/docker/` pins its base by digest (`image:tag@sha256:...`), that `tests/unit/test_cve_compose_labels.py` refuses one that does not, and how to read the digest (`docker buildx imagetools inspect`). The Doris prose as above.
- `CHANGELOG.md`, `[Unreleased]`, Changed: the holdout and nuisance images pin their base image by digest, as the acceptance images do, and the backend images pulled at run time are pinned by digest.
- `CLAUDE.md`: no new command. Only the prose of the `tests/integration` entry naming the Doris images, as above. No landmine needed: the test carries the convention.

## What stays unchanged

- The acceptance Dockerfiles, already pinned, and so the four acceptance fixture fingerprints and `evals/baselines/cve/`. The implementer checks that `git diff` touches no Dockerfile of an acceptance target or the sentinel (`CVE_TARGETS` and `SENTINEL_SERVICE`); if one is touched, its target's baseline file is deleted in the same commit and recorded twice, as CONTRIBUTING.md says.
- The honeypot and judge baselines, `src/`, prompts, `uv.lock`.
- The grammar and its fingerprint, the nuisance counter and its fingerprint.
- The `RUN` lines and the pinned server versions inside each Dockerfile.
- `docs/holdout-rule.md` and `docs/nuisance-rule.md`.

## Edge cases

- A target that calibrated live before and calibrates dead on the new base: a fixture repair. It is fixed within this work (a `RUN` adjusted, never the version under test) and named in the log entry with its cause. If it cannot be repaired here, the plan stops and the maintainer decides, since a holdout target that cannot pass is reported as not run until repaired.
- A tag that no longer exists on its registry: pin the digest of the image the local store or cache still holds if it can be found, otherwise stop and report.
- Disk space: the root filesystem is near full, and a full rebuild adds new layers. Every unused image and the build cache were pruned on 2026-10-28 before implementation (maintainer's decision), freeing the disk to 104 GB, so the rebuild never shares it with superseded images. Volumes are kept.
- Two Dockerfiles naming the same tag get the same digest, read once, so a shared base stays shared, an already pinned line of that tag included (see the Dockerfiles section).
- Leftover containers of the eval images still running at step 4 keep the old images referenced, so they are removed first (step 4), and the holdout run itself refuses to start while one runs.
- The worktree `.claude/worktrees/nuisance-batch3` is merged into main and can be removed (`git worktree remove`), so greps over the repository do not pick up its copies of the Dockerfiles.

## Verification

```bash
uv run pytest tests/unit/test_cve_images.py tests/unit/test_cve_compose_labels.py tests/unit/test_mysql_backend.py tests/unit/test_nuisance_fix_checks.py -q   # red first, then green
docker rm -f mcp-auditor-cve-doris mcp-auditor-cve-mysql mcp-auditor-cve-mysql-moto mcp-auditor-cve-n8n-responder mcp-auditor-cve-ckan-responder mcp-auditor-cve-contextforge-responder   # persistent backends and responders restart from the pinned images
docker rmi mcp-auditor-kit-n8n-standin:local mcp-auditor-kit-flyto-redirector:local mcp-auditor-cve-ckan-responder:local mcp-auditor-cve-contextforge-responder:local mcp-auditor-cve-n8n-responder:local   # built only when missing, so rebuilt from the pinned bases
docker ps -a --format '{{.ID}} {{.Image}}'   # no leftover container of an eval image before the rebuild
docker compose -f evals/docker/compose.yml build
uv run python -m evals.run_cve_benchmark --calibrate
uv run python -m evals.run_holdout calibrate
uv run python -m evals.run_nuisance calibrate
uv run pytest -n auto
uv run ruff check .
uv run pyright
```

The three calibrations exit 0. The full suite, ruff and pyright are green.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the later passes. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, on 2026-10-28, not what is true now (a tag's digest can move on its registry before implementation). A human who edits the corresponding fact by hand deletes the line rather than update it.

- SETTLED: `docker buildx imagetools inspect image:tag --format '{{json .Manifest}}'` returns the index (or manifest list) digest under the top-level `digest` key, without pulling (verified by running it against the registries)
- SETTLED: `docker run` and `docker image inspect` accept `name:tag@sha256:<digest>` and resolve a locally held image by it (verified on the local daemon, Docker 29.9.1, containerd image store, with `mysql:8.0.46@sha256:7dcd...` and `apache/doris:all-in-one-4.1.3@sha256:82a5...`)
- SETTLED: `apache/doris:all-in-one-4.1.3@sha256:82a5cabc7900ebcd3d080412d636c0cebd6602799fffe2605c652b2ea7d42609` (registry index digest, equal to the local image's repo digest)
- SETTLED: `mysql:8.0.46@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` (registry index digest, equal to the local image's repo digest, and the same index `mysql:8.0` serves)
- SETTLED: `motoserver/moto:5.2.5@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a` (registry index digest, equal to the local image's repo digest)
- SETTLED: `arcadedata/arcadedb:26.6.1@sha256:b89478bd698ebfb6301918ec6745818a02759515b7d00dd1c86c842470274f5b` (registry, read 2026-10-28)
- SETTLED: `arcadedata/arcadedb:26.7.1@sha256:37db3d210bde5849ba5c772ce33b8666b215a77f7b88331fda31fbbf2d130738` (registry, read 2026-10-28)
- SETTLED: `golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59` (registry, read 2026-10-28)
- SETTLED: `mcr.microsoft.com/dotnet/sdk:10.0@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b` (registry, a Docker manifest list, read 2026-10-28)
- SETTLED: `mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` (registry, read 2026-10-28)
- SETTLED: `node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e` (registry, read 2026-10-28)
- SETTLED: `node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5` (registry, read 2026-10-28, the same index as `node:20-bookworm`)
- SETTLED: `node:20-bookworm@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5` (registry, read 2026-10-28)
- SETTLED: `node:20.18-bookworm-slim@sha256:ffc11dbf16dd0abcbb7b837410601b4d5592db2d03741e13a4a5336ab74d7ccb` (registry, read 2026-10-28)
- SETTLED: `node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293` (registry, read 2026-10-28)
- SETTLED: `node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0` (registry, read 2026-10-28, the digest the acceptance Dockerfiles already pin)
- SETTLED: `node:22-bookworm@sha256:18a6d90fd60542269850c80ca03b29b1d9b14d6b221ac7ee8e35b0d33ef904bd` (registry, read 2026-10-28)
- SETTLED: `node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da` (registry, read 2026-10-28)
- SETTLED: `node:24-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c` (registry, read 2026-10-28)
- SETTLED: `python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60` (registry, read 2026-10-28)
- SETTLED: `python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159` (registry, read 2026-10-28, also the inline stand-in and redirector Dockerfiles)
- SETTLED: `python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337` (registry, read 2026-10-28)
- SETTLED (maintainer, 2026-10-28): one digest per tag. The seven lines pinned to `node:22-bookworm-slim@sha256:c3de60bf...` (`Dockerfile.n8n-responder`, the three compose services of the n8n holdout target, `Dockerfile.n8n`, `-vuln`, `-flaw-2.50.1`) move to `4b150b48...`, the digest the tag serves today, with the unpinned lines of the tag

## Implementation steps

### Step 1: Refuse unpinned bases and pin every image reference

- **Files**:
  - `tests/unit/test_cve_images.py` (new cases for `unpinned_bases`)
  - `tests/unit/test_cve_compose_labels.py` (new parametrized test)
  - `tests/unit/test_mysql_backend.py` (line 37 literal)
  - `evals/cve_images.py` (`unpinned_bases`)
  - `evals/docker/Dockerfile.*` (the 65 unpinned `FROM` lines, plus the seven lines pinned to the old `node:22-bookworm-slim@sha256:c3de60bf...`, see the Dockerfiles section), edited mechanically by a script, not one by one
  - `evals/docker/compose.yml` (fingerprint labels of every changed service)
  - `evals/nuisance_fix_checks/cve_2026_44694_n8n.py`, `evals/nuisance_fix_checks/cve_2026_55787_flyto.py` (inline `FROM`)
  - `evals/doris_backend.py`, `evals/mysql_backend.py` (run-time image constants)
  - `evals/nuisance_admission.json` (the `doris` and `mysql` backend `image` strings, lines ~1283 and ~3965)
  - `tests/integration/test_nuisance_doris_backend.py` (docstring and skip message prose), `CONTRIBUTING.md`, `CLAUDE.md` (the `tests/integration` entry), `CHANGELOG.md` (`[Unreleased]`, Changed)
- **Do**:
  1. Optional housekeeping first: `git worktree remove .claude/worktrees/nuisance-batch3` (merged into main) so greps do not pick up its copies. Check `git worktree list` and that the branch is merged before removing.
  2. Tests first. In `tests/unit/test_cve_images.py`, add the nine `unpinned_bases` cases listed in the plan (Files, `tests/unit/test_cve_compose_labels.py` section), each calling `unpinned_bases([...instruction lines...])` and asserting the returned list. Use a module constant for a valid 64-hex digest. In `tests/unit/test_cve_compose_labels.py`, add `test_every_base_image_is_pinned_by_digest` exactly as in the plan, importing `unpinned_bases` from `evals.cve_images`. Change `tests/unit/test_mysql_backend.py` line 37 to the pinned string `"mysql:8.0.46@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"`. Run them: the new cases fail on the import, then (once the function exists) the Dockerfile test is red on 65 lines.
  3. Implement `unpinned_bases(instructions: Sequence[str]) -> list[str]` in `evals/cve_images.py` beside `dockerfile_instructions`, with the logic of the plan (case-insensitive `FROM`, skip leading `--flag=value` words, reference is the next word, remember the word after a case-insensitive `AS` as a stage name, pinned when matching `@sha256:[0-9a-f]{64}$`, exempt `scratch` and earlier stage names, return the rest in order). Keep it under ~20 lines, split a small helper if needed. Unit tests green.
  4. Re-read every digest live before writing it (the Due diligence record is a starting point, not a substitute): for each distinct tag on an unpinned line, `docker buildx imagetools inspect <image:tag> --format '{{json .Manifest}}'` and take the top-level `digest`. Never pull (the disk is near full). If a live digest differs from the record, use the live one and note it for the step 2 log entries. A tag that no longer exists: follow the plan's edge case (local store or cache, otherwise stop and report).
  5. Pin with a script (Python or sed, kept in the scratchpad, not committed): every `FROM image:tag` without `@sha256:` becomes `FROM image:tag@sha256:<digest>`, keeping any `--platform` flag and `AS name`. One digest per tag. Also move the seven lines pinned to `node:22-bookworm-slim@sha256:c3de60bf...` (`Dockerfile.n8n-responder`, `Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n`, `-patched`, `-redirect`, `Dockerfile.n8n`, `-vuln`, `-flaw-2.50.1`) to today's digest of that tag. Do not touch any other already pinned line. Then `git diff --stat evals/docker/` and confirm no Dockerfile of an acceptance target or the sentinel (`CVE_TARGETS`, `SENTINEL_SERVICE`) changed. If one did, stop: the plan requires a baseline reset in that case, which is not expected.
  6. Update the fingerprint labels in `evals/docker/compose.yml`: run `uv run pytest tests/unit/test_cve_compose_labels.py -q` and copy each printed value into its service's `org.mcp-auditor.dockerfile-fingerprint` label (scripted if many), until the label test is green.
  7. Inline Dockerfiles: `FROM python:3.12-slim` becomes `FROM python:3.12-slim@sha256:<the same digest as the Dockerfiles of that tag>` in `_STAND_IN_DOCKERFILE` and `_REDIRECTOR_DOCKERFILE`.
  8. Run-time images: `DORIS_IMAGE = "apache/doris:all-in-one-4.1.3@sha256:<digest>"`, `MYSQL_CLIENT_IMAGE = "mysql:8.0.46@sha256:<digest>"` in `evals/doris_backend.py`, `_MOTO_IMAGE = "motoserver/moto:5.2.5@sha256:<digest>"` in `evals/mysql_backend.py` (digests re-read live as in 4). Set the same strings for the doris and mysql backend `image` fields of `evals/nuisance_admission.json`, so `backend_problems` stays empty and `load_admission` green. Leave the other unit tests that use `apache/doris:all-in-one-4.1.3` as free test data unchanged.
  9. Prose: in `tests/integration/test_nuisance_doris_backend.py` (docstring and skip message), `CONTRIBUTING.md` and the `CLAUDE.md` `tests/integration` entry, say the two Doris images are pulled pinned by digest (keep the tags named for the reader). In `CONTRIBUTING.md`, beside the fingerprint label sentence, add that every `FROM` under `evals/docker/` pins its base by digest (`image:tag@sha256:...`), that `tests/unit/test_cve_compose_labels.py` refuses one that does not, and that the digest is read with `docker buildx imagetools inspect image:tag --format '{{json .Manifest}}'` (the index digest). In `CHANGELOG.md` `[Unreleased]`, Changed: the holdout and nuisance images pin their base image by digest, as the acceptance images do, and the backend images pulled at run time are pinned by digest.
  10. Do not rebuild images, remove containers or run calibrations in this step (step 2). Do not edit `docs/holdout-log.md` or `docs/nuisance-log.md` yet.
- **Test**:
  - `unpinned_bases`: the nine cases of the plan (tag only reported, tag plus digest not, digest without tag not, `--platform` with `AS` reports the bare reference, multi-stage stage reference exempt and a second unpinned stage reported, lower-case `from` reported, `scratch` not, `${BASE}` reported, short digest reported).
  - `test_every_base_image_is_pinned_by_digest`: red on the 65 lines before step 5, green on every `Dockerfile.*` after.
  - `test_each_compose_service_is_labeled_with_its_dockerfile_fingerprint`: green after step 6.
  - `tests/unit/test_mysql_backend.py`: green with the pinned literal. Admission and backend parity tests (`tests/unit/test_nuisance_*`, `load_admission`) green.
- **Verify**:
  - Loop: `uv run pytest tests/unit/test_cve_images.py tests/unit/test_cve_compose_labels.py tests/unit/test_mysql_backend.py tests/unit/test_nuisance_fix_checks.py -q` red first, then green. `uv run pytest tests/unit -n auto --maxprocesses 4` green.
  - `grep -iE '^FROM' evals/docker/Dockerfile.* | grep -v '@sha256:' ` prints only stage references or `scratch` (expected: nothing).
  - Closing check: `uv run pytest -n auto` (the Docker image integration tests rebuild the changed compose images on first run, expected), `uv run ruff check .`, `uv run pyright`, all green.

### Step 2: Rebuild every eval image from the pinned bases, recalibrate, log

- **Files**:
  - `docs/holdout-log.md`, `docs/nuisance-log.md` (one entry each)
  - Only if a target fails to calibrate: the `RUN` lines of its Dockerfile under `evals/docker/` and its compose fingerprint label (never the version under test), or its fixture module
- **Do**:
  0. Confirm no eval run is in progress on the host, from this session or another (calibration, holdout, nuisance, gate, admission dossier): `ps aux | grep -E 'evals\.run_|nuisance-dossier|claude -p'` and ask the maintainer when in doubt. Step 2 removes containers and backends a running eval would lose mid-run, so it starts only on a quiet host.
  1. `df -h /` and `docker system df` before anything, both noted for the log entries.
  2. Clear what keeps the old images in use: `docker rm -f mcp-auditor-cve-doris mcp-auditor-cve-mysql mcp-auditor-cve-mysql-moto` (confirm the names against `DORIS_CONTAINER`, `MYSQL_CONTAINER`, `MOTO_CONTAINER` in the modules), the responder containers `mcp-auditor-cve-n8n-responder`, `mcp-auditor-cve-ckan-responder`, `mcp-auditor-cve-contextforge-responder` (`*_RESPONDER_CONTAINER` in `evals/n8n_backend.py`, `evals/ckan_backend.py`, `evals/contextforge_backend.py`, tolerate one absent), and every leftover container of an eval image: list `docker ps -a --format '{{.ID}} {{.Image}} {{.Status}}'` and remove those whose image is a compose service tag or a fix-check image (anonymous holdout containers such as android and desktop-commander, `Created` ones included). Remove only containers of this project's images.
  3. `docker rmi mcp-auditor-kit-n8n-standin:local mcp-auditor-kit-flyto-redirector:local mcp-auditor-cve-ckan-responder:local mcp-auditor-cve-contextforge-responder:local mcp-auditor-cve-n8n-responder:local` (these are rebuilt only when their tag is missing, `mcp-auditor-cve-n8n-responder:local` included since `Dockerfile.n8n-responder` moves). Tolerate one already absent.
  3b. The prune is already done (maintainer's decision, 2026-10-28, before implementation): every container of the host removed, then `docker image prune -a -f` and `docker builder prune -a -f`, volumes kept (they hold the Doris cluster's state, whose reset is a separate decision). Images went from 109 (42.7 GB) to 0, the build cache from 38.6 GB to 0, and the root filesystem from 37 GB free (89 %) to 104 GB free (69 %). Every image therefore rebuilds from its pinned base and re-resolves its dependencies, the five `docker rmi` above being no-ops. If an image exists again by the time step 2 starts (a build run in between), prune again the same way after step 2's container removal. The rebuild pulls every base and the Doris and MySQL images again, so it is long.
  4. `docker compose -f evals/docker/compose.yml build`. Then recalibrate every layer, no LLM, each run in the background if long, output read by tail rather than in full:
     - `uv run python -m evals.run_cve_benchmark --calibrate` (acceptance, should be unaffected, expected exit 0)
     - `uv run python -m evals.run_holdout calibrate` (expected exit 0)
     - `uv run python -m evals.run_nuisance calibrate` (expected exit 0, rebuilds the fix-check images, the five removed ones included, and restarts the Doris, MySQL and moto backends from the pinned references)
  5. After the backends restart, check that `docker image inspect <pinned DORIS_IMAGE>` and `<pinned MYSQL_IMAGE>` resolve (non-empty id). If inspect by `name:tag@digest` does not resolve, the provenance would read empty: fix the lookup (`backend_image_ids` in `evals/cve_baseline.py`, the nuisance backend provenance) with a unit test first, rather than accept it.
  6. A target that no longer calibrates: a fixture repair within this step (adjust a `RUN`, update its fingerprint label, rerun that target with `--cve ID`), named in the log entry with its cause. If it cannot be repaired, stop and report to the maintainer without committing a workaround.
  7. Log entries, dated 2026-10-28 (or the day of the run), in the style of the existing entries of each log:
     - `docs/holdout-log.md`: every holdout image's base is pinned by digest and the Doris backend images too, the images were rebuilt and every target recalibrated without an LLM (state the result, and any repair with its cause, and any digest that differed from the plan's record), the fixture fingerprints of the targets move (CVE-2025-66335's through its backend image as well), before any holdout run. No rule version.
     - `docs/nuisance-log.md`: the Dockerfiles now meet the Images clause of the rule (base digest pinned), the backend images are pinned by digest, the admission records the new backend image strings, and `run_nuisance calibrate` is green (state the result). No rule version.
     - No `docs/labeling-log.md` entry. No edit to `docs/holdout-rule.md`, `docs/nuisance-rule.md`, `docs/adr/` or past plans.
  8. Confirm `git diff` touches no acceptance Dockerfile, no file under `evals/baselines/`, `src/` or `uv.lock`.
- **Test**: no new test, unless step 5 or 6 requires a code fix (then its unit test first).
- **Verify**:
  - The three calibrations exit 0.
  - `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright`, all green.
