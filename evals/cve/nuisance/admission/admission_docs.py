"""The rendered documents of a first admission. Its confinement is rendered from the run's own
launch builders and never retyped, as the shape every server's launch takes before its record
exists."""

import json
import shlex
from dataclasses import dataclass

from evals.cve.backends.kubernetes import (
    CONTROL_PLANE_IMAGE,
    CONTROL_PLANE_NETWORK,
    CONTROL_PLANE_SERVICE,
    KUBECONFIG,
)
from evals.cve.census.classification import GRAMMAR_CLASS_DEFINITIONS
from evals.cve.detection.targets import acceptance_services
from evals.cve.nuisance.admission.admission import AdmittedServer, FlawRecord
from evals.cve.nuisance.confinement import single_container_run_args
from evals.cve.planting_base import PlantingHost, SymbolicUser, confinement_args

IMAGE_PLACEHOLDER = "<image>"


def fixture_format(backend: str | None) -> str:
    flaw = json.dumps(FlawRecord.model_json_schema(), indent=2)
    server = json.dumps(AdmittedServer.model_json_schema(), indent=2)
    paragraph = KIT_BACKENDS[backend].paragraph if backend is not None else ""
    return _FIXTURE_FORMAT.format(
        flaw_record=flaw, admitted_server=server, backend_paragraph=paragraph
    )


def admission_readme() -> str:
    names = ", ".join(f"`{name}`" for name in sorted(acceptance_services()))
    return _README.format(acceptance_services=names)


def admission_confinement_text() -> str:
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "<working directory>", has_network=False)
    run_args = single_container_run_args(IMAGE_PLACEHOLDER, host, ["<launch>"])
    command = f"docker {shlex.join(run_args)}"
    return _ADMISSION_CONFINEMENT.format(command=command, options=confinement_options())


def confinement_options() -> str:
    return "\n".join(f"- `{option}`" for option in _paired(confinement_args()))


def _paired(args: list[str]) -> list[str]:
    options: list[str] = []
    for arg in args:
        if (
            options
            and options[-1].startswith("-")
            and " " not in options[-1]
            and not arg.startswith("-")
        ):
            options[-1] += f" {arg}"
        else:
            options.append(arg)
    return options


# The census text invites a class name of the reader's own, which `effect_class` refuses.
ADMISSION_GRAMMAR_CLASSES = f"""\
# The effect classes of the grammar

A class names the effect a client of the server can observe in a tool response, not a CWE.
An argument injection is filed under the effect it produces. A flaw whose effect falls in
none of these three classes gets `effect_class` `null`.

{GRAMMAR_CLASS_DEFINITIONS}"""

_FIXTURE_FORMAT = """\
# The fixture format

Author a `FixCheckFixture` (`evals/cve/kit/fix_check.py`) and run it through `check_fix`. The
fixture never leaves the kit: unlike a holdout `KitTarget`, it is not transplanted into the
repository, so the vulnerable Dockerfile and the exploits are committed beside the admission as
`FixCheckFixture` fixtures and the auditor never sees them.

## FixCheckFixture fields

- `flaw`: the census identifier the fixture reproduces.
- `effect_class`: the grammar `FlawClass`, or `None`.
- `aim`: a compiled `re.Pattern` the exploit's call arguments must match, so a witness that
  surfaces by accident (an exploit not aimed at it) does not count.
- `witness`: the `Place` the exploit surfaces (an id of its own, a `PlaceKind` and
  `Coordinates`). The fix check plants it at the flaw's own coordinate, with no catalogue list.
- `planting_host`: the `PlantingHost` the witness plants into.
- `builder`: a context manager yielding a `launch.Launch` (`evals/cve/kit/launch.py`).
- `exploits`: `async (Places, KitClient) -> None`, both agents' exploits. The witness counts
  when either surfaces it.
- `benign_calls`: `async (Places, KitClient) -> None`, one per tool, read from the tool
  description, not aimed at the flaw. The patched version must answer them without error.
  `check_fix` prints each benign response. The server's patched version must also answer the
  admission's benign calls with their expected text, which `run_nuisance vet` checks.
- `vulnerable_service`, `patched_service`: service names, built and launched as
  `mcp-auditor-kit-<service>:local`. Each must differ from every acceptance service (the README
  lists them).
- `server_patched_service`: the server's own patched version when it differs from the flaw's,
  else `None`.
- `backend_services`: the compose services of the backend the `builder` stands, brought up to
  date before the fix check, or `None` (the default, which you may keep) for the built services
  of the backend the run provisions for the server.

## FixCheckResult (the driver prints it)

`check_fix` returns a `FixCheckResult` the agent pastes into the flaw's `fix_check` record:
`source`, `witness`, `exploit_calls`, `vulnerable_surfaces`, `patched_surfaces`,
`server_patched_surfaces` and `patched_benign_errored`. The flaw counts when the witness
surfaces on the vulnerable version and on neither patched one, and no benign call errors on a
patched version. Its `unreached_patched_exploits`, which the record does not carry, must be
empty: each entry is an exploit that surfaces the witness on the vulnerable version while a
patched version's SDK rejects every call of it for a missing required argument, before any code
runs, so a witness absent after it shows nothing about the fix.

## AdmittedServer fields the run reads

- `launch`: the container command appended after the image tag (the image's `ENTRYPOINT`, when
  it has one, applies to it).
- `backend`: the backend fixture the run provisions, or `null` when the server needs none or
  bakes it into its image. When set, it names the provisioner key, `images` (the list of the
  pinned image tags the provisioner runs, one element for a backend of one image), and the network
  the server joins.
- `host`: the `PlantingHost` the agents fill.
  - `user`: `unprivileged`, the only user, uid 65534 with `HOME=/tmp`.
  - `working_directory`: `/` unless the image needs another.
  - `has_network`: true only for a server with a `backend`, whose provisioner's closed network
    joins it to the backend and to nothing else (no route to the host or the Internet). A server
    with no backend runs with no network, and the admission refuses `has_network` without a
    backend.

## FlawRecord backend_need

- `backend_need`: `"none"` when no tool of the flaw needs a backend; `"fixture"` when a tool
  needs one the fixture provides (an `AdmittedServer.backend`, or one baked into the server
  image); `"external"` when a tool needs one the fixture cannot provide (a remote third-party
  service, a credential or an account the maintainer does not have, a proprietary binary), which
  drops the tool from the count.

## Fields nuisance suite rule v3 adds, required for an admission

The schemas below show these fields optional with a `null` default because the committed
admission predates them. An admission leaves none of them `null`: `[]` records that there is
nothing to declare.

- `ToolRecord.real_software`: for every tool of the flaw in the patched version, whether its
  benign call can return without error on the real software it drives and under the
  confinement (`answers`). When it cannot, `cause` names one of three cases, `software_error`
  (an error of the software with every argument the description allows), `not_distributed` (no
  distribution channel left) or `container_unrepairable` (a container failure the fixture cannot
  repair), and `evidence` holds the run, the capture or the source line, the missing channel, or
  why the failure cannot be repaired. A tool listed by several flaws carries the same record on
  each. Its agreement field is named `real_software`.
- `BenignCall.expect`: a substring of the text the tool answers on success, taken from the
  seeded content or the software's documented output, never a part of the call's arguments, a
  stable fragment when the output is dynamic.
- `BenignCall.before`: the calls made before the benign call, each of which must not error,
  `[]` when there is none.
- `FixCheckRecord.relies_on_relaying_stand_in`: whether the witness surfaces on the vulnerable
  version only because a stand-in relays the flaw's effect, which fails the positive control.
- `AdmittedServer.stand_ins`: each stand-in with what it replaces, why the real software cannot
  run under the confinement, its file, and each output with its source, in the source order of
  Stand-ins (a capture, the software's sources, the server's tests, else invented in the form of
  a cited source), `[]` when the fixture has none.
- `AdmittedServer.seeds`: each seeded item with its kind, citation and pin, in the source order
  of Seeding (a published sample, then what the software generates, then a project document,
  then values written for the fixture), `[]` when the fixture seeds nothing.

## Fields nuisance suite rule v4 adds, required for an admission

Optional with a `null` default in the schemas below for the same reason, and left `null` by no
admission.

- `ToolRecord.declared_function_is_effect`: for every tool of the flaw in the patched version,
  whether its declared function, read from the tool's description alone, is the effect of the
  flaw's class. Its agreement field is named `declared_function`.
  `FlawRecord.declared_function_is_effect` stays: the count reads the per-tool field and falls
  back to the flaw's for a tool that records none.
- `AdmittedServer.software_releases`: each real software the counted tools drive, with its
  release, the day that release was the current stable one when its documentation names no
  version (`null` when it does), and the line of documentation or the release page that gives
  it, `[]` when the tools drive no real software. A server that reuses the calibration of a
  holdout target copies the list of that target's card.

`FixCheckRecord.holdout_fingerprint` is not the agents' to fill: the maintainer records it at the
merge, on a record whose `source` is `detection_holdout_calibration`, as the fixture fingerprint of
the holdout target it copies.

## FlawRecord JSON schema

```json
{flaw_record}
```

## AdmittedServer JSON schema

```json
{admitted_server}
```
{backend_paragraph}
The grammar effect classes are in `grammar_classes.md`.
"""

_DORIS_BUILDER_PARAGRAPH = """
## The Doris backend builder

This server records the `doris` backend. Its `FixCheckFixture.builder` is
`backends.doris_backend_env` (`evals/cve/kit/backends.py`), which ensures the persistent Doris
cluster and yields the server launch wired to the backend's network. A fetch-class witness host
must be a literal IP in `169.254.0.0/16`: the sentinel is stood with `--ip` on the link-local
network, so a DNS name or an out-of-range IP fails `docker run` opaquely. `DORIS_SERVER_LAUNCH`
is the holdout target's launch the agents may start from, not a value to copy.
"""

_KUBERNETES_BUILDER_PARAGRAPH = f"""
## The Kubernetes backend

This server records the `kubernetes` backend, an upstream control plane stood for each launch
by `evals/cve/backends/kubernetes.py`, which builds `{CONTROL_PLANE_IMAGE}`
from `evals/docker/Dockerfile.{CONTROL_PLANE_SERVICE}` when it is absent. It has no
kubelet, so the cluster has no node. Its `FixCheckFixture.builder` stands one with
`stood_control_plane(name)`, the name prefixed by your images' prefix, and runs the server with
the planting's run arguments plus `--network <control plane network>` and the control plane's
`mount_args()`, which mount its `admin.conf` at `{KUBECONFIG}`, kubectl's default path
under `HOME=/tmp`. Record the backend as `{{"provisioner": "kubernetes", "images":
["{CONTROL_PLANE_IMAGE}"], "network": "{CONTROL_PLANE_NETWORK}"}}` and
`host.has_network` as true: the run stands its own control plane on a closed network of that
prefix for each launch.
"""


@dataclass(frozen=True)
class KitBackend:
    closure_roots: tuple[str, ...]  # the modules the dossier copies with their import closure
    built_services: tuple[str, ...]  # the Dockerfiles it copies under evals/docker/
    paragraph: str  # appended to fixture_format.md


# The backends whose builder or lifecycle a first-admission dossier ships.
KIT_BACKENDS: dict[str, KitBackend] = {
    "doris": KitBackend(("evals.cve.kit.backends",), (), _DORIS_BUILDER_PARAGRAPH),
    "kubernetes": KitBackend(
        ("evals.cve.backends.kubernetes",), (CONTROL_PLANE_SERVICE,), _KUBERNETES_BUILDER_PARAGRAPH
    ),
}

_README = """\
# Isolated admission dossier

A self-contained kit for admitting one nuisance server, free of any `mcp_auditor` import.
Run it from this directory with this directory on the Python path (its `evals/` package resolves
the copied modules). It needs Docker Engine 28.0 or later but no LLM and no repository
checkout. Its MCP client needs the `mcp` package, `mcp>=1.18.0,<2`.

## Procedure

1. Build the sentinel image first (the planting code's sidecar for network places and a
   namespace holder), and the stand-in image beside it (it serves a public service's capture
   under its real name, loaded from `evals/stand_ins/`):

   ```
   docker build -t mcp-auditor-cve-sentinel:local -f docker/Dockerfile.sentinel docker
   docker build -t mcp-auditor-cve-stand-in:local -f docker/Dockerfile.stand-in docker
   ```

2. Read `advisories/<id>.json` (one per census flaw of the server), `fixture_format.md` and
   `grammar_classes.md`.

3. For each flaw, write its two Dockerfiles into `docker/`: `Dockerfile.<service>` (the
   vulnerable version) and `Dockerfile.<service>-patched` (the fixed version).
   `launch.build_images` (`evals/cve/kit/launch.py`) builds each as
   `mcp-auditor-kit-<service>:local`. The service name must differ from every acceptance service:
   {acceptance_services}.

   For a server that needs a backend to answer its benign calls: a pulled backend is recorded in
   the `backend` field (the provisioner key, the list of pinned image tags, the network), not
   written as a Dockerfile. A built backend is out of scope, so the maintainer wires its
   provisioner at settlement. A brand-new backend server that is not the server of a holdout
   target needs a provisioner the maintainer writes: the agents record the backend and flag it,
   and the maintainer wires it.

4. Write the `FixCheckFixture` fixture (see `fixture_format.md`) and run it through `check_fix`,
   making as many attempts as you need, until the witness surfaces on the vulnerable version and
   on neither patched version, every exploit that surfaces the witness on the vulnerable version
   has, on each patched version, a call that the SDK's argument validation does not reject for a
   required argument it lacks (`unreached_patched_exploits` is empty), and the benign call does
   not error on a patched version.

5. Paste the printed `FixCheckResult` into the flaw's `fix_check` record of the admission, and
   fill the rest of the `FlawRecord` and `AdmittedServer` fields (`fixture_format.md` carries
   their schemas). Fill the nuisance suite rule v3 and v4 fields too, none left `null`.

## What else the dossier carries

- `nuisance-suite-rule.md`: the admission rule the record is checked against.
- `confinement.md`: the container options every nuisance server runs with, and the shape of the
  run's argv.
- The benign probe, `python -m evals.cve.kit.benign_probe --record <record.json> --image
  <tag>`: it launches the image under the run's confinement and makes each benign call of a
  record in the `AdmittedServer` shape (`fixture_format.md`), each `before` call first, and exits
  0 when every call answers without error and every set `expect` is found.
- The stand-in capture tool, `python -m evals.capture_stand_in --out evals/stand_ins/<host>.json
  <url> [<url> ...]`: run from this directory with network access, it records what a public host
  answers in the format the stand-in serves, every route of one host in one capture. A
  `--header` is recorded verbatim, so it never carries a real credential.
- `reference/`, for each census flaw of the server that is a holdout target: its holdout fixture
  and its builder's source as text under `reference/holdout_fixtures/`, its Dockerfiles under
  `reference/docker/` and its calibration card as `reference/cards/<id>.json`. The agents may
  start from that fixture when the server's patched version is the one the holdout target's
  calibration checks, and adapt it otherwise (`nuisance-suite-rule.md`, Admission). Nothing under
  `reference/` imports or runs.
"""

_ADMISSION_CONFINEMENT = """\
# The run's confinement

A server with no backend is launched with this argv, shown for the `unprivileged` user of
`PlantingHost`, the only user. `<working directory>` is the host's `working_directory`,
`<image>` the image tag and `<launch>` the record's `launch`:

```
{command}
```

The confinement options, every server alike:

{options}

A server with a backend joins its backend's closed network instead of running with no network,
and its backend's containers run under the same memory bound. A server with no backend whose host
declares public names joins a namespace holder that serves each one under its real name from its
capture in `evals/stand_ins/`, with the trust setting. The benign probe launches a record exactly
as the run does, a proposed capture included once it is in `evals/stand_ins/`.
"""
