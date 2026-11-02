# Closed eval networks

## Context

[ADR 034](../docs/adr/034-closed-eval-networks.md) decides that no network a container of the nuisance suite, the CVE holdout or the CVE acceptance layer joins routes to the host, to the host's local network or to the Internet, and that a public service a server needs at start, a benign call needs or a flaw's published mechanism goes through is served by a stand-in under its real name, resolved inside the network. This plan implements it. The product's confinement under ADR 018 is unchanged.

What the code does today, checked at `3a8120b`:

1. **Networks are plain bridges.** Seven sites run `docker network create --label mcp-auditor-cve` with no isolation: the per-launch planting network (`DockerPlanting.create_network`), the ten responder bridges (`Responder._ensure_network`), the two Doris networks (`doris_backend._doris_network`), the MySQL bridge (`mysql_backend._ensure_network`), the Neo4j bridge (`neo4j_backend._ensure_network`), and two fix-check bridges (`cve_2026_35402_neo4j_cypher._ensure_bridge`, `cve_2026_11720_googleapis._ensure_internal_bridge`). An eighth path, `nuisance_audit._network_args`, puts a networked server with no backend on Docker's default `bridge`, which cannot be made internal. No admitted server takes it: all 13 servers with `has_network` true have a backend.
2. **`--internal` alone does not close the host.** A throwaway patch measured on 2026-11-01 and 2026-11-02 on Docker 29.9.2 showed that an `--internal` network keeps an address on the host's bridge device, and a container on it reaches a host service listening on that address. With `-o com.docker.network.bridge.gateway_mode_ipv4=isolated` as well, the bridge has no host address, and the same container finds no route to the host, its LAN, `169.254.169.254` or the Internet. The `isolated` mode came with Docker Engine 28.0 and is accepted only on an internal network.
3. **Persistent networks are reused by name.** Every persistent site tests existence by name only, so a network of the same name left open by an older run is kept silently. Docker refuses to create a network over an existing name and refuses to remove a network with a container attached.
4. **Public names.** Every name a responder serves is already pinned with `--add-host` on the server's container to the responder's fixed address, so the responders survive a closed network. What does not survive, as the throwaway patch showed: the benign calls of holdout CVE-2026-104120 (`https://example.com/`), CVE-2026-58485 (`https://example.com/`), CVE-2026-5323 (`http://example.com/`, headless Chromium), CVE-2026-33060 (`https://demo.ckan.org`) and acceptance CVE-2025-65513 (`http://example.com/`), the three `169-254-*.sslip.io` names the CVE-2026-58485 exploits resolve, and the start of the apify nuisance server, which fetches its default Actor definitions from `https://api.apify.com` through `apify-client` (8 retries with backoff, so `initialize` outlasts the connect timeout), on vet and on its fix check CVE-2026-46341 alike.
5. **The patched SSRF guards of those five targets resolve the name and refuse a private address,** so a stand-in on the per-launch bridge (an auto-allocated private subnet) would be refused. The existing way round is the one `_start_n8n_stub` takes: a public-looking address bound on the namespace holder's loopback, the name in the holder's `/etc/hosts`. A container that joins a holder takes the holder's `/etc/hosts` and Docker refuses `--add-host` on it (`conflicting options: custom host-to-IP mapping and the network mode`), so the names go on the holder.
6. **`egress_warning`** (`evals/cve_calibration.py`) probes `example.com` from the host process when a networked target's patched benign call errors. Its premise, a benign call that reaches a public host on purpose, goes away.
7. **The calibrate paths sweep nothing.** `run_holdout run`, `run_nuisance run` and `vet` remove the containers of their images left running at the end (`run_images.sweep_containers`). `run_holdout calibrate`, `run_nuisance calibrate`, every mode of `run_cve_benchmark` and `run_nuisance gate` do not. Servers that run Node as PID 1 and do not exit on stdin EOF (holdout CVE-2026-19978 android, CVE-2025-11489 desktop-commander, the serverless fix-check images) outlive their launch there.
8. **Fingerprints.** `cve_baseline.fixture_fingerprint` hashes the planting and environment modules, so every acceptance and holdout fingerprint moves with this change. The four recorded acceptance fingerprints already differ from the ones computed at `3a8120b`. `nuisance_images.nuisance_fixture_fingerprint` hashes the backend fixture as provisioner, image tag and network name, not what the backend serves.

## Decisions (taken with the maintainer)

1. Every network a container of the three Docker suites joins (nuisance run, vet, calibrate and gate, holdout calibrate and run, acceptance calibrate, survey and graded run) is created `--internal` with `-o com.docker.network.bridge.gateway_mode_ipv4=isolated`. The code refuses to run, with a clear error, when the Docker daemon cannot create such a network, and never falls back to an open one. Docker Engine 28.0 or later becomes a README prerequisite of the eval suites. A persistent network (Doris, MySQL and moto, Neo4j, the responder bridges, the fix-check bridges) that exists but is not closed is recreated, its containers replaced first, never reused silently.
2. Public names are resolved inside the network by pinning, following the existing patterns: `--add-host` on a server that joins a backend bridge, the holder's `/etc/hosts` for a container that joins a holder, and an address bound on the holder's loopback where the patched server refuses private addresses.
3. Stand-ins: `example.com` (holdout 104120, 58485, 5323, acceptance 65513), `demo.ckan.org` (holdout 33060), `api.apify.com` (the apify nuisance server's start, its fix check CVE-2026-46341 included). The three `169-254-*.sslip.io` names of CVE-2026-58485 are pinned to the address sslip.io maps them to, with no stand-in content. Stand-in content is a one-time capture of the real service, verbatim, stored in the repository with its capture date and the command that produced it, only the routes the benign calls, the server start and the exploits use. Nothing invented that names the audit, a fixture or a flaw. The `api.apify.com` capture is taken with exactly the token the server sends, `Authorization: Bearer calib-token` (the value `apify_network_args` passes as `APIFY_TOKEN`), never with the maintainer's own token, and whatever the real API answers is recorded verbatim, a 401 included. The capture command handles no secret. If the recorded answers keep the server from starting or from answering its benign call, that is the real behaviour of the server launched with a dummy token: the maintainer step records it and stops for a decision under the nuisance rule's liveness clause (the benign call must return without error, `docs/nuisance-rule.md`), and the capture is not altered.
4. An HTTPS stand-in presents a certificate from a fixture authority. Each affected server is told to trust it through its runtime's own setting, declared per target, the trust setting ADR 034 names in its consequences. The authority's private key is committed, so the authority carries a critical X.509 `nameConstraints` extension whose permitted DNS subtrees are exactly the hosts the stand-ins serve over HTTPS, and its key cannot sign for any other name. The list is derived from the declared stand-ins, and adding a stand-in host means regenerating the authority.
5. `egress_warning`, `_egress_reachable` and `_EGRESS_CANARY` are deleted, with their tests and mentions.
6. `admission_problems` refuses a nuisance server with `has_network` true and no backend, and the default-bridge path of `nuisance_audit._network_args` goes away.
7. The nuisance fixture fingerprint covers what each backend serves, for the 13 servers with a backend.
8. Every calibrate path gets a guaranteed final sweep of the containers of its images, as the run paths have.
9. Governance: the 4 acceptance baselines are deleted in a commit of their own and recorded twice afterwards (ADR 024, CLAUDE.md). Every holdout target is recalibrated with a holdout log entry. Nuisance `vet` and `calibrate` run complete and green, with a nuisance log entry. The acceptance fixture change gets a labeling log entry. No nuisance or holdout run has taken place, so no comparison breaks there.
10. A Docker integration test proves the isolation: from a container on a fixture network, the Internet, the host (every host address, the would-be gateway included), the host's LAN and `169.254.169.254` are unreachable, a pinned name resolves and an unpinned name fails fast.
11. The living docs change in the same work: README, CLAUDE.md, CHANGELOG `[Unreleased]`, CONTRIBUTING.

Choices this plan makes inside those decisions, each with its reason:

- **A stand-in is pinned to the address the real name resolved to at capture**, recorded in the capture, not to a documentation range. The address is public by any guard's reading: Python's `ipaddress` calls RFC 5737 and `198.18.0.0/15` private, and the common Node guards call them reserved, while a real public address passes all of them. It is bound on the holder's loopback only, in a namespace with no route out, so it collides with nothing and reaches nothing. The apify API stand-in is the exception: it is a backend singleton on the apify bridge at a fixed address (see its section), since `apify-client` checks no address.
- **The authority also excludes every subdomain of a permitted host.** A permitted DNS subtree `example.com` admits `www.example.com` as well (RFC 5280 adds any labels on the left), so each permitted host `<host>` gets an excluded subtree `.<host>`, which OpenSSL matches against subdomains only. The authority then signs for the permitted hosts exactly, and nothing else, in every runtime the plan relies on (Python `ssl` and Node both verify through OpenSSL, measured in the due diligence record).
- **Stand-in content is mounted at launch, never baked.** `test_no_dockerfile_copies_from_the_build_context` forbids `COPY`, because the fingerprint hashes Dockerfile instructions only, and inlining a capture into a `RUN` would make it unreadable. A generic stand-in image (`Dockerfile.stand-in`) replays a capture file mounted read-only, and the capture's text enters the fingerprint as content.
- **Existing networks keep their names.** `backend.network` is a recorded field of 13 admission entries, checked by `backend_problems`, so a rename moves fixture data for nothing. An open network of the right name is recreated in place.
- **The isolation is checked on every creation, not only once.** The daemon could accept the option and ignore it, so each creation inspects the network it made and raises when it is not internal, not `isolated`, or has IPv6 enabled (an IPv6 gateway would reopen the host). A preflight at each command's start gives the same error before any build.

## Approach

Three layers, in the order the steps below land them:

1. **Closed networks.** One clean module, `evals/closed_network.py`, creates, verifies and ensures closed networks behind a small Docker port, and every creation site calls it. Each command checks once at start that the daemon can create one.
2. **Stand-ins.** A capture format and a capture command, a fixture authority name-constrained to the HTTPS stand-in hosts and one certificate per such host, the stand-in image, a registry that loads a capture into a `StandIn` at call time, and planting support: a `PlantingHost` may declare public names by host, which planting loads, pins on the holder, serves from stand-in containers joined to the holder, and probes like a sentinel. The apify backend gains a stand-in singleton for `api.apify.com` on its bridge.
3. **Hygiene and fingerprints.** The final sweep on every calibrate path, the nuisance fingerprint over what backends serve, the egress warning deleted, the default-bridge path removed.

Then the maintainer captures the three services, the targets are wired, every suite's Docker check runs green, and the acceptance baseline is reset and recorded.

## Files

### `evals/closed_network.py` (new, clean)

Imports nothing from `mcp_auditor` (it is copied into the calibration and nuisance dossiers, see `calibration_dossier.py` below), only `cve_planting_base.LABEL`.

```python
CLOSED_OPTIONS = ("--internal", "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated")

class ClosedNetworkUnsupported(RuntimeError): ...

@dataclass(frozen=True)
class NetworkFacts:
    labelled: bool
    internal: bool
    gateway_mode: str | None
    ipv6: bool
    containers: tuple[str, ...]

class NetworkDocker(Protocol):
    def inspect(self, name: str) -> NetworkFacts | None: ...
    def create(self, name: str, options: Sequence[str]) -> None: ...
    def remove(self, name: str) -> None: ...
    def remove_containers(self, names: Sequence[str]) -> None: ...

def is_closed(facts: NetworkFacts) -> bool: ...
def create_closed_network(name: str, *options: str, docker: NetworkDocker = DOCKER_NETWORKS) -> None: ...
def ensure_closed_network(name: str, *options: str, docker: NetworkDocker = DOCKER_NETWORKS) -> None: ...
def check_closed_network_support(docker: NetworkDocker = DOCKER_NETWORKS) -> None: ...
```

- `create_closed_network` runs `docker network create --label mcp-auditor-cve <CLOSED_OPTIONS> <options> <name>`, then inspects it. A daemon error (Docker before 28.0 rejects `isolated`) or a network that is not closed once created raises `ClosedNetworkUnsupported`, naming Docker Engine 28.0 and quoting the daemon's message, after removing what it created.
- `ensure_closed_network`: absent, it creates. Present and closed, it keeps it and its containers. Present, labelled and open, it removes the attached containers (all fixture containers, the network being ours by name and label), logs each removed name, removes the network and creates it closed. Present and unlabelled, it raises `ForeignNetwork` (a sibling of `ClosedNetworkUnsupported`) naming the network: a network of our name that we did not make is never touched. A module-level lock per network name serialises concurrent ensures within one process (the six calibration workers), and a create that fails on "already exists" inspects again instead of failing.
- `check_closed_network_support` creates a throwaway closed network under a random labelled name, verifies it and removes it.
- `DOCKER_NETWORKS` is the production port: `docker network inspect -f '{{json .}}'`, parsed into `NetworkFacts` (`Internal`, `Options["com.docker.network.bridge.gateway_mode_ipv4"]`, `EnableIPv6`, `Labels`, `Containers[*].Name`), `docker network create`, `docker network rm`, `docker rm -f`. The parse of the inspect JSON is a pure function, unit-tested on a recorded inspect output.

The callers' existing "start the container when it is not running" logic then restarts what the recreation removed: `Responder.ensure`, `ensure_doris` (reruns the cluster and reprovisions its schema, a cold start paid once), `mysql_backend._ensure_container`, the Neo4j database.

### Creation sites

- `evals/cve_planting_docker.py` `DockerPlanting.create_network`: `create_closed_network(name)`. Its module docstring says the networks are closed.
- `evals/responder_backend.py` `Responder._ensure_network`: `ensure_closed_network(self.bridge, "--subnet", self.subnet)`. `Responder` gains `run_args: tuple[str, ...] = ()`, extra `docker run` arguments of the singleton (the mounts of the apify API stand-in).
- `evals/doris_backend.py` `_doris_network`, `evals/mysql_backend.py` `_ensure_network`, `evals/neo4j_backend.py` `_ensure_network`, `evals/nuisance_fix_checks/cve_2026_35402_neo4j_cypher.py` `_ensure_bridge`, `evals/nuisance_fix_checks/cve_2026_11720_googleapis.py` `_ensure_internal_bridge`: `ensure_closed_network(name, *subnet_options)`, the `docker network ls` lookups deleted.
- `evals/nuisance_audit.py`: `_network_args` deleted, `_single_container_launch` passes `no_network_args()`. Its docstring loses the default bridge.

### Preflight in each command

`evals/run_images.py` gains `refuse_without_closed_networks()`, which turns `ClosedNetworkUnsupported` into `Refused("the Docker daemon cannot create a closed network", [message, "Docker Engine 28.0 or later is required"])`. It runs before any build or launch in: `nuisance_run.run_nuisance`, `nuisance_vet_command.vet_servers`, `nuisance_calibrate_command.calibrate` (before `kit_launch.build_images`), the nuisance gate session's open, `holdout_run.run_holdout` and `run_holdout._calibrate`. Where a command has injected deps (`NuisanceDeps`, `VetDeps`, `HoldoutDeps`, the gate harness), the check is a dep, `check_networks: Callable[[], None]`, so the refusal is unit-tested with a fake. Each entry maps `Refused` to its refusal exit (3): `run_nuisance.main` and `run_holdout.main` catch `Refused` around every subcommand, and `Refused` is not a `ValueError`, so it passes through `run_holdout._calibrate`'s handler to `main`.

`run_cve_benchmark` is the exception: its `main` runs `cve_preflight.preflight_ok()` before `_run`, and that preflight rebuilds stale images, so a check in `_run` would come after a build. The check goes in `preflight_ok`, right after `_docker_ready()`, printing the daemon's message and the Docker Engine 28.0 requirement and returning `False`, so every mode exits 4 as for any other missing Docker prerequisite (README: "`4` on a crash, Docker unreachable or an image missing included"). `preflight_ok` takes the check as a parameter defaulting to `check_closed_network_support`, so its refusal is unit-tested with a fake. The two existing tests of `tests/unit/test_cve_preflight.py` run under a `docker` shim that answers `info` only and exits 1 on anything else, so the default check would fail them: they pass a check that succeeds.

### Final sweep on every calibrate path

`evals/run_images.py` gains a value object naming the pair every sweep needs:

```python
@dataclass(frozen=True)
class ContainerSweep:
    running_containers: Callable[[Sequence[str]], list[str]]
    remove_containers: Callable[[Sequence[str]], None]

DOCKER_SWEEP = ContainerSweep(running_containers, remove_containers)
```

The field names are those of the `ContainerHost` protocol of `nuisance_run_containers` (and of `HoldoutDeps`), so a `ContainerSweep` satisfies it and `sweep_run_containers` accepts one.

- `run_holdout._calibrate_targets` and `run_cve_benchmark._run` take a `sweep: ContainerSweep` that their caller (`_calibrate`, `main`) passes as the module's `DOCKER_SWEEP`, read at call time rather than bound as a parameter default, so a test's monkeypatch of the module attribute takes effect, and wrap their work in `try/finally: sweep_containers(tags, sweep.running_containers, sweep.remove_containers)`, the tags being `image_tag` over `target_services(targets)` (vulnerable, patched, sentinel and stand-in images). `_run` covers `--calibrate`, `--survey` and the graded run in one place.
- `nuisance_calibrate_command.calibrate` sweeps the kit image tags of `_services(targets)` and the built backend tags of the admitted servers (`built_backend_tags(admission.servers)`, the stand-in included), as `vet` sweeps its backend tags. Without the backend tags, the apify fix check leaves the API stand-in singleton running on `STAND_IN_IMAGE`, and `run_holdout run`, whose tags include `image_tag("stand-in")` once a holdout target lists the stand-in, refuses at its start on that container.
- `run_nuisance gate` has no calibrate step and no sweep either, so its session sweeps the server tags and the built backend tags at its end as `run` does, through the harness. This goes past decision 8's letter on purpose: the gate launches the same Node servers that outlive their launch, and its provisioners stand the same responders.
- The unit tests that drive these commands through `main` (`tests/unit/test_run_holdout.py` on `run_holdout.main(["calibrate"])`, `tests/unit/test_run_cve_benchmark.py` and its given on `run_cve_benchmark.main`, `tests/unit/test_nuisance_fix_checks.py` on `run_nuisance.main(["calibrate"])`) monkeypatch module attributes (`calibrate_all`, `confirm_admission`, `preflight_ok`) and never inject deps. With the defaults they would reach the real `docker ps` and `docker rm -f` from the sweep's `finally` (removing a developer's containers of those images, or raising `FileNotFoundError`, which `sweep_containers` does not catch, on a machine without Docker), and the real network check in `_calibrate`. The commands read the sweep and the check through a module attribute (`DOCKER_SWEEP`, `check_closed_network_support` as imported there) that these tests and their givens monkeypatch with fakes, so no unit test reaches Docker.
- `run_cve_benchmark.py` is at 297 lines and `holdout_run.py` at 306: the sweep goes in with no growth elsewhere, and if `run_cve_benchmark.py` passes 300 the calibrate and survey branches of `_run` move to a sibling module.

### Stand-in captures, `evals/stand_ins/` (new directory) and `evals/capture_stand_in.py` (new)

One JSON file per host, `evals/stand_ins/<host>.json`:

```json
{
  "host": "example.com",
  "address": "<the first IPv4 the name resolved to at capture>",
  "captured_at": "2026-11-0XT..:..:..Z",
  "command": "uv run python -m evals.capture_stand_in --out evals/stand_ins/example.com.json https://example.com/ https://example.com/robots.txt http://example.com/ http://example.com/robots.txt",
  "request_headers": [],
  "routes": [
    {"scheme": "https", "method": "GET", "target": "/", "status": 200, "headers": [["Content-Type", "text/html"], ...], "body": "..."}
  ]
}
```

- `evals/capture_stand_in.py`: `uv run python -m evals.capture_stand_in --out PATH URL [URL ...] [--header 'NAME: VALUE' ...]`. All URLs share one host. It resolves the host's IPv4, GETs each URL with `httpx` (no redirect following, `Accept-Encoding: identity`, and each `--header` sent as given), records the status, every response header and the body as UTF-8 text, whatever the status (a 401 or a 404 is recorded like a 200), and refuses a body that is not UTF-8. Each `--header` is written verbatim, name and value, into `request_headers` and into `command`: the only header a capture sends is a credential the fixture's server itself sends, a dummy value already committed in the launch, so the command handles no secret and reads no environment variable. A capture is taken whole, never appended, so one file carries one date: adding a route recaptures every route. The pure part, `capture_record(provenance: CaptureProvenance, responses) -> dict`, is unit-tested, and the I/O shell stays thin. `CaptureProvenance` is a frozen dataclass of `host`, `address`, `captured_at`, `command` and `request_headers`, the fields the shell resolves, reads from the clock and from its own argv before any request.
- The `api.apify.com` capture sends `--header 'Authorization: Bearer calib-token'`, the header `apify-client` builds from the `APIFY_TOKEN` of `apify_network_args` (`Authorization: Bearer ${token}` in its `http_client.js`), and no credential of the maintainer's.
- `evals/stand_ins/tls/generate.sh [--out DIR] HOST...` (new, `DIR` defaulting to the script's own directory): the `openssl` commands that make the fixture authority (`fixture-authority.pem`, `fixture-authority-key.pem`) and, per host given, a leaf (`<host>.pem`, `<host>-key.pem`, `basicConstraints=critical,CA:FALSE`, `subjectAltName=DNS:<host>`, `extendedKeyUsage=serverAuth`, `authorityKeyIdentifier=keyid`), with long validity. The hosts given are every HTTPS stand-in host on each run: a host declared as a stand-in (by an acceptance or holdout target's `PublicNames.stand_ins`, or as `apify_backend.API_HOST`) whose capture has an `https` route, today `example.com`, `demo.ckan.org` and `api.apify.com`. The script writes a temporary openssl config whose authority section is `basicConstraints = critical,CA:TRUE`, `keyUsage = critical,keyCertSign,cRLSign`, `subjectKeyIdentifier = hash` and `nameConstraints = critical,@constraints`, and whose `[constraints]` section holds `permitted;DNS.<i> = <host>` and `excluded;DNS.<i> = .<host>` for each host given, then signs the authority with `openssl req -x509 -config <that file> -extensions <that section>`. Each run makes a new authority and every leaf from it, and removes the TLS files of a host it was not given, since the host list is fixed inside the authority: adding a stand-in host regenerates the authority and moves every leaf. The authority's key is committed with the rest. The name constraints keep it from signing for any name but the listed hosts, and these keys are fixture material, trusted only by fixture containers told to trust the authority.
- What is replayed: the status, the body, and the `Content-Type` and `Location` headers. The other recorded headers are provenance only, so a replayed `Strict-Transport-Security` or `Alt-Svc` cannot change a client's behaviour.

### `evals/docker/Dockerfile.stand-in` (new) and compose service `stand-in`

A pinned Python base (digest read on the pulled image, as for every base), and an inline replay server in `ENTRYPOINT` (no `COPY`, as the responders do): it reads `/stand-in/capture.json`, serves HTTP on `BIND_ADDR:80` and HTTPS on `BIND_ADDR:443` with `/stand-in/cert.pem` and `/stand-in/key.pem` (`BIND_ADDR` defaults to every address), answers a request matching a captured `(scheme, method, target)` with its recorded response, and answers any other with `404` and an empty body, writing `miss <scheme> <method> <target>` to stderr. The compose service `stand-in` builds `mcp-auditor-cve-stand-in:local` with its fingerprint label, outside the `nuisance` profile, so the CI's bare `docker compose build` builds it.

### `evals/cve_planting_base.py`

```python
STAND_IN_SERVICE = "stand-in"
STAND_IN_IMAGE = "mcp-auditor-cve-stand-in:local"

@dataclass(frozen=True)
class StandIn:  # a loaded capture, made by public_stand_ins.stand_in at call time
    host: str
    address: str  # the IPv4 the real name resolved to at capture
    capture: str  # the capture file's text, replayed verbatim
    certificate: str  # the leaf for host, from the fixture authority
    key: str
    authority: str  # the fixture authority's certificate

@dataclass(frozen=True)
class PublicNames:
    stand_ins: tuple[str, ...] = ()  # hosts served by a stand-in, e.g. example.com
    trust: tuple[str, ...] = ()  # env names pointed at the fixture authority, e.g. NODE_EXTRA_CA_CERTS
    ip_label_domains: tuple[str, ...] = ()  # wildcard-DNS domains that answer a dashed IPv4 label, e.g. sslip.io

@dataclass(frozen=True)
class PlantingHost:
    user: SymbolicUser
    working_directory: str
    has_network: bool
    public_names: PublicNames = PublicNames()
```

`PlantingSpec` gains `stand_ins: tuple[StandIn, ...] = ()`, defaulted like `layout` because `tests/unit/support/test_doris_serialization_given.py` builds a `PlantingSpec` directly. `planting_spec` leaves it empty, as it reads no file, and `planted` fills it (below). The trust names are read from `spec.host.public_names`. `PlantingDocker` gains `start_stand_in(run_args) -> str`, `remove_stand_in(name)` and `probe_listener(target_args, host, port) -> bool`.

### `evals/cve_planting_spec.py` and `evals/cve_endpoint_address.py`

`cve_planting_spec.py` is at 291 lines, so the pinning is a function of `cve_endpoint_address.py` (77 lines, already a clean and fingerprinted module, whose `BindAddressDraft` already names `bind_addresses`, `address_setups` and `host_entries`), `pin_public_names(host, sentinels, draft)`, and `_SpecDraft.finish` calls it. After the places, it pins what the declared names give without a capture, the spec staying pure (a stand-in's address is pinned by the planting, which loads its capture):

- a second stand-in for one host is refused.
- for each `ip_label_domains` entry and each sentinel whose endpoint host is an IPv4 literal, `(f"{dashed}.{domain}", literal)` joins `host_entries`, `dashed` being the literal with dots replaced by dashes: the rule sslip.io applies to such a name, for the planted addresses only.
- `trust` without a stand-in is refused, so a trust setting never travels alone.
- `needs_holder` becomes true when a sentinel is bound or a stand-in is declared, so a launch with stand-ins always joins a holder, its reference arm (which plants no sentinel) included.

Refusals are `ValueError`s naming the host and the property, as the spec's others do.

### `evals/cve_planting_stand_ins.py` (new, clean) and `evals/cve_planting.py`

`cve_planting.py` is at 255 lines, so the stand-in setup is a module of its own, called by `planted` and `_set_up`:

- `planted` gains `stand_ins_directory: Path = STAND_INS_DIRECTORY`, as `fixture_fingerprint` takes `docker_directory`, so the builders' calls stay as they are and a unit test passes a tmp directory. First, `with_stand_ins(spec, directory) -> PlantingSpec` loads each host the planting host declares through `stand_in(host, directory)` and returns the spec with `stand_ins` set, each stand-in's address appended to `address_setups` and `(host, address)` to `host_entries`, so the holder and address-setup code reads them as it reads a bound sentinel's. An address already in `address_setups` (a bound sentinel's) is refused with a `ValueError` naming the stand-in host, so a stand-in and a sentinel never share one. The loader already refuses an address that is not global unicast, loopback and the reserved block included. The load runs outside the setup's `try`, so a missing or malformed capture raises as a fixture error rather than as a `PlantingFailed` the runner would count as a skipped run. A host that declares no stand-in reads no file.
- `serve_stand_ins(spec, holder, docker, stack)`, after the sentinels: for each of `spec.stand_ins`, writes the capture, the leaf and its key as host files (`write_host_file`, removed by the stack), starts the stand-in with `[*confinement_args(), "--cap-add", "NET_BIND_SERVICE", "--network", f"container:{holder}", "-e", f"BIND_ADDR={address}", "-v", f"{capture}:/stand-in/capture.json:ro", ...cert and key..., STAND_IN_IMAGE]`, and registers its removal.
- `trust_args(spec, docker, stack) -> tuple[env, mounts]`: when `spec.host.public_names.trust` is set, writes the authority of the loaded stand-ins once, mounts it at `/etc/ssl/extra-ca.pem:ro` into the target, and sets each named variable to that path. `PlantedArgs.env` and `PlantedArgs.mounts` carry them, so every builder that uses `args.run_args()` passes them on.
- the probe: after the sentinels' probe, `probe_listener(probe_args, host, 80)` and `probe_listener(probe_args, host, 443)` for each stand-in, from a container started with the target's own arguments, so the name resolves through the target's `/etc/hosts`. A stand-in not listening raises `PlantingFailed("stand-in for <host> is not serving")`.
- `RecordingPlanting` (`tests/integration/support/test_cve_planting_given.py`, a `DockerPlanting` subclass that records what it made) records `start_stand_in` too, so the teardown count of scenario 14 covers the stand-in.
- `DockerPlanting.remove_stand_in` reads the container's stderr (`docker logs`) before `docker rm -f` and logs each `miss` line as a warning naming the host, so a route the capture lacks shows up in a calibration log. `probe_listener` runs busybox `nc -z -w 5` from `SENTINEL_IMAGE` with the target's arguments, retried within the sentinel probe's budget.
- The local `stand_in` of `_probe_endpoints` (the probe container) is renamed `probe_args`, so "stand-in" names one thing.

`cve_planting.py`'s module docstring says the network it owns is closed. `cve_environments.py`'s docstring loses "a plain labelled bridge with the host gateway and Internet egress" and states the closed network and the stand-ins, `cve_endpoint_address.py`'s states that a stand-in address is bound like an IPv4 literal.

### `evals/public_stand_ins.py` (new, clean)

No file is read at import: a target names a stand-in by its host only, a plain string, and the planting and the fingerprint load its capture at call time through `stand_in(host, directory=STAND_INS_DIRECTORY)`, as `dockerfile_fingerprint(service, docker_directory=DOCKER_DIRECTORY)` reads a Dockerfile, so a unit test injects a tmp directory and reads the committed captures only when it means to.

Loads a capture into a `StandIn`: `stand_in(host, directory=STAND_INS_DIRECTORY) -> StandIn` reads `<directory>/<host>.json` (`STAND_INS_DIRECTORY` being `evals/stand_ins/`) through a pydantic `StandInCapture` model (refusing a file whose `host` is not its name, an `address` that is not a global unicast IPv4, a route with a scheme other than `http` or `https`, an empty `command` or `captured_at`), and the leaf, its key and the authority from `<directory>/tls/`. `stand_in_files(host, directory=STAND_INS_DIRECTORY)` gives the paths without reading them, for the apify singleton's mounts and the apify backend's `served` paths. The module holds no stand-in value. Its callers are the planting (`with_stand_ins`), the fixture fingerprint (`planting_host_parts`) and, for paths only, the apify backend. It is clean, importing nothing from `mcp_auditor`, because `planted`, copied into the dossiers, imports its loader.

### `evals/calibration_dossier.py`

`CLEAN_MODULES` gains `closed_network`, `public_stand_ins` and `cve_planting_stand_ins`. The capture directory is not copied: no kit fixture declares a stand-in, so the kit's planting never loads a capture, and the kit's `STAND_INS_DIRECTORY` names a directory it does not hold. `nuisance_dossier` copies `doris_backend.py`, which now imports `closed_network`, but it builds its tree through `copy_clean_sources`, which copies every `CLEAN_MODULES` entry: `closed_network` reaches the nuisance dossier through that, and `_BACKEND_SOURCES` stays as it is. `test_holdout_kit_isolation.py` and `test_nuisance_dossier.py` keep guarding that the exported trees import nothing from `mcp_auditor`.

### `evals/cve_baseline.py`

`_ENVIRONMENT_PATHS` gains `closed_network.py`, `public_stand_ins.py` and `cve_planting_stand_ins.py`. `planting_host_parts(host, stand_ins_directory=STAND_INS_DIRECTORY)` appends, only when `host.public_names` declares something, each declared stand-in's host, then, loaded through `stand_in(host, stand_ins_directory)`, its address and the SHA-256 of its capture, leaf, key and authority, then the trust names and the IP-label domains. `fixture_fingerprint` gains `stand_ins_directory: Path = STAND_INS_DIRECTORY` beside `docker_directory` and passes it on, so scenario 6 fingerprints tmp captures. A host with no public names reads no file and gives the same parts as today, so the nuisance fingerprint, which shares the function, does not move through it. A target that declares a stand-in lists `STAND_IN_SERVICE` in its `images`, so the stand-in Dockerfile's instructions enter its fingerprint and its image is built with the target's, pinned by a real-data test.

### Targets

- `evals/cve_targets.py` CVE-2025-65513: its own `PlantingHost(UNPRIVILEGED, "/", has_network=True, PublicNames(stand_ins=("example.com",)))`, `images=("fetch", "sentinel", "stand-in")`. No trust: the benign call is plain HTTP. `cve_exploits.benign_fetch_ssrf`'s comment says the control reaches the `example.com` stand-in on a public address, not the Internet.
- `evals/holdout_fixtures/cve_2026_104120_fetch.py`: `stand_ins=("example.com",)`, `trust=("SSL_CERT_FILE",)`. The patched image's `httpx` 0.28.1 builds its context from `SSL_CERT_FILE` when `trust_env` holds, and `make_client` keeps the default. The capture includes `/robots.txt` as well, though both images' entrypoint passes `--ignore-robots-txt`, so `fetch` skips its robots pre-check and requests the page only.
- `evals/holdout_fixtures/cve_2026_58485_searxng.py`: `stand_ins=("example.com",)`, `trust=("NODE_EXTRA_CA_CERTS",)` (Node 24, `undici` takes the process's extra authorities), `ip_label_domains=("sslip.io",)`.
- `evals/holdout_fixtures/cve_2026_33060_ckan.py`: `stand_ins=("demo.ckan.org",)`, `trust=("NODE_EXTRA_CA_CERTS",)` (Node 20 on Alpine).
- `evals/holdout_fixtures/cve_2026_5323_a11y.py`: `stand_ins=("example.com",)`, no trust. Chromium takes its trust from an NSS database, not an environment variable, and the benign call is plain HTTP. If Chromium tries HTTPS first, the stand-in's certificate fails and Chromium falls back to HTTP at once, which the recalibration confirms.
- Each of these five lists `"stand-in"` in its `images`. Their benign calls, exploits and kept places are unchanged.

### Apify backend, `evals/apify_backend.py`

- A second singleton, `_API_STAND_IN = Responder(image=STAND_IN_IMAGE, container="mcp-auditor-cve-apify-api-stand-in", bridge=APIFY_BRIDGE, subnet=APIFY_SUBNET, ip="198.18.1.3", dockerfile=Dockerfile.stand-in, run_args=<mounts of stand_in_files("api.apify.com")>)`, paths only, read by Docker at `docker run`, so importing the backend reads no file. The fix check's per-launch responders sit at `.100` to `.250`, so `.3` is free. `apify-client` checks no address, so the bridge address serves.
- `ensure_apify_responder` ensures both singletons, so the run, vet and the fix check CVE-2026-46341 (which already calls it) all get the API stand-in.
- `API_HOST = "api.apify.com"` names the stand-in's host, read by `stand_in_files`, the pin and the constraints test. `apify_network_args` adds `--add-host api.apify.com:198.18.1.3`. The server already runs with `NODE_TLS_REJECT_UNAUTHORIZED=0`, the trust setting it had for `docs.apify.com`, so no other setting is added, and the authority's name constraints do not bear on it.
- The capture covers the routes both versions (0.9.20 and 0.9.21) request at start with no `actors` input: the default Actors' definitions as `apify-client` fetches them, requested with `Authorization: Bearer calib-token` and recorded as the real API answers that token. The implementer lists them from the image's `tools_loader.js` and `apify-client` calls, and confirms with the stand-in's miss log on a first vet.

### `evals/nuisance_backends.py`, `evals/nuisance_images.py` and `evals/nuisance_fingerprint.py` (new)

- `RegisteredBackend.built_service: str | None` becomes `built_services: tuple[str, ...]` (apify builds two images, its responder and the stand-in), and `built_backend_services` flattens them. The tests that read the old field change with it: `test_nuisance_backends_built.py` (a built backend's `image` is the tag of one of its `built_services`, a pulled one has none) and `test_nuisance_compose.py`'s `test_each_built_backend_is_a_nuisance_profiled_compose_service`, which iterates every built service and asserts the `nuisance` profile: the `stand-in` service sits outside that profile on purpose (the acceptance targets need it on CI's bare build), so the test holds every built service to be a compose service and every one but `STAND_IN_SERVICE` to be nuisance-profiled.
- `RegisteredBackend` gains `served: tuple[Path, ...]`, what the backend serves and how it joins the server: its backend module (`<name>_backend.py`, plus `responder_backend.py` for the responders and `closed_network.py` for all), the Dockerfiles of the images it builds, and for apify the API capture and its leaf, given by `stand_in_files`, paths the fingerprint reads at call time. Seeds live in the backend modules (`_provision_doris_schema`, the moto seed, the Neo4j provisioning), so they are covered.
- `nuisance_fixture_fingerprint` moves out of `nuisance_images.py` into a new `evals/nuisance_fingerprint.py`, with the signature `nuisance_fixture_fingerprint(server, docker_directory=DOCKER_DIRECTORY, backends=BACKENDS)`. It cannot stay: reading `BACKENDS` means importing `nuisance_backends`, which imports `nuisance_provisioners`, which imports `image_tag` from `nuisance_images`, so `nuisance_images` importing `nuisance_backends` is an import cycle that fails on whichever module loads first. Its callers (`nuisance_run.py`, `nuisance_gate_session.py`, `nuisance_gate_session_recording.py`, and the tests `test_nuisance_run.py`, `support/test_nuisance_gate_session_given.py`, `test_nuisance_images.py`, `test_nuisance_compose.py`) import it from there. It adds `backend_content(backends[key].served)`: a Dockerfile by its instructions, a Python module by `fingerprint_sources`, any other file by its SHA-256. The docstring's In list says so. A server with no backend gains a `None`.

### `evals/nuisance_admission.py`, `evals/nuisance_dossier.py`

- `admission_problems` gains `_network_problems(server)`: `has_network` true with no backend gives `"<package>: has_network without a backend: a server with no backend runs with no network"`.
- The dossier's `has_network` paragraph: true only for a server with a backend, whose provisioner's closed network joins it to the backend and to nothing else. The admission refuses `has_network` without a backend.

### `evals/cve_calibration.py`

`_EGRESS_CANARY`, `egress_warning`, `_egress_reachable` and their call in `_patched_conditions` deleted, with the `socket` import. `_patched_conditions` returns `patched_dead_conditions(...)` directly.

### Stale docstrings

Each module whose docstring describes an open network says the network is closed: `responder_backend.py`, each `*_backend.py` that mentions egress or DNS aliasing, `doris_backend.py`, `nuisance_audit.py`, the `_DORIS_BUILDER_PARAGRAPH` of `nuisance_dossier.py` if it names egress.

## What stays unchanged

- The product: `src/` is untouched, and so is the confinement of ADR 018 (`--network` choices of `adapters/server_launch`, the confined regimes, `README.md`'s "Confined by default" paragraph).
- The honeypot e2e suite and the judge isolation eval: stdio subprocesses with no network backend, and no server at all.
- Every benign call, exploit, kept place, aim and tools filter of every target and server. The admission's fields except what the maintainer steps below may repair, each logged.
- The responders' content and addresses, their `--add-host` pins, the n8n stub and the ContextForge `/etc/hosts` rebinding.
- Network names, so `backend.network` in the admission stays as recorded.
- The build: images keep their network and fetch from the Internet at build time (ADR 024 accepts it).
- The grammar and its golden master.

## Edge cases

- **A persistent network created by an older run, open.** Recreated by `ensure_closed_network` after its containers are removed, which costs a Doris cold start once on a machine that had the cluster. A network of our name with no `mcp-auditor-cve` label refuses. A run and a calibration on one machine must not overlap, as the docs already state: a recreation removes what is attached.
- **Concurrent launches at concurrency 6.** Per-launch networks keep random names. Persistent ensures run under the backends' launch locks and the per-name lock of `closed_network`. Stand-in addresses are bound inside each launch's own holder, so two launches binding `example.com`'s address do not collide. The preflight's throwaway network is created once per command, before any launch.
- **Docker before 28.0, or a daemon that accepts and ignores the option.** The preflight refuses with the daemon's message and the version, and every creation verifies what it made, so no launch runs on an open network.
- **IPv6.** A network with IPv6 enabled (a daemon `default-network-opts`) would keep an IPv6 gateway. The verification refuses it.
- **Alpine and musl images.** An unpinned lookup fails after 5 to 10 s there (glibc fails in milliseconds), against a 30 s tool-call timeout. The pinned names are read from `/etc/hosts` with no DNS, so the stand-in hosts cost nothing. A stray lookup a server makes on its own shows as a slow call or a timeout in vet or calibration, and is read case by case.
- **`--add-host` on a holder-joined container.** Docker refuses it, so every public name of a planted launch goes on the holder, and `planting_spec` forces a holder whenever a stand-in is declared.
- **A stand-in route the capture lacks.** The stand-in answers `404` with an empty body and the planting teardown logs the miss with the host. The fix is a fresh capture of every route, never a hand-written response. A miss on a route the real service also answers `404` (some `/robots.txt`) is captured all the same, so the replay is the real answer.
- **Chromium and HTTPS.** CVE-2026-5323's Chromium may upgrade `http://example.com/` to HTTPS. The stand-in answers 443 with a certificate Chromium does not trust, so the upgrade fails at once and Chromium falls back to HTTP. If the recalibration shows otherwise, the maintainer step stops.
- **CVE-2026-5323's first exploit timed out under the throwaway patch** and the next two failed on the process bound the stuck Chromium held. The logs do not show a public lookup in its exploits (IP literals). The recalibration with the `example.com` stand-in settles it. If exploit 0 still times out, the step stops and reports to the maintainer rather than tuning the fixture blind.
- **The sslip.io dotted form.** Only the dashed names of the planted addresses resolve, as decision 3 names them. A dotted form (`169.254.169.254.sslip.io`) or another wildcard service the auditor tries fails, the consequence ADR 034 states.
- **The CI runner's Docker version.** `ci.yml` runs the integration tests with `CVE_PLANTING_REQUIRED=1` and `cve-calibration.yml` runs `--calibrate --ci` on `ubuntu-latest`. Before step 1 lands, the implementer reads the Docker Engine version of the runner image from its published software list. Below 28.0, both workflows gain a pinned Docker Engine install step in the same commit. Read on 2026-11-02: `ubuntu-latest` is `ubuntu-24.04`, image `20261026.354.1`, Docker Server 28.0.4, so no install step is needed unless the image has changed by then.
- **The Apify capture and its token.** The capture sends `Authorization: Bearer calib-token`, the dummy token the server sends, and records what the real API answers to it, a 401 included, verbatim. No token of the maintainer's is ever used, so the capture cannot carry account data. If those answers keep the apify server from starting or from answering its benign call (on vet, or on the patched side of the fix check CVE-2026-46341), that is the real behaviour of the server launched with a dummy token: the maintainer step that sees it records it and stops for a decision under the nuisance rule's liveness clause. The capture is never altered, edited or retaken with another token to make the server answer.
- **A new HTTPS stand-in host.** The authority's name constraints list the HTTPS stand-in hosts, so adding one regenerates the authority and every leaf (`generate.sh` given the whole new list), its own commit. Every target that declares a stand-in, and the apify nuisance server, then moves fingerprint, since the authority, each leaf and each key enter it: an acceptance fixture change under ADR 024, and a holdout and nuisance fixture change logged as the ones of this plan are.
- **Certificate expiry.** The leaves carry a long validity, recorded by the script. An expired leaf fails calibration visibly, on the TLS error.

## Test scenarios

Test-first: each scenario is written red before its code. Fakes, not mocks. Given/then pairs where they abstract something.

### Unit

1. `tests/unit/test_closed_network.py` (+ given/then, a `FakeNetworkDocker` in `tests/fakes/network_docker.py` holding networks with their label, internal flag, gateway mode, IPv6 flag and attached containers, configurable to reject the `isolated` option with a daemon message or to accept and ignore it):
   - an absent network is created closed.
   - a closed network is kept, its attached containers still there.
   - an open labelled network ends closed, its attached containers gone, under the same name.
   - an unlabelled network of the same name refuses, and is left as it was.
   - a daemon that rejects the option raises `ClosedNetworkUnsupported` naming Docker Engine 28.0 and the daemon's message, and leaves no network.
   - a daemon that accepts the option and leaves the network open raises, and leaves no network.
   - a network created with IPv6 enabled raises.
   - the support check leaves no network behind on success and on failure.
   - the inspect parse reads a recorded `docker network inspect` output of a closed network and of an open one.
2. `tests/unit/test_cve_planting_stand_ins.py` (+ given/then on `FakePlantingDocker`, which gains stand-ins, listener probes and a configurable dead stand-in, the given writing each case's captures and TLS files into a tmp directory passed to `planted` as `stand_ins_directory`):
   - a launch with a stand-in joins a holder that carries the name pinned to the stand-in's address, and that address is set up on the holder's loopback.
   - the stand-in serves the capture, the leaf and the key loaded from its directory, inside the holder, bound to its address.
   - a stand-in whose capture address equals a bound sentinel's is refused before any container starts, naming the stand-in host.
   - a trust setting reaches the target as a mounted authority and the named variables pointing at it.
   - a stand-in that does not listen fails the planting, and nothing is left: holder, stand-in, sentinels, network and host files removed.
   - teardown removes the stand-in and its host files.
   - a launch with no public names plants exactly as today (holder only for a bound sentinel) and reads no file.
3. Planting spec (in the planting spec tests, or a new file when the existing one is past 300 lines):
   - an IP-label domain pins the dashed name of every IPv4-literal endpoint to that literal, and nothing for a name endpoint.
   - two stand-ins for one host are refused.
   - a trust setting with no stand-in is refused.
4. `tests/unit/test_public_stand_ins.py`, real data: every committed capture loads, names its own host, carries a date and a command, a global IPv4 address, routes in `http` or `https` only, and its host has a leaf. A capture whose `host` differs from its file name, or whose address is private, in loopback or in the reserved block, is refused (tmp files passed as `directory`). Real data as well, read with `cryptography`'s `x509` (already locked at 50.0.2 through `mcp[crypto]` and `google-auth`, added to the `dev` group since a test now imports it directly): the committed authority carries a critical `nameConstraints` extension whose permitted DNS subtrees equal the set of HTTPS stand-in hosts (the hosts of the committed captures with an `https` route) and whose excluded DNS subtrees are `.<host>` for each of them, and every committed leaf names one of those hosts. With no capture and no authority committed, both sets are empty and the case passes. Once every stand-in is declared, a real-data case holds the hosts of the committed captures equal to the declared stand-in hosts (every acceptance and holdout target's `PublicNames.stand_ins` and `apify_backend.API_HOST`), so the constraints list derives from the declared stand-ins.
5. `tests/unit/test_capture_stand_in.py`: `capture_record` keeps status, headers and body verbatim, a 401 like a 200, records each sent request header with its name and value in `request_headers`, and refuses a non-UTF-8 body.
6. `tests/unit/test_cve_baseline.py`: the fixture fingerprint, on tmp captures passed as `stand_ins_directory`, moves when a stand-in's capture, leaf, address or trust setting changes, and does not move for a target without public names. A target that declares a stand-in lists the `stand-in` service in its images (real data, every acceptance and holdout target).
7. `tests/unit/test_nuisance_fingerprint.py` (the fingerprint cases of `test_nuisance_images.py` move with the function): the nuisance fingerprint moves when a served file of the server's backend changes (a tmp registry), and stays for a server with no backend. Real data: every `served` path of `BACKENDS` exists.
8. `tests/unit/test_nuisance_admission.py`: a server with `has_network` and no backend is refused with its package named. `tests/unit/test_nuisance_audit.py`: the default-bridge test is deleted, a backend-less server launches with `--network none`.
9. `tests/unit/test_apify_backend.py`: the server's arguments pin `api.apify.com` to the API stand-in's address beside the two documentation names. `tests/unit/test_nuisance_backends_built.py`: apify's built services are the responder and the stand-in, and the run removes and rebuilds both. `tests/unit/test_nuisance_compose.py`: every built service is a compose service, nuisance-profiled except the stand-in.
10. `tests/unit/test_cve_calibration.py`: the four egress cases are deleted.
11. Sweeps, on the command functions with a fake `ContainerSweep` and a fake per-target check: a leftover of the run's images is removed after `run_holdout calibrate`, after `run_nuisance calibrate` (a leftover of a built backend image included), after each `run_cve_benchmark` mode, after the nuisance gate (a built backend leftover included), and also when the work raised.
12. Preflight, on the commands with injected deps (run, vet, gate, holdout run): a failing network check refuses before any rebuild, with the Docker version in the reasons. `run_holdout calibrate` and `run_nuisance calibrate`, driven through `main` with the module attribute monkeypatched to fail, exit 3 before any build. `cve_preflight.preflight_ok` with a failing check returns `False` before any image is ensured (`tests/unit/test_cve_preflight.py` or its existing home).

### Integration (Docker, skip without Docker, fail under `CVE_PLANTING_REQUIRED=1`)

13. `tests/integration/test_closed_networks.py` (+ `support/test_closed_networks_given.py` and `_then.py`), with the sentinel image and a listener the test opens on the host's `0.0.0.0`:
    - from a container on a network made by `create_closed_network`: `nc` to every IPv4 address of the host's interfaces at the listener's port fails, `nc` to `1.1.1.1:443` and `169.254.169.254:80` fails, `ip route` shows no default route, a name pinned with `--add-host` resolves, and an unpinned name fails within 15 s (the musl bound with margin) instead of hanging.
    - the control: the same container on a plain labelled network reaches the listener through its gateway, so the closed case cannot pass because the listener was unreachable anyway.
    - an open labelled network with a container attached ends closed under `ensure_closed_network`, the container removed.
    - the same reachability checks from a container started with a planted launch's own arguments (`has_network` true, an IP-literal sentinel, so a holder), since that is the path every networked target takes.
14. `tests/integration/test_cve_planting.py`: a planted stand-in, the host declaring it by name and `planted` reading it from a `tmp_path` stand-ins directory where the given writes a capture and makes a throwaway authority and leaf by running `generate.sh --out <tmp_path>/tls <the test's host>` (skipped like Docker when `openssl` is absent), so the script itself and its name constraints are exercised: read by name from the target's arguments, it serves the capture's body over HTTP and over HTTPS when the client trusts the name-constrained authority, an uncaptured route answers `404`, and teardown logs the miss. The client is the stand-in image's Python, which verifies TLS. The module fixture builds the stand-in image beside the sentinel.
15. The existing planting integration cases (bridge aliases, holder-bound literals, the teardown count) pass unchanged on closed networks.

## Steps

Each step is one commit, made after the maintainer's go on the diff, and leaves `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` green. CI's calibration stays green at every commit: the per-launch network closes in the same commit that gives CVE-2025-65513 its stand-in.

1. **Closed persistent networks.** `closed_network.py` with its fake and unit tests, every persistent creation site, the preflight in every command, the default-bridge path removed and the admission refusal, the dossier copy lists, the integration test of scenario 13 except its planted case. Docs: README prerequisite (Docker Engine 28.0 for the eval suites), CLAUDE.md Landmines (a closed network needs both options, plain `--internal` reaches the host on its bridge address), CLAUDE.md Commands (the integration entry counts the closed-network test among the Docker image tests, and the entries of `run_holdout calibrate`, `run_nuisance calibrate`, `run_nuisance gate`, `run_holdout run`, `run_nuisance run` and `vet` gain the refusal on a daemon that cannot create a closed network with its exit, `3`, and `run_cve_benchmark`'s the preflight failure, `4`), CONTRIBUTING (the Docker version beside the Docker prerequisite, `tests/integration/test_closed_networks.py` in the list of Docker integration tests, and the same refusal and exit in the paragraphs on those commands), CHANGELOG. The CI runner check comes first. The apify server stops answering from here until step 5, which wires the API stand-in on the captures of step 4, a manual command only.
2. **Final sweeps.** `ContainerSweep` and the sweeps of scenario 11. Docs: CLAUDE.md Commands and CONTRIBUTING, on `run_holdout calibrate`, `run_nuisance calibrate`, `run_nuisance gate` and every `run_cve_benchmark` mode, say that at its end, even when it raises, the command removes with `docker rm -f` the containers of its images still running, as the run entries already say. CHANGELOG.
3. **Stand-in machinery.** Capture format and command, `generate.sh`, `Dockerfile.stand-in` and its compose service, `StandIn` and `PublicNames`, the planting spec and `cve_planting_stand_ins.py`, the fingerprint parts, the registry module whole (`stand_in` and `stand_in_files`, tested on tmp captures), `planted`'s `stand_ins_directory`, the `CLEAN_MODULES` entries of `public_stand_ins` and `cve_planting_stand_ins`, `cryptography` in the `dev` group for the name-constraints test, scenarios 2 to 6 and 14. No target declares a stand-in yet, so every per-launch network is still open. `cve-calibration.yml`'s two `paths` filters gain `evals/closed_network.py`, `evals/public_stand_ins.py` and `evals/stand_ins/**`, which its `evals/cve_*.py` filter misses, so a later change to the network module or a capture still runs the CI calibration. Docs: CLAUDE.md Commands (`capture_stand_in`, `generate.sh`) and Landmines (stand-in content is mounted from captures, never copied into an image, and public names of a holder-joined launch go on the holder).
4. **Maintainer step: captures** (network access, no LLM). Run `generate.sh` with every HTTPS stand-in host, `example.com`, `demo.ckan.org` and `api.apify.com`, which makes the name-constrained authority and the three leaves, capture `example.com` (`/`, `/robots.txt`, over HTTPS and HTTP), `demo.ckan.org` (the `status_show` route the patched and vulnerable ckan servers request, read from the image) and `api.apify.com` (the start routes, sent with `--header 'Authorization: Bearer calib-token'` and recorded as answered, a 401 included, see the Apify edge case). Read each capture before committing: nothing in it may name the audit, a fixture or a flaw. Commit the captures and the TLS files.
5. **Wiring.** The targets declare their stand-ins only now, after the captures, because the planting and the fingerprint read a declared stand-in's capture at call time, and a capture needs the command of step 3. The per-launch planting network closed (`DockerPlanting.create_network`), the five targets' public names and trust settings, the apify API stand-in and its backend entries, the nuisance fingerprint over served content (scenario 7), the egress warning deleted, the stale docstrings, the planted case of scenario 13. Docs: README Safety paragraph rewritten (every fixture network is internal with an isolated gateway, so it reaches neither the host nor the Internet, public names are pinned inside the network and served by stand-ins replaying a dated capture, an HTTPS stand-in's authority is trusted through the setting each target declares and is name-constrained to the HTTPS stand-in hosts, and the orphan sweep and the recreation of an open persistent network), CHANGELOG. The labeling log entry for the acceptance fixture change, naming the commits of steps 1 to 4, in this commit (**State**: the acceptance baseline at `b036714` no longer compares, as it already did not at `3a8120b`. **What changes**. **Fingerprint**: the grammar fingerprint unchanged. **The four questions of ADR 016**, answered as an instrument change raised by ADR 034 and not by a measurement).
6. **Maintainer step: the suites' Docker checks** (Docker, no LLM). In order: `uv run python -m evals.run_nuisance vet` (59 of 59), `uv run python -m evals.run_nuisance calibrate` (every result matches its recorded fix check, CVE-2026-46341 included), `uv run python -m evals.run_holdout calibrate` (every target live, every fingerprint having moved), `uv run python -m evals.run_cve_benchmark --calibrate` (4 of 4). After each, `docker ps --filter label=mcp-auditor-cve` shows no server, holder, sentinel or per-launch stand-in: only the persistent backends kept on purpose and never swept (the Doris cluster, the MySQL engine and its moto stub), all on closed networks. A red item is read: a capture miss is a recapture (step 4 again, its own commit), a server that resolves another public name stops the step and is reported, and an apify server that does not start or answer on the recorded `api.apify.com` answers is recorded and stops the step for the maintainer's decision under the nuisance rule's liveness clause, the capture unaltered. Then one commit with the log entries: `docs/nuisance-log.md` (the closed networks, the `api.apify.com` stand-in on the apify backend and the served content in the fingerprint, vet and calibrate green at a named commit), `docs/holdout-log.md` (every target recalibrated without an LLM at a named commit, the fixture fingerprints moved before any holdout run, the four stand-in targets with their stand-in and trust setting, the sslip.io pins of CVE-2026-58485, infrastructure only with no rule version opened, as the 2026-10-28 digest-pinning entry did).
7. **Reset.** Delete the four files of `evals/baselines/cve/` in a commit of their own (`chore(evals): reset the CVE acceptance baseline`).
8. **Maintainer step: recording** (Docker and an LLM key, volume and cost announced before launching). `uv run python -m evals.run_cve_benchmark --record-baseline` twice at one commit on a clean tree (exploratory, then confirmed), then commit `evals/baselines/cve/` with the labeling log entry of the recording (State, Fingerprint with the four fixture fingerprints, The recording, the four questions), as the 2026-10-15 recording entry does.

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration/test_closed_networks.py tests/integration/test_cve_planting.py tests/integration/test_holdout_kit.py -n 0
docker compose -f evals/docker/compose.yml build
openssl x509 -in evals/stand_ins/tls/fixture-authority.pem -noout -ext nameConstraints
uv run python -m evals.run_nuisance vet
uv run python -m evals.run_nuisance calibrate
uv run python -m evals.run_holdout calibrate
uv run python -m evals.run_cve_benchmark --calibrate
docker ps -a --filter label=mcp-auditor-cve
docker network ls --filter label=mcp-auditor-cve --format '{{.Name}}' | xargs -r -n1 docker network inspect -f '{{.Name}} {{.Internal}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}'
```

The `openssl x509` command shows the authority's critical name constraints, the HTTPS stand-in hosts permitted and their `.<host>` subdomains excluded. The `docker ps -a` command lists only the persistent pulled backends (Doris, MySQL, moto), which no sweep removes by design. The last command lists every persistent fixture network left on the host after the checks, each `true isolated`.

## Due diligence record

What the plan's due-diligence pass concluded about each external fact the plan cites or defers, on 2026-11-02, read by the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- SETTLED: `--internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated` (verified against the Docker Engine 28 release notes, 28.0.0, and the port-publishing docs: `isolated` only with `internal`, no address on the bridge; the local 29.9.2 daemon refuses `isolated` alone with "gateway mode 'isolated' can only be used for an internal network")
- SETTLED: Docker Engine 28.0 as the minimum for `isolated` (verified against the Docker Engine 28.0.0 release notes)
- SETTLED: the inspect fields `Internal`, `EnableIPv6`, `Options["com.docker.network.bridge.gateway_mode_ipv4"]`, `Labels`, `Containers` (verified on a throwaway closed network inspected on Docker 29.9.2)
- SETTLED: `ubuntu-latest` is `ubuntu-24.04` with Docker Server 28.0.4, image `20261026.354.1` (verified against actions/runner-images README and Ubuntu2404-Readme.md)
- SETTLED: `SSL_CERT_FILE` for CVE-2026-104120, httpx 0.28.1 in both fetch images building its context from it under `trust_env` (verified on the built images' `httpx/_config.py` and with a throwaway TLS server)
- SETTLED: `NODE_EXTRA_CA_CERTS` for CVE-2026-58485 (Node 24.22.1, undici `Agent`) and CVE-2026-33060 (Node 20.20.2, axios) (verified with a throwaway TLS server in the built patched images)
- SETTLED: `apify-client` 2.25.0 defaults `maxRetries = 8`, `minDelayBetweenRetriesMillis = 500`, `baseUrl = 'https://api.apify.com'` (verified in the apify image's `apify_client.js`)
- SETTLED: `169-254-169-254.sslip.io` resolves to `169.254.169.254` by the dashed-label rule (verified against nip.io, to which sslip.io now redirects and which calls the two domains interchangeable)
- SETTLED: Python's `ipaddress` calls `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `198.18.0.0/15` private and not global (verified on Python 3.12.3)
- SETTLED: `nc -z -w 5` from `SENTINEL_IMAGE` (verified against the sentinel image's BusyBox 1.38.0 `nc` help)
- SETTLED: `--ignore-robots-txt` in both CVE-2026-104120 entrypoints, so `fetch` requests no `/robots.txt` (verified in the Dockerfiles and the patched server's source; corrected in the plan)
- OPEN (deferred): the `example.com` capture (address, routes, and whether `http://example.com/` answers 200 or redirects to HTTPS), produced by the captures step only (implementation step 9)
- OPEN (deferred): the `demo.ckan.org` capture and its address, the `status_show` route (`/api/3/action/status_show` by the server's default `getPortalApiPath`) to be confirmed at capture
- SETTLED: `apify-client` 2.25.0 sends the token as `Authorization: Bearer ${token}` on every request (verified in the apify image's `apify-client/dist/http_client.js`), so the capture's `--header 'Authorization: Bearer calib-token'` is the header the server sends with the `APIFY_TOKEN` of `apify_network_args`
- OPEN (deferred): the `api.apify.com` start routes and what the real API answers the dummy token on them (200 or 401), produced by the captures step only (implementation step 9), and whether the apify server starts and answers its benign call on those answers, read on the vet of implementation step 10
- SETTLED: a root with a critical `nameConstraints` extension (permitted DNS subtrees, plus excluded `.<host>`) is accepted for a permitted name and refused for any other through each trust setting the plan relies on (measured on 2026-11-02 in throwaway containers run with `--network none`, on the pinned base digests of the target images: `python:3.12-slim` with `httpx` 0.28.1 installed, Python 3.12.16 and OpenSSL 3.5.7, under `SSL_CERT_FILE`, `node:20-alpine` with Node 20.20.2 and OpenSSL 3.0.19 and `node:24-bookworm-slim` with Node 24.22.1 and OpenSSL 3.5.9, under `NODE_EXTRA_CA_CERTS`, both through `https.get` and through `fetch` (undici): `example.com` answered 200, a leaf for an unlisted name signed by the same key failed with `permitted subtree violation`, `www.example.com` failed with `excluded subtree violation`, and the same leaves without the trust setting failed as untrusted. `openssl verify` 3.0.13 on the host gave the same results. The target images themselves were not run, so the axios client of CVE-2026-33060 is covered through Node's `https`, on which it sits)
- SETTLED: a permitted DNS subtree alone admits the host's subdomains (`openssl verify` accepted a `www.example.com` leaf under a root permitting `example.com` only), and an excluded `.<host>` subtree refuses them while keeping `<host>` (OpenSSL's leading-dot reading, the one verifier of every runtime above)
- OPEN (deferred): the digest of the Python base of `Dockerfile.stand-in`, read on the pulled image at implementation
- OPEN (unverified): Chromium 156 (CVE-2026-5323) falling back to HTTP at once when an HTTPS upgrade of `http://example.com/` fails on the certificate, left to the recalibration as the plan states
- OPEN (unverified): the common Node SSRF guards calling RFC 5737 and `198.18.0.0/15` reserved, a justification only, immaterial since the pinned address is a real public one

## Implementation steps

The eight steps of `## Steps` are cut into fourteen, for the context budget of one implementer session: the plan's step 1 becomes steps 1 to 3, its step 3 becomes steps 6 to 8, and its step 5 becomes steps 10 and 11, with the nuisance fingerprint over served content moved ahead into step 5 because it reads no capture (only apify's own `served` entries do, and they land in step 10). The plan's maintainer steps keep their content: captures (step 9), the suites' Docker checks (step 12), the reset (step 13) and the recording (step 14). A maintainer step is done by hand, not dispatched to an implementer. Every step is one commit, and leaves CI's calibration green: the per-launch network closes only in step 11, with the stand-in of CVE-2025-65513.

Commands used throughout. Red phase: `uv run pytest <test files> -n 0`. Short loop: `uv run pytest tests/unit -n auto --maxprocesses 6` (with `--lf` on failure, then the full loop again). In the loop, `uv run pyright <changed files>`. A Docker integration file under change: `CVE_PLANTING_REQUIRED=1 uv run pytest <file> -n 0`. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` with no file argument, all green.

### Step 1: The closed-network module and its isolation proof

**Files**
- `tests/fakes/network_docker.py` (new, `FakeNetworkDocker`)
- `tests/unit/test_closed_network.py`, `tests/unit/support/test_closed_network_given.py`, `tests/unit/support/test_closed_network_then.py` (new, given/then only where they abstract something)
- Two recorded `docker network inspect -f '{{json .}}'` outputs, one closed and one open, as constants in the given (recorded on the local daemon from throwaway networks)
- `tests/integration/test_closed_networks.py`, `tests/integration/support/test_closed_networks_given.py`, `tests/integration/support/test_closed_networks_then.py` (new)
- `evals/closed_network.py` (new, clean: imports only `cve_planting_base.LABEL`, nothing from `mcp_auditor`)
- `evals/calibration_dossier.py` (`CLEAN_MODULES` gains `closed_network`)
- `CLAUDE.md`, `CONTRIBUTING.md`

**Do**
0. Before anything, read the Docker Server version of the current `ubuntu-latest` runner image (actions/runner-images, `Ubuntu2404-Readme.md`). At 28.0 or later, nothing to do. Below 28.0, stop and report: `ci.yml` and `cve-calibration.yml` then need a pinned Docker Engine install step in this commit, a decision the plan defers to that reading.
1. Tests first. `FakeNetworkDocker` implements the `NetworkDocker` protocol over an in-memory map of networks (label, internal, gateway mode, IPv6, attached containers), configurable to reject the `isolated` option with a daemon message, to accept it and leave the network open, or to enable IPv6. Write scenario 1 of `## Test scenarios` (nine cases) and run it red.
2. `evals/closed_network.py` as the plan's Files section specifies: `CLOSED_OPTIONS`, `ClosedNetworkUnsupported`, `ForeignNetwork` (sibling, `RuntimeError`), `NetworkFacts`, `NetworkDocker`, `is_closed` (internal, gateway mode `isolated`, IPv6 off), `create_closed_network` (create, inspect, raise naming Docker Engine 28.0 and quoting the daemon's message after removing what it created), `ensure_closed_network` (absent creates, closed keeps, labelled-open removes its containers with a logged name each, removes and recreates, unlabelled raises `ForeignNetwork`; a per-name `threading.Lock` in a module dict; a create failing on "already exists" inspects again), `check_closed_network_support` (random labelled name, create, verify, remove in a `finally`), the pure parse of the inspect JSON into `NetworkFacts`, and `DOCKER_NETWORKS`, the subprocess-backed port. Keep functions under 20 lines, the module under 300.
3. `CLEAN_MODULES` gains `closed_network`, so the calibration and nuisance dossiers carry it before step 2 makes `doris_backend.py` import it.
4. Integration test, scenario 13 without its planted case: a host listener on `0.0.0.0` (a thread with a TCP socket), the sentinel image (built by the module fixture as `test_cve_planting.py` builds it), and from a container on a `create_closed_network` network: `nc -z -w 5` to every IPv4 address of the host's interfaces at the listener's port fails, to `1.1.1.1:443` and `169.254.169.254:80` fails, `ip route` has no default route, an `--add-host` name resolves, an unpinned name fails within 15 s. The control: on a plain labelled network the same container reaches the listener through its gateway. The recreation: an open labelled network with a running container attached ends closed under `ensure_closed_network`, the container gone. Every network and container the test makes is labelled and removed. Skip without Docker, fail under `CVE_PLANTING_REQUIRED=1`, as the existing Docker tests do (reuse their skip helper).
5. Docs: `CLAUDE.md` Landmines, a closed network needs both `--internal` and `-o com.docker.network.bridge.gateway_mode_ipv4=isolated` (plain `--internal` keeps a host address on the bridge, which a container reaches), `CLAUDE.md` Commands, the integration entry counts the closed-network test among the Docker tests. `CONTRIBUTING.md` line 14, `tests/integration/test_closed_networks.py` in the list of Docker integration tests.

**Test**
- The nine unit cases of scenario 1.
- The three integration cases of scenario 13 above (closed reachability, open control, recreation).

**Verify**
- `uv run pytest tests/unit/test_closed_network.py -n 0` green.
- `CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration/test_closed_networks.py -n 0` green on the local daemon.
- `uv run pytest tests/unit/test_holdout_kit_isolation.py tests/unit/test_nuisance_dossier.py -n 0` green.
- Closing checks green.

### Step 2: Persistent networks closed, no default bridge, admission refusal

**Files**
- `tests/unit/test_nuisance_admission.py` (and its given if a fixture server with `has_network` and no backend needs one)
- `tests/unit/test_nuisance_audit.py`
- `evals/responder_backend.py`, `evals/doris_backend.py`, `evals/mysql_backend.py`, `evals/neo4j_backend.py`
- `evals/nuisance_fix_checks/cve_2026_35402_neo4j_cypher.py`, `evals/nuisance_fix_checks/cve_2026_11720_googleapis.py`
- `evals/nuisance_audit.py`, `evals/nuisance_admission.py`, `evals/nuisance_dossier.py`
- `CHANGELOG.md`

**Do**
1. Tests first: `test_nuisance_admission.py`, a server with `has_network` true and no backend is refused with `"<package>: has_network without a backend: a server with no backend runs with no network"`. `test_nuisance_audit.py`, delete the default-bridge test, add that a backend-less server launches with `--network none` (the arguments `no_network_args()` gives). Run red.
2. `nuisance_admission.admission_problems` gains `_network_problems(server)`. Confirm on the real admission that no server trips it (all 13 networked servers have a backend).
3. `nuisance_audit.py`: delete `_network_args`, `_single_container_launch` passes `no_network_args()`, docstring loses the default bridge.
4. The six persistent sites call `ensure_closed_network(name, *subnet_options)` and lose their `docker network ls` lookups: `Responder._ensure_network` (`"--subnet", self.subnet`), `doris_backend._doris_network` (both networks, the link-local one with its subnet), `mysql_backend._ensure_network`, `neo4j_backend._ensure_network`, `cve_2026_35402_neo4j_cypher._ensure_bridge`, `cve_2026_11720_googleapis._ensure_internal_bridge`. The callers' existing start-when-not-running logic restarts what a recreation removed; read each caller to confirm it checks the container's state after the network ensure, not before (reorder if needed).
5. Stale docstrings of these modules (open network, egress, DNS aliasing) say the network is closed. `nuisance_dossier.py`: the `has_network` paragraph (true only for a server with a backend, whose provisioner's closed network joins it to the backend and to nothing else, and the admission refuses `has_network` without a backend), and `_DORIS_BUILDER_PARAGRAPH` if it names egress.
6. `CHANGELOG.md` `[Unreleased]`: the nuisance backends' and fix checks' networks are closed (no route to the host or the Internet), an open one of the same name left by an older run is recreated, and the admission refuses `has_network` without a backend.

**Test**
- The admission refusal, the backend-less launch with `--network none`.

**Verify**
- `uv run pytest tests/unit/test_nuisance_admission.py tests/unit/test_nuisance_audit.py tests/unit/test_nuisance_dossier.py -n 0` green.
- Closing checks green. The apify server stops answering from here until step 10 (its start needs `api.apify.com`), accepted by the plan.

### Step 3: The closed-network preflight in every command

**Files**
- `tests/unit/test_cve_preflight.py`
- `tests/unit/test_nuisance_run.py` (or a new `tests/unit/test_nuisance_run_networks.py` on `test_nuisance_run_given`, the existing file being at 455 lines and its given at 324: put any new given in a new support file, not in the over-limit ones), `tests/unit/test_nuisance_vet.py`, `tests/unit/test_nuisance_gate_session.py` (or a sibling file, it is at 332), `tests/unit/test_holdout_run.py` (or a sibling, it is at 412), and the givens that build the deps (`support/test_nuisance_run_given.py`, `support/test_nuisance_gate_session_given.py`, `support/test_holdout_run_given.py`, the vet given) gain a passing `check_networks`
- `tests/unit/test_run_holdout.py`, `tests/unit/test_nuisance_fix_checks.py` (monkeypatch the module attribute where a test drives `main` past its nothing-drawn exit)
- `evals/run_images.py`, `evals/cve_preflight.py`, `evals/calibration_dossier.py` and `evals/nuisance_dossier.py` (the kit instructions' Docker version)
- `evals/nuisance_run.py`, `evals/nuisance_vet_command.py`, `evals/nuisance_calibrate_command.py`, `evals/nuisance_gate_session.py`, `evals/nuisance_gate_session_model.py`, `evals/holdout_run.py`, `evals/run_holdout.py`
- `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

**Do**
1. Tests first (scenario 12): with injected deps on `run_nuisance`, `vet_servers`, the gate session and `run_holdout`, a `check_networks` that raises `ClosedNetworkUnsupported` refuses before any rebuild (the fake rebuild never called, asserted on the outcome the givens already expose), with "Docker Engine 28.0 or later is required" among the reasons. `cve_preflight.preflight_ok(check=failing)` returns `False` and no image is ensured; the two existing preflight tests pass a succeeding check (their `docker` shim answers `info` only). Run red.
2. `run_images.refuse_without_closed_networks(check=check_closed_network_support)` turns `ClosedNetworkUnsupported` into `Refused("the Docker daemon cannot create a closed network", [message, "Docker Engine 28.0 or later is required"])`.
3. Deps: `NuisanceDeps`, `VetDeps`, `HoldoutDeps` and `NuisanceGateHarness` gain `check_networks: Callable[[], None]`, their default builders passing `check_closed_network_support`. Each command calls `refuse_without_closed_networks(deps.check_networks)` before any build or launch, after its nothing-admitted or nothing-drawn early exit (so those exits need no Docker). `holdout_run.py` is at 306 lines: the field, its default and the call are all it gains.
4. Commands with no deps: `nuisance_calibrate_command.calibrate` (before `kit_launch.build_images`, after its early exits) and `run_holdout._calibrate` (after "no holdout target is drawn") call it with the module attribute `check_closed_network_support` as imported there, read at call time, so a test monkeypatches it. `Refused` reaches `main`, which maps it to exit 3 (`run_holdout._calibrate` catches `ValueError` only, and `Refused` is not one: confirm).
5. `cve_preflight.preflight_ok(store=None, check=check_closed_network_support)`: right after `_docker_ready()`, a `ClosedNetworkUnsupported` prints the daemon's message and the Docker Engine 28.0 requirement and returns `False` (exit 4 in every mode).
6. Docs: `README.md`, Docker Engine 28.0 or later as a prerequisite of the eval suites (the CVE benchmark's prerequisites paragraph, line 164, and the nuisance and holdout ones). `CLAUDE.md` Commands, the entries of `run_holdout calibrate`, `run_holdout run`, `run_nuisance calibrate`, `run_nuisance run`, `vet` and `gate` gain the refusal on a daemon that cannot create a closed network (exit 3), `run_cve_benchmark`'s the preflight failure (exit 4). `CONTRIBUTING.md`, the Docker version beside the Docker prerequisite (line 14), the same refusal and exit in the paragraphs on those commands. The kit instructions that `calibration_dossier.py` and `nuisance_dossier.py` write ("It needs Docker but no LLM") name Docker Engine 28.0 or later, since the copied `closed_network` refuses an older daemon. `CHANGELOG.md` `[Unreleased]`.

**Test**
- The refusal before any rebuild for run, vet, gate and holdout run, and the reasons.
- `run_holdout.main(["calibrate"])` and `run_nuisance.main(["calibrate"])` exit 3 before any build when the monkeypatched module attribute `check_closed_network_support` raises `ClosedNetworkUnsupported`, written red first like the others.
- `preflight_ok` returning `False` on a failing check before any image.
- The existing tests of these commands still pass with the passing check.

**Verify**
- `uv run pytest tests/unit/test_cve_preflight.py tests/unit/test_nuisance_run.py tests/unit/test_nuisance_vet.py tests/unit/test_nuisance_gate_session.py tests/unit/test_holdout_run.py tests/unit/test_run_holdout.py tests/unit/test_nuisance_fix_checks.py tests/unit/test_run_cve_benchmark.py -n 0` green.
- `grep -rn "check_closed_network_support" tests/unit` shows no test reaching the real check (each one monkeypatched or injected).
- Closing checks green.

### Step 4: A final sweep on every calibrate path and the gate

**Files**
- `tests/unit/test_run_holdout.py`, `tests/unit/test_run_cve_benchmark.py`, `tests/unit/support/test_run_cve_benchmark_given.py`, `tests/unit/test_nuisance_fix_checks.py`, the gate session test (or a sibling) and its given
- `evals/run_images.py`, `evals/run_holdout.py`, `evals/run_cve_benchmark.py` (and a sibling module for its calibrate and survey branches if it passes 300 lines), `evals/nuisance_calibrate_command.py`, `evals/nuisance_gate_session.py`, `evals/nuisance_gate_session_model.py`
- `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

**Do**
1. Tests first (scenario 11), with a fake `ContainerSweep` (a `RunningContainers`-style fake recording removals, as in `test_holdout_run_given`) monkeypatched as the module's `DOCKER_SWEEP` where the test drives `main`, injected through the harness for the gate: a leftover of the run's images is removed after `run_holdout calibrate`, after `run_nuisance calibrate` (a built backend leftover included), after `run_cve_benchmark --calibrate`, `--survey` and a graded run, after the gate (a built backend leftover included), and also when the work raised. Every existing test driving these `main`s monkeypatches `DOCKER_SWEEP` (put it in the shared givens or an autouse fixture of those files), so no unit test reaches `docker ps` or `docker rm -f`. Run red.
2. `run_images.ContainerSweep` (fields `running_containers`, `remove_containers`, matching `ContainerHost`) and `DOCKER_SWEEP`.
3. `run_holdout._calibrate_targets` and `run_cve_benchmark._run` take `sweep: ContainerSweep`, passed by `_calibrate` and `main` as the module attribute `DOCKER_SWEEP` read at call time, and wrap their work in `try/finally: sweep_containers(tags, sweep.running_containers, sweep.remove_containers)`, `tags` being `image_tag` over `target_services(targets)`. `run_cve_benchmark.py` is at 297 lines: if it passes 300, move the calibrate and survey branches of `_run` to a sibling module.
4. `nuisance_calibrate_command.calibrate` sweeps, in a `finally` around the build and the calibration, the kit image tags of `_services(targets)` and `built_backend_tags(admission.servers)`, through its module's `DOCKER_SWEEP`.
5. Gate: `NuisanceGateHarness` gains the sweep (a `ContainerSweep` field, `DOCKER_SWEEP` in `default_harness`), and `run_gate` sweeps the server tags and the built backend tags at its end in a `finally`, as `run` does.
6. Docs: `CLAUDE.md` Commands and `CONTRIBUTING.md`, on `run_holdout calibrate`, `run_nuisance calibrate`, `run_nuisance gate` and every `run_cve_benchmark` mode: at its end, even when it raises, the command removes with `docker rm -f` the containers of its images still running. `CHANGELOG.md` `[Unreleased]`.

**Test**
- The sweep after each of the six paths, on success and on a raised error, with the built backend leftovers for nuisance calibrate and the gate.

**Verify**
- `uv run pytest tests/unit/test_run_holdout.py tests/unit/test_run_cve_benchmark.py tests/unit/test_nuisance_fix_checks.py tests/unit/test_nuisance_gate_session.py -n 0` green.
- Closing checks green.

### Step 5: The nuisance fingerprint covers what each backend serves

**Files**
- `tests/unit/test_nuisance_fingerprint.py` (new, the fingerprint cases of `test_nuisance_images.py` moved into it), `tests/unit/test_nuisance_images.py`
- `tests/unit/test_nuisance_backends_built.py`, `tests/unit/test_nuisance_compose.py`, `tests/unit/support/test_nuisance_admission_given.py`, `tests/unit/test_nuisance_run.py`, `tests/unit/support/test_nuisance_gate_session_given.py` (import paths and the renamed field)
- `evals/nuisance_fingerprint.py` (new), `evals/nuisance_images.py`, `evals/nuisance_backends.py`
- `evals/nuisance_run.py`, `evals/nuisance_gate_session.py`, `evals/nuisance_gate_session_recording.py` (imports only)

**Do**
1. Tests first (scenario 7): moved cases pass on the new import; the fingerprint moves when a served file of the server's backend changes (a tmp registry passed as `backends`, a tmp Dockerfile, module and plain file), and is unchanged for a server with no backend (its part is `None`); real data, every `served` path of `BACKENDS` exists. `test_nuisance_backends_built.py`: a built backend's `image` is the tag of one of its `built_services`, a pulled one has none. `test_nuisance_compose.py`'s `test_each_built_backend_is_a_nuisance_profiled_compose_service` iterates every entry of `built_services`. Run red.
2. `RegisteredBackend.built_service` becomes `built_services: tuple[str, ...]`, `built_backend_services` flattens. `RegisteredBackend` gains `served: tuple[Path, ...]`: its backend module, `responder_backend.py` for the responders, `closed_network.py` for all, the Dockerfiles of the images it builds (apify's capture paths come in step 10).
3. `nuisance_fixture_fingerprint(server, docker_directory=DOCKER_DIRECTORY, backends=BACKENDS)` moves into `evals/nuisance_fingerprint.py` (the import cycle `nuisance_images` → `nuisance_backends` → `nuisance_provisioners` → `nuisance_images` forbids keeping it), adds `backend_content(backends[key].served)` (Dockerfile by `dockerfile_instructions`, Python module by `fingerprint_sources`, other file by SHA-256), docstring's In list updated. Callers import it from there.

**Test**
- Moved fingerprint cases, served-content movement, no-backend stability, real-data `served` existence, `built_services` pin, compose coverage.

**Verify**
- `uv run pytest tests/unit/test_nuisance_fingerprint.py tests/unit/test_nuisance_images.py tests/unit/test_nuisance_backends_built.py tests/unit/test_nuisance_compose.py tests/unit/test_nuisance_run.py tests/unit/test_nuisance_gate_session.py -n 0` green.
- Closing checks green.

### Step 6: Stand-in captures, their registry and the stand-in image

**Files**
- `tests/unit/test_capture_stand_in.py`, `tests/unit/test_public_stand_ins.py` (new)
- `evals/capture_stand_in.py`, `evals/public_stand_ins.py` (new, clean), `evals/stand_ins/tls/generate.sh` (new)
- `evals/cve_planting_base.py` (`STAND_IN_SERVICE`, `STAND_IN_IMAGE`, `StandIn`)
- `evals/docker/Dockerfile.stand-in` (new), `evals/docker/compose.yml` (service `stand-in`, outside the `nuisance` profile)
- `evals/calibration_dossier.py` (`CLEAN_MODULES` gains `public_stand_ins`)
- `pyproject.toml`, `uv.lock` (`cryptography` in the `dev` group)
- `CLAUDE.md`

**Do**
1. Tests first. Scenario 5 on `capture_record(provenance: CaptureProvenance, responses)`: status, headers and body verbatim, a 401 recorded like a 200, each `--header` recorded with its name and value in `request_headers`, a non-UTF-8 body refused. Scenario 4 on `stand_in(host, directory)` with tmp files (capture, and dummy leaf, key and authority text under `tls/`): loads into a `StandIn`; a `host` other than the file name, a private, loopback or `198.18.0.0/15` address, a non-`http(s)` scheme, an empty `command` or `captured_at` are refused; real data, every committed capture under `evals/stand_ins/` loads and has a leaf, and the committed authority's critical `nameConstraints` permit exactly the HTTPS stand-in hosts (the committed captures with an `https` route) and exclude `.<host>` for each, every committed leaf naming one of them (both vacuous until step 9: no capture and no authority give two empty sets, keep the tests). `stand_in_files` gives paths without reading. Add `cryptography` to the `dev` group (`uv add --dev cryptography`, the locked 50.0.2) since the constraints test imports it. Run red.
2. `capture_stand_in.py` per the plan: argparse (`--out`, URLs sharing one host, `--header 'NAME: VALUE'`, repeatable, sent and recorded verbatim, no environment read), resolve the host's first IPv4, `httpx` GET with no redirect following and `Accept-Encoding: identity`, every status recorded, `CaptureProvenance` (host, address, captured_at from the clock, command from argv, request headers), the pure `capture_record`, a thin I/O shell. One capture is written whole.
3. `public_stand_ins.py`: pydantic `StandInCapture` and its route model, `STAND_INS_DIRECTORY`, `stand_in`, `stand_in_files`. No file read at import.
4. `generate.sh [--out DIR] HOST...` per the plan: a temporary openssl config with the authority section (`basicConstraints = critical,CA:TRUE`, `keyUsage = critical,keyCertSign,cRLSign`, `subjectKeyIdentifier = hash`, `nameConstraints = critical,@constraints`) and a `[constraints]` section of `permitted;DNS.<i> = <host>` and `excluded;DNS.<i> = .<host>` per host given, the authority signed with `openssl req -x509 -config ... -extensions ...`, then per host a leaf (`CA:FALSE`, `subjectAltName=DNS:<host>`, `serverAuth`, `authorityKeyIdentifier=keyid`), long validity. Every run makes a new authority and every leaf, and removes the TLS files of a host not given. Check by hand in `tmp_path` that `openssl verify -CAfile` accepts a listed host's leaf and refuses, with `permitted subtree violation`, a leaf for an unlisted name signed with the generated key, and with `excluded subtree violation` one for `www.<host>`. Do not run it into the repository here: step 9 does.
5. `Dockerfile.stand-in`: a pinned Python base (read the digest with `docker buildx imagetools inspect python:<tag> --format '{{json .Manifest}}'`, the index digest), the replay server inline in `ENTRYPOINT` (no `COPY`): reads `/stand-in/capture.json`, HTTP on `BIND_ADDR:80`, HTTPS on `BIND_ADDR:443` with `/stand-in/cert.pem` and `/stand-in/key.pem`, `BIND_ADDR` defaulting to every address, replays status, body, `Content-Type` and `Location` for a captured `(scheme, method, target)`, else `404` empty with `miss <scheme> <method> <target>` on stderr. Compose service `stand-in`, image `mcp-auditor-cve-stand-in:local`, fingerprint label computed by `cve_images.dockerfile_fingerprint`, no profile. Build it once and check by hand that it serves a tmp capture over both ports.
6. `CLAUDE.md` Commands: `uv run python -m evals.capture_stand_in ...` and `evals/stand_ins/tls/generate.sh HOST...`, each with what it needs (network access, `openssl`) and that its output is committed by hand. The `generate.sh` entry says it is given every HTTPS stand-in host at once, since the authority's name constraints list them, so adding one regenerates the authority and every leaf. The `capture_stand_in` entry says a `--header` is recorded verbatim, so it carries only the dummy credential the fixture's server sends, never a real one.

**Test**
- Scenario 5 (four cases), scenario 4 (load, five refusals, real data, the authority's name constraints), `stand_in_files`.
- Existing `test_cve_compose_labels.py` on the new Dockerfile: label, no `COPY`, pinned base.

**Verify**
- `uv run pytest tests/unit/test_capture_stand_in.py tests/unit/test_public_stand_ins.py tests/unit/test_cve_compose_labels.py tests/unit/test_holdout_kit_isolation.py -n 0` green.
- `docker compose -f evals/docker/compose.yml build stand-in` succeeds.
- Closing checks green.

### Step 7: Planting support for public names and stand-ins

**Files**
- `tests/fakes/planting_docker.py` (stand-ins, listener probes, a configurable dead stand-in)
- `tests/unit/test_cve_planting_stand_ins.py`, `tests/unit/support/test_cve_planting_stand_ins_given.py`, `tests/unit/support/test_cve_planting_stand_ins_then.py` (new)
- `tests/unit/test_cve_planting_endpoints.py` (scenario 3, or a new file if it would pass 300 lines)
- `evals/cve_planting_base.py` (`PublicNames`, `PlantingHost.public_names`, `PlantingSpec.stand_ins`, `PlantingDocker` methods, `PlantedArgs.env` and `.mounts` if absent)
- `evals/cve_endpoint_address.py` (`pin_public_names`), `evals/cve_planting_spec.py` (`_SpecDraft.finish` calls it, `needs_holder`)
- `evals/cve_planting_stand_ins.py` (new, clean), `evals/cve_planting.py`, `evals/cve_planting_docker.py`
- `evals/calibration_dossier.py` (`CLEAN_MODULES` gains `cve_planting_stand_ins`)

**Do**
1. Tests first: scenario 3 (IP-label pinning of IPv4-literal endpoints only, two stand-ins for one host refused, trust without a stand-in refused) and scenario 2 (seven cases, the given writing captures and dummy TLS files into `tmp_path` passed to `planted` as `stand_ins_directory`). Run red.
2. `cve_planting_base.py` per the plan's section: `PublicNames`, `PlantingHost.public_names = PublicNames()`, `PlantingSpec.stand_ins: tuple[StandIn, ...] = ()`, `PlantingDocker.start_stand_in(run_args) -> str`, `remove_stand_in(name)`, `probe_listener(target_args, host, port) -> bool`.
3. `cve_endpoint_address.pin_public_names(host, sentinels, draft)` and its call in `_SpecDraft.finish`; `needs_holder` also true when a stand-in is declared. Refusals are `ValueError`s naming host and property. `cve_planting_spec.py` is at 291 lines: the call only.
4. `cve_planting_stand_ins.py`: `with_stand_ins(spec, directory)` (load each declared host, append its address to `address_setups` and `(host, address)` to `host_entries`, refuse an address already set up, naming the stand-in host), `serve_stand_ins(spec, holder, docker, stack)`, `trust_args(spec, docker, stack)`, the stand-in probe raising `PlantingFailed("stand-in for <host> is not serving")`.
5. `cve_planting.planted(..., stand_ins_directory: Path = STAND_INS_DIRECTORY)`: `with_stand_ins` before the setup's `try`, `serve_stand_ins` after the sentinels, trust env and mounts into `PlantedArgs`, the stand-in probe after the sentinels' probe; the probe-container local `stand_in` renamed `probe_args`, and the comments and names of `cve_planting.py` and `cve_planting_docker.py` that call the probe container a stand-in (the module docstring, `_probe_endpoints`'s comment, `_stand_in_read`, `_STAND_IN_RUN_TIMEOUT`) say probe instead. A host with no public names reads no file.
6. `DockerPlanting.start_stand_in`, `remove_stand_in` (reads `docker logs` stderr before `docker rm -f`, logs each `miss` line as a warning naming the host), `probe_listener` (busybox `nc -z -w 5` from `SENTINEL_IMAGE` with the target's arguments, retried within the sentinel probe's budget).
7. `cve_planting.py` must stay under 300 lines (255 now): the stand-in logic lives in the new module.

**Test**
- Scenario 2 (seven), scenario 3 (three).
- Every existing planting unit test unchanged and green.

**Verify**
- `uv run pytest tests/unit/test_cve_planting_stand_ins.py tests/unit/test_cve_planting_endpoints.py tests/unit/test_cve_planting.py tests/unit/test_cve_planting_layout.py tests/unit/test_holdout_kit_isolation.py -n 0` green.
- Closing checks green.

### Step 8: Stand-ins in the fixture fingerprint and a planted stand-in on Docker

**Files**
- `tests/unit/test_cve_baseline.py`
- `tests/integration/test_cve_planting.py`, `tests/integration/support/test_cve_planting_given.py` (a `RecordingPlanting` that records `start_stand_in`; the given writes a capture and makes a throwaway authority and leaf by running `evals/stand_ins/tls/generate.sh --out <tmp_path>/tls <host>`), `tests/integration/support/test_cve_planting_then.py` if a check abstracts something
- `evals/cve_baseline.py`
- `.github/workflows/cve-calibration.yml`
- `CLAUDE.md`

**Do**
1. Tests first. Scenario 6: on tmp captures passed as `stand_ins_directory`, the fixture fingerprint moves when a stand-in's capture, leaf, address or trust setting changes, and does not move for a target without public names; real data, every acceptance and holdout target that declares a stand-in lists `STAND_IN_SERVICE` in its `images` (vacuous until step 11, keep it). Scenario 14 (integration): a planted stand-in declared by name, read from the target's arguments, serves the capture's body over HTTP and over HTTPS when the client (the stand-in image's Python, verifying TLS) trusts the name-constrained authority `generate.sh` made, an uncaptured route answers `404`, teardown logs the miss, and the teardown count covers the stand-in. Skip like Docker when `openssl` is absent. The module fixture builds the stand-in image beside the sentinel. Run red.
2. `cve_baseline.py`: `_ENVIRONMENT_PATHS` gains `public_stand_ins.py` and `cve_planting_stand_ins.py`. `planting_host_parts(host, stand_ins_directory=STAND_INS_DIRECTORY)` appends, only when `host.public_names` declares something, each stand-in host, its address and the SHA-256 of its capture, leaf, key and authority, then the trust names and IP-label domains. `fixture_fingerprint` gains `stand_ins_directory` and passes it on. A host with no public names gives today's parts, so no current fingerprint moves through this function.
3. `cve-calibration.yml`, both `paths` filters gain `evals/closed_network.py`, `evals/public_stand_ins.py` and `evals/stand_ins/**`.
4. `CLAUDE.md` Landmines: stand-in content is mounted from captures, never copied into an image, and a holder-joined launch's public names go on the holder (Docker refuses `--add-host` there).

**Test**
- Scenario 6 (four movements, one stability, real-data images), scenario 14, scenario 15 (the existing planting integration cases unchanged).

**Verify**
- `uv run pytest tests/unit/test_cve_baseline.py -n 0` green.
- `CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration/test_cve_planting.py -n 0` green.
- Closing checks green.

### Step 9 (maintainer, by hand): captures

Network access, no LLM. As the plan's step 4: `evals/stand_ins/tls/generate.sh example.com demo.ckan.org api.apify.com` (every HTTPS stand-in host at once, the authority's name constraints listing them), then `capture_stand_in` for `example.com` (`/`, `/robots.txt`, over HTTPS and HTTP), `demo.ckan.org` (the `status_show` route both ckan images request, read from the image, by default `/api/3/action/status_show`), `api.apify.com` (the start routes of 0.9.20 and 0.9.21 with no `actors` input, listed from the image's `tools_loader.js` and `apify-client` calls, always with `--header 'Authorization: Bearer calib-token'`, the token the server sends, and no token of the maintainer's). Whatever the API answers is recorded verbatim, a 401 included, and never retaken with another token. Read each capture: nothing naming the audit, a fixture or a flaw. `openssl x509 -in evals/stand_ins/tls/fixture-authority.pem -noout -ext nameConstraints` shows the three permitted hosts and their three excluded `.<host>` subtrees. `uv run pytest tests/unit/test_public_stand_ins.py -n 0` green on the committed captures and authority. If `http://example.com/` answers a redirect rather than a page, stop and report before committing: CVE-2025-65513 and CVE-2026-5323 declare no trust setting, so their benign calls would fail on the HTTPS stand-in. One commit with the captures and the TLS files.

### Step 10: The apify API stand-in

**Files**
- `tests/unit/test_apify_backend.py`, `tests/unit/test_nuisance_backends_built.py`, `tests/unit/test_nuisance_run_backends.py`, `tests/unit/test_nuisance_compose.py`
- `evals/responder_backend.py` (`Responder.run_args: tuple[str, ...] = ()`, appended to the singleton's `docker run`)
- `evals/apify_backend.py`, `evals/nuisance_backends.py` (apify entry)

**Do**
1. Tests first (scenario 9): the server's arguments pin `api.apify.com` to `198.18.1.3` beside the two documentation names; apify's built services are the responder and `stand-in`, and the run removes and rebuilds both (on the givens `test_nuisance_run_backends.py` already uses); every built service is a compose service, nuisance-profiled except `STAND_IN_SERVICE`, which sits outside the profile so CI's bare build builds it. Run red.
2. `apify_backend.py`: `API_HOST = "api.apify.com"`, `_API_STAND_IN = Responder(image=STAND_IN_IMAGE, container="mcp-auditor-cve-apify-api-stand-in", bridge=APIFY_BRIDGE, subnet=APIFY_SUBNET, ip="198.18.1.3", dockerfile=<Dockerfile.stand-in>, run_args=<read-only mounts of stand_in_files(API_HOST) at /stand-in/capture.json, cert.pem, key.pem>)`; `ensure_apify_responder` ensures both; `apify_network_args` adds `--add-host api.apify.com:198.18.1.3`. No new trust setting (`NODE_TLS_REJECT_UNAUTHORIZED=0` already set). Importing the module reads no file.
3. `nuisance_backends.py`: apify `built_services=("apify-responder", STAND_IN_SERVICE)`, `served` gains `Dockerfile.stand-in` (a Dockerfile of an image it now builds, as step 5 sets) and the API capture and its leaf from `stand_in_files`. Docstring of `apify_backend.py` names the stand-in.

**Test**
- The pin, the two built services, the rebuild and removal of both, real-data `served` existence (step 5's test) now covering the capture.

**Verify**
- `uv run pytest tests/unit/test_apify_backend.py tests/unit/test_nuisance_backends_built.py tests/unit/test_nuisance_compose.py tests/unit/test_nuisance_fingerprint.py -n 0` green.
- By hand, `uv run python -m evals.run_nuisance vet --server <apify package>` answers (Docker), its stand-in logging no miss. A miss is a recapture (step 9 again, its own commit, still with `Authorization: Bearer calib-token`), never a hand-written route. If the server does not start or its benign call errors on what the real API answered the dummy token (a 401 included), the step stops and reports: that is the server's real behaviour with a dummy token, the maintainer records it and decides under the nuisance rule's liveness clause, and neither the capture nor the token changes.
- Closing checks green.

### Step 11: Closed per-launch networks and the five targets' stand-ins

**Files**
- `tests/unit/test_cve_calibration.py` (the four egress cases deleted), `tests/unit/test_cve_baseline.py` (real-data case now non-vacuous, no change expected), `tests/unit/test_public_stand_ins.py` (the committed captures equal the declared stand-ins)
- `tests/integration/test_closed_networks.py` and its given (the planted case of scenario 13)
- `evals/cve_planting_docker.py` (`create_network` through `create_closed_network`), `evals/cve_baseline.py` (`_ENVIRONMENT_PATHS` gains `closed_network.py`)
- `evals/cve_targets.py` (CVE-2025-65513), `evals/cve_exploits.py` (the `benign_fetch_ssrf` comment)
- `evals/holdout_fixtures/cve_2026_104120_fetch.py`, `cve_2026_58485_searxng.py`, `cve_2026_33060_ckan.py`, `cve_2026_5323_a11y.py`
- `evals/cve_calibration.py`
- Docstrings of `evals/cve_planting.py`, `evals/cve_environments.py`, `evals/cve_endpoint_address.py`
- `README.md`, `CLAUDE.md`, `CHANGELOG.md`, `docs/labeling-log.md`

**Do**
1. Tests first: the planted case of scenario 13 (from a container started with a planted launch's arguments, `has_network` true and an IP-literal sentinel so a holder, the host, its LAN, `1.1.1.1` and `169.254.169.254` are unreachable). Delete the egress cases of `test_cve_calibration.py`. In `test_public_stand_ins.py`, the real-data case of scenario 4 that holds the hosts of the committed captures equal to the declared stand-in hosts (every acceptance and holdout target's `PublicNames.stand_ins`, and `apify_backend.API_HOST`), so the authority's name constraints, already held equal to the captures' HTTPS hosts, derive from the declared stand-ins. Run the planted case and this one red.
2. `DockerPlanting.create_network` calls `create_closed_network(name)`; module docstring says the networks are closed. `_ENVIRONMENT_PATHS` gains `closed_network.py`.
3. Targets, each listing `"stand-in"` in its `images`, benign calls, exploits and kept places unchanged: CVE-2025-65513 its own `PlantingHost(UNPRIVILEGED, "/", has_network=True, PublicNames(stand_ins=("example.com",)))`; 104120 `stand_ins=("example.com",)`, `trust=("SSL_CERT_FILE",)`; 58485 `stand_ins=("example.com",)`, `trust=("NODE_EXTRA_CA_CERTS",)`, `ip_label_domains=("sslip.io",)`; 33060 `stand_ins=("demo.ckan.org",)`, `trust=("NODE_EXTRA_CA_CERTS",)`; 5323 `stand_ins=("example.com",)`, no trust. `benign_fetch_ssrf`'s comment: the control reaches the `example.com` stand-in on a public address, not the Internet.
4. `cve_calibration.py`: delete `_EGRESS_CANARY`, `egress_warning`, `_egress_reachable`, their call and the `socket` import; `_patched_conditions` returns `patched_dead_conditions(...)` directly. `grep -rn "egress_warning\|_EGRESS_CANARY" .` (outside `plans/` and `docs/adr/`) is empty.
5. Stale docstrings: `cve_planting.py` (the network it owns is closed), `cve_environments.py` (loses "a plain labelled bridge with the host gateway and Internet egress", states the closed network and the stand-ins), `cve_endpoint_address.py` (a stand-in address is bound like an IPv4 literal).
6. Docs: `README.md` Safety paragraph of the CVE benchmark (line 202) rewritten as the plan's step 5 states it (closed networks reaching neither the host nor the Internet, public names pinned inside the network and served by stand-ins replaying a dated capture, an HTTPS stand-in's authority trusted through each target's declared setting and name-constrained to the HTTPS stand-in hosts, so its committed key signs for no other name, the orphan sweep and the recreation of an open persistent network). `CLAUDE.md` Landmines, the closed-network entry of step 1 gains that every fixture network creation goes through `evals/closed_network.py`. `CHANGELOG.md` `[Unreleased]`. `docs/labeling-log.md`: the acceptance fixture change entry naming the commits of steps 1 to 10 (**State**, **What changes**, **Fingerprint** with the grammar fingerprint unchanged, **The four questions of ADR 016** answered as an instrument change raised by ADR 034, not by a measurement).
7. By hand, `uv run python -m evals.run_cve_benchmark --calibrate --cve CVE-2025-65513` green (Docker, no LLM), since CI's calibration runs on this commit. Red, the step stops and reports before committing: the target's fixture is not tuned here.

**Test**
- The planted case of scenario 13, the captures equal to the declared stand-ins, the existing calibration and baseline tests minus the egress cases, scenario 15 on closed networks.

**Verify**
- `CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration/test_closed_networks.py tests/integration/test_cve_planting.py tests/integration/test_holdout_kit.py -n 0` green.
- `uv run pytest tests/unit/test_cve_calibration.py tests/unit/test_cve_baseline.py tests/unit/test_cve_targets.py tests/unit/test_holdout_targets.py tests/unit/test_public_stand_ins.py -n 0` green.
- Closing checks green.

### Step 12 (maintainer, by hand): the suites' Docker checks

As the plan's step 6, in order, each followed by `docker ps --filter label=mcp-auditor-cve` (only the Doris cluster, the MySQL engine and its moto stub left, on closed networks): `uv run python -m evals.run_nuisance vet` (59 of 59), `uv run python -m evals.run_nuisance calibrate` (every result matching, CVE-2026-46341 included), `uv run python -m evals.run_holdout calibrate` (every target live, every fingerprint moved), `uv run python -m evals.run_cve_benchmark --calibrate` (4 of 4). Then the last command of `## Verification` shows every persistent fixture network `true isolated`. A capture miss is a recapture (step 9 again, its own commit); a server resolving another public name, CVE-2026-5323 failing on HTTPS or its exploit 0 timing out stops the step and is reported. An apify server that does not start or answer on the recorded `api.apify.com` answers (vet, or the patched side of CVE-2026-46341) is recorded in the nuisance log entry and stops the step for the maintainer's decision under the nuisance rule's liveness clause, the capture and its dummy token unchanged. A holdout fixture that stays red is repaired by the calibration agent under the holdout rule ("Repairing a fixture is calibration, done by the calibration agent"), and a nuisance fixture by the admission agents under the nuisance rule, never in a step of this plan. One commit with the `docs/nuisance-log.md` and `docs/holdout-log.md` entries the plan's step 6 describes.

### Step 13: Reset the CVE acceptance baseline

Delete the four files of `evals/baselines/cve/` in a commit of its own: `chore(evals): reset the CVE acceptance baseline`. Closing checks green (no test reads a recorded acceptance baseline file; if one does, stop and report).

### Step 14 (maintainer, by hand): recording

As the plan's step 8: volume and cost announced before launching, `uv run python -m evals.run_cve_benchmark --record-baseline` twice at one commit on a clean tree (exploratory, then confirmed), then commit `evals/baselines/cve/` with the labeling log entry of the recording (State, Fingerprint with the four fixture fingerprints, The recording, the four questions), as the 2026-10-15 recording entry does.
