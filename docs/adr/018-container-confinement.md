# ADR 018: Container Confinement on Generic Base Images

**Date:** 2026-09-22
**Status:** Accepted

## Context

ADR 017 decides that the server under audit runs confined by default and leaves the mechanism to this decision.

A one-time count of the MCP Registry on 2026-09-22, which nothing in this repository recomputes, found that about 94% of the servers that install locally publish no container image, and that `npx` and `uvx` launch about four of five installable packages. The registry holds what authors chose to publish, so it under-counts servers that only exist as a repository, but for the third-party server this decision is about, it is the population this decision can count.

## Decision

**The server runs in a Docker container built on a generic base image chosen by ecosystem.** The launcher decides the image: an `npx` command runs in a Node image, a `uvx` command in a uv image. The table from launcher to image has these two entries and no other, so a server that needs its own image takes `--image`. A command that is already a `docker run` passes through untouched. The image carries the runtime, so the auditor does not have to reproduce the target's environment on each host: it audits an npm server on a machine without Node, and one profile is meant to serve Linux, macOS and WSL.

**Only self-fetching launchers are in the table.** `npx` and `uvx` fetch the server themselves. `python server.py`, `node server.js` or `uv run` start local code whose environment, a virtual environment or a lockfile, is not in the container, so that code would fail at import or produce findings about the harness rather than about the server. Under the default those commands stop, and they run with `--image` or with `--unconfined`.

**The filesystem is closed, except for the paths the command names.** Each argument that is an existing path is mounted at the same path and writable, because it is the surface under audit and a server audited on those paths writes to them. A short table of refused roots, the filesystem root and the home directory among them, requires the user to mount that root explicitly, so that auditing a filesystem server pointed at `/` does not silently mount the host. The container runs as the invoking user, so what the server writes into a mounted path stays owned by that user. The environment is the image's: none of the host's variables is passed, not even the handful the MCP SDK forwards to a plain subprocess, since those carry the user's identity and home path.

**The container runs without capabilities, without privilege escalation, and with a bound on process count and memory.** The bounds are there because the auditor sends resource-abuse payloads by design, and a server that mishandles a 1MB string or a deeply nested object exhausts the memory of whatever runs it. ADR 013's guard refuses a payload written to take a host down, which is a different thing from a server that turns an ordinary payload into that.

**The container sits on the default bridge, egress open.** Egress is a precondition of the mechanism: the image is generic, so the launcher fetches the server at start, and a container with no network has nothing to run. Even with egress open, a service bound to the host's loopback alone is out of the container's reach, measured on Linux. A service the host exposes on all its interfaces stays reachable, and so does the rest of the network the host sits on. The Docker Desktop runtimes resolve the host by name. An open egress diverges from the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), which says to "disable network access unless explicitly needed", and the fetch at start is that need.

## Alternatives considered

### OS-level confinement of the host process

**Rejected.** Bubblewrap on Linux and Seatbelt on macOS confine a process without an image and without a container start. They need the target's runtime on the host, and one implementation per platform, the macOS one on an interface Apple has marked deprecated since 2017.

### An image of the target

**Rejected.** The population above has none.

### An internal network with a DNS sinkhole

**Deferred.** A network with no gateway, a resolver that answers every name with a sink, and a listener that records what arrives would satisfy the OWASP clause without losing detection, and turn an SSRF attempt into an observed request. It is a feature of its own.

## Consequences

- Docker is a prerequisite, so an air-gapped host cannot audit. Each launch costs a container start, a pull of the base image on first run, and a fetch of the server package every time. Running the auditor requires the right to start containers, which on a standard installation means membership in the `docker` group, itself equivalent to root on the host.
- A malicious server can still exfiltrate what it read, because the confinement bounds what the server reaches without bounding where it sends.
- ADR 004 defines resource abuse by a timeout, an out-of-memory or no response, and the memory bound produces that signal. The report does not distinguish a limit the auditor set from a defect in the server. The container reports whether it was killed on memory, which is the fact that would distinguish them, and nothing here reads it yet.
- An information-leakage finding whose severity came from the host path the server disclosed now rests on a container path, so the same flaw is reported at a different severity.
- The target can change from one run to the next. The cache is empty at each launch, so an unpinned `npx` resolves the latest version each time, and a resumed audit may resume against another version than the one checkpointed. The image tag is mutable too, so the report records the digest that ran beside the regime.
- The target's identity, for resuming an audit and in the report, stays the user's command and the regime it asked for, not the assembled container command.
- Only Linux has been tried. macOS and WSL are expected to work through Docker Desktop and have not been tried, and Windows without WSL is out of scope.
- The server's stderr and the container runtime's own output share one stream, so a launch failure and a server error read alike.
- The CVE benchmark's containers are not confined by this profile, and hardening them is a separate change, justified on its own.
