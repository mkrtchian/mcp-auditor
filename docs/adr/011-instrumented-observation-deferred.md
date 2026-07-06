# ADR 011: Black-Box Auditing, Instrumented Observation Deferred

**Date:** 2026-07-06
**Status:** Accepted

## Context

mcp-auditor is a black-box dynamic auditor. It calls a server's tools and judges what comes back through the protocol. It sees a tool's response and nothing else.

Some vulnerabilities never surface in that response. A tool can overwrite a file, spawn a process, or exfiltrate over the network while returning a clean, correct payload. CVE-2025-68144 is a concrete case: `git_diff` with a crafted `--output=/path` argument overwrites an arbitrary file and returns nothing that reveals it.

Standard security guidance treats effect observation as the way to catch this class. The OWASP MCP guidance names filesystem, syscall, and outbound-network anomalies as the signals for command-execution and exfiltration threats. ADR 004 recorded a related gap: it noted that some threats do not surface in the response and are invisible to the tool, and it pointed ACCESS_CONTROL at "a future white-box analysis mode".

So the question is whether to add an instrumented mode that observes host state (filesystem and process changes around a tool call), or to stay black-box.

This decision is only about instrumentation. Two other extensions stay inside the black-box model and are out of scope here: cross-tool attack chains and declared-scope awareness. Both work from protocol responses alone.

## Decision

### Black-box stays the default

The auditor keeps observing only what the protocol returns. This keeps the tool zero-config and cheap to maintain, and it leaves open the path to auditing remote servers the auditor does not launch, once that transport is supported.

### The silent side-effect class is a documented limit, not an exclusion

Vulnerabilities whose only effect is a silent write, a spawned process, or out-of-band exfiltration are out of reach of the black-box default. This is a limit to state plainly, not a class to pretend does not matter. The OWASP guidance and CVE-2025-68144 show it is central.

### The instrumented mode is deferred, and its seam is named

Building it is deferred. When it is built, an `ExecutionObserver` seam is the intended shape: a component that snapshots and diffs host state around each execute step, injected through the same factory-closure pattern the graph already uses for its ports, so the domain and the prompts stay pure. This ADR reserves the name and the shape. It adds no code now.

### The gate is a tracked signal, not a vague intention

The CVE benchmark records a CVE it cannot reach without instrumentation with an out-of-scope status, reachable-only-with-instrumentation, rather than as a detection miss. The count of those is the gate signal. When the class grows to a material share of the reference-server CVEs the benchmark tracks, or when users ask for it, a new ADR decides whether to build the mode and fixes its scope. The natural starting point is narrow: local stdio servers, a filesystem diff, one platform first.

## Alternatives considered

### Build the instrumented mode now

**Rejected** because the cost lands before the evidence. Even a minimal filesystem-diff observer around the local subprocess the tool already spawns is net-new work: portable state capture across platforms, false-positive filtering to separate a malicious write from a server's own logs and temp files, and the extra test surface the project's fake-based testing standard requires. That load is real for a solo maintainer, and the value is not yet shown by eval data. Cheaper black-box extensions, cross-tool chains and declared-scope awareness, unlock more real CVEs first.

### Exclude instrumentation permanently

**Rejected** because the class is real and central, not marginal. CVE-2025-68144, the OWASP anomaly-detection guidance, and ADR 004's own deferred white-box note all point the same way. A permanent exclusion would contradict the evidence and the project's own prior note.

### Make instrumentation the default

**Rejected** because it removes zero-config and the path to remote-server auditing, the properties that make the tool usable. A default that has to launch every server in a controlled sandbox is a different tool.

## Consequences

- The silent side-effect class is out of reach of the current tool. The README scope note and the CVE benchmark will both state this, and the benchmark records such a CVE as reachable-only-with-instrumentation, not as a detection miss.
- The `ExecutionObserver` name is the reserved seam. No port is added now. When the gate fires, a new ADR decides the build and its scope.
- ADR 004 pointed at a future white-box mode for ACCESS_CONTROL, whose problem is not knowing a tool's intended scope. That mode covers two distinct capabilities: declared-scope awareness and effect observation. This ADR speaks only to effect observation, and defers it. ADR 004's category decision is unchanged.
