# ADR 017: Confined Target Execution by Default

**Date:** 2026-09-22
**Status:** Accepted
**Supersedes:** ADR 011 (the clause rejecting a default that launches every server in a sandbox as "a different tool", and the zero-config property its decision claims)

## Context

The auditor starts the server under audit as a subprocess on the host, with the user's privileges, and sends it adversarial payloads, command injection included. A user pointing the auditor at a third-party server runs that server's code, and whatever an injection triggers in it, on their own machine.

ADR 013 names execution isolation of the target as the durable control its guard stands in for. The MCP specification's [security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices) (revision 2026-07-28, section on local server compromise) say the client SHOULD "execute MCP server commands in a sandboxed environment with minimal default privileges".

## Decision

**The server under audit runs confined by default**: it cannot reach the rest of the host filesystem, the host's loopback-bound services, or the auditor's environment, it runs under the invoking user's identity, and it cannot raise its privileges. It can reach the paths the audit command names, and it can reach the network. ADR 018 gives the mechanism and its bounds. The auditor itself keeps running on the host.

**When the mechanism is unavailable, or cannot take the command, the CLI stops and names the ways forward**: install the mechanism, supply an image, or run with `--unconfined`. The refusal happens before any of the target's code runs, and it is the only check the CLI makes on the regime. The reason is that consent to run third-party code unconfined is taken before the launch, and in the command.

**The one way out is `--unconfined`**, a flag that names the state the user chooses. There is no configuration-file key for it. The file loads from the working directory, so a target audited from its own clone supplies that file. Its other keys already shape an audit from the target's side, a weakness this decision does not fix. The line is drawn at the one key that would decide whether the target's code is confined. The hard stop guarantees that an unconfined run is declared, it does not prevent one since the flag is one word away.

**The report records the execution regime beside the target**, as the regime the CLI applied and not as a verified state. A `docker run` the user wrote passes through untouched and is recorded as the user's own container, since the auditor applied no profile to it. Checking that the regime holds would test the host's Docker installation, which the auditor does not audit. The regime is part of the target's identity, so an audit cannot be resumed under the other regime: it starts over.

**The default lives in the composition root, behind a launch type with named constructors.** Today the client's connect call takes a raw command, so any new execution path is unconfined by omission. The launch type closes that gap. A remote server, when that transport exists, launches nothing. It is a regime of its own, named here so that the transport does not add it as a bypass later.

## Alternatives considered

### Warn, then run unconfined

**Rejected.** The information arrives with the launch or after it, when the code already runs.

### Ask for confirmation on a terminal

**Rejected.** The regime then depends on an answer the command does not carry, so two identical invocations can run under two regimes, and a report cannot be reproduced from its command.

### Confinement as an opt-in flag

**Rejected.** The default is the setting most runs use, so it has to be the confined one, and the specification puts the sandbox on the client by default, not on the user's request.

## Consequences

- Zero-config is gone, the cost ADR 011 named. The mechanism becomes a prerequisite, and the README's quick start and scope note change. `--dry-run` launches the server too, so it stands under the same rule.
- Auditing the user's own local server is the `--unconfined` case: it is their code, and the threat this decision answers is code they did not write. The README's CI recipe changes to say so.
- ADR 013's guard stays in force. Its sentence that the table is "what stands until it ships" expected isolation to make the guard redundant, and it does not: the paths the command names are mounted for writing, so a destructive payload still destroys the files under those paths, which are the ones the audit was pointed at. The same section's statement that the target runs as a host subprocess with the user's privileges describes the default this decision replaces.
- ADR 014 reads the same fact the other way. It expects isolation to hold a secret read to a container's environment, and one of the read targets it names is a path the tool's own arguments already reach, which is a host path mounted in. A value read there is a live host secret, and nothing redacts it. The regime record says whether the run was confined, and within a confined run it does not tell a read from a mounted path from one from the container's own environment.
- No instrument in this repository measures the shipped default. The evals run unconfined on purpose, since they launch this repository's own honeypots, and the CVE benchmark launches its own containers.
- The choice between stopping and warning is a posture: third-party code does not run unconfined without the user having typed the word. It does not follow from where consent is taken by itself.
- ADR 011 deferred effect observation partly on the cost of capturing host state across platforms. A container answers that part: a filesystem diff against its base image works the same on every platform. The two other costs it named, telling a malicious write from the server's own logs and the test surface, remain. Nothing here builds the observer.
