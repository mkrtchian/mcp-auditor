# ADR 036: An Audited Server That Stops Answering Is Relaunched

**Date:** 2026-11-16
**Status:** Accepted
**Supersedes:** nothing.

## Context

When a tool call gets no answer within the tool call timeout, the auditor records a timeout as the response and sends the next call, whether or not the server can still answer.

Some servers run a tool inside the loop that reads their requests, so they answer nothing while one call lasts. On 2026-11-16, in the audit of a Kubernetes server, the auditor sent a `resource_abuse` payload that started a `kubectl` watch with no practical end, and the server answered no later call. 29 test cases in a row and the chain steps after them timed out at 60 seconds each, about 40 minutes in all. The judge ruled on each of those test cases as on any other: a timeout is judged PASS in every category except `resource_abuse`. The report did not say that every call after the `kubectl` watch had gone to a server that no longer answered. When a server exits during the audit, the auditor goes on the same way, and every later call ends in a lost connection.

That audit was a run of the detection suite, and its replay ([ADR 030](030-credit-replayed-on-patched.md)) sent the same calls to the patched version, which stopped answering at the same call. A timeout is also an ordinary response for the replay. If the patched version stops answering before the call that earned a credit, the nonce does not surface, and the replay keeps the credit as checked although the fix was not tested.

## Decision

**After a tool call times out or ends in a lost connection, the auditor relaunches a server that no longer answers.** After a lost connection it relaunches at once. After a timeout, it sends an MCP `ping`, and relaunches a server that does not answer. Any response counts as an answer, an error included. A server can leave every ping unanswered, so the auditor also sends one after each handshake, while the server is known to answer. A server that stays silent then is not pinged after a timeout, and its timeouts are counted like those of a server that answers the ping. A relaunch starts the server again from the same server command, and the audit goes on with the next call.

**A tool that keeps timing out on a server that answers the ping stops being called.** When the calls of a tool time out several times in a row while the server answers the ping, that tool gets no further call. When the calls of the next tool audited time out as many times in a row, the server is taken as stuck, and the auditor relaunches it.

**Before a relaunch, the auditor ends the old server where it can.** Under the unconfined regime (a process on the host) it ends the server's process group. Under the confined regime (the default container) it reads whether the container was OOM-killed, for the report, then removes it: the container keeps its name even once stopped, and Docker refuses to start another one under that name. A declared container is a `docker run` the user wrote ([ADR 017](017-confined-target-execution.md)), and the auditor adds nothing to that command, not even a name. It removes the container only when the command sets a `--name`.

**Relaunches are bounded.** A tool whose calls lead to a relaunch several times in a row gets no further call, and the audit goes on with the next tool. When a relaunch fails, the server is taken as down: the auditor sends no further call and writes the report. The numbers of timeouts and of relaunches in a row are constants of the auditor, with no flag.

**The report names each relaunch with the call that preceded it.** A tool that did not get all its calls has a coverage gap, which makes the audit incomplete, and `--ci` exits 3. Relaunches alone do not make an audit incomplete. An attack chain cut by a relaunch is not resumed. It is judged on the steps it made, as a chain cut by a blocked payload is ([ADR 013](013-non-destructive-payloads.md)), and the steps it did not make are not a coverage gap.

**The relaunch lives in `AuditedServer`, the domain service every tool call of an audit goes through, above the MCP client.**

**The replay relaunches where the run did.** It calls the client directly, so it does its own relaunch of the patched version, after the same calls as the run, whatever the patched version answered, and nowhere else. When the patched version stops answering at a call where the run did not relaunch, the replay attempt fails and is made again. A credit that no attempt could replay stays unchecked, as in ADR 030.

## Alternatives considered

**Ending the audit when the server stops answering.** One payload the auditor wrote would cost the user the audit of every later tool.

**Relaunching after several timeouts in a row on one tool, even when the server answers the ping.** A server with one slow tool answers the ping and serves the next call. Relaunching it would lose its state.

**Relaunching inside the MCP client, for every caller.** A no-LLM check of an evaluation suite, such as a calibration check or a vet, would then relaunch a server that stopped answering and report its fixture as working.

**Letting the replay relaunch wherever the patched version stops answering.** The patched version could be relaunched at a call where the vulnerable version was not. Later calls would then find a different state on each version, so a nonce missing on the patched version would no longer show that the fix holds.

## Consequences

- A relaunched server loses its memory and what earlier calls wrote inside its container, so the attack context ([ADR 035](035-attack-context-merged-in-code.md)) can name things that are gone. A mounted path, the host's files under the unconfined regime and a backend keep their state.
- Under the confined regime a relaunch fetches the server package again, so an unpinned `npx` or `uvx` command can launch a different version.
- On a server that runs its tools in the loop that reads its requests, a call that outlasts the tool call timeout and the ping's own timeout ends in a relaunch. `MCP_AUDITOR_TOOL_CALL_TIMEOUT` raises the timeout of every call, so a slow tool can finish. A tool that never returns can leave the audit incomplete, unless `--tools` leaves it out.
- The calls that led to a relaunch are judged on the timeout or the lost connection they returned, and the judge is not told that the server stopped answering. A call that stops the server can end with no finding in a complete audit. The report then shows it only as a relaunch.
- Without a `--name`, a declared container is not removed, and a blocked server can keep running in it beside the relaunched one. A declared container the auditor removes is gone with its logs and its files.
- The detection and nuisance suites launch every server as a declared container, and take a relaunch that fails as a failure to launch, which their rules have retried.
- In a replay, a call that times out while the patched version answers the ping counts as answered: the credit it earned in the run stays checked, though the fix was not tested at that call.
