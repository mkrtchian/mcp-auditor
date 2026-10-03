# ADR 026: Relaying Named Environment Variables to the Server Under Audit

**Date:** 2026-10-02
**Status:** Accepted
**Supersedes:** for the variables the user names, ADR 018 (the sentence "The environment is the image's: none of the host's variables is passed" and the clause that follows it) and ADR 017 (the words "or the auditor's environment" in its list of what a confined server cannot reach)

## Context

A server on the stdio transport takes its credentials from its environment. The authorization part of the MCP specification says an implementation on that transport "SHOULD NOT follow this specification, and instead retrieve credentials from the environment" ([Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), revision 2026-07-28). A server that needs a token cannot be audited without one.

The auditor passes none of the variables such a server needs. Under ADR 018 the container gets the image's environment and the profile's `HOME`, and an unconfined server gets the variables the MCP SDK forwards, `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM` and `USER`. The workarounds available today put the value in the command, as `env TOKEN=...` under `--unconfined` or `docker run -e TOKEN=...`, so the token ends up in the report, which records that command as the target. A `docker run --env-file` keeps the value out of the command, but a `docker run` the user writes runs without the confinement profile.

## Decision

**`--env NAME` relays the variable NAME from the auditor's environment to the server, and redacts its value.** Before the target launches, the CLI refuses `--env TOKEN=abc`, since a value typed in the command stays in the shell history and the process list. It suggests exporting the variable and passing `--env TOKEN`, or `--env-plain` for a value that is not secret. It also refuses a name the auditor's environment does not hold, and `HOME` under the confined regime, since relaying it would replace the profile's value.

**`--env-plain` relays a variable without redaction**, for a value the server needs that is not secret, such as a region. It takes a name or `NAME=value`. The report records the value.

**How the variable reaches the server depends on the regime.** Under the confined regime, the `docker run` the auditor assembles carries `-e NAME` without a value, and the auditor adds the value to the environment of the `docker` process, which the MCP SDK otherwise starts with the variables above and Docker's own settings only. Under `--unconfined`, the server receives it in the environment the SDK starts it with. Under the `declared_container` regime the report records, the `docker run` the user wrote is not modified. The auditor adds the value to the `docker` process in the same way, so the variable reaches the server only through a flag such as `-e NAME` in that command.

**There is no configuration-file key for either option.** The file is read from the working directory, which is the target's clone when a user audits a server from its repository. A key would let that repository ask for the user's secrets by name.

**Each `--env` value is replaced by a marker such as `[value of NAME, redacted by mcp-auditor]` in everything the server sends, its tool list and error output included, before the auditor stores or forwards it.** Under ADR 014 the generator's payloads prove an injection by reading, among other targets, the process environment, which holds every relayed token. The marker keeps the proof only if its reader knows where it comes from, so the marker names the auditor as its author, and when a variable is relayed, every prompt that carries a server response says that a marker stands for a value the server returned. A response that holds the marker for `GITHUB_TOKEN` then shows the read as clearly as the token would. The generator and judge models, the checkpoints, the trace, the report and the terminal receive the marker. The report records the names of `--env` variables, never their values.

## Alternatives considered

### A secret option beside a plain `--env`

**Rejected.** In that design the unredacted option would be `--env`, the flag Docker users type out of habit, so a token passed with it would reach the report unredacted. Here `--env` is the redacting option, and the opt-out, `--env-plain`, names what it gives up, as `--unconfined` does.

### Redaction by value length

**Rejected.** A 7-character password would reach the report unredacted, and a value that is not secret, such as `eu-west-1`, would still be replaced in responses.

## Consequences

- The server holds every relayed value in the clear. Every tool call the audit makes runs with the real credential. A hostile server can send it out, since egress is open (ADR 018).
- Redaction matches the value as it was relayed. A value the server returns encoded, split or truncated stays unredacted. A short or common value is replaced wherever it occurs, including in responses that have nothing to do with the variable.
- A server that echoes a payload holding a marker, or writes one on its own, produces what looks like a read of the environment.
- A secret the server returns that was not relayed with `--env`, from a mounted file for example, stays unredacted, as ADR 017 states.
- `docker inspect` shows the relayed values in the container's configuration until it is removed. An auditor killed before removal, or a `docker run` the user wrote without `--rm`, leaves them behind. Membership in the `docker` group gives root on the host (ADR 018), and root can read the auditor's own environment while it runs.
- The relayed names are not part of the target's identity, so an interrupted audit resumes with whatever variables the new run relays. Nothing flags a change.
