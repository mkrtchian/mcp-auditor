# ADR 034: Eval Fixture Networks Reach Neither the Host nor the Internet

**Date:** 2026-11-02
**Status:** Accepted
**Supersedes:** nothing.

## Context

Three suites run MCP servers under Docker: the nuisance suite, including the gate of its acceptance servers, the CVE holdout and the acceptance layer of the CVE benchmark. The honeypot e2e suite runs its own servers, written in this repository, as stdio subprocesses with no network backend, and the judge isolation eval runs no server, so this decision does not concern them.

The holdout and the acceptance layer run vulnerable versions on purpose, and the nuisance suite runs them too, to check that the flaws it counts are fixed. A networked fixture sits on an ordinary Docker bridge network with a route to the host and to the Internet, so a server on it can reach the services the host exposes on its interfaces and the local network the host sits on.

Some benign calls fetch `demo.ckan.org` or `example.com`, so a calibration or an audit depends on what those services return at run time, and on whether they answer at all.

[ADR 018](018-container-confinement.md) keeps the product's egress open because the generic image fetches the audited server's package at start, and it leaves the hardening of the benchmark's containers to a separate change justified on its own. An eval image is built in advance with the server installed, so an eval container has nothing to fetch at start.

On 2026-11-01, a throwaway patch cut every fixture network off from the Internet, and on 2026-11-02 off from the host as well. The suites' Docker checks, which use no LLM, were run under each patch and gave the same result item by item: 58 of 59 nuisance servers answered their benign calls, 53 of the 54 nuisance fix checks passed, and 26 of 30 holdout targets and 3 of 4 acceptance targets passed calibration. Each red item went green when rerun on its own with egress restored, and its failure came from the closed network: a server start or a benign call that resolves a public name, and on two holdout targets the exploits resolve one too (one of these two targets reaches an internal address through a public wildcard-DNS name, as its advisory describes).

## Decision

This decision covers every network a container of these three suites joins, in every step that launches such a container. The product's confinement under ADR 018 is unchanged.

**No fixture network routes to the host or to its local network.** These suites aim adversarial payloads at flawed servers, so a payload that works reaches everything its server can reach. What a fixture plants is synthetic, while what the host and its local network expose is real.

**No fixture network routes to the Internet either.** A service that the server needs at start, that a benign call needs, or that a flaw's published mechanism goes through is served by a stand-in under its real name, resolved inside the network. A request to any other address finds no route and fails. The reason is that what a server reads while it runs has to come from the fixture. The build keeps its network and fetches from the Internet, a source of drift that [ADR 024](024-cve-acceptance-gate.md) accepts, records by image ID and checks before each run with a benign call or a calibration. Content read at run time leaves no such trace. An outside service that stops answering turns a live target dead or takes a server out of the nuisance count, with no change to the commit or the images.

## Alternatives considered

**Keeping egress.** Rejected. It is the closest to what an adopter's server sees, but it leaves the host and its local network within reach of a working payload. A reading also depends on what outside services return that day.

**Filtered egress**, with the host and the private ranges blocked and the public Internet open. Rejected. It settles the first rule only: a server still reads content that no run records.

**An internal network with a DNS sinkhole and a recording listener, the alternative ADR 018 deferred.** This decision keeps the internal network and leaves out the sinkhole and the listener. The oracle reads its proofs in tool responses only ([ADR 029](029-nonce-only-proof.md)), so a recorded request would prove nothing.

## Consequences

The shared environment code of the CVE benchmark, which creates its networks, is part of every acceptance target's fingerprint, so the 4 acceptance baselines are deleted and recorded again under [ADR 024](024-cve-acceptance-gate.md).

No nuisance run, gate run or holdout run has taken place, so a changed fixture takes no server or target out of a comparison. The holdout targets whose exploits or benign calls resolve a public name are recalibrated under the holdout rule before the first run, and the nuisance server that resolves a public name at start is checked again.

A false alarm that real content would provoke does not show up in the nuisance figure. A detection that routes through a public service succeeds only where the fixture stands in for that service.

The stand-ins are fixture content: what a stand-in serves is part of the fingerprint of each server and target that reaches it, and it falls under each suite's rules for its fixtures (`docs/nuisance-rule.md` for the nuisance suite, `docs/holdout-rule.md` for the holdout and the acceptance layer).

A stand-in under a real HTTPS name presents a certificate the server accepts only because the fixture tells it to, so a server that reaches such a stand-in runs with a trust setting that its documented launch does not set.

The product's audits still leave the host and its local network within reach of the server under audit ([ADR 018](018-container-confinement.md)). Cutting the server under audit off from them while still letting it fetch its package at start is possible, at a cost of its own for the servers the product audits, and it is not settled here.
