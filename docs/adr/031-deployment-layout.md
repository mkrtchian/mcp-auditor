# ADR 031: A Deployment Layout as a Second Source of Nonce Places

**Date:** 2026-10-13
**Status:** Accepted
**Supersedes:** in [ADR 029](029-nonce-only-proof.md), that the places of the nonce come only from the published catalogue. The nonce as the only proof, a fresh one per place at each launch, is unchanged.

## Context

[ADR 029](029-nonce-only-proof.md) takes the places of the nonce from a catalogue of attacker techniques. These places, such as system files, credential paths, the process account or internal endpoints, are the same whatever the server's scope. A flaw reaches them when its primitive is general, such as a read of any file, a command the caller chooses or a fetch to any URL. A flaw whose primitive is confined to the tree the server is scoped to reaches none of them.

So the instrument can credit no confined flaw. It still reports a capability number, which then covers general primitives only. This decision lets the number cover some confined flaws too. It does not rest on their share, which is small in the holdout census. The decision follows a reading of that census in aggregate, and no one involved computed the draw order, so the layout could not be aimed at the flaws a draw would reach.

## Decision

**The places of the nonce come from 2 sources: the catalogue of ADR 029, and a deployment layout written before the holdout draw.** The layout reproduces a project deployed from git: a checkout, the bare repository it was cloned from, and the project files a deployment carries. Every acceptance and holdout target is launched as its documentation prescribes, with the layout mounted and the checkout as its scope wherever the launch takes a scope.

**Under 3 conditions, a place enters the layout, the same for every target:**

1. A published source or the software's own default names it.
2. It is present in every target and its patched twin, with the same ownership and mount mode whether a flaw reaches it or not.
3. No path segment that the layout invents names a security concept.

The layout as a whole meets 2 more: no runtime reads a place at launch, and its paths stay out of the auditor's prompts under the contamination test of [ADR 014](014-proving-impact.md), widened to those paths.

**A place is kept for a target when 2 checks pass:**

1. Calibration shows that the flaw reaches it, as for a catalogue place.
2. The auditor has a route to it through what the server reveals under the run conditions: its scope, a listing, an error, the clone's record of its origin, or a documented default path relative to a location the server revealed.

ADR 029 asks the auditor to look where an attacker would look. For a layout place, the published or default name and the route meet that requirement. A mechanical check, or an agent that sees neither the flaw nor the exploit, judges the route. Calibration reads the flaw's mechanism to test reach, as for a catalogue place, but no one who reads it judges the route. The route decides only which places are kept: the credit does not depend on it, since ADR 029 grades any nonce a response surfaces.

**A server that fails with the layout falls back to a pre-registered launch.** When a check finds that the documented launch and a benign call succeed without the layout and fail with it, the target runs with the layout mounted but without the checkout as its scope. This check runs no exploit, so it cannot be aimed at a flaw. The fallback keeps a target that the layout breaks from being given up as a flaw that no nonce can prove. The report names each fallback.

**The layout is frozen before the first holdout draw and never changed to make a target pass.** It enters the selection rule (`docs/holdout-rule.md`) once a fixture used for nothing else has confirmed the layout's places. Only a version of the rule that extends the census can add to the layout. Any version can remove a place, with its reason logged, and never because of a holdout result.

## Alternatives considered

**The catalogue alone, with every confined flaw declared a gap.** Rejected. The instrument would then credit no confined flaw.

**A bare repository and a project dotfile added to the catalogue as 2 standalone places.** Rejected. A tree gives a clean negative control on the patched twin, and it keeps the repository's committed history and every place under one ownership and mount mode. Two standalone places carry none of this.

**A layout chosen by the type of server.** Rejected. A server's type is tied to its flaws, so the choice would fall to the calibration agent, which reads the flaw's mechanism.

**A database place or a loopback service, built now.** Rejected. The principle asks that the instrument can credit confined flaws, and a file tree meets it. Going further is a matter of cost against yield, read on the census as a whole: each form would reach 1 or 2 of its flaws, for a new way to plant the nonce, its own calibration and a reset. Built later, it costs the same reset and cannot bring back a candidate given up before it exists, a cost this decision accepts. Both are declared gaps, each reported with its share of the census, like writes that no tool reads back and servers with neither a file nor a repository scope.

## Consequences

The capability number measures detection in the benchmark's deployment. The container of that deployment already holds the credentials the catalogue names, and the layout adds a project deployed from git to it. The report says whether each credit came from a catalogue place or a layout place, so a reader can tell which part of the deployment a number rests on.

The layout's shape comes from the spent acceptance targets, and it favours servers scoped to a file tree or a repository. The layout was written before any holdout flaw was drawn, so which holdout flaws it reaches shows in calibration, not in its design.

Numbers graded before and after this change are not comparable. Confined targets now enter the denominator with 1 or 2 places, against about 20 for a general target, so their detection is less stable and they may stay out of the gated set. At the reset this decision triggers, and at each change of the layout, the acceptance layer's general targets run with and without it, and the paired difference is published as the only measure of what the layout costs in detection.

The fixture fingerprint changes, so the acceptance baseline resets ([ADR 024](024-cve-acceptance-gate.md)). The layout is frozen before the holdout's run conditions are logged, because a scope full of files may need a larger budget.
