from datetime import date
from pathlib import Path
from typing import Any

from evals.cve.census.census import (
    CLASSIFIERS,
    Census,
    CensusFlaw,
    Discovery,
    TermHits,
    census_flaw,
    derived_parts,
)
from evals.cve.census.classification import (
    Classification,
    Criterion,
    Primitive,
    SoftwareKind,
    Transport,
)
from evals.cve.census.grouping import NO_PROOF_GROUP, READERS, ProofJudgment
from evals.cve.census.identity import merge
from evals.cve.census.prefilter import INITIAL_TERMS
from evals.cve.census.sources import AdvisoryRecord, SourceFile, SourceName, SourceProvenance
from evals.cve.census.work import AgentRecord, AgentRole, HitDecision, VulnerableMcpEntry
from tests.unit.support import advisory_sources

FLAW_WITH_A_CVE = "CVE-2025-0001"
ITS_GHSA = "GHSA-aaaa-bbbb-cccc"
GHSA_ONLY_FLAW = "GHSA-dddd-eeee-ffff"
OSV_ONLY_FLAW = "PYSEC-2025-1"

OUTSIDE_THE_GRAMMAR: dict[str, Any] = {
    "effect_class": "authorization_bypass",
    "first_failed_criterion": Criterion.GRAMMAR_CLASS,
}
NOT_PINNABLE: dict[str, Any] = {"pinnable": False, "first_failed_criterion": Criterion.PINNABLE}


def a_census() -> Census:
    flaws = [
        census_flaw(flaw, [Discovery.PREFILTER])
        for flaw in merge(
            [
                advisory_sources.a_ghsa(ITS_GHSA, FLAW_WITH_A_CVE),
                advisory_sources.an_nvd(FLAW_WITH_A_CVE),
                advisory_sources.a_ghsa(GHSA_ONLY_FLAW),
                advisory_sources.an_osv(OSV_ONLY_FLAW),
            ],
            recorded={},
        )
    ]
    dates = {flaw.identifier: flaw.disclosure_date for flaw in flaws}
    classifications = {
        classifier: [
            a_classification(
                flaw=flaw,
                disclosure_date=disclosed,
                **(OUTSIDE_THE_GRAMMAR if flaw == GHSA_ONLY_FLAW else {}),
            )
            for flaw, disclosed in dates.items()
        ]
        for classifier in CLASSIFIERS
    }
    groupings = {reader: [no_proof(GHSA_ONLY_FLAW)] for reader in READERS}
    derived = derived_parts(flaws, classifications, groupings)
    return Census(
        sources=a_provenance(),
        agents=[
            AgentRecord(role=AgentRole.COLLECTOR, scope="ghsa", model="claude-opus-5-5"),
            *(
                AgentRecord(role=AgentRole.READER, scope=reader, model="claude-opus-4-8")
                for reader in READERS
            ),
        ],
        prefilter=[TermHits(term=term, hit_count=2) for term in INITIAL_TERMS],
        hits=[_a_hit(ITS_GHSA), _a_hit(GHSA_ONLY_FLAW)],
        flaws=flaws,
        vulnerablemcp=[
            VulnerableMcpEntry(cve_id=FLAW_WITH_A_CVE, listed=date(2025, 7, 3), found=True)
        ],
        classifications=classifications,
        date_mismatches=derived.date_mismatches,
        figures=derived.figures,
        groupings=groupings,
        known_gap=derived.known_gap,
    )


def _a_hit(source_id: str) -> HitDecision:
    return HitDecision(
        source=SourceName.GHSA,
        source_id=source_id,
        decision="keep",
        software_kind=a_classification().software_kind,
        reason="A filesystem MCP server.",
        agent="ghsa collector",
    )


def a_provenance() -> SourceProvenance:
    a_file = SourceFile(name="all.zip", downloaded=date(2026, 10, 8), sha256="0" * 64)
    return SourceProvenance(
        ghsa_commit="1" * 40,
        nvd_feeds=[a_file.model_copy(update={"name": "nvdcve-2.0-2025.json.gz"})],
        osv_export=a_file,
    )


def written(tmp_path: Path, census: Census) -> Path:
    path = tmp_path / "census.json"
    path.write_text(census.model_dump_json(indent=2))
    return path


def with_a_cve_of(census: Census, flaw_id: str, server_package: str) -> Census:
    """A valid census that also classifies `flaw_id` under `server_package`."""
    flaw = a_flaw_with_records(advisory_sources.an_nvd(flaw_id))
    classification = a_classification(
        flaw=flaw_id, disclosure_date=flaw.disclosure_date, server_package=server_package
    )
    classifications = {
        classifier: [*census.classifications[classifier], classification]
        for classifier in CLASSIFIERS
    }
    return recomputed(
        census.model_copy(
            update={"flaws": [*census.flaws, flaw], "classifications": classifications}
        )
    )


def a_flaw_with_records(*records: AdvisoryRecord) -> CensusFlaw:
    [flaw] = merge(records, recorded={})
    return census_flaw(flaw, [Discovery.PREFILTER])


def recomputed(census: Census) -> Census:
    derived = derived_parts(census.flaws, census.classifications, census.groupings)
    return census.model_copy(update=derived._asdict())


def a_classification(**overrides: Any) -> Classification:
    fields: dict[str, Any] = {
        "flaw": "CVE-2025-1234",
        "software_kind": SoftwareKind.SERVER,
        "server_package": "npm:@acme/files",
        "affected_versions": "< 1.2.0",
        "vulnerable_version": "1.1.0",
        "first_patched_version": "1.2.0",
        "pinnable": True,
        "disclosure_date": date(2025, 6, 10),
        "transport": Transport.STDIO,
        "primitive": Primitive.TOOLS,
        "effect_in_tool_response": True,
        "runs_in_container": True,
        "effect_class": "read_outside_scope",
        "first_failed_criterion": None,
        **overrides,
    }
    return Classification(**fields)


def no_proof(flaw: str) -> ProofJudgment:
    return a_judgment(flaw, group=NO_PROOF_GROUP)


def a_judgment(flaw: str, group: str = "authorization_bypass") -> ProofJudgment:
    return ProofJudgment(
        flaw=flaw,
        group=group,
        proof="A nonce planted in a record only the bypass returns.",
        reason="The tool returns the record it reads.",
    )
