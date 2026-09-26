from mcp_auditor.domain.models import AuditCategory, CoverageGap, TestCaseBatch


def find_coverage_gap(
    batch: TestCaseBatch, budget: int, categories: list[AuditCategory]
) -> CoverageGap | None:
    received = len(batch.cases)
    covered = {payload.category for payload in batch.cases}
    lacks_categories = len(covered) < min(budget, len(categories))
    if received >= budget and not lacks_categories:
        return None
    missing = [c for c in categories if c not in covered] if lacks_categories else []
    return CoverageGap(requested_cases=budget, received_cases=received, missing_categories=missing)


def completion_size(
    budget: int, categories: list[AuditCategory], missing: list[AuditCategory]
) -> int:
    covered = len(categories) - len(missing)
    still_needed = min(budget, len(categories)) - covered
    return still_needed * max(1, budget // len(categories))
