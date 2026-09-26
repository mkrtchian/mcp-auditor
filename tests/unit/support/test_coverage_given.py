from mcp_auditor.domain import AuditCategory, AuditPayload, TestCaseBatch


def a_batch_of(num_cases: int, categories: list[AuditCategory] | None = None) -> TestCaseBatch:
    cycled = list(AuditCategory) if categories is None else categories
    return TestCaseBatch(
        cases=[
            AuditPayload(
                category=cycled[i % len(cycled)],
                description="test payload",
                arguments={"input": "malicious"},
            )
            for i in range(num_cases)
        ]
    )
