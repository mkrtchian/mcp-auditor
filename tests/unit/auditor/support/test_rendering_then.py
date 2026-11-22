import json

from tests.unit.auditor.support.markdown_sections import summary_of


def json_has_owasp_for_category(
    json_str: str,
    category: str,
    expected_code: str,
    expected_title: str,
) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for case in tool_report["cases"]:
            result = case["judge_result"]
            if result and result["category"] == category:
                assert result["owasp"]["code"] == expected_code
                assert result["owasp"]["title"] == expected_title
                return
    raise AssertionError(f"No result with category {category} found")


def json_has_null_owasp(json_str: str) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for case in tool_report["cases"]:
            result = case["judge_result"]
            if result:
                assert result["owasp"] is None


def markdown_contains_tool_headings(markdown: str, tool_names: list[str]) -> None:
    for name in tool_names:
        assert f"## {name}" in markdown


def markdown_contains_finding(
    markdown: str,
    category: str,
    severity: str,
    justification: str,
) -> None:
    heading = f"### FAIL -- {category} ({severity})"
    assert heading in markdown
    block = markdown.split(heading, 1)[1].split("###", 1)[0]
    assert f"**Justification**: {justification}" in block


def markdown_summary_has_counts(
    markdown: str,
    tools: int,
    findings: int,
    per_severity_dict: dict[str, int],
) -> None:
    summary = summary_of(markdown)
    assert f"**Tools audited**: {tools}\n" in summary
    assert f"**Findings**: {findings}\n" in summary
    for severity, count in per_severity_dict.items():
        assert f"{count} {severity}" in summary


def markdown_includes_pass_without_severity(markdown: str) -> None:
    assert "PASS" in markdown
    for line in markdown.splitlines():
        if "PASS" in line:
            for severity_word in ["low", "medium", "high", "critical"]:
                assert severity_word not in line.lower()


def json_chain_has_owasp(json_str: str, category: str, expected_code: str) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for chain in tool_report.get("chains", []):
            result = chain.get("judge_result")
            if result and result["category"] == category:
                assert "owasp" in result, f"Expected owasp on chain judge_result for {category}"
                assert result["owasp"]["code"] == expected_code
                return
    raise AssertionError(f"No chain with category {category} found")


def tool_section(markdown: str, tool_name: str) -> str:
    sections = markdown.split("\n## ")
    return next(section for section in sections if section.startswith(tool_name))
