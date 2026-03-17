import json


def json_round_trips(json_str: str, expected_tool_count: int) -> None:
    data = json.loads(json_str)
    assert len(data["tool_reports"]) == expected_tool_count
    assert "token_usage" in data


def json_has_enum_strings(json_str: str) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for result in tool_report["results"]:
            assert isinstance(result["verdict"], str)
            assert isinstance(result["severity"], str)
            assert result["verdict"] == result["verdict"].lower()
            assert result["severity"] == result["severity"].lower()


def markdown_contains_tool_headings(md: str, tool_names: list[str]) -> None:
    for name in tool_names:
        assert f"## {name}" in md


def markdown_contains_finding(
    md: str,
    category: str,
    severity: str,
    justification_fragment: str,
) -> None:
    assert category in md
    assert severity in md
    assert justification_fragment in md


def markdown_summary_has_counts(
    md: str,
    tools: int,
    findings: int,
    per_severity_dict: dict[str, int],
) -> None:
    assert str(tools) in md
    assert str(findings) in md
    for severity, count in per_severity_dict.items():
        assert f"{count} {severity}" in md


def markdown_includes_pass_without_severity(md: str) -> None:
    assert "PASS" in md
    for line in md.splitlines():
        if "PASS" in line:
            for severity_word in ["low", "medium", "high", "critical"]:
                assert severity_word not in line.lower()
