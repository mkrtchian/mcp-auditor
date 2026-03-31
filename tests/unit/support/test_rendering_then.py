import json


def json_round_trips(json_str: str, expected_tool_count: int) -> None:
    data = json.loads(json_str)
    assert len(data["tool_reports"]) == expected_tool_count
    assert "token_usage" in data


def json_has_enum_strings(json_str: str) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for case in tool_report["cases"]:
            result = case["eval_result"]
            if result is None:
                continue
            assert isinstance(result["verdict"], str)
            assert isinstance(result["severity"], str)
            assert result["verdict"] == result["verdict"].lower()
            assert result["severity"] == result["severity"].lower()


def json_has_owasp_for_category(
    json_str: str,
    category: str,
    expected_code: str,
    expected_title: str,
) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for case in tool_report["cases"]:
            result = case["eval_result"]
            if result and result["category"] == category:
                assert result["owasp"]["code"] == expected_code
                assert result["owasp"]["title"] == expected_title
                return
    raise AssertionError(f"No result with category {category} found")


def json_has_no_owasp(json_str: str) -> None:
    data = json.loads(json_str)
    for tool_report in data["tool_reports"]:
        for case in tool_report["cases"]:
            result = case["eval_result"]
            if result:
                assert "owasp" not in result


def markdown_contains_tool_headings(markdown: str, tool_names: list[str]) -> None:
    for name in tool_names:
        assert f"## {name}" in markdown


def markdown_contains_finding(
    markdown: str,
    category: str,
    severity: str,
    justification_fragment: str,
) -> None:
    assert category in markdown
    assert severity in markdown
    assert justification_fragment in markdown


def markdown_summary_has_counts(
    markdown: str,
    tools: int,
    findings: int,
    per_severity_dict: dict[str, int],
) -> None:
    assert str(tools) in markdown
    assert str(findings) in markdown
    for severity, count in per_severity_dict.items():
        assert f"{count} {severity}" in markdown


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
            result = chain.get("eval_result")
            if result and result["category"] == category:
                assert "owasp" in result, f"Expected owasp on chain eval_result for {category}"
                assert result["owasp"]["code"] == expected_code
                return
    raise AssertionError(f"No chain with category {category} found")
