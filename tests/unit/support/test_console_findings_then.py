def summary_row_reads(output: str, tool_name: str, expected_cells: list[str]) -> None:
    (row,) = [line for line in output.splitlines() if f" {tool_name} " in line]
    cells = [cell.strip() for cell in row.split("│") if cell.strip()]
    assert cells == expected_cells


def findings_recap_reads(output: str, expected_lines: list[str]) -> None:
    inner_lines = output.splitlines()[1:-1]
    lines = [line.strip("│ ") for line in inner_lines if line.strip("│ ")]
    assert lines == expected_lines
