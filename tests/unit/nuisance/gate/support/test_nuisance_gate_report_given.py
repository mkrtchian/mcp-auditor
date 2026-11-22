import itertools


def row_of(markdown: str, package: str) -> str:
    [row] = [line for line in markdown.splitlines() if line.startswith(f"| {package} |")]
    return row


def section(markdown: str, header: str) -> list[str]:
    lines = markdown.splitlines()
    start = lines.index(header) + 1
    return list(itertools.takewhile(bool, lines[start:]))
