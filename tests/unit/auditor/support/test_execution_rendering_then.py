def markdown_has_no_confined_lines(markdown: str) -> None:
    for label in ("**Writable on host**", "**Read-only on host**", "**Killed on memory**"):
        assert label not in markdown
