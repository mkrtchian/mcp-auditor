def summary_of(markdown: str) -> str:
    return markdown.split("## Summary\n", 1)[1].split("\n## ", 1)[0]
