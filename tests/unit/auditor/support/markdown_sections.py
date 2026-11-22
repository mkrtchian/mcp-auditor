def section_of(markdown: str, heading: str) -> str:
    sections = (part.split("\n", 1) for part in markdown.split("\n## ")[1:])
    return next(body for title, body in sections if title == heading)
