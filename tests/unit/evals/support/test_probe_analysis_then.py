def lists_defects(defects: list[str], *words: str) -> None:
    assert any(all(word in defect for word in words) for defect in defects), defects
