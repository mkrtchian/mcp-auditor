from evals.cell_grid import CellTag, GridBox, GridSection
from evals.gate import Cell


def box_of(sections: list[GridSection], cell: Cell) -> GridBox | None:
    tool, category = cell
    rows = [row for section in sections for row in section.rows if row.tool == tool]
    assert len(rows) == 1, f"expected one row for {tool}, found {len(rows)}"
    return rows[0].boxes[category]


def tag_of(sections: list[GridSection], cell: Cell) -> CellTag:
    box = box_of(sections, cell)
    assert box is not None, f"no box for {cell}"
    return box.tag
