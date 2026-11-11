"""The scratch workbook of the excel-mcp-server fix check: one sheet whose A1 holds the nonce.

Written with the standard library, a zip of the five parts a spreadsheet reader needs, because
the fix check runs on the host, where no spreadsheet library is installed. The cell is an inline
string, which openpyxl reads like a shared one.
"""

import io
import zipfile

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_PACKAGE = "http://schemas.openxmlformats.org/package/2006"
_OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_RELATIONSHIPS_TYPE = "application/vnd.openxmlformats-package.relationships+xml"
_SHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml"


def workbook_holding(nonce: str, sheet: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in _parts(nonce, sheet).items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _parts(nonce: str, sheet: str) -> dict[str, str]:
    return {
        "[Content_Types].xml": (
            f'<Types xmlns="{_PACKAGE}/content-types">'
            f'<Default Extension="rels" ContentType="{_RELATIONSHIPS_TYPE}"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" ContentType="{_SHEET_TYPE}.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" '
            f'ContentType="{_SHEET_TYPE}.worksheet+xml"/></Types>'
        ),
        "_rels/.rels": _relationship("officeDocument", "xl/workbook.xml"),
        "xl/workbook.xml": (
            f'<workbook xmlns="{_MAIN}" xmlns:r="{_OFFICE}">'
            f'<sheets><sheet name="{sheet}" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": _relationship("worksheet", "worksheets/sheet1.xml"),
        "xl/worksheets/sheet1.xml": (
            f'<worksheet xmlns="{_MAIN}"><sheetData><row r="1">'
            f'<c r="A1" t="inlineStr"><is><t>{nonce}</t></is></c></row></sheetData></worksheet>'
        ),
    }


def _relationship(kind: str, target: str) -> str:
    return (
        f'<Relationships xmlns="{_PACKAGE}/relationships">'
        f'<Relationship Id="rId1" Type="{_OFFICE}/{kind}" Target="{target}"/></Relationships>'
    )
