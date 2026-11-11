import io
import zipfile

from evals.cve.nuisance.fix_checks.excel_witness_workbook import workbook_holding


def test_the_workbook_holds_the_nonce_in_the_first_cell_of_the_named_sheet():
    archive = zipfile.ZipFile(io.BytesIO(workbook_holding("MCPAUDIT-abc123", "Data")))

    assert 'name="Data"' in archive.read("xl/workbook.xml").decode()
    assert "<t>MCPAUDIT-abc123</t>" in archive.read("xl/worksheets/sheet1.xml").decode()


def test_the_workbook_is_a_package_of_the_parts_a_reader_opens():
    archive = zipfile.ZipFile(io.BytesIO(workbook_holding("MCPAUDIT-abc123", "Data")))

    assert sorted(archive.namelist()) == [
        "[Content_Types].xml",
        "_rels/.rels",
        "xl/_rels/workbook.xml.rels",
        "xl/workbook.xml",
        "xl/worksheets/sheet1.xml",
    ]
