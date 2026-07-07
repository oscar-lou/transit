"""Tests for find_dataset()'s filename/sheet-tab matching. Includes tests
that PIN a real, demonstrated limitation (substring matching can false-
positive on an unrelated file, or silently miss a renamed one) rather than
hiding it - so a future fix to the matching strategy is a deliberate,
visible change to these tests, not a silent behavior shift.
"""
import openpyxl
import pytest

import consolidate_noncompliant as cnc


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cnc, "DATA_DIR", str(tmp_path))
    return tmp_path


def _write_blank_xlsx(path) -> None:
    """A real (if empty) xlsx file - needed even for filename-only match
    tests, because find_dataset() falls back to actually opening every
    .xlsx in data/ with openpyxl when no filename matches, so a fake/empty
    byte string raises BadZipFile instead of just failing to match."""
    openpyxl.Workbook().save(path)


def test_matches_by_filename_substring(data_dir):
    _write_blank_xlsx(data_dir / "AIAGO_Workstation_CS.xlsx")
    path, sheet = cnc.find_dataset("aiago_workstation_cs")
    assert path.endswith("AIAGO_Workstation_CS.xlsx")
    assert sheet is None


def test_returns_none_when_nothing_matches(data_dir):
    _write_blank_xlsx(data_dir / "Totally_Unrelated_File.xlsx")
    assert cnc.find_dataset("aiago_workstation_cs") is None


def test_renaming_a_known_file_makes_it_invisible(data_dir):
    """A real risk: renaming AIAGO_Workstation_CS.xlsx to something that no
    longer contains 'aiago_workstation_cs' as a substring makes the whole
    report vanish from the pipeline with no error - just a console
    '! not found' line in load_all(). This test documents that behavior."""
    _write_blank_xlsx(data_dir / "AIAGO_Workstation_CrowdStrike_Report.xlsx")
    assert cnc.find_dataset("aiago_workstation_cs") is None


def test_false_positive_on_coincidental_filename_substring(data_dir):
    """A real, demonstrated risk: short registry keys like 'dlp' match ANY
    filename containing that substring, even an unrelated file. Whichever
    file os.listdir() happens to return first for a shared substring wins -
    not necessarily the real report."""
    _write_blank_xlsx(data_dir / "Random_DLP_Meeting_Notes.xlsx")
    found = cnc.find_dataset("dlp")
    assert found is not None
    assert "Random_DLP_Meeting_Notes" in found[0]


def test_matches_a_sheet_inside_a_multi_tab_workbook(data_dir):
    """When no filename matches, find_dataset() falls back to checking sheet
    names inside every .xlsx in data/ (e.g. CompliantReport(Working).xlsx's
    'CMDB' and 'AD_Users' tabs)."""
    wb = openpyxl.Workbook()
    wb.active.title = "26May"
    wb.create_sheet("CMDB")
    wb.create_sheet("AD_Users")
    wb.save(data_dir / "CompliantReport(Working).xlsx")

    path, sheet = cnc.find_dataset("cmdb")
    assert sheet == "CMDB"

    path, sheet = cnc.find_dataset("ad_users")
    assert sheet == "AD_Users"


def test_standalone_file_takes_priority_over_a_sheet_match(data_dir):
    """load_all()'s documented priority: a standalone file wins over a sheet
    living inside some other workbook, checked first (filename pass happens
    before the sheet-tab pass)."""
    (data_dir / "CMDB_Mapping.xlsx").write_bytes(b"")
    wb = openpyxl.Workbook()
    wb.create_sheet("CMDB")
    wb.save(data_dir / "Other_Workbook.xlsx")

    path, sheet = cnc.find_dataset("cmdb")
    assert path.endswith("CMDB_Mapping.xlsx")
    assert sheet is None
