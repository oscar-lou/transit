"""Tests for _heal_headers() - recovers a header cell corrupted at the
source (a real AIAGO_Workstation_CS.xlsx export had column 8's name replaced
with the literal number 0).
"""
import openpyxl
import pytest

import consolidate_noncompliant as cnc

EXPECTED = ["gis_bu", "hostname", "install_status", "os", "last_seen", "agent_version",
            "proc_agent_installed", "proc_cs_version_status", "proc_agent_reporting",
            "Compliance", "report_date"]


@pytest.mark.parametrize("value,expected", [
    ("0", True), ("123", True), ("-1", True), ("3.14", True), ("", True), (None, True),
    ("proc_cs_version_status", False), ("b_v2", False), ("0x", False), ("a1", False),
])
def test_looks_like_corruption(value, expected):
    assert cnc._looks_like_corruption(value) is expected


def test_heals_the_real_world_corrupted_column():
    headers = list(EXPECTED)
    headers[7] = "0"  # the actual corruption seen in production
    assert cnc._heal_headers(headers, EXPECTED) == EXPECTED


def test_does_not_touch_a_clean_header_row():
    headers = list(EXPECTED)
    assert cnc._heal_headers(headers, EXPECTED) == headers


def test_does_not_clobber_a_genuine_two_column_reorder():
    """If two expected columns are simply swapped, both names are still
    present elsewhere in the row - the guard must leave a real reorder
    alone rather than 'fixing' it back to the original order."""
    expected = ["a", "b", "c"]
    headers = ["a", "c", "b"]
    assert cnc._heal_headers(headers, expected) == headers


def test_skips_when_column_count_differs():
    expected = ["a", "b", "c"]
    headers = ["a", "b"]
    assert cnc._heal_headers(headers, expected) == headers


def test_skips_when_no_expected_headers_given():
    headers = ["x", "y"]
    assert cnc._heal_headers(headers, None) == headers
    assert cnc._heal_headers(headers, []) == headers


def test_genuine_novel_rename_is_left_alone():
    """Regression for a real, previously-accepted trade-off: a value that
    still LOOKS like a plausible column name (has letters, e.g. a deliberate
    upstream rename 'b' -> 'b_v2') must NOT be healed back to the old name -
    that would silently mask the fact anything changed. Only genuinely
    corruption-shaped values (blank, or purely numeric - see
    _looks_like_corruption) get healed; see
    test_heals_the_real_world_corrupted_column and
    test_heals_a_blank_corrupted_column below for what still does."""
    expected = ["a", "b", "c"]
    headers = ["a", "b_v2", "c"]
    assert cnc._heal_headers(headers, expected) == headers, (
        "REGRESSION: a plausible rename got silently rewritten back to the old name")


def test_heals_a_blank_corrupted_column():
    """Blank is corruption-shaped too (no letters, can't be a real column
    name), same as the literal-number-0 case already covered above."""
    expected = ["a", "b", "c"]
    headers = ["a", "", "c"]
    assert cnc._heal_headers(headers, expected) == expected


def test_corrupted_header_end_to_end_still_classifies_correctly(tmp_path):
    """Drives a genuinely corrupted xlsx (column 8's header replaced with the
    literal number 0, exactly as seen in production) through the FULL read
    path - _read_xlsx_rows -> normalize_file -> cs_issue - and asserts the
    resulting finding is classified correctly, not blank. The heal function
    itself is already pinned in isolation above; this pins the downstream
    result, so a change that breaks the wiring between healing and
    classification (not just the heal itself) would be caught here.

    Uses FILE_REGISTRY's own column list (not the local EXPECTED constant)
    so this test can't silently drift from what normalize_file() actually
    expects.
    """
    columns = cnc.FILE_REGISTRY["aiago_workstation_cs"]["columns"]
    corrupted_headers = list(columns)
    corrupted_headers[7] = 0  # literal int, matching the real corruption openpyxl reads back
    data_row = ["AIAGO", "HHOWKLC-TEST01", "Installed", "Windows 11 Enterprise",
                "2026-07-01", "7.30.10", "Yes", "Outdated", "Yes", "Non-Compliant", "2026-07-01"]

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(corrupted_headers)
    ws.append(data_row)
    path = tmp_path / "AIAGO_Workstation_CS.xlsx"
    wb.save(path)

    rows = cnc.normalize_file(str(path), registry_key="aiago_workstation_cs")

    assert len(rows) == 1, f"expected exactly one normalized row, got {rows!r}"
    assert rows[0]["issue"] == "CrowdStrike agent outdated", (
        f"REGRESSION: header self-heal did not propagate to correct "
        f"classification - got issue={rows[0]['issue']!r}")
    assert rows[0]["issue"] != "CrowdStrike status not reported", (
        "REGRESSION: corrupted header caused cs_reason to read as blank")
