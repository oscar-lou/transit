"""Tests for _heal_headers() - recovers a header cell corrupted at the
source (a real AIAGO_Workstation_CS.xlsx export had column 8's name replaced
with the literal number 0).
"""
import openpyxl

import consolidate_noncompliant as cnc

EXPECTED = ["gis_bu", "hostname", "install_status", "os", "last_seen", "agent_version",
            "proc_agent_installed", "proc_cs_version_status", "proc_agent_reporting",
            "Compliance", "report_date"]


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


def test_known_limitation_a_genuine_novel_rename_also_gets_healed():
    """Documents a real, accepted trade-off rather than hiding it: the guard
    can only tell 'reorder' apart from 'corruption' (both expected names
    present elsewhere in the row) - it CANNOT tell 'corruption' apart from 'a
    genuine rename to a brand-new name'. Both look identical: the actual
    value matches no expected column, and the expected name is otherwise
    absent from the row. So a deliberate upstream rename ('b' -> 'b_v2')
    gets silently rewritten back to 'b' here, same as real corruption would.
    If that ever needs to change, this test should fail first and make the
    trade-off an explicit decision, not a silent behavior change.
    """
    expected = ["a", "b", "c"]
    headers = ["a", "b_v2", "c"]
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
