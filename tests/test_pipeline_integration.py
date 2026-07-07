"""End-to-end smoke test: runs generate_mock_data()'s fixtures through the
real pipeline (load_all -> resolve -> build_notifications), the same way
this was manually re-verified by hand after every change made to this file
in the past. Automates that manual "run --regen and eyeball the output"
workflow into assertions, so a future change can't silently reintroduce one
of the bugs already found and fixed:
  - the Terry-SP/Terry-CP Lau overlap-ranking bug
  - Zapp/DLP's unfiltered-export compliance gating
  - the DLP/Purview cross-source dedup
  - servers staying in the worklist but out of notifications
"""
import openpyxl

import consolidate_noncompliant as cnc


def _run_pipeline():
    rows = cnc.load_all()
    cmdb_names = cnc.read_cmdb_mapping()
    ad = cnc.read_ad_users()
    overrides = cnc.read_overrides()
    groups, review, unresolved = cnc.build_notifications(rows, cmdb_names, ad, overrides)
    return rows, groups, review, unresolved


def test_full_pipeline_against_mock_fixtures(tmp_path, monkeypatch):
    monkeypatch.setattr(cnc, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(cnc, "OUTPUT_DIR", str(tmp_path / "output"))

    cnc.generate_mock_data()
    rows, groups, review, unresolved = _run_pipeline()

    # Terry-SP Lau: must resolve cleanly despite 'Terry-CP Lau' sharing "terry".
    assert "terry-sp.lau@example.com" in groups

    # Zapp's compliant mock row (WS-EMEA-030) must never generate a finding.
    zapp_hosts = {r["hostname"] for g in groups.values() for r in g["rows"] if r["source"] == "Zapp"}
    assert "WS-EMEA-030" not in zapp_hosts

    # DLP dedup: WS-APAC-001 has the same finding in both AIAGO_Windows_Purview
    # and DLP_Deployment mocks - must be counted once, not twice.
    ws001_purview = [r for g in groups.values() for r in g["rows"]
                     if r["hostname"] == "WS-APAC-001" and r["source"] == "Purview"]
    assert len(ws001_purview) == 1

    # DLP-only host (WS-APAC-006, never in the thinner Purview exports) must
    # still be picked up.
    assert any(r["hostname"] == "WS-APAC-006"
               for g in groups.values() for r in g["rows"])

    # Servers must never reach groups/review/unresolved.
    server_hosts = {"SRV-EMEA-DB01", "SRV-AMS-APP3", "SRV-EMEA-VDI9"}
    assert not any(r["hostname"] in server_hosts for g in groups.values() for r in g["rows"])
    assert not any(r["hostname"] in server_hosts for r, how, cands in review)
    assert not any(r["hostname"] in server_hosts for r, how in unresolved)

    # ...but servers DO still appear in the worklist for visibility.
    worklist_path = cnc.write_worklist(rows)
    wb = openpyxl.load_workbook(worklist_path, read_only=True, data_only=True)
    ws = wb["Worklist"]
    worklist_hostnames = {row[1] for row in ws.iter_rows(values_only=True, min_row=2)}
    assert server_hosts <= worklist_hostnames


def test_build_notifications_skips_server_rows_directly():
    """Narrower unit-level check of the same server-skip, independent of the
    mock fixtures, so it still pins the behavior if the fixtures change."""
    rows = [
        {"kind": "Server", "hostname": "SRV1", "bu": "AIAGO", "source": "CrowdStrike",
         "issue": "x", "action": "y", "assigned_to": ""},
        {"kind": "Workstation", "hostname": "WS1", "bu": "AIAGO", "source": "CrowdStrike",
         "issue": "x", "action": "y", "assigned_to": "a@b.com"},
    ]
    ad = {"exact": {}, "by_surname": {}}
    groups, review, unresolved = cnc.build_notifications(rows, {}, ad, {})

    assert "a@b.com" in groups
    all_seen_hosts = ({r["hostname"] for g in groups.values() for r in g["rows"]}
                       | {r["hostname"] for r, how, cands in review}
                       | {r["hostname"] for r, how in unresolved})
    assert "SRV1" not in all_seen_hosts
