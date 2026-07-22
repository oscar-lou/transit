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
import os

import openpyxl

import consolidate_noncompliant as cnc


def _run_pipeline():
    rows = cnc.load_all()
    cmdb_names = cnc.read_cmdb_mapping()
    ad = cnc.read_ad_users()
    overrides = cnc.read_overrides()
    groups, review, unresolved = cnc.build_notifications(rows, cmdb_names, ad, overrides)
    return rows, groups, review, unresolved


def test_full_pipeline_against_mock_fixtures(data_and_output_dir):
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

    # DLP's compliant mock row (WS-APAC-007, compliance="Compliant") must be
    # gated out by is_compliant_text() before it ever becomes a finding - it
    # should never even reach `rows`, let alone groups/review/unresolved.
    assert not any(r["hostname"] == "WS-APAC-007" for r in rows), (
        "REGRESSION: DLP's Compliant row (WS-APAC-007) was not gated out - "
        "is_compliant_text() gating broke for the DLP source")

    # BitLocker's compliant mock row (WS-APAC-008, compliant="Compliant") must
    # likewise be gated out before it ever becomes a finding.
    assert not any(r["hostname"] == "WS-APAC-008" for r in rows), (
        "REGRESSION: BitLocker's Compliant row (WS-APAC-008) was not gated out - "
        "is_compliant_text() gating broke for the BitLocker source")

    # BitLocker's two non-compliant shapes must each become a finding with the
    # right issue text - not just "any finding".
    bitlocker_rows = [r for r in rows if r["source"] == "BitLocker"]
    assert any(r["hostname"] == "WS-APAC-009"
               and r["issue"] == "BitLocker drive encryption not enabled"
               for r in bitlocker_rows), "WS-APAC-009 (notEncrypted) misclassified"
    assert any(r["hostname"] == "WS-APAC-010"
               and r["issue"] == "BitLocker status not reported"
               for r in bitlocker_rows), "WS-APAC-010 (no telemetry) misclassified"

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


def test_ambiguous_name_lands_in_review_and_never_in_groups():
    """The most important safety invariant: exercises build_notifications()'s
    ACTUAL review/groups routing - not just resolve_name_to_email() in
    isolation, which is already covered elsewhere (test_name_resolution.py::
    test_genuine_tie_goes_to_review_not_guessed). A genuinely ambiguous name
    (two real AD people both 'Smith, Robert', tying on surname+given) must
    never be guessed into the send set. If 'elif conf == "low":
    review.append(...)' in build_notifications() were ever changed to add to
    groups instead (or as well), this test fails."""
    ad = {
        "exact": {},
        "by_surname": {
            "smith": [
                {"disp": "Smith, Robert-RA", "email": "robert.a.smith@example.com",
                 "given": {"robert"}},
                {"disp": "Smith, Robert-RB", "email": "robert.b.smith@example.com",
                 "given": {"robert"}},
            ],
        },
    }
    rows = [{
        "kind": "Workstation", "hostname": "MAC-AMS-22", "bu": "AMS-Corp",
        "source": "CrowdStrike", "issue": "x", "action": "y",
        "assigned_to": "Smith, Robert",
    }]

    groups, review, unresolved = cnc.build_notifications(rows, {}, ad, {})

    assert groups == {}, (
        f"REGRESSION: ambiguous name reached the send set - got groups={groups!r}")
    assert unresolved == [], (
        f"ambiguous-but-real name should go to review, not unresolved - got {unresolved!r}")
    assert len(review) == 1, f"expected exactly one review entry, got {review!r}"
    r, how, cands = review[0]
    assert r["hostname"] == "MAC-AMS-22"
    assert set(cands) == {"robert.a.smith@example.com", "robert.b.smith@example.com"}, (
        f"expected both tied candidates listed for review, got {cands!r}")


def test_write_html_preview_renders_all_recipients(data_and_output_dir):
    """write_html_preview() must produce a real, openable HTML file covering
    every confidently-resolved recipient - the whole point is being able to
    eyeball the rendered formatting before any real send."""
    cnc.generate_mock_data()
    rows, groups, review, unresolved = _run_pipeline()
    assert groups, "test fixture sanity check - need at least one recipient"

    path = cnc.write_html_preview(groups)
    assert os.path.exists(path)

    content = open(path, encoding="utf-8").read()
    assert content.startswith("<!doctype html>")
    for email in groups:
        assert cnc.html.escape(email) in content, (
            f"HTML preview is missing recipient {email!r}")
