"""End-to-end smoke test: runs generate_mock_data()'s fixtures through the
real pipeline (load_all -> resolve -> build_notifications), the same way
this was manually re-verified by hand after every change made to this file
in the past. Automates that manual "run --regen and eyeball the output"
workflow into assertions, so a future change can't silently reintroduce one
of the bugs already found and fixed:
  - the Terry-SP/Terry-CP Lau overlap-ranking bug
  - Zapp/DLP/CrowdStrike/BitLocker's unfiltered-export compliance gating

Server-kind coverage (worklist-only, never notified) no longer has a mock-
fixture source - the old aiago_server_cs entry relied on a file that no
longer exists under the current dated-CSV naming convention and was removed,
not merely renamed (see the "crowdstrike" FILE_REGISTRY comment). That
behavior itself is still directly covered at the unit level, independent of
any mock fixture, by test_build_notifications_skips_server_rows_directly
below.
"""
import os

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

    # WS-APAC-001 has findings from THREE different sources (CrowdStrike,
    # Zapp, Purview/DLP) - all must survive (dedup is keyed on (hostname,
    # source), so different sources for the same host are never deduped
    # against each other) and consolidate into ONE email, not one per source.
    ws001_sources = {r["source"] for g in groups.values() for r in g["rows"] if r["hostname"] == "WS-APAC-001"}
    assert ws001_sources == {"CrowdStrike", "Zapp", "Purview"}, (
        f"expected WS-APAC-001 to carry findings from all three sources, got {ws001_sources!r}")

    # DLP-only host (WS-APAC-006, no CrowdStrike finding) must still be picked up.
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

    # CrowdStrike's compliant mock row (WS-APAC-011, compliant="1") must be
    # gated out too - this source is unfiltered under the current real schema
    # (unlike the old, pre-filtered aiago_workstation_cs export it replaced).
    assert not any(r["hostname"] == "WS-APAC-011" for r in rows), (
        "REGRESSION: CrowdStrike's compliant row (WS-APAC-011) was not gated out - "
        "is_compliant_text() gating broke for the CrowdStrike source")

    # CrowdStrike's non-compliant rows all share the same real shape (agent
    # not installed - the only one observed in the real data) and must
    # classify accordingly.
    crowdstrike_rows = [r for r in rows if r["source"] == "CrowdStrike"]
    assert crowdstrike_rows, "test fixture sanity check - need at least one CrowdStrike finding"
    assert all(r["issue"] == "CrowdStrike agent not installed" for r in crowdstrike_rows), (
        f"REGRESSION: unexpected CrowdStrike issue text(s): "
        f"{ {r['issue'] for r in crowdstrike_rows} }")


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
