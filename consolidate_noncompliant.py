#!/usr/bin/env python3
"""
Non-compliant report -> per-recipient notification builder.

Pipeline:
  1. Read the several attached .xlsx reports (CrowdStrike + Purview, across
     workstation / server / Mac), which use different column names for the
     same things, and reconcile them into ONE canonical worklist.
  2. Resolve WHO to notify for each finding:
       - workstation: assigned_to (Purview) -> else CMDB hostname->email lookup
       - server:      BU admin/team address (servers have no end user)
  3. Consolidate per recipient (one message per person, not one per file) and
     compose an Outlook email + a Teams message.
  4. STUB the send: write a preview workbook of exactly what would go out.
     Real Outlook/Teams sending via Microsoft Graph is wired in later, once a
     service account with Mail.Send (and Teams send) permission exists.

Inputs (drop into data/, .xlsx or .csv):
  - the 5 report files (AIAGO_*_CS.xlsx / AIAGO_*_Purview.xlsx)
  - a CMDB export named like 'CMDB_Mapping.xlsx' (hostname -> user email) to
    resolve hosts that carry no assigned_to. Without it, those hosts show up
    as UNRESOLVED so you know precisely what's missing.

Outputs (in output/):
  - noncompliant_consolidated.xlsx   (Worklist + BU Summary)
  - notifications_preview.xlsx       (Notifications + Unresolved)  <- nothing sent

Run:
  python consolidate_noncompliant.py            # read data/, build outputs
  python consolidate_noncompliant.py --regen    # rewrite mock data first
"""

from __future__ import annotations

import csv
import os
import sys
from datetime import datetime, date

try:
    import openpyxl
    HAVE_XLSX = True
except ImportError:
    HAVE_XLSX = False


# ===========================================================================
# CONFIG
# ===========================================================================

DATA_DIR = os.environ.get("COMPLIANCE_DATA_DIR", "data")
OUTPUT_DIR = os.environ.get("COMPLIANCE_OUTPUT_DIR", "output")

CS_LATEST = {"windows": "7.35.20709", "mac": "7.35.20704", "linux": "7.35.18803"}
PURVIEW_LATEST = {
    "windows": {"mocamp": "4.18.26040.7", "engine": "1.1.26020.3"},
    "macos": {"mocamp": "101.26042.0020", "engine": "not tracked"},
}

# --- notification settings -------------------------------------------------
REMEDIATION_DAYS = 5            # SLA from the CrowdStrike email
FROM_TEAM = "IT Compliance"     # appears in the message signature

# Host -> user email lookup that does NOT arrive in the vendor files. Drop a
# CMDB export into data/ named like 'CMDB_Mapping.xlsx' with these columns; it
# fills the gap for CS-only / Mac-Purview hosts that have no assigned_to.
CMDB_MAPPING = {
    "stem": "cmdb_mapping",
    "map": {"hostname": "Host Name", "email": "Assigned User Email"},
}

# Servers have no end user -> route to a BU admin/team address. Maintained by
# whoever owns BU routing; a missing BU means that server is reported as
# UNRESOLVED rather than mis-sent. Fill in real addresses.
BU_TEAM_EMAIL = {
    "APAC-Retail": "apac-it@example.com",
    "EMEA-Ops": "emea-it@example.com",
    "AMS-Corp": "ams-it@example.com",
}


# ===========================================================================
# FILE REGISTRY
# One entry per known report. `meta` records what the file IS; `map` translates
# that file's column names -> our canonical field names. New report -> new
# entry, nothing else changes. Matching is by filename stem, case-insensitive.
# ===========================================================================

FILE_REGISTRY = {
    "aiago_workstation_cs": {
        "meta": {"source": "CrowdStrike", "platform": "Windows", "kind": "Workstation"},
        "map": {
            "bu": "gis_bu", "hostname": "hostname", "install_status": "install_status",
            "os": "os", "last_seen": "last_seen", "agent_version": "agent_version",
            "cs_reason": "proc_cs_version_status",
            "compliance": "Compliance", "report_date": "report_date",
        },
    },
    "aiago_mac_cs": {
        "meta": {"source": "CrowdStrike", "platform": "Mac", "kind": "Workstation"},
        "map": {
            "bu": "BU", "hostname": "computer_name", "os": "os_version",
            "last_seen": "last_seen", "cs_reason": "proc_cs_version_status",
            "compliance": "Compliance", "report_date": "report_date",
        },
    },
    "aiago_server_cs": {
        "meta": {"source": "CrowdStrike", "platform": None, "kind": "Server"},  # platform from ser_os
        "map": {
            "bu": "gis_bu", "hostname": "ser_name", "install_status": "ser_install_status",
            "sys_class": "ser_sys_class_name", "os": "ser_os", "last_seen": "last_seen",
            "agent_version": "agent_version", "cs_reason": "proc_cs_version_status",
            "compliance": "Compliance", "report_date": "report_date",
        },
    },
    "aiago_windows_purview": {
        "meta": {"source": "Purview", "platform": "Windows", "kind": "Workstation"},
        "map": {
            "bu": "gis_bu", "hostname": "name", "install_status": "install_status",
            "os": "os", "assigned_to": "assigned_to", "last_seen": "purview_last_seen",
            "mocamp_version": "purview_defender_mocamp_version",
            "engine_version": "purview_defender_engine_version",
            "config_status": "purview_configuration_status",
            "policy_status": "purview_policy_status",
            "compliance": "compliance", "report_date": "report_date",
        },
    },
    "aiago_mac_purview": {
        "meta": {"source": "Purview", "platform": "Mac", "kind": "Workstation"},
        "map": {
            "bu": "gis_bu", "hostname": "intune_computer_name",
            "last_seen": "purview_last_seen", "last_sync": "purview_last_policy_sync_time",
            "mocamp_version": "purview_defender_mocamp_version",
            "engine_version": "purview_defender_engine_version",
            "config_status": "purview_configuration_status",
            "policy_status": "purview_policy_status",
            "compliance": "compliance", "report_date": "report_date",
        },
    },
}

CANON_COLUMNS = [
    "bu", "hostname", "source", "platform", "kind",
    "issue", "action", "detail",
    "last_seen", "assigned_to", "compliance", "report_date", "source_file",
]


# ===========================================================================
# CELL HELPERS + FILE I/O
# ===========================================================================

def cell_to_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.date().isoformat()
    if isinstance(v, date):
        return v.isoformat()
    return str(v).strip()


def _read_csv_rows(path: str) -> list:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _read_xlsx_rows(path: str) -> list:
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    it = ws.iter_rows(values_only=True)
    try:
        headers = [cell_to_str(h) for h in next(it)]
    except StopIteration:
        wb.close()
        return []
    out = []
    for row in it:
        if row is None or all(c is None for c in row):
            continue
        out.append({h: (row[i] if i < len(row) else None) for i, h in enumerate(headers)})
    wb.close()
    return out


def _read_any(path: str) -> list:
    return _read_xlsx_rows(path) if path.lower().endswith(".xlsx") else _read_csv_rows(path)


# ===========================================================================
# REASON -> ISSUE + ACTION
# ===========================================================================

def cs_issue(reason: str) -> tuple:
    r = (reason or "").strip().lower()
    if r == "unknown":
        return ("CrowdStrike agent not installed",
                "Install the CrowdStrike sensor (latest from the Prod share)")
    if r == "outdated":
        return ("CrowdStrike agent outdated",
                f"Update sensor to latest (Win {CS_LATEST['windows']} / "
                f"Mac {CS_LATEST['mac']} / Linux {CS_LATEST['linux']})")
    if r == "latest":
        return ("Agent current but NOT reporting",
                "Check network connectivity / power the machine on so it reports")
    return (f"CrowdStrike status: {reason}", "Refer to remediation guidance")


def purview_issue(config_status: str, policy_status: str) -> tuple:
    # NOTE: exact vocabulary of these two columns not yet confirmed. We surface
    # both raw values and give the email's generic action; tighten once seen.
    detail = f"config={config_status or 'n/a'}, policy={policy_status or 'n/a'}"
    return ("Purview DLP not compliant",
            "Check 'Purview DLP Enrollment' in Software Center; follow Onboarding/Troubleshooting deck",
            detail)


# ===========================================================================
# LOAD + NORMALIZE
# ===========================================================================

def _match_registry(stem: str):
    key = stem.lower()
    if key in FILE_REGISTRY:
        return key, FILE_REGISTRY[key]
    for rk, entry in FILE_REGISTRY.items():
        if key.startswith(rk) or rk in key:
            return rk, entry
    return None, None


def _platform_from_os(os_text: str) -> str:
    t = (os_text or "").lower()
    if "win" in t:
        return "Windows"
    if "mac" in t or "osx" in t or "darwin" in t:
        return "Mac"
    if "linux" in t or "rhel" in t or "ubuntu" in t or "centos" in t:
        return "Linux"
    return "Unknown"


def normalize_file(path: str) -> list:
    stem = os.path.splitext(os.path.basename(path))[0]
    rk, entry = _match_registry(stem)
    if not entry:
        print(f"  ! skipped (unknown report): {os.path.basename(path)}")
        return []

    cmap, meta = entry["map"], entry["meta"]
    rows = []
    for raw in _read_any(path):
        f = {canon: cell_to_str(raw.get(col, "")) for canon, col in cmap.items()}
        platform = meta["platform"] or _platform_from_os(f.get("os"))
        if meta["source"] == "CrowdStrike":
            issue, action = cs_issue(f.get("cs_reason"))
            detail = f"reason={f.get('cs_reason') or 'n/a'}"
            if f.get("agent_version"):
                detail += f", agent={f['agent_version']}"
        else:
            issue, action, detail = purview_issue(f.get("config_status"), f.get("policy_status"))

        rows.append({
            "bu": f.get("bu") or "(no BU)",
            "hostname": f.get("hostname"),
            "source": meta["source"],
            "platform": platform,
            "kind": meta["kind"],
            "issue": issue,
            "action": action,
            "detail": detail,
            "last_seen": f.get("last_seen"),
            "assigned_to": f.get("assigned_to", ""),
            "compliance": f.get("compliance"),
            "report_date": f.get("report_date"),
            "source_file": os.path.basename(path),
        })
    print(f"  + {os.path.basename(path):32s} {len(rows):4d} rows  [{meta['source']}/{meta['kind']}]")
    return rows


def load_all() -> list:
    skip = CMDB_MAPPING["stem"]
    files = sorted(f for f in os.listdir(DATA_DIR)
                   if f.lower().endswith((".xlsx", ".csv"))
                   and skip not in os.path.splitext(f)[0].lower())
    all_rows = []
    print(f"Reading reports from '{DATA_DIR}/':")
    for name in files:
        all_rows.extend(normalize_file(os.path.join(DATA_DIR, name)))
    return all_rows


# ===========================================================================
# CONSOLIDATED WORKLIST OUTPUT
# ===========================================================================

def summarize_by_bu(rows: list) -> dict:
    bus = {}
    for r in rows:
        b = bus.setdefault(r["bu"], {"total": 0, "CrowdStrike": 0, "Purview": 0,
                                     "Workstation": 0, "Server": 0})
        b["total"] += 1
        b[r["source"]] = b.get(r["source"], 0) + 1
        b[r["kind"]] = b.get(r["kind"], 0) + 1
    return dict(sorted(bus.items()))


def write_worklist(rows: list) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not HAVE_XLSX:
        path = os.path.join(OUTPUT_DIR, "noncompliant_consolidated.csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CANON_COLUMNS)
            w.writeheader()
            for r in sorted(rows, key=lambda x: (x["bu"], x["source"], x["hostname"])):
                w.writerow({c: r.get(c, "") for c in CANON_COLUMNS})
        return path

    path = os.path.join(OUTPUT_DIR, "noncompliant_consolidated.xlsx")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Worklist"
    ws.append([c.replace("_", " ").title() for c in CANON_COLUMNS])
    for r in sorted(rows, key=lambda x: (x["bu"], x["source"], x["hostname"])):
        ws.append([r.get(c, "") for c in CANON_COLUMNS])
    ws.freeze_panes = "A2"

    summary = wb.create_sheet("BU Summary")
    summary.append(["Business Unit", "Total", "CrowdStrike", "Purview", "Workstation", "Server"])
    for bu, s in summarize_by_bu(rows).items():
        summary.append([bu, s["total"], s["CrowdStrike"], s["Purview"], s["Workstation"], s["Server"]])
    summary.freeze_panes = "A2"
    wb.save(path)
    return path


# ===========================================================================
# RECIPIENT RESOLUTION
# ===========================================================================

def read_cmdb_mapping() -> dict:
    """hostname (UPPER) -> user email, from a CMDB export dropped into data/."""
    if not os.path.isdir(DATA_DIR):
        return {}
    stem = CMDB_MAPPING["stem"]
    m = CMDB_MAPPING["map"]
    for f in os.listdir(DATA_DIR):
        base = os.path.splitext(f)[0].lower()
        if base.startswith(stem) or stem in base:
            out = {}
            for raw in _read_any(os.path.join(DATA_DIR, f)):
                host = cell_to_str(raw.get(m["hostname"], "")).upper()
                email = cell_to_str(raw.get(m["email"], ""))
                if host and "@" in email:
                    out[host] = email
            return out
    return {}


def resolve_recipient(row: dict, cmdb_map: dict) -> tuple:
    """Return (email_or_None, how)."""
    if row["kind"] == "Server":
        email = BU_TEAM_EMAIL.get(row["bu"])
        if email:
            return email, "team (BU admin)"
        return None, "unresolved: server, no BU team email"
    at = (row.get("assigned_to") or "").strip()
    if "@" in at:
        return at, "user (assigned_to)"
    host = (row.get("hostname") or "").strip().upper()
    if host in cmdb_map:
        return cmdb_map[host], "user (CMDB)"
    return None, "unresolved: no assigned_to, not in CMDB"


# ===========================================================================
# MESSAGE COMPOSITION  (one consolidated message per recipient)
# ===========================================================================

def compose_email(findings: list) -> tuple:
    by_host = {}
    for f in findings:
        by_host.setdefault(f["hostname"], []).append(f)

    subject = f"Action required: {len(by_host)} device(s) need compliance remediation"
    lines = ["Hello,", "",
             f"The following device(s) associated with you are currently flagged "
             f"non-compliant and need remediation within {REMEDIATION_DAYS} business days:", ""]
    for host, fs in by_host.items():
        lines.append(f"* {host}  ({fs[0]['platform']} {fs[0]['kind']})")
        for f in fs:
            lines.append(f"    - [{f['source']}] {f['issue']}  ->  {f['action']}")
        lines.append("")
    lines += ["If a device has been decommissioned or reimaged, please have the "
              "CMDB inventory updated so it stops appearing on this report.", "",
              "Thank you,", FROM_TEAM]
    return subject, "\n".join(lines)


def compose_teams(findings: list) -> str:
    hosts = sorted({f["hostname"] for f in findings})
    items = "; ".join(f"{f['hostname']} ({f['issue']})" for f in findings[:5])
    more = "" if len(findings) <= 5 else f" (+{len(findings) - 5} more finding(s))"
    return (f"You have {len(hosts)} non-compliant device(s) needing attention within "
            f"{REMEDIATION_DAYS} business days: {items}{more}. "
            f"See the email for full remediation steps.")


def build_notifications(rows: list, cmdb_map: dict) -> tuple:
    groups, unresolved = {}, []
    for r in rows:
        email, how = resolve_recipient(r, cmdb_map)
        if not email:
            unresolved.append((r, how))
            continue
        g = groups.setdefault(email, {"how": how, "rows": []})
        g["rows"].append(r)
    return groups, unresolved


def write_notifications_preview(groups: dict, unresolved: list) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not HAVE_XLSX:
        path = os.path.join(OUTPUT_DIR, "notifications_preview.csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Recipient", "ResolvedBy", "Hosts", "Findings", "EmailSubject", "EmailBody", "TeamsMessage"])
            for email, g in sorted(groups.items()):
                subj, body = compose_email(g["rows"])
                hosts = len({r["hostname"] for r in g["rows"]})
                w.writerow([email, g["how"], hosts, len(g["rows"]), subj, body, compose_teams(g["rows"])])
        return path

    path = os.path.join(OUTPUT_DIR, "notifications_preview.xlsx")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Notifications"
    ws.append(["Recipient", "Resolved By", "Hosts", "Findings", "Email Subject", "Email Body", "Teams Message"])
    for email, g in sorted(groups.items()):
        subj, body = compose_email(g["rows"])
        hosts = len({r["hostname"] for r in g["rows"]})
        ws.append([email, g["how"], hosts, len(g["rows"]), subj, body, compose_teams(g["rows"])])
    ws.freeze_panes = "A2"

    ur = wb.create_sheet("Unresolved")
    ur.append(["Hostname", "Source", "Platform", "Kind", "BU", "Reason no recipient"])
    for r, how in unresolved:
        ur.append([r["hostname"], r["source"], r["platform"], r["kind"], r["bu"], how])
    ur.freeze_panes = "A2"
    wb.save(path)
    return path


def print_notify_summary(groups: dict, unresolved: list, cmdb_map: dict) -> None:
    by_how = {}
    for g in groups.values():
        by_how[g["how"]] = by_how.get(g["how"], 0) + 1
    print("\n" + "#" * 72)
    print(f"# {len(groups)} recipient(s) to notify   |   {len(unresolved)} finding(s) UNRESOLVED")
    print(f"# CMDB mapping entries loaded: {len(cmdb_map)}")
    print("#" * 72)
    for how, n in sorted(by_how.items()):
        print(f"  {n:3d} recipient(s) resolved by {how}")
    if unresolved:
        print("\n  UNRESOLVED (no recipient - need CMDB mapping or a BU team email):")
        for r, how in unresolved:
            print(f"    - {r['hostname']:16s} {r['source']:11s} {r['kind']:11s} {r['bu']:12s}  [{how}]")


# ===========================================================================
# MOCK DATA  (real schemas; doubles as a schema fixture / test)
# ===========================================================================

def _write_mock(name: str, headers: list, rows: list) -> None:
    if HAVE_XLSX:
        p = os.path.join(DATA_DIR, f"{name}.xlsx")
        wb = openpyxl.Workbook(); ws = wb.active
        ws.append(headers)
        for r in rows:
            ws.append([r.get(h, "") for h in headers])
        wb.save(p)
    else:
        p = os.path.join(DATA_DIR, f"{name}.csv")
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=headers); w.writeheader(); w.writerows(rows)
    print(f"  wrote {p}")


def generate_mock_data() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"Generating mock data in '{DATA_DIR}/' ({'xlsx' if HAVE_XLSX else 'csv'}):")
    RD = "2026-06-30"

    _write_mock("AIAGO_Workstation_CS",
        ["gis_bu", "hostname", "install_status", "os", "last_seen", "agent_version",
         "proc_agent_installed", "proc_cs_version_status", "proc_agent_reporting", "Compliance", "report_date"],
        [
            {"gis_bu": "APAC-Retail", "hostname": "WS-APAC-001", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "2026-05-20", "agent_version": "7.30.10", "proc_agent_installed": "yes", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "APAC-Retail", "hostname": "WS-APAC-002", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "", "agent_version": "", "proc_agent_installed": "no", "proc_cs_version_status": "Unknown", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "EMEA-Ops", "hostname": "WS-EMEA-014", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "2026-06-28", "agent_version": "7.35.20709", "proc_agent_installed": "yes", "proc_cs_version_status": "Latest", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Mac_CS",
        ["BU", "computer_name", "os_version", "proc_agent_installed", "last_seen",
         "proc_cs_version_status", "proc_agent_reporting", "Compliance", "report_date"],
        [
            {"BU": "APAC-Retail", "computer_name": "MAC-APAC-07", "os_version": "macOS 14.5", "proc_agent_installed": "no", "last_seen": "", "proc_cs_version_status": "Unknown", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
            {"BU": "AMS-Corp", "computer_name": "MAC-AMS-22", "os_version": "macOS 14.4", "proc_agent_installed": "yes", "last_seen": "2026-06-27", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Server_CS",
        ["gis_bu", "ser_name", "ser_install_status", "ser_sys_class_name", "ser_os",
         "last_seen", "agent_version", "proc_agent_installed", "proc_cs_version_status", "proc_agent_reporting", "Compliance", "report_date"],
        [
            {"gis_bu": "EMEA-Ops", "ser_name": "SRV-EMEA-DB01", "ser_install_status": "Installed", "ser_sys_class_name": "Server", "ser_os": "Windows Server 2022", "last_seen": "2026-05-30", "agent_version": "7.28.5", "proc_agent_installed": "yes", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "AMS-Corp", "ser_name": "SRV-AMS-APP3", "ser_install_status": "Installed", "ser_sys_class_name": "Server", "ser_os": "Red Hat Linux 9", "last_seen": "", "agent_version": "", "proc_agent_installed": "no", "proc_cs_version_status": "Unknown", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Windows_Purview",
        ["gis_bu", "name", "install_status", "os", "assigned_to", "purview_last_seen",
         "purview_defender_mocamp_version", "purview_defender_engine_version",
         "purview_configuration_status", "purview_policy_status", "compliance", "report_date"],
        [
            {"gis_bu": "APAC-Retail", "name": "WS-APAC-001", "install_status": "Installed", "os": "Windows 11 24H2", "assigned_to": "alice@example.com", "purview_last_seen": "2026-06-25", "purview_defender_mocamp_version": "4.18.25000.1", "purview_defender_engine_version": "1.1.25000.1", "purview_configuration_status": "Misconfigured", "purview_policy_status": "Not Applied", "compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "EMEA-Ops", "name": "WS-EMEA-030", "install_status": "Installed", "os": "Windows 11 24H2", "assigned_to": "carol@example.com", "purview_last_seen": "2026-06-20", "purview_defender_mocamp_version": "", "purview_defender_engine_version": "", "purview_configuration_status": "Not Onboarded", "purview_policy_status": "Pending", "compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Mac_Purview",
        ["gis_bu", "intune_computer_name", "purview_configuration_status", "purview_policy_status",
         "purview_last_seen", "purview_last_policy_sync_time", "purview_defender_mocamp_version",
         "purview_defender_engine_version", "compliance", "report_date"],
        [
            {"gis_bu": "AMS-Corp", "intune_computer_name": "MAC-AMS-22", "purview_configuration_status": "Not Onboarded", "purview_policy_status": "Not Applied", "purview_last_seen": "2026-06-18", "purview_last_policy_sync_time": "2026-06-10", "purview_defender_mocamp_version": "", "purview_defender_engine_version": "", "compliance": "Non-Compliant", "report_date": RD},
        ])

    # CMDB hostname -> user email (the mapping the vendor files DON'T provide).
    # WS-EMEA-014 is deliberately absent to demonstrate an UNRESOLVED finding.
    _write_mock("CMDB_Mapping",
        ["Host Name", "Assigned User Email"],
        [
            {"Host Name": "WS-APAC-001", "Assigned User Email": "alice@example.com"},
            {"Host Name": "WS-APAC-002", "Assigned User Email": "bob@example.com"},
            {"Host Name": "MAC-APAC-07", "Assigned User Email": "dana@example.com"},
            {"Host Name": "MAC-AMS-22", "Assigned User Email": "evan@example.com"},
        ])


# ===========================================================================
# ENTRY POINT
# ===========================================================================

def _data_dir_has_files() -> bool:
    return os.path.isdir(DATA_DIR) and any(
        f.lower().endswith((".xlsx", ".csv")) for f in os.listdir(DATA_DIR))


def main() -> None:
    print(f"[i/o mode: {'XLSX' if HAVE_XLSX else 'CSV'}]\n")
    if "--regen" in sys.argv or not _data_dir_has_files():
        generate_mock_data()
        print()

    rows = load_all()
    if not rows:
        print("No rows loaded - check that report files are in data/.")
        return

    worklist = write_worklist(rows)

    cmdb_map = read_cmdb_mapping()
    groups, unresolved = build_notifications(rows, cmdb_map)
    preview = write_notifications_preview(groups, unresolved)
    print_notify_summary(groups, unresolved, cmdb_map)

    print(f"\nConsolidated worklist   -> {worklist}")
    print(f"Notification preview    -> {preview}   (NOTHING SENT)")


if __name__ == "__main__":
    main()
