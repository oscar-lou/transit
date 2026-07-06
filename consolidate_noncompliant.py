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

# Host -> assigned-user NAME, from the CMDB export (drop into data/, 'cmdb' in
# the filename). Join key is 'Name' (hostname); 'Assigned to' is a DISPLAY NAME,
# not an email - it gets resolved to an address via AD_Users below.
CMDB_MAPPING = {
    "stem": "cmdb",
    "map": {"hostname": "Name", "name": "Assigned to"},
}

# Directory export that turns a name into an email. Drop into data/ with
# 'ad_users' in the filename. CMDB 'Assigned to' and AD 'DisplayName' use
# DIFFERENT conventions (e.g. "Chan, Tai Man Terry" vs "Chan, Terry-TM"), so the
# match is fuzzy - see resolve_name_to_email(). Only confident matches are used
# to send; ambiguous ones go to a review list, never a guessed email.
# If the sheet has separate GivenName/Surname columns, those are AUTHORITATIVE
# and used directly (no guessing at how DisplayName is formatted). If a row
# lacks them, we fall back to parsing DisplayName for just that row.
AD_USERS = {
    "stem": "ad_users",
    "map": {"name": "DisplayName", "email": "EmailAddress",
            "given": "GivenName", "surname": "Surname"},
}

# Manual name -> email overrides for the exceptions the fuzzy match can't get
# (non-standard names, externals, etc). Optional file, 'overrides' in the name.
# These are AUTHORITATIVE: an override always wins. This is how you fix a
# mis/less-resolved name once and have it stick.
OVERRIDES = {
    "stem": "overrides",
    "map": {"name": "Name", "email": "Email"},
}

# Only these confidence levels are turned into an actual email. Anything lower
# is held for human review rather than risking the wrong recipient.
NOTIFY_CONFIDENCE = {"high", "medium"}

# Servers have no end user -> route to a BU admin/team address. Maintained by
# whoever owns BU routing; a missing BU means that server is reported as
# UNRESOLVED rather than mis-sent. Fill in real addresses.
# All AIAGO server/workstation rows currently carry gis_bu = "AIAGO" (a single
# BU code, not the APAC-Retail/EMEA-Ops/AMS-Corp examples this dict used to
# have) - every one of the 68 real server rows was going UNRESOLVED because
# "AIAGO" had no entry. Put the real server-team distro list here.
BU_TEAM_EMAIL = {
    "AIAGO": "REPLACE-WITH-REAL-SERVER-TEAM-EMAIL@aia.com",
}


# ===========================================================================
# FILE REGISTRY
# One entry per known report. `meta` records what the file IS; `map` translates
# that file's column names -> our canonical field names. New report -> new
# entry, nothing else changes. Matching is by filename stem, case-insensitive.
# ===========================================================================

# "columns": the exact real header order for that report. Used only to
# self-heal a corrupted header cell (a real export had column 8's name
# replaced with the literal number 0) - see _heal_headers(). Also doubles as
# the header row generate_mock_data() writes, so mock and prod can't drift.
FILE_REGISTRY = {
    "aiago_workstation_cs": {
        "meta": {"source": "CrowdStrike", "platform": "Windows", "kind": "Workstation"},
        "map": {
            "bu": "gis_bu", "hostname": "hostname", "install_status": "install_status",
            "os": "os", "last_seen": "last_seen", "agent_version": "agent_version",
            "agent_installed": "proc_agent_installed",
            "cs_reason": "proc_cs_version_status",
            "compliance": "Compliance", "report_date": "report_date",
        },
        "columns": ["gis_bu", "hostname", "install_status", "os", "last_seen", "agent_version",
                    "proc_agent_installed", "proc_cs_version_status", "proc_agent_reporting",
                    "Compliance", "report_date"],
    },
    "aiago_mac_cs": {
        "meta": {"source": "CrowdStrike", "platform": "Mac", "kind": "Workstation"},
        "map": {
            "bu": "BU", "hostname": "computer_name", "os": "os_version",
            "last_seen": "last_seen", "agent_installed": "proc_agent_installed",
            "cs_reason": "proc_cs_version_status",
            "compliance": "Compliance", "report_date": "report_date",
        },
        "columns": ["BU", "computer_name", "os_version", "proc_agent_installed", "last_seen",
                    "proc_cs_version_status", "proc_agent_reporting", "Compliance", "report_date"],
    },
    "aiago_server_cs": {
        "meta": {"source": "CrowdStrike", "platform": None, "kind": "Server"},  # platform from ser_os
        "map": {
            "bu": "gis_bu", "hostname": "ser_name", "install_status": "ser_install_status",
            "sys_class": "ser_sys_class_name", "os": "ser_os", "last_seen": "last_seen",
            "agent_version": "agent_version", "agent_installed": "proc_agent_installed",
            "cs_reason": "proc_cs_version_status",
            "compliance": "Compliance", "report_date": "report_date",
        },
        "columns": ["gis_bu", "ser_name", "ser_install_status", "ser_sys_class_name", "ser_os",
                    "last_seen", "agent_version", "proc_agent_installed", "proc_cs_version_status",
                    "proc_agent_reporting", "Compliance", "report_date"],
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
        "columns": ["gis_bu", "name", "install_status", "os", "assigned_to", "purview_last_seen",
                    "purview_defender_mocamp_version", "purview_defender_engine_version",
                    "purview_configuration_status", "purview_policy_status", "compliance",
                    "report_date"],
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
        "columns": ["gis_bu", "intune_computer_name", "purview_configuration_status",
                    "purview_policy_status", "purview_last_seen", "purview_last_policy_sync_time",
                    "purview_defender_mocamp_version", "purview_defender_engine_version",
                    "compliance", "report_date"],
    },
    # Fuller CMDB-joined DLP/Purview export (same filename family as Zapp
    # below). Deliberately positioned AFTER aiago_windows_purview/
    # aiago_mac_purview: load_all() dedupes rows by (hostname, source),
    # keeping whichever copy loaded first, so this only ADDS hosts the two
    # thinner exports above missed entirely (verified: 13 real non-compliant
    # hosts, e.g. Caroline Choi/Jordy Ngan/Tanya Kan, present here but absent
    # from those files) rather than double-counting the ~50 hosts both cover.
    # Same compliance criteria (config/policy status) as the files above -
    # unlike the sibling 'Crowdstrike' CSV (deliberately NOT added: its own
    # 'compliant' flag only checks install presence, not version currency,
    # which disagrees with cs_issue()'s policy on real hosts - see git log).
    # This export lists EVERY device, not just non-compliant ones, so
    # is_compliant_text() in normalize_file() gates on it before it becomes a finding.
    # key "dlp" (not "aiago_dlp_full") deliberately - find_dataset() matches by
    # substring against the real filename, e.g. "...Deployment-DLP.csv", which
    # doesn't contain "aiago_dlp_full" (see how "zapp" below is handled too).
    "dlp": {
        "meta": {"source": "Purview", "platform": None, "kind": "Workstation"},
        "map": {
            "bu": "business_unit_code", "hostname": "name", "install_status": "install_status",
            "os": "os", "sys_class": "sys_class_name", "assigned_to": "assigned_to",
            "last_seen": "purview_last_seen",
            "mocamp_version": "purview_defender_mocamp_version",
            "engine_version": "purview_defender_engine_version",
            "config_status": "purview_configuration_status",
            "policy_status": "purview_policy_status",
            "compliance": "compliance", "report_date": "report_date",
        },
        "columns": ["name", "manufacturer", "chassis_type", "model_id", "serial_number", "company",
                    "assigned_to", "hardware_status", "install_status", "os", "os_domain", "u_vlan",
                    "u_dr_availability", "u_dr_grouping", "u_security_zone", "sys_class_name",
                    "last_discovered", "virtual", "u_non_discoverable_ci", "u_gis_exclusion",
                    "report_date", "purview_device_name", "purview_configuration_status",
                    "purview_policy_status", "purview_valid_user", "purview_last_seen", "purview_os",
                    "purview_os_version", "purview_last_ip_address", "perview_device_id",
                    "purview_last_policy_sync_time", "purview_is_dlp_enabled",
                    "purview_defender_engine_version", "purview_defender_mocamp_version",
                    "purview_has_dlp_ac_bandwidth_exceeded", "purview_first_time_onboarded",
                    "purview_required", "compliance", "business_unit_code", "ageing_status"],
    },
    # Zscaler App (client connector) deployment - NOT covered by any of the
    # other reports. This export lists EVERY device (compliant and not)
    # rather than being pre-filtered, so is_compliant_text() gates it too.
    "zapp": {
        "meta": {"source": "Zapp", "platform": None, "kind": "Workstation"},
        "map": {
            "bu": "business_unit_code", "hostname": "hostname", "install_status": "install_status",
            "os": "os", "sys_class": "sys_class_name", "assigned_to": "assigned_to",
            "last_seen": "last_seen_connected_to_zia",
            "zapp_installed": "zapp_installed", "zapp_missing": "zapp_missing",
            "zapp_version": "zapp_version",
            "compliance": "compliant", "report_date": "report_date",
        },
        "columns": ["hostname", "business_unit_code", "zapp", "zapp_required", "zapp_whitelist_bu",
                    "manufacturer", "chassis_type", "model_id", "serial_number", "company",
                    "assigned_to_company", "assigned_to", "install_status", "os", "sys_class_name",
                    "last_discovered", "virtual", "zapp_version", "zapp_user",
                    "last_seen_connected_to_zia", "registration_timestamp", "report_date",
                    "policy_name", "device_state", "last_seen_with_client_connector_active",
                    "zapp_installed", "zapp_missing", "host_name", "compliant", "ageing_30_days",
                    "ageing_60_days", "ageing_90_days", "run_at"],
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


def _heal_headers(headers: list, expected: list, where: str = "") -> list:
    """Recover a header that got clobbered at the source (seen in the wild:
    'proc_cs_version_status' exported as the literal number 0). Only heals a
    slot when the actual name doesn't match ANY expected column (so a real
    rename is never touched) and the expected name is otherwise missing
    entirely from the row (so a genuine reorder is never misaligned)."""
    if not expected or len(headers) != len(expected):
        return headers
    healed = list(headers)
    changed = False
    for i, exp in enumerate(expected):
        if headers[i] != exp and headers[i] not in expected and exp not in headers:
            healed[i] = exp
            changed = True
            print(f"  ! header self-heal {where}: column {i} read as {headers[i]!r}; "
                  f"expected file layout says {exp!r} - using that")
    return healed if changed else headers


def _read_xlsx_rows(path: str, sheet: str = None, expected_headers: list = None) -> list:
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb[sheet] if sheet else wb.active
    it = ws.iter_rows(values_only=True)
    try:
        headers = [cell_to_str(h) for h in next(it)]
    except StopIteration:
        wb.close()
        return []
    headers = _heal_headers(headers, expected_headers, where=os.path.basename(path))
    out = []
    for row in it:
        if row is None or all(c is None for c in row):
            continue
        out.append({h: (row[i] if i < len(row) else None) for i, h in enumerate(headers)})
    wb.close()
    return out


def _read_any(path: str, sheet: str = None, expected_headers: list = None) -> list:
    if path.lower().endswith(".xlsx"):
        return _read_xlsx_rows(path, sheet, expected_headers)
    return _read_csv_rows(path)


def _read_headers(path: str, sheet: str = None, expected_headers: list = None) -> list:
    """Just the header row, for the pre-flight column check."""
    if path.lower().endswith(".xlsx"):
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        ws = wb[sheet] if sheet else wb.active
        try:
            headers = [cell_to_str(h) for h in next(ws.iter_rows(values_only=True))]
        except StopIteration:
            headers = []
        wb.close()
        return _heal_headers(headers, expected_headers, where=os.path.basename(path))
    with open(path, newline="", encoding="utf-8-sig") as f:
        try:
            return [cell_to_str(h) for h in next(csv.reader(f))]
        except StopIteration:
            return []


# ===========================================================================
# REASON -> ISSUE + ACTION
# ===========================================================================

def cs_issue(reason: str, agent_installed: str = "") -> tuple:
    inst = (agent_installed or "").strip().lower()
    r = (reason or "").strip().lower()
    # 'agent not installed' is the authoritative signal: some files (Workstation)
    # leave the reason blank for agent-less hosts instead of writing "Unknown".
    if inst == "no" or r == "unknown":
        return ("CrowdStrike agent not installed",
                "Install the CrowdStrike sensor (latest from the Prod share)")
    if r == "outdated":
        return ("CrowdStrike agent outdated",
                f"Update sensor to latest (Win {CS_LATEST['windows']} / "
                f"Mac {CS_LATEST['mac']} / Linux {CS_LATEST['linux']})")
    if r == "latest":
        return ("Agent current but NOT reporting",
                "Check network connectivity / power the machine on so it reports")
    if not r:
        return ("CrowdStrike status not reported",
                "Verify agent status on the host; refer to remediation guidance")
    return (f"CrowdStrike status: {reason}", "Refer to remediation guidance")


def purview_issue(config_status: str, policy_status: str, platform: str = "",
                  mocamp: str = "", engine: str = "") -> tuple:
    cfg = (config_status or "").strip()
    pol = (policy_status or "").strip()
    detail = (f"config={cfg or 'n/a'}, policy={pol or 'n/a'}, "
              f"mocamp={mocamp or 'n/a'}, engine={engine or 'n/a'}")
    ref = PURVIEW_LATEST.get("macos" if platform == "Mac" else "windows", {})
    statuses = {cfg.lower(), pol.lower()}

    if "notupdated" in statuses:
        ref_txt = f"mocamp {ref.get('mocamp', '?')} / engine {ref.get('engine', '?')}"
        return ("Microsoft Defender / Purview components not updated",
                f"Update Defender to the reference versions ({ref_txt}); "
                f"confirm 'Purview DLP Enrollment' in Software Center",
                detail)
    if not cfg and not pol:
        # Blank telemetry across the Purview columns = host has no Purview data,
        # i.e. it isn't onboarded / reporting to Purview DLP. This is the
        # majority case and matches the email's Software Center enrollment step.
        return ("Purview DLP not enrolled / not reporting",
                "In Software Center, check 'Purview DLP Enrollment' and click "
                "Install to enroll; follow the Onboarding / Troubleshooting deck",
                detail)
    return (f"Purview status: config={cfg or 'n/a'}, policy={pol or 'n/a'}",
            "Follow the Onboarding / Troubleshooting deck",
            detail)


def is_compliant_text(value: str) -> bool:
    """True if a source's own 'compliance' column says this row is already
    compliant. The original 5 AIAGO exports are pre-filtered to non-compliant
    rows only (this is always False for them), but the fuller unfiltered
    exports (Zapp, the merged DLP export) list EVERY device, so normalize_file
    gates on this before generating a finding - otherwise a compliant device
    would get reported as a finding too."""
    return (value or "").strip().lower() in ("1", "true", "yes", "compliant")


def zapp_issue(zapp_installed: str, zapp_missing: str) -> tuple:
    if (zapp_missing or "").strip().lower() in ("1", "true", "yes") or \
       (zapp_installed or "").strip().lower() in ("0", "false", "no"):
        return ("Zapp (Zscaler Client Connector) not installed",
                "Install Zapp from Software Center; confirm it registers and connects to ZIA")
    return ("Zapp reporting non-compliant",
            "Verify Zapp registration/connectivity; refer to remediation guidance")


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


def normalize_file(path: str, sheet: str = None, registry_key: str = None) -> list:
    stem = sheet or os.path.splitext(os.path.basename(path))[0]
    if registry_key:
        entry = FILE_REGISTRY[registry_key]
    else:
        _, entry = _match_registry(stem)
    label_src = f"{os.path.basename(path)}" + (f" [{sheet}]" if sheet else "")
    if not entry:
        print(f"  ! skipped (unknown report): {label_src}")
        return []

    cmap, meta = entry["map"], entry["meta"]
    rows = []
    for raw in _read_any(path, sheet, expected_headers=entry.get("columns")):
        f = {canon: cell_to_str(raw.get(col, "")) for canon, col in cmap.items()}
        # The original 5 exports are pre-filtered to non-compliant rows, so
        # this is always False for them. The fuller unfiltered exports (Zapp,
        # the merged DLP export) list EVERY device, so skip the ones their
        # own 'compliance' column already says are fine - a no-op for the
        # pre-filtered sources since 'compliance' there is always non-compliant.
        if is_compliant_text(f.get("compliance")):
            continue

        # Platform: fixed for most files. For servers it comes from ser_os, but
        # that column is sometimes empty while ser_sys_class_name carries the
        # OS signal (e.g. "Citrix VDI", "Linux Server"); try os first, then
        # fall back to sys_class so those rows aren't mislabelled "Unknown".
        platform = meta["platform"]
        if not platform:
            platform = _platform_from_os(f.get("os"))
            if platform == "Unknown":
                platform = _platform_from_os(f.get("sys_class"))
            if platform == "Unknown":
                # neither column buckets to Win/Mac/Linux (e.g. "Citrix VDI");
                # keep the most specific raw label rather than a bare "Unknown".
                platform = f.get("os") or f.get("sys_class") or "Unknown"
        if meta["source"] == "CrowdStrike":
            issue, action = cs_issue(f.get("cs_reason"), f.get("agent_installed"))
            detail = f"reason={f.get('cs_reason') or 'n/a'}, installed={f.get('agent_installed') or 'n/a'}"
            if f.get("agent_version"):
                detail += f", agent={f['agent_version']}"
        elif meta["source"] == "Zapp":
            issue, action = zapp_issue(f.get("zapp_installed"), f.get("zapp_missing"))
            detail = (f"installed={f.get('zapp_installed') or 'n/a'}, "
                      f"missing={f.get('zapp_missing') or 'n/a'}, "
                      f"version={f.get('zapp_version') or 'n/a'}")
        else:
            issue, action, detail = purview_issue(
                f.get("config_status"), f.get("policy_status"),
                platform, f.get("mocamp_version"), f.get("engine_version"))

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
            "source_file": label_src,
        })
    print(f"  + {label_src:40s} {len(rows):4d} rows  [{meta['source']}/{meta['kind']}]")
    return rows


def load_all() -> list:
    """Find each of the known reports, whether it's its own file or a tab
    inside a larger multi-tab workbook (e.g. everything living in one
    'CompliantReport(Working).xlsx'). Each report is loaded exactly once, by
    whichever form is found first (standalone file takes priority).

    Some reports overlap in host coverage by design (e.g. "dlp" is a
    fuller re-export of the same check as aiago_windows_purview/mac_purview -
    see FILE_REGISTRY comment), so rows are deduplicated by (hostname,
    source), keeping whichever copy was loaded first. FILE_REGISTRY lists the
    thinner/original exports before their fuller counterparts, so this keeps
    the original's row for any host both cover and only ADDS hosts unique to
    the fuller export - never double-counts, never drops a host either side
    catches alone."""
    all_rows = []
    print(f"Reading reports from '{DATA_DIR}/':")
    for rk in FILE_REGISTRY:
        found = find_dataset(rk)
        if not found:
            print(f"  ! not found (file or tab): {rk}")
            continue
        path, sheet = found
        all_rows.extend(normalize_file(path, sheet, registry_key=rk))

    seen, deduped, dropped = set(), [], 0
    for r in all_rows:
        key = ((r.get("hostname") or "").strip().upper(), r["source"])
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        deduped.append(r)
    if dropped:
        print(f"  (dropped {dropped} row(s) already covered by an earlier-loaded "
              f"report for the same host+source)")
    return deduped


# ===========================================================================
# CONSOLIDATED WORKLIST OUTPUT
# ===========================================================================

SOURCE_KINDS = ["CrowdStrike", "Purview", "Zapp"]  # summary columns in write_worklist()


def summarize_by_bu(rows: list) -> dict:
    bus = {}
    for r in rows:
        b = bus.setdefault(r["bu"], {"total": 0, "Workstation": 0, "Server": 0,
                                     **{s: 0 for s in SOURCE_KINDS}})
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
    summary.append(["Business Unit", "Total"] + SOURCE_KINDS + ["Workstation", "Server"])
    for bu, s in summarize_by_bu(rows).items():
        summary.append([bu, s["total"]] + [s[k] for k in SOURCE_KINDS] + [s["Workstation"], s["Server"]])
    summary.freeze_panes = "A2"
    wb.save(path)
    return path


# ===========================================================================
# RECIPIENT RESOLUTION
# ===========================================================================

# ===========================================================================
# RECIPIENT RESOLUTION   hostname -> name (CMDB) -> email (AD_Users, fuzzy)
# ===========================================================================

def _list_sheets(path: str) -> list:
    if not path.lower().endswith(".xlsx"):
        return [None]
    wb = openpyxl.load_workbook(path, read_only=True)
    names = wb.sheetnames
    wb.close()
    return names


# ===========================================================================
# DATASET LOCATOR
# A "dataset" (a report, or CMDB, or AD_Users, or Overrides) can arrive two
# ways: as its OWN file (data/CMDB_Mapping.xlsx), or as ONE SHEET inside a
# larger multi-tab workbook (e.g. "CompliantReport(Working).xlsx" with a
# 'CMDB' tab and an 'AD_Users' tab). find_dataset() checks both, by matching
# the stem keyword against filenames first, then against sheet names inside
# every .xlsx in data/. This is the ONLY place that needs to know which shape
# the input actually took.
# ===========================================================================

def find_dataset(stem_keyword: str):
    """-> (path, sheet_name_or_None) for the first match, else None."""
    if not os.path.isdir(DATA_DIR):
        return None
    key = stem_keyword.lower()
    xlsx_files = []
    for fn in os.listdir(DATA_DIR):
        if not fn.lower().endswith((".xlsx", ".csv")):
            continue
        path = os.path.join(DATA_DIR, fn)
        base = os.path.splitext(fn)[0].lower()
        # 1. filename itself matches -> standalone file, own active sheet
        if base.startswith(key) or key in base:
            return path, None
        if fn.lower().endswith(".xlsx"):
            xlsx_files.append(path)
    # 2. no filename matched -> look for a matching TAB inside every workbook.
    # Sheet tabs likely won't carry the "aiago_" file-prefix, so compare with
    # that stripped, and match in either direction (key-in-sheet or
    # sheet-in-key) since tab names are often abbreviated.
    core_key = key.replace("_", "").replace("aiago", "")
    for path in xlsx_files:
        for sheet in _list_sheets(path):
            s = (sheet or "").lower().replace(" ", "").replace("_", "")
            if len(s) >= 3 and (core_key in s or s in core_key):
                return path, sheet
    return None


def _find_file(stem: str):
    """Back-compat wrapper: standalone-file-only lookup (used by report loader,
    which still assumes each report is its own file unless told otherwise)."""
    found = find_dataset(stem)
    if found and found[1] is None:
        return found[0]
    return found[0] if found else None


def read_cmdb_mapping() -> dict:
    """hostname (UPPER) -> assigned-user display name (raw)."""
    found = find_dataset(CMDB_MAPPING["stem"])
    if not found:
        print("No CMDB file/sheet in data/ - CS-only workstations will be unresolved.")
        return {}
    path, sheet = found
    m = CMDB_MAPPING["map"]
    out = {}
    for raw in _read_any(path, sheet):
        host = cell_to_str(raw.get(m["hostname"], "")).upper()
        name = cell_to_str(raw.get(m["name"], ""))
        if host and name:
            out[host] = name
    where = f"{os.path.basename(path)}" + (f" [{sheet}]" if sheet else "")
    print(f"CMDB '{where}': {len(out)} host->name entries.")
    return out


# --- name normalization / parsing ------------------------------------------

def strip_external(name: str) -> tuple:
    """Remove a trailing [External]-style tag; return (clean_name, is_external)."""
    n = name or ""
    low = n.lower()
    ext = "[external" in low or "(external" in low
    for tag in ("[external]", "(external)", "[external ]", "- external"):
        idx = low.find(tag)
        if idx != -1:
            n = n[:idx]
            break
    return n.strip(" -"), ext


def norm_name(name: str) -> str:
    clean, _ = strip_external(name)
    return " ".join(clean.lower().replace(".", " ").replace(",", " , ").split())


def parse_name_variants(name: str) -> list:
    """-> list of (surname, [given tokens]) candidate parses, most likely first.
    A comma is unambiguous: 'Surname, Given...'. Without one we can't tell
    which side is the surname - CMDB's 'Assigned to'/'Owner' writes
    'Given [Middle] Surname' (e.g. 'Michele De Filippo', surname = 'De
    Filippo'), so try every trailing chunk as a (possibly multi-word)
    surname, shortest first, plus the legacy single-word-prefix reading as a
    last resort. Caller tries each until one resolves against AD."""
    clean, _ = strip_external(name)
    clean = clean.lower()
    if "," in clean:
        surname, given = clean.split(",", 1)
        given_tokens = [t for t in given.replace("-", " ").replace(".", " ").split() if t]
        return [(surname.strip(), given_tokens)]

    parts = [t for t in clean.replace("-", " ").replace(".", " ").split() if t]
    if len(parts) <= 1:
        return [(parts[0] if parts else "", [])]

    variants = [(" ".join(parts[len(parts) - k:]), tuple(parts[:len(parts) - k]))
                for k in range(1, len(parts))]
    variants.append((parts[0], tuple(parts[1:])))  # legacy 'Surname Given...' fallback
    seen, out = set(), []
    for surname, given_tuple in variants:
        v = (surname, given_tuple)
        if v not in seen:
            seen.add(v)
            out.append((surname, list(given_tuple)))
    return out


def parse_name(name: str) -> tuple:
    """-> (surname, [given tokens]), single best-guess parse. See
    parse_name_variants() for callers that need to try multiple readings."""
    return parse_name_variants(name)[0]


def name_tokens(text: str) -> set:
    """Lowercase, split on space/hyphen/period/comma -> set of tokens.
    Used on structured GivenName values (e.g. 'Terry' or 'Tai Man')."""
    t = (text or "").lower().replace("-", " ").replace(".", " ").replace(",", " ")
    return {tok for tok in t.split() if tok}


def read_ad_users() -> dict:
    """Build lookup structures from the AD_Users export. Prefers the authoritative
    Surname/GivenName columns when present; falls back to parsing DisplayName
    only for rows where those columns are blank, so it degrades gracefully if
    a real export happens not to carry them."""
    found = find_dataset(AD_USERS["stem"])
    if not found:
        print("No AD_Users file/sheet in data/ - names can't be resolved to emails.")
        return {"exact": {}, "by_surname": {}, "count": 0}
    path, sheet = found
    m = AD_USERS["map"]
    exact, by_surname = {}, {}
    n = n_structured = 0
    for raw in _read_any(path, sheet):
        disp = cell_to_str(raw.get(m["name"], ""))
        email = cell_to_str(raw.get(m["email"], ""))
        if not disp or "@" not in email:
            continue
        n += 1
        exact[norm_name(disp)] = email

        surname_col = cell_to_str(raw.get(m.get("surname", ""), ""))
        given_col = cell_to_str(raw.get(m.get("given", ""), ""))
        if surname_col:
            n_structured += 1
            surname = surname_col.strip().lower()
            given_tokens = name_tokens(given_col)
        else:
            surname, given_list = parse_name(disp)
            given_tokens = set(given_list)

        by_surname.setdefault(surname, []).append(
            {"disp": disp, "email": email, "given": given_tokens})
    where = f"{os.path.basename(path)}" + (f" [{sheet}]" if sheet else "")
    print(f"AD_Users '{where}': {n} name->email entries "
          f"({n_structured} using Surname/GivenName columns, "
          f"{n - n_structured} parsed from DisplayName).")
    return {"exact": exact, "by_surname": by_surname, "count": n}


def read_overrides() -> dict:
    found = find_dataset(OVERRIDES["stem"])
    if not found:
        return {}
    path, sheet = found
    m = OVERRIDES["map"]
    out = {}
    for raw in _read_any(path, sheet):
        name = cell_to_str(raw.get(m["name"], ""))
        email = cell_to_str(raw.get(m["email"], ""))
        if name and "@" in email:
            out[norm_name(name)] = email
    if out:
        where = f"{os.path.basename(path)}" + (f" [{sheet}]" if sheet else "")
        print(f"Overrides '{where}': {len(out)} manual entries.")
    return out


def resolve_name_to_email(name: str, ad: dict, overrides: dict) -> tuple:
    """-> (email_or_None, method, confidence, candidate_emails).
    Confidence: high (override/exact), medium (unique heuristic), low (review)."""
    key = norm_name(name)
    if key in overrides:
        return overrides[key], "override", "high", []
    if key in ad["exact"]:
        return ad["exact"][key], "exact name", "high", []

    # A comma-less name is ambiguous about which part is the surname (see
    # parse_name_variants), so try every plausible reading and return on the
    # first one that resolves cleanly. Remember the first reading that at
    # least found a surname bucket, so an ambiguous-but-real match still
    # goes to review instead of being reported as "no AD match" just because
    # a *later*, wrong reading found nothing.
    fallback = None
    for surname, given_list in parse_name_variants(name):
        given = set(given_list)
        candidates = ad["by_surname"].get(surname, [])
        if not candidates:
            continue
        # candidates sharing at least one given-name token (e.g. "terry").
        # A shared *count* of 1 (just "terry") is weaker evidence than 2
        # ("terry" + "sp"), so rank by overlap size instead of treating any
        # overlap as equally good - e.g. query 'Terry-SP Lau' -> {terry, sp}
        # should prefer AD's 'Terry-SP.Lau' ({terry, sp}, full match) over
        # 'Terry-CP.Lau' ({terry}, partial match), not flag both as tied.
        shared = [c for c in candidates if given & c["given"]]
        if shared:
            best = max(len(given & c["given"]) for c in shared)
            shared = [c for c in shared if len(given & c["given"]) == best]
        if len(shared) == 1:
            return shared[0]["email"], "heuristic (surname+given)", "medium", []
        if fallback is not None:
            continue
        if len(shared) > 1:
            fallback = (None, "review: several AD names share surname+given", "low",
                        [c["email"] for c in shared])
        elif len(candidates) == 1:
            fallback = (None, "review: surname-only match (no given overlap)", "low",
                        [candidates[0]["email"]])
        else:
            fallback = (None, "review: surname matches several, no given overlap", "low",
                        [c["email"] for c in candidates])
    if fallback:
        return fallback
    return None, "no AD match (surname)", "none", []


def resolve_recipient(row: dict, cmdb_names: dict, ad: dict, overrides: dict) -> tuple:
    """-> (email_or_None, how, confidence, candidate_emails)."""
    if row["kind"] == "Server":
        email = BU_TEAM_EMAIL.get(row["bu"])
        if email:
            return email, "team (BU admin)", "high", []
        return None, "unresolved: server, no BU team email", "none", []

    at = (row.get("assigned_to") or "").strip()
    if "@" in at:                                   # Purview sometimes has the email directly
        return at, "user (assigned_to email)", "high", []

    name = at or cmdb_names.get((row.get("hostname") or "").strip().upper(), "")
    if not name:
        return None, "unresolved: no assigned user (CMDB/assigned_to)", "none", []

    email, method, conf, cands = resolve_name_to_email(name, ad, overrides)
    if email and conf in NOTIFY_CONFIDENCE:
        return email, f"user ({method})", conf, []
    return None, f"{method}: '{name}'", conf, cands


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


def build_notifications(rows: list, cmdb_names: dict, ad: dict, overrides: dict) -> tuple:
    groups, review, unresolved = {}, [], []
    for r in rows:
        email, how, conf, cands = resolve_recipient(r, cmdb_names, ad, overrides)
        if email:
            g = groups.setdefault(email, {"how": how, "rows": []})
            g["rows"].append(r)
        elif conf == "low":                       # has a name, but uncertain -> review
            review.append((r, how, cands))
        else:                                     # no user / no team at all
            unresolved.append((r, how))
    return groups, review, unresolved


def write_notifications_preview(groups: dict, review: list, unresolved: list) -> str:
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

    # Review: has a name, but the match was uncertain -> a human picks the right
    # email and adds it to the overrides file. NOTHING here is emailed.
    rv = wb.create_sheet("Review")
    rv.append(["Hostname", "Source", "Kind", "BU", "Why held", "Possible emails (pick one -> overrides)"])
    for r, how, cands in review:
        rv.append([r["hostname"], r["source"], r["kind"], r["bu"], how, "  |  ".join(cands)])
    rv.freeze_panes = "A2"

    ur = wb.create_sheet("Unresolved")
    ur.append(["Hostname", "Source", "Platform", "Kind", "BU", "Reason no recipient"])
    for r, how in unresolved:
        ur.append([r["hostname"], r["source"], r["platform"], r["kind"], r["bu"], how])
    ur.freeze_panes = "A2"
    wb.save(path)
    return path


def print_notify_summary(groups: dict, review: list, unresolved: list) -> None:
    by_how = {}
    for g in groups.values():
        by_how[g["how"]] = by_how.get(g["how"], 0) + 1
    print("\n" + "#" * 72)
    print(f"# {len(groups)} recipient(s) to notify   |   "
          f"{len(review)} finding(s) HELD FOR REVIEW   |   {len(unresolved)} UNRESOLVED")
    print("#" * 72)
    for how, n in sorted(by_how.items()):
        print(f"  {n:3d} recipient(s) via {how}")
    if review:
        print("\n  HELD FOR REVIEW (uncertain name match - not emailed):")
        for r, how, cands in review:
            print(f"    - {r['hostname']:16s} {how}")
    if unresolved:
        print("\n  UNRESOLVED (no user/team):")
        for r, how in unresolved:
            print(f"    - {r['hostname']:16s} {r['kind']:11s} {r['bu']:12s} [{how}]")


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

    _write_mock("AIAGO_Workstation_CS", FILE_REGISTRY["aiago_workstation_cs"]["columns"],
        [
            {"gis_bu": "APAC-Retail", "hostname": "WS-APAC-001", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "2026-05-20", "agent_version": "7.30.10", "proc_agent_installed": "yes", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "APAC-Retail", "hostname": "WS-APAC-002", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "", "agent_version": "", "proc_agent_installed": "no", "proc_cs_version_status": "", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "EMEA-Ops", "hostname": "WS-EMEA-014", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "2026-06-28", "agent_version": "7.35.20709", "proc_agent_installed": "yes", "proc_cs_version_status": "Latest", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
            # two AD names share the given token "terry" ('Terry' vs 'Terry-SP'),
            # but the CMDB name carries the full 'Terry-SP' suffix - should
            # resolve uniquely to the fuller-overlap candidate, not go to review
            {"gis_bu": "APAC-Retail", "hostname": "WS-APAC-005", "install_status": "Installed", "os": "Windows 11 24H2", "last_seen": "2026-06-15", "agent_version": "7.30.10", "proc_agent_installed": "yes", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Mac_CS", FILE_REGISTRY["aiago_mac_cs"]["columns"],
        [
            {"BU": "APAC-Retail", "computer_name": "MAC-APAC-07", "os_version": "macOS 14.5", "proc_agent_installed": "no", "last_seen": "", "proc_cs_version_status": "Unknown", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
            {"BU": "AMS-Corp", "computer_name": "MAC-AMS-22", "os_version": "macOS 14.4", "proc_agent_installed": "yes", "last_seen": "2026-06-27", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Server_CS", FILE_REGISTRY["aiago_server_cs"]["columns"],
        [
            # both columns populated -> ser_os wins ("Windows")
            {"gis_bu": "EMEA-Ops", "ser_name": "SRV-EMEA-DB01", "ser_install_status": "Installed", "ser_sys_class_name": "Server", "ser_os": "Windows Server 2022", "last_seen": "2026-05-30", "agent_version": "7.28.5", "proc_agent_installed": "yes", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
            # ser_os empty, class carries OS signal -> fallback to class ("Linux")
            {"gis_bu": "AMS-Corp", "ser_name": "SRV-AMS-APP3", "ser_install_status": "Installed", "ser_sys_class_name": "Linux Server", "ser_os": "", "last_seen": "", "agent_version": "", "proc_agent_installed": "no", "proc_cs_version_status": "Unknown", "proc_agent_reporting": "no", "Compliance": "Non-Compliant", "report_date": RD},
            # ser_os empty, class not a Win/Mac/Linux word -> keep literal ("Citrix VDI")
            {"gis_bu": "EMEA-Ops", "ser_name": "SRV-EMEA-VDI9", "ser_install_status": "Installed", "ser_sys_class_name": "Citrix VDI", "ser_os": "", "last_seen": "2026-06-01", "agent_version": "7.29.1", "proc_agent_installed": "yes", "proc_cs_version_status": "Outdated", "proc_agent_reporting": "yes", "Compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Windows_Purview", FILE_REGISTRY["aiago_windows_purview"]["columns"],
        [
            {"gis_bu": "APAC-Retail", "name": "WS-APAC-001", "install_status": "Installed", "os": "Windows 11 24H2", "assigned_to": "Chan, Tai Man Terry", "purview_last_seen": "2026-06-25", "purview_defender_mocamp_version": "4.18.25000.1", "purview_defender_engine_version": "1.1.25000.1", "purview_configuration_status": "NotUpdated", "purview_policy_status": "NotUpdated", "compliance": "Non-Compliant", "report_date": RD},
            {"gis_bu": "EMEA-Ops", "name": "WS-EMEA-030", "install_status": "Installed", "os": "Windows 11 24H2", "assigned_to": "carol@example.com", "purview_last_seen": "", "purview_defender_mocamp_version": "4.18.25000.1", "purview_defender_engine_version": "", "purview_configuration_status": "", "purview_policy_status": "", "compliance": "Non-Compliant", "report_date": RD},
            # comma-less 'Given Surname' - the CMDB 'Assigned to'/'Owner' convention seen in prod
            {"gis_bu": "APAC-Retail", "name": "WS-APAC-003", "install_status": "Installed", "os": "Windows 11 24H2", "assigned_to": "Siu Ming Wong", "purview_last_seen": "2026-06-20", "purview_defender_mocamp_version": "4.18.25000.1", "purview_defender_engine_version": "1.1.25000.1", "purview_configuration_status": "NotUpdated", "purview_policy_status": "NotUpdated", "compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("AIAGO_Mac_Purview", FILE_REGISTRY["aiago_mac_purview"]["columns"],
        [
            {"gis_bu": "AMS-Corp", "intune_computer_name": "MAC-AMS-22", "purview_configuration_status": "Not Onboarded", "purview_policy_status": "Not Applied", "purview_last_seen": "2026-06-18", "purview_last_policy_sync_time": "2026-06-10", "purview_defender_mocamp_version": "", "purview_defender_engine_version": "", "compliance": "Non-Compliant", "report_date": RD},
        ])

    _write_mock("Zapp_Deployment", FILE_REGISTRY["zapp"]["columns"],
        [
            # not compliant, client missing entirely -> a finding
            {"hostname": "WS-APAC-001", "business_unit_code": "APAC-Retail", "zapp": "FALSE",
             "assigned_to": "Terry Chan", "install_status": "Installed", "os": "Windows 11 24H2",
             "sys_class_name": "Computer", "zapp_installed": "0", "zapp_missing": "1",
             "compliant": "0", "report_date": RD},
            # compliant device in this UNFILTERED export -> must be skipped, not emailed
            {"hostname": "WS-EMEA-030", "business_unit_code": "EMEA-Ops", "zapp": "TRUE",
             "assigned_to": "carol@example.com", "install_status": "Installed", "os": "Windows 11 24H2",
             "sys_class_name": "Computer", "zapp_installed": "1", "zapp_missing": "0",
             "compliant": "1", "report_date": RD},
        ])

    _write_mock("DLP_Deployment", FILE_REGISTRY["dlp"]["columns"],
        [
            # same host+finding as AIAGO_Windows_Purview's WS-APAC-001 above -
            # load_all()'s dedup must drop this copy, not double-email Terry
            {"name": "WS-APAC-001", "business_unit_code": "APAC-Retail", "assigned_to": "Chan, Tai Man Terry",
             "install_status": "Installed", "os": "Windows 11 24H2", "sys_class_name": "Computer",
             "purview_configuration_status": "NotUpdated", "purview_policy_status": "NotUpdated",
             "purview_last_seen": "2026-06-25", "compliance": "Non-compliant", "report_date": RD},
            # host this fuller export catches that the thinner Purview exports
            # above never listed at all - must be ADDED, not dropped
            {"name": "WS-APAC-006", "business_unit_code": "APAC-Retail", "assigned_to": "Wong, Siu Ming",
             "install_status": "Installed", "os": "Windows 11 24H2", "sys_class_name": "Computer",
             "purview_configuration_status": "", "purview_policy_status": "",
             "purview_last_seen": "", "compliance": "Non-compliant", "report_date": RD},
            # compliant device in this UNFILTERED export -> must be skipped
            {"name": "WS-APAC-007", "business_unit_code": "APAC-Retail", "assigned_to": "carol@example.com",
             "install_status": "Installed", "os": "Windows 11 24H2", "sys_class_name": "Computer",
             "purview_configuration_status": "Updated", "purview_policy_status": "Updated",
             "purview_last_seen": "2026-06-29", "compliance": "Compliant", "report_date": RD},
        ])

    # CMDB export: hostname ('Name') -> assigned user DISPLAY NAME ('Assigned to').
    # Names use the fuller convention; AD_Users below uses the shorter one.
    # WS-EMEA-014 absent -> stays unresolved.
    _write_mock("CMDB_Mapping",
        ["Name", "Serial number", "Assigned to", "Install Status", "Operating System"],
        [
            {"Name": "WS-APAC-001", "Serial number": "SN-A1", "Assigned to": "Chan, Tai Man Terry", "Install Status": "Installed", "Operating System": "Windows 11 24H2"},
            {"Name": "WS-APAC-002", "Serial number": "SN-A2", "Assigned to": "Wong, Siu Ming", "Install Status": "Installed", "Operating System": "Windows 11 24H2"},
            {"Name": "MAC-APAC-07", "Serial number": "SN-A7", "Assigned to": "Lee, John Xavier [External]", "Install Status": "Installed", "Operating System": "macOS 14.5"},
            {"Name": "MAC-AMS-22", "Serial number": "SN-M22", "Assigned to": "Smith, Robert", "Install Status": "Installed", "Operating System": "macOS 14.4"},
            {"Name": "WS-EMEA-014", "Serial number": "SN-E14", "Assigned to": "Lam, Wai Lok Kelvin", "Install Status": "Installed", "Operating System": "Windows 11 24H2"},
            {"Name": "WS-APAC-005", "Serial number": "SN-A5", "Assigned to": "Terry-SP Lau", "Install Status": "Installed", "Operating System": "Windows 11 24H2"},
        ])

    # AD directory: DisplayName -> EmailAddress. Note the shorter convention and
    # the two "Smith, Robert-*" rows that make "Smith, Robert" ambiguous.
    # Real AD exports often carry Surname/GivenName as separate columns rather
    # than relying on DisplayName formatting. Kelvin Lam demonstrates exactly
    # why that matters: his DisplayName is given-name-first with NO comma, so
    # naive parsing would misread "Kelvin" as the surname. The Surname/GivenName
    # columns sidestep that entirely.
    _write_mock("AD_Users",
        ["DisplayName", "Surname", "GivenName", "EmailAddress", "Department"],
        [
            {"DisplayName": "Chan, Terry-TM", "Surname": "Chan", "GivenName": "Terry", "EmailAddress": "terry.chan@example.com", "Department": "Retail"},
            {"DisplayName": "Wong, Siu Ming", "Surname": "Wong", "GivenName": "Siu Ming", "EmailAddress": "siuming.wong@example.com", "Department": "Ops"},
            {"DisplayName": "Lee, John-JX [External]", "Surname": "Lee", "GivenName": "John", "EmailAddress": "john.lee@consultant.com", "Department": "Contractor"},
            {"DisplayName": "Smith, Robert-RA", "Surname": "Smith", "GivenName": "Robert", "EmailAddress": "robert.a.smith@example.com", "Department": "Finance"},
            {"DisplayName": "Smith, Robert-RB", "Surname": "Smith", "GivenName": "Robert", "EmailAddress": "robert.b.smith@example.com", "Department": "Legal"},
            {"DisplayName": "Kelvin Lam", "Surname": "Lam", "GivenName": "Kelvin", "EmailAddress": "kelvin.lam@example.com", "Department": "IT"},
            # 'Lau' shares the given token "terry" between both rows, but only
            # Terry-SP's given carries the full {"terry","sp"} that matches the
            # CMDB name above - regression test for the overlap-size ranking.
            {"DisplayName": "Lau, Terry-CP", "Surname": "Lau", "GivenName": "Terry", "EmailAddress": "terry-cp.lau@example.com", "Department": "Retail"},
            {"DisplayName": "Lau, Terry-SP", "Surname": "Lau", "GivenName": "Terry-SP", "EmailAddress": "terry-sp.lau@example.com", "Department": "Legal"},
        ])


# ===========================================================================
# PRE-FLIGHT HEADER CHECK
# Reads each file's real header row and reports, by name, any column the code
# expects but can't find - so a renamed/mismatched column announces itself
# instead of silently producing blank fields. Warns; never blocks the run.
# ===========================================================================

def validate_headers() -> bool:
    print("Pre-flight header check:")
    all_ok = True

    checks = []  # (stem_keyword, required_columns, optional_columns, label, expected_headers)
    for rk, entry in FILE_REGISTRY.items():
        checks.append((rk, list(entry["map"].values()), [],
                        f"{entry['meta']['source']}/{entry['meta']['kind']}", entry.get("columns")))
    checks.append((CMDB_MAPPING["stem"], list(CMDB_MAPPING["map"].values()), [], "CMDB", None))
    checks.append((AD_USERS["stem"], [AD_USERS["map"]["name"], AD_USERS["map"]["email"]],
                   [AD_USERS["map"].get("surname", ""), AD_USERS["map"].get("given", "")], "AD_Users", None))
    checks.append((OVERRIDES["stem"], list(OVERRIDES["map"].values()), [], "Overrides", None))

    for stem_keyword, required, optional, label, expected_headers in checks:
        found = find_dataset(stem_keyword)
        if not found:
            if label == "Overrides":
                continue  # optional file, silently skip if absent
            all_ok = False
            print(f"  !  {label}: no matching file or sheet found in '{DATA_DIR}/'")
            continue
        path, sheet = found
        actual = _read_headers(path, sheet, expected_headers)
        where = f"{os.path.basename(path)}" + (f" [{sheet}]" if sheet else "")
        missing = [c for c in required if c not in actual]
        missing_opt = [c for c in optional if c and c not in actual]
        if missing:
            all_ok = False
            print(f"  !  {where}  ({label}) missing column(s): {', '.join(missing)}")
            print(f"       actually has: {', '.join(actual) or '(no headers)'}")
        else:
            note = f"  (no {'/'.join(missing_opt)} - will parse names from DisplayName instead)" if missing_opt else ""
            print(f"  OK {where}  ({label}){note}")

    if not all_ok:
        print("  -> Update the column name(s) in FILE_REGISTRY / CMDB_MAPPING / AD_USERS")
        print("     to match the 'file actually has' list above, then re-run.")
    print()
    return all_ok


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

    validate_headers()

    rows = load_all()
    if not rows:
        print("No rows loaded - check that report files are in data/.")
        return

    worklist = write_worklist(rows)

    cmdb_names = read_cmdb_mapping()
    ad = read_ad_users()
    overrides = read_overrides()
    groups, review, unresolved = build_notifications(rows, cmdb_names, ad, overrides)
    preview = write_notifications_preview(groups, review, unresolved)
    print_notify_summary(groups, review, unresolved)

    print(f"\nConsolidated worklist   -> {worklist}")
    print(f"Notification preview    -> {preview}   (NOTHING SENT)")


if __name__ == "__main__":
    main()