#!/usr/bin/env python3
"""
Compliance notification pipeline - local scaffold (standard library only).

What this does, end to end:
  1. Generates four mock source files (CMDB, Windows Update, Zscaler,
     CrowdStrike) as CSV, if they don't already exist.
  2. Runs the full pipeline: normalize -> correlate on serial -> evaluate
     each compliance rule -> collect the devices that fail.
  3. "Sends" a notification for each failure by PRINTING it. The real
     Microsoft Graph send gets wired in here later, once the service
     account and Mail.Send / Teams permission exist.

Why stdlib only: your interpreter is the embeddable Python build, and we
haven't yet confirmed pip can reach PyPI. This runs regardless. When real
.xlsx exports arrive, we swap csv -> openpyxl in read_source() and change
nothing else.

Run it:
    python compliance_scaffold.py            # generate (if needed) + run
    python compliance_scaffold.py --regen    # rewrite the mock files first
"""

from __future__ import annotations

import csv
import os
import sys
from datetime import datetime, date


# ===========================================================================
# CONFIG
# Everything that changes month-to-month or site-to-site lives here, NOT in
# the logic below. This is the only block you touch for routine maintenance.
# ===========================================================================

DATA_DIR = os.environ.get("COMPLIANCE_DATA_DIR", "data")

# "As of" date for the run. Pinned locally so results are deterministic and
# testable. In production this single line becomes: REPORT_DATE = date.today()
REPORT_DATE = date(2026, 6, 30)

# Windows baseline. An all-24H2 fleet means ONE build. Bump the revision each
# Patch Tuesday. Stored "BASE.REVISION"; we compare the revision as an integer.
WINDOWS_TARGET_BUILD = "26100.8655"   # KB5094126, June 2026

# A device must have checked in within this many days to count as "seen".
STALE_DAYS = 7

# Minimum acceptable agent versions.
ZSCALER_MIN_VERSION = "4.2.0"
CROWDSTRIKE_MIN_VERSION = "7.10.0"

# CMDB lifecycle states we treat as "this is a live device worth checking".
# Anything else (Retired, Disposed, In Stock...) is skipped - no emails about
# laptops nobody is using.
ACTIVE_STATUSES = {"in use", "active", "deployed", "assigned"}

# Where ownerless / shared devices route instead of a person.
IT_FALLBACK_EMAIL = "it-compliance@example.com"

# Column mapping: canonical_field -> the column name in THAT vendor's export.
# When a real file arrives with different headers, you edit the mapping here.
# The logic never refers to vendor column names directly, only canonical ones.
COLUMN_MAP = {
    "cmdb": {
        "serial": "Serial Number",
        "hostname": "Asset Name",
        "owner_email": "Assigned User Email",
        "status": "Lifecycle Status",
    },
    "windows": {
        "serial": "SerialNumber",
        "hostname": "DeviceName",
        "os_build": "OSBuild",
    },
    "zscaler": {
        "serial": "Device Serial",
        "hostname": "Hostname",
        "version": "ZCC Version",
        "last_seen": "Last Connected",
        "registered": "Registration State",
    },
    "crowdstrike": {
        "serial": "serial_number",
        "hostname": "hostname",
        "version": "sensor_version",
        "last_seen": "last_seen",
        "rfm": "reduced_functionality_mode",
    },
}


# ===========================================================================
# NORMALIZATION HELPERS
# Small, defensive parsers. Real vendor data is messy; none of these should
# ever raise - they return None / a safe default and let the rule decide.
# ===========================================================================

def norm_serial(value: str) -> str:
    """Serials are the join key. Uppercase + strip so 'sn003' matches 'SN003'."""
    return (value or "").strip().upper()


def parse_build_revision(build: str):
    """'26100.8655' -> 8655 (int). None if unparseable."""
    try:
        return int(str(build).split(".")[-1])
    except (ValueError, AttributeError):
        return None


def parse_version(v: str) -> tuple:
    """'7.10.0' -> (7, 10, 0). Tolerates junk; missing parts become 0."""
    parts = []
    for chunk in str(v or "").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def parse_date(s: str):
    """Accept the common export date shapes. Returns a date or None."""
    s = (s or "").strip().replace("T", " ").split(" ")[0]
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def days_since(d):
    """Days between a date and the report date. None if no date."""
    return None if d is None else (REPORT_DATE - d).days


# ===========================================================================
# INGEST + CORRELATE
# ===========================================================================

def read_source(name: str) -> list:
    """Read one CSV and map vendor columns -> canonical fields.

    utf-8-sig quietly strips the BOM Excel likes to add. Swap this function's
    body for openpyxl to read .xlsx; nothing downstream changes.
    """
    path = os.path.join(DATA_DIR, f"{name}.csv")
    cmap = COLUMN_MAP[name]
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for raw in csv.DictReader(f):
            rec = {canon: raw.get(col, "") for canon, col in cmap.items()}
            rec["serial"] = norm_serial(rec.get("serial"))
            rows.append(rec)
    return rows


def index_by_serial(rows: list) -> dict:
    return {r["serial"]: r for r in rows if r["serial"]}


def correlate() -> list:
    """Join everything onto the CMDB, which is the only source that knows the
    owner. Result: one record per CMDB device with the three feeds attached
    (or None where that device had no row in a given feed)."""
    cmdb = index_by_serial(read_source("cmdb"))
    win = index_by_serial(read_source("windows"))
    zsc = index_by_serial(read_source("zscaler"))
    crwd = index_by_serial(read_source("crowdstrike"))

    devices = []
    for serial, c in cmdb.items():
        devices.append({
            "serial": serial,
            "hostname": c.get("hostname"),
            "owner_email": c.get("owner_email"),
            "status": c.get("status"),
            "windows": win.get(serial),
            "zscaler": zsc.get(serial),
            "crowdstrike": crwd.get(serial),
        })
    return devices


# ===========================================================================
# COMPLIANCE RULES
# Each returns (passed: bool, reason: str). A missing feed record is a fail -
# "we have no evidence this device is protected" is itself non-compliant.
# ===========================================================================

def check_windows(rec) -> tuple:
    if rec is None:
        return False, "no Windows Update record"
    have = parse_build_revision(rec.get("os_build"))
    target = parse_build_revision(WINDOWS_TARGET_BUILD)
    if have is None:
        return False, f"unreadable build '{rec.get('os_build')}'"
    if have >= target:
        return True, f"build {rec.get('os_build')} OK"
    return False, f"build {rec.get('os_build')} below {WINDOWS_TARGET_BUILD}"


def check_zscaler(rec) -> tuple:
    if rec is None:
        return False, "no Zscaler record"
    state = (rec.get("registered") or "").strip().lower()
    if state not in ("registered", "enrolled", "true", "yes"):
        return False, f"connector not registered ({rec.get('registered')})"
    age = days_since(parse_date(rec.get("last_seen")))
    if age is None:
        return False, "no / unreadable last-seen"
    if age > STALE_DAYS:
        return False, f"last connected {age} days ago"
    if parse_version(rec.get("version")) < parse_version(ZSCALER_MIN_VERSION):
        return False, f"version {rec.get('version')} below {ZSCALER_MIN_VERSION}"
    return True, "OK"


def check_crowdstrike(rec) -> tuple:
    if rec is None:
        return False, "no CrowdStrike record"
    if (rec.get("rfm") or "").strip().lower() in ("true", "yes", "1", "rfm"):
        return False, "sensor in reduced functionality mode"
    age = days_since(parse_date(rec.get("last_seen")))
    if age is None:
        return False, "no / unreadable last-seen"
    if age > STALE_DAYS:
        return False, f"last seen {age} days ago"
    if parse_version(rec.get("version")) < parse_version(CROWDSTRIKE_MIN_VERSION):
        return False, f"version {rec.get('version')} below {CROWDSTRIKE_MIN_VERSION}"
    return True, "OK"


# label -> (rule function, device key holding that feed's record)
CHECKS = {
    "Windows Update": (check_windows, "windows"),
    "Zscaler": (check_zscaler, "zscaler"),
    "CrowdStrike": (check_crowdstrike, "crowdstrike"),
}


def evaluate(device: dict) -> list:
    """Return a list of (check_label, reason) for every FAILED check."""
    failures = []
    for label, (fn, key) in CHECKS.items():
        ok, reason = fn(device[key])
        if not ok:
            failures.append((label, reason))
    return failures


# ===========================================================================
# PIPELINE
# ===========================================================================

def run_pipeline() -> list:
    """Correlate, skip non-active devices, evaluate, keep only failures."""
    results = []
    for d in correlate():
        status = (d.get("status") or "").strip().lower()
        if status and status not in ACTIVE_STATUSES:
            continue  # retired / in-stock / disposed -> never notify
        failures = evaluate(d)
        if failures:
            results.append((d, failures))
    return results


# ===========================================================================
# NOTIFY  (stubbed - prints instead of sending)
# Swap the print block for a Graph sendMail / Teams call later. The owner
# resolution and message body are already what you want to keep.
# ===========================================================================

def notify(device: dict, failures: list) -> None:
    recipient = (device.get("owner_email") or "").strip()
    routed = ""
    if "@" not in recipient:
        recipient, routed = IT_FALLBACK_EMAIL, "  (no owner on file -> routed to IT)"

    subject = f"Action needed: {device['hostname']} failed a compliance check"
    body_lines = [
        f"Device {device['hostname']} (serial {device['serial']}) failed "
        f"the following check(s):",
        "",
    ]
    body_lines += [f"  - {label}: {reason}" for label, reason in failures]
    body_lines += ["", "Please contact IT to remediate. This is an automated message."]
    body = "\n".join(body_lines)

    print("=" * 72)
    print(f"TO:      {recipient}{routed}")
    print(f"SUBJECT: {subject}")
    print("-" * 72)
    print(body)
    print()


# ===========================================================================
# MOCK DATA GENERATOR
# Writes the four files using the EXACT column names declared in COLUMN_MAP,
# so this doubles as the schema spec you hand the Zscaler / CrowdStrike owners
# ("please make your export look like this"). Covers the edge cases that
# matter: stale check-in, RFM, missing feed record, retired device, ownerless
# shared device, and a lowercase serial to prove normalization works.
# ===========================================================================

def _write(name: str, fieldnames: list, rows: list) -> None:
    path = os.path.join(DATA_DIR, f"{name}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote {path}  ({len(rows)} rows)")


def generate_mock_data() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"Generating mock data in '{DATA_DIR}/' ...")

    _write("cmdb",
           ["Serial Number", "Asset Name", "Assigned User Email", "Lifecycle Status"],
           [
               {"Serial Number": "SN001", "Asset Name": "LT-ALICE", "Assigned User Email": "alice@example.com", "Lifecycle Status": "In Use"},
               {"Serial Number": "SN002", "Asset Name": "LT-BOB",   "Assigned User Email": "bob@example.com",   "Lifecycle Status": "In Use"},
               {"Serial Number": "SN003", "Asset Name": "LT-CAROL", "Assigned User Email": "carol@example.com", "Lifecycle Status": "In Use"},
               {"Serial Number": "SN004", "Asset Name": "LT-DAVE",  "Assigned User Email": "dave@example.com",  "Lifecycle Status": "In Use"},
               {"Serial Number": "SN005", "Asset Name": "LT-ERIN",  "Assigned User Email": "erin@example.com",  "Lifecycle Status": "In Use"},
               {"Serial Number": "SN006", "Asset Name": "LT-FRANK", "Assigned User Email": "frank@example.com", "Lifecycle Status": "Retired"},
               {"Serial Number": "SN007", "Asset Name": "KIOSK-LOBBY", "Assigned User Email": "", "Lifecycle Status": "In Use"},
               {"Serial Number": "SN008", "Asset Name": "LT-GRACE", "Assigned User Email": "grace@example.com", "Lifecycle Status": "In Use"},
           ])

    _write("windows",
           ["SerialNumber", "DeviceName", "OSBuild"],
           [
               {"SerialNumber": "SN001", "DeviceName": "LT-ALICE", "OSBuild": "26100.8655"},
               {"SerialNumber": "SN002", "DeviceName": "LT-BOB",   "OSBuild": "26100.8500"},   # FAIL: behind
               {"SerialNumber": "sn003", "DeviceName": "LT-CAROL", "OSBuild": "26100.8655"},   # lowercase serial on purpose
               {"SerialNumber": "SN004", "DeviceName": "LT-DAVE",  "OSBuild": "26100.8655"},
               {"SerialNumber": "SN005", "DeviceName": "LT-ERIN",  "OSBuild": "26100.8246"},   # FAIL: behind
               {"SerialNumber": "SN006", "DeviceName": "LT-FRANK", "OSBuild": "26100.8246"},   # behind, but retired -> skipped
               {"SerialNumber": "SN007", "DeviceName": "KIOSK-LOBBY", "OSBuild": "26100.8655"},
               {"SerialNumber": "SN008", "DeviceName": "LT-GRACE", "OSBuild": "26100.8655"},
           ])

    _write("zscaler",
           ["Device Serial", "Hostname", "ZCC Version", "Last Connected", "Registration State"],
           [
               {"Device Serial": "SN001", "Hostname": "LT-ALICE", "ZCC Version": "4.3.1", "Last Connected": "2026-06-29", "Registration State": "Registered"},
               {"Device Serial": "SN002", "Hostname": "LT-BOB",   "ZCC Version": "4.3.1", "Last Connected": "2026-06-28", "Registration State": "Registered"},
               {"Device Serial": "SN003", "Hostname": "LT-CAROL", "ZCC Version": "4.3.1", "Last Connected": "2026-06-10", "Registration State": "Registered"},  # FAIL: stale
               {"Device Serial": "SN004", "Hostname": "LT-DAVE",  "ZCC Version": "4.3.1", "Last Connected": "2026-06-30", "Registration State": "Registered"},
               {"Device Serial": "SN005", "Hostname": "LT-ERIN",  "ZCC Version": "4.3.1", "Last Connected": "2026-06-29", "Registration State": "Registered"},
               {"Device Serial": "SN007", "Hostname": "KIOSK-LOBBY", "ZCC Version": "4.3.1", "Last Connected": "2026-06-29", "Registration State": "Unregistered"},  # FAIL + ownerless
               {"Device Serial": "SN008", "Hostname": "LT-GRACE", "ZCC Version": "4.3.1", "Last Connected": "2026-06-29", "Registration State": "Registered"},
           ])

    _write("crowdstrike",
           ["serial_number", "hostname", "sensor_version", "last_seen", "reduced_functionality_mode"],
           [
               {"serial_number": "SN001", "hostname": "LT-ALICE", "sensor_version": "7.12.0", "last_seen": "2026-06-29", "reduced_functionality_mode": "false"},
               {"serial_number": "SN002", "hostname": "LT-BOB",   "sensor_version": "7.12.0", "last_seen": "2026-06-29", "reduced_functionality_mode": "false"},
               {"serial_number": "SN003", "hostname": "LT-CAROL", "sensor_version": "7.12.0", "last_seen": "2026-06-29", "reduced_functionality_mode": "false"},
               {"serial_number": "SN004", "hostname": "LT-DAVE",  "sensor_version": "7.12.0", "last_seen": "2026-06-29", "reduced_functionality_mode": "true"},   # FAIL: RFM
               # SN005 intentionally ABSENT -> "no CrowdStrike record" failure
               {"serial_number": "SN007", "hostname": "KIOSK-LOBBY", "sensor_version": "7.12.0", "last_seen": "2026-06-29", "reduced_functionality_mode": "false"},
               {"serial_number": "SN008", "hostname": "LT-GRACE", "sensor_version": "7.12.0", "last_seen": "2026-06-29", "reduced_functionality_mode": "false"},
           ])


# ===========================================================================
# ENTRY POINT
# ===========================================================================

def main() -> None:
    regen = "--regen" in sys.argv
    if regen or not os.path.isdir(DATA_DIR):
        generate_mock_data()
        print()

    results = run_pipeline()

    print("#" * 72)
    print(f"# Compliance run as of {REPORT_DATE}   "
          f"target build {WINDOWS_TARGET_BUILD}   stale > {STALE_DAYS}d")
    print(f"# {len(results)} device(s) need a notification")
    print("#" * 72)
    print()

    for device, failures in results:
        notify(device, failures)


if __name__ == "__main__":
    main()
