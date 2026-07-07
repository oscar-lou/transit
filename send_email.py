#!/usr/bin/env python3
"""
Phase 2: actually send the consolidated compliance notifications, via
Microsoft Graph (Mail.Send, application permission, client-credentials auth).

This is a SEPARATE, EXPLICIT invocation from consolidate_noncompliant.py.
Running `python consolidate_noncompliant.py` never sends anything - it only
ever writes the preview workbook, same as before this file existed. Sending
only happens when THIS script is run directly, and only in the mode you
explicitly choose.

Reuses consolidate_noncompliant.py's pipeline as-is (load_all, CMDB/AD_Users
resolution, build_notifications, compose_email) - nothing about message
composition or recipient resolution is reimplemented here.

Modes (mutually exclusive; --dry-run is the default if none given):
  --dry-run       (default) send nothing; identical to consolidate_noncompliant's
                  existing preview behavior (console summary + notifications_preview.xlsx).
  --send-to-self  Really call Graph, but every message is redirected to
                  COMPLIANCE_TEST_INBOX, with a banner at the top of the body
                  showing who it would really have gone to. Use this to
                  verify the send pipe end-to-end before going live.
  --send-live     Send to the real resolved recipients. Refuses outright
                  unless --i-understand-this-emails-real-people is also given.

Safety:
  - Only ever sends to the confidently-resolved `groups` from
    build_notifications() - never REVIEW or UNRESOLVED. Asserted in code
    (_assert_no_overlap_with_review_or_unresolved), as defense in depth on
    top of build_notifications() already partitioning rows correctly.
  - MAX_SEND caps recipients per run; --allow-bulk overrides it.
  - Every send attempt (sent/failed/skipped) is logged to output/send_log.csv.
  - Idempotency: skips (and logs as skipped) a recipient+finding-set+mode
    already sent successfully today, so re-running doesn't double-email.
  - One recipient failing never aborts the run - logged, loop continues.

Auth (env vars only - never hardcoded, never interactive/device-code):
  GRAPH_TENANT_ID      Azure AD tenant ID
  GRAPH_CLIENT_ID      app registration (client) ID - needs Mail.Send
                       (Application, admin-consented)
  GRAPH_CLIENT_SECRET  client secret for that app registration
  GRAPH_SENDER_UPN     mailbox to send FROM (app-only Mail.Send always sends
                       as a specific mailbox, e.g. compliance-bot@aia.com)
  COMPLIANCE_TEST_INBOX   required for --send-to-self: your own test mailbox

  All of the above can also go in a .env file next to this script (gitignored,
  never committed) instead of real shell env vars - loaded automatically on
  import. A real environment variable always takes priority over .env.

Run:
  python send_email.py                                          # dry-run (default)
  python send_email.py --send-to-self
  python send_email.py --send-live --i-understand-this-emails-real-people
  python send_email.py --selftest                                # no network, no creds needed
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime

# Guarantee consolidate_noncompliant.py (always a sibling of this file) is
# importable regardless of the caller's cwd or interpreter startup flags -
# e.g. PYTHONSAFEPATH (Python 3.11+) disables the usual auto-add of the
# script's own directory to sys.path, which some managed/corporate machines
# set by policy and which otherwise turns this into a ModuleNotFoundError.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv(path: str) -> None:
    """Minimal .env loader (KEY=VALUE per line, '#' comments and blanks
    skipped) - deliberately no new dependency on python-dotenv, matching
    the rest of this codebase's stdlib-only style. An already-set real
    environment variable always wins over the .env file, so this never
    shadows a CI/production value with a stale local one."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

import consolidate_noncompliant as cnc

# ===========================================================================
# CONFIG
# ===========================================================================

MAX_SEND = 25  # recipients per run before --allow-bulk is required

GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_SEND_URL = "https://graph.microsoft.com/v1.0/users/{upn}/sendMail"

REQUIRED_GRAPH_ENV = {
    "GRAPH_TENANT_ID": "Azure AD tenant ID",
    "GRAPH_CLIENT_ID": "app registration (client) ID, granted Mail.Send (Application, admin-consented)",
    "GRAPH_CLIENT_SECRET": "client secret for that app registration",
    "GRAPH_SENDER_UPN": "mailbox to send FROM (app-only Mail.Send always sends as a specific mailbox)",
}

SEND_LOG_COLUMNS = ["timestamp", "mode", "intended_recipient", "actual_recipient",
                    "subject", "result", "error", "finding_signature"]


# ===========================================================================
# GRAPH CALLS  (raw urllib, not requests/msal - no new dependency beyond
# what's already optional in consolidate_noncompliant.py; also keeps every
# HTTP call in exactly two small, easily-mockable functions for the self-test)
# ===========================================================================

def _get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    req = urllib.request.Request(GRAPH_TOKEN_URL.format(tenant=tenant_id), data=data, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    return payload["access_token"]


def _graph_send_mail(token: str, sender_upn: str, to_email: str, subject: str, body_text: str) -> int:
    message = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body_text},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": "true",
    }
    req = urllib.request.Request(
        GRAPH_SEND_URL.format(upn=sender_upn),
        data=json.dumps(message).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def send_one(token: str, sender_upn: str, to_email: str, subject: str, body: str) -> tuple:
    """-> (result, error). Never raises - one bad recipient must not abort the run."""
    try:
        _graph_send_mail(token, sender_upn, to_email, subject, body)
        return "sent", ""
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode(errors="replace")
        except Exception:
            detail = ""
        return "failed", f"HTTP {e.code}: {detail[:300]}"
    except Exception as e:
        return "failed", str(e)


def _load_graph_credentials():
    missing = [v for v in REQUIRED_GRAPH_ENV if not os.environ.get(v)]
    if missing:
        print("Refusing to send: missing required environment variable(s):")
        for v in missing:
            print(f"  {v:20s} - {REQUIRED_GRAPH_ENV[v]}")
        return None
    return {v: os.environ[v] for v in REQUIRED_GRAPH_ENV}


# ===========================================================================
# AUDIT LOG + IDEMPOTENCY
# ===========================================================================

def _send_log_path() -> str:
    return os.path.join(cnc.OUTPUT_DIR, "send_log.csv")


def _finding_set_signature(rows: list) -> str:
    """Stable signature for 'the same finding-set', used by the idempotency
    guard. Based on (hostname, source, issue) per row, not row order."""
    items = sorted((r["hostname"], r["source"], r["issue"]) for r in rows)
    blob = "|".join(f"{h}::{s}::{i}" for h, s, i in items)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _log_row(mode: str, intended: str, actual: str, subject: str, result: str, error: str, sig: str) -> dict:
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "mode": mode,
        "intended_recipient": intended,
        "actual_recipient": actual,
        "subject": subject,
        "result": result,
        "error": error,
        "finding_signature": sig,
    }


def _load_prior_successful_sends() -> set:
    """-> set of (intended_recipient, finding_signature, date, mode) already
    sent successfully. Keyed by mode too, so a --send-to-self test run never
    blocks (or is blocked by) a --send-live run for the same recipient."""
    path = _send_log_path()
    if not os.path.exists(path):
        return set()
    out = set()
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("result") == "sent":
                day = (row.get("timestamp") or "")[:10]
                out.add((row.get("intended_recipient", ""), row.get("finding_signature", ""),
                          day, row.get("mode", "")))
    return out


def _append_send_log(rows: list) -> None:
    if not rows:
        return
    path = _send_log_path()
    os.makedirs(cnc.OUTPUT_DIR, exist_ok=True)
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=SEND_LOG_COLUMNS)
        if write_header:
            w.writeheader()
        w.writerows(rows)


# ===========================================================================
# SAFETY GUARD
# ===========================================================================

def _assert_no_overlap_with_review_or_unresolved(groups: dict, review: list, unresolved: list) -> None:
    """Defense in depth: build_notifications() already partitions every row
    into exactly one of groups/review/unresolved, so this should never fire
    in correct operation. It exists to catch a future refactor bug, not a
    case we expect to hit - if it ever does fire, refuse to send ANYTHING
    this run rather than risk emailing the wrong finding to someone."""
    blocked = {(r["hostname"], r["source"], r["issue"]) for r, how, cands in review}
    blocked |= {(r["hostname"], r["source"], r["issue"]) for r, how in unresolved}
    for email, g in groups.items():
        for r in g["rows"]:
            key = (r["hostname"], r["source"], r["issue"])
            assert key not in blocked, (
                f"SAFETY: finding {key} intended for {email} also appears in the "
                f"review/unresolved list - refusing to send anything this run"
            )


# ===========================================================================
# PIPELINE  (reuses consolidate_noncompliant.py end to end)
# ===========================================================================

def build_groups() -> tuple:
    """Runs the exact same resolution pipeline as consolidate_noncompliant.main(),
    minus the mock-data-generation step (which callers opt into explicitly,
    e.g. the self-test) and minus writing the worklist - this module only
    needs recipient groups, not the full worklist workbook."""
    rows = cnc.load_all()
    cmdb_names = cnc.read_cmdb_mapping()
    ad = cnc.read_ad_users()
    overrides = cnc.read_overrides()
    return cnc.build_notifications(rows, cmdb_names, ad, overrides)


def _run_with_groups(mode: str, groups: dict, review: list, unresolved: list,
                      allow_bulk: bool = False, confirm_live: bool = False) -> int:
    _assert_no_overlap_with_review_or_unresolved(groups, review, unresolved)

    if mode == "dry-run":
        preview = cnc.write_notifications_preview(groups, review, unresolved)
        cnc.print_notify_summary(groups, review, unresolved)
        print(f"\n[dry-run] Notification preview -> {preview}   (NOTHING SENT)")
        return 0

    if mode == "send-live" and not confirm_live:
        print("Refusing to send: --send-live requires --i-understand-this-emails-real-people "
              "(this will email real people - pass it explicitly to proceed).")
        return 1

    if len(groups) > MAX_SEND and not allow_bulk:
        print(f"Refusing to send: {len(groups)} recipient(s) exceeds MAX_SEND={MAX_SEND}. "
              f"Pass --allow-bulk if this many recipients is really intended.")
        return 1

    test_inbox = None
    if mode == "send-to-self":
        test_inbox = os.environ.get("COMPLIANCE_TEST_INBOX", "")
        if not test_inbox or "@" not in test_inbox or "replace" in test_inbox.lower():
            print("Refusing to send: --send-to-self requires the COMPLIANCE_TEST_INBOX "
                  "environment variable set to your real test mailbox address "
                  "(edit .env - it still has the placeholder value, or isn't set at all).")
            return 1

    creds = _load_graph_credentials()
    if creds is None:
        return 1
    try:
        token = _get_graph_token(creds["GRAPH_TENANT_ID"], creds["GRAPH_CLIENT_ID"],
                                  creds["GRAPH_CLIENT_SECRET"])
    except Exception as e:
        print(f"Refusing to send: could not acquire a Graph token - {e}")
        return 1

    prior_sent = _load_prior_successful_sends()
    today = date.today().isoformat()
    log_rows = []
    sent_count = fail_count = skip_count = 0

    for email, g in sorted(groups.items()):
        subject, body = cnc.compose_email(g["rows"])
        sig = _finding_set_signature(g["rows"])

        if (email, sig, today, mode) in prior_sent:
            print(f"  skip (already sent today via {mode}): {email}")
            log_rows.append(_log_row(mode, email, email, subject, "skipped-duplicate", "", sig))
            skip_count += 1
            continue

        actual, send_subject, send_body = email, subject, body
        if mode == "send-to-self":
            actual = test_inbox
            send_subject = f"[TEST -> {email}] {subject}"
            send_body = f"[TEST — would have gone to: {email}]\n\n{body}"

        result, error = send_one(token, creds["GRAPH_SENDER_UPN"], actual, send_subject, send_body)
        if result == "sent":
            sent_count += 1
            print(f"  sent    {email} -> {actual}: {subject}")
        else:
            fail_count += 1
            print(f"  FAILED  {email} -> {actual}: {subject}  [{error}]")
        log_rows.append(_log_row(mode, email, actual, subject, result, error, sig))

    _append_send_log(log_rows)
    print(f"\n{sent_count} sent, {fail_count} failed, {skip_count} skipped (duplicate) "
          f"out of {len(groups)} recipient(s). Audit log -> {_send_log_path()}")
    return 0 if fail_count == 0 else 1


def run(mode: str, allow_bulk: bool = False, confirm_live: bool = False) -> int:
    groups, review, unresolved = build_groups()
    return _run_with_groups(mode, groups, review, unresolved, allow_bulk, confirm_live)


# ===========================================================================
# SELF-TEST  (no network calls, no real credentials - safe to run any time)
# ===========================================================================

def selftest() -> int:
    """Integration self-test: runs generate_mock_data()'s fixtures through the
    real pipeline (load_all -> resolve -> build_notifications) in an isolated
    scratch directory, then proves the two safety behaviors that matter most,
    with the actual Graph HTTP calls monkeypatched out:
      1. --send-to-self redirects every message to COMPLIANCE_TEST_INBOX and
         preserves the original intended recipient in a visible body banner.
      2. --send-live without --i-understand-this-emails-real-people refuses
         outright and calls Graph zero times.
    Run: python send_email.py --selftest
    """
    print("Running send_email self-test against generate_mock_data() fixtures (no network calls)...")

    scratch = tempfile.mkdtemp(prefix="compliance_selftest_")
    orig_data_dir, orig_output_dir = cnc.DATA_DIR, cnc.OUTPUT_DIR
    orig_env = {k: os.environ.get(k) for k in
                list(REQUIRED_GRAPH_ENV) + ["COMPLIANCE_TEST_INBOX"]}
    real_graph_send, real_get_token = _graph_send_mail, _get_graph_token
    sent_calls = []

    def fake_send(token, sender_upn, to_email, subject, body_text):
        sent_calls.append((to_email, subject, body_text))
        return 202

    cnc.DATA_DIR = os.path.join(scratch, "data")
    cnc.OUTPUT_DIR = os.path.join(scratch, "output")

    try:
        cnc.generate_mock_data()
        groups, review, unresolved = build_groups()
        assert groups, "self-test fixture produced no confidently-resolved recipients to test with"

        globals()["_graph_send_mail"] = fake_send
        globals()["_get_graph_token"] = lambda *a, **k: "fake-token"
        os.environ["COMPLIANCE_TEST_INBOX"] = "test-inbox@example.com"
        os.environ["GRAPH_TENANT_ID"] = "fake-tenant"
        os.environ["GRAPH_CLIENT_ID"] = "fake-client"
        os.environ["GRAPH_CLIENT_SECRET"] = "fake-secret"
        os.environ["GRAPH_SENDER_UPN"] = "sender@example.com"

        rc = _run_with_groups("send-to-self", groups, review, unresolved,
                               allow_bulk=True, confirm_live=False)
        assert rc == 0, f"send-to-self self-test run should succeed, got rc={rc}"
        assert len(sent_calls) == len(groups), (
            f"expected {len(groups)} redirected send(s), got {len(sent_calls)}")
        for to_email, subject, body in sent_calls:
            assert to_email == "test-inbox@example.com", (
                f"expected every send redirected to TEST_INBOX, got {to_email}")
            assert "would have gone to" in body, "banner must preserve original intended recipient"
        print(f"  OK  --send-to-self redirected all {len(sent_calls)} message(s) to "
              f"COMPLIANCE_TEST_INBOX with the original-recipient banner intact")

        sent_calls.clear()
        rc2 = _run_with_groups("send-live", groups, review, unresolved,
                                allow_bulk=True, confirm_live=False)
        assert rc2 != 0, "send-live without confirmation must return non-zero"
        assert not sent_calls, "send-live without confirmation must not call Graph"
        print("  OK  --send-live without --i-understand-this-emails-real-people "
              "refuses and sends nothing")
    finally:
        globals()["_graph_send_mail"] = real_graph_send
        globals()["_get_graph_token"] = real_get_token
        cnc.DATA_DIR, cnc.OUTPUT_DIR = orig_data_dir, orig_output_dir
        for k, v in orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(scratch, ignore_errors=True)

    print("Self-test passed.")
    return 0


# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Send (or dry-run) the consolidated compliance notifications via Microsoft "
                    "Graph. Always a separate, explicit step from consolidate_noncompliant.py.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true",
                       help="(default) send nothing; identical to the existing preview behavior")
    mode.add_argument("--send-to-self", action="store_true",
                       help="really call Graph, but redirect every recipient to COMPLIANCE_TEST_INBOX")
    mode.add_argument("--send-live", action="store_true",
                       help="send to the real resolved recipients (requires the confirmation flag below)")
    p.add_argument("--i-understand-this-emails-real-people", action="store_true",
                   help="required together with --send-live, or it refuses")
    p.add_argument("--allow-bulk", action="store_true",
                   help=f"allow sending to more than MAX_SEND ({MAX_SEND}) recipients in one run")
    p.add_argument("--selftest", action="store_true",
                   help="run built-in safety self-tests against generate_mock_data() fixtures and "
                        "exit (no network calls, no real credentials needed)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.selftest:
        return selftest()

    mode = "dry-run"
    if args.send_to_self:
        mode = "send-to-self"
    elif args.send_live:
        mode = "send-live"

    return run(mode, allow_bulk=args.allow_bulk,
               confirm_live=args.i_understand_this_emails_real_people)


if __name__ == "__main__":
    sys.exit(main())
