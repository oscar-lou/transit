#!/usr/bin/env python3
"""
Verifies this machine can actually reach and authenticate to the Databricks
workspace this project runs on - nothing else. Doesn't touch report data,
doesn't run the pipeline; it only answers "is Databricks connectivity/auth
working from here right now."

This is deliberately separate from send_email.py's --selftest: selftest()
proves the send pipeline's own logic with everything mocked out (no network,
no real credentials, safe to run anywhere, anytime). This script is the
opposite - it makes a REAL network call to a REAL workspace, so a clean
run here means something selftest() can't: that auth is actually configured
correctly on this machine, not just that the code would work if it were.

Auth is never chosen or hardcoded here - it uses the Databricks SDK's own
"unified authentication" resolution (whatever is already configured: a
notebook's injected context, DATABRICKS_HOST/DATABRICKS_TOKEN env vars, an
OAuth service principal, a CLI profile, ...). See
https://docs.databricks.com/en/dev-tools/auth.html for how to set one up.

Run:
  python check_databricks_connection.py
  python check_databricks_connection.py --host https://adb-....azuredatabricks.net
  python check_databricks_connection.py --secret-scope compliance-automation
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    from databricks.sdk import WorkspaceClient
    HAVE_DATABRICKS_SDK = True
except ImportError:
    HAVE_DATABRICKS_SDK = False

# This project's workspace, per the access granted for it - used only as the
# default so a plain `python check_databricks_connection.py` on the company
# laptop needs no extra flags. DATABRICKS_HOST (or --host) always overrides.
DEFAULT_HOST = "https://adb-7405611327863691.11.azuredatabricks.net"


def check_connection(host: str, secret_scope: str = None, client=None) -> tuple:
    """-> (ok: bool, message: str). `client` is an injection point for tests
    (a fake WorkspaceClient-shaped object) - production callers never pass
    it, so main() always exercises the real SDK's unified auth resolution."""
    if not HAVE_DATABRICKS_SDK:
        return False, ("databricks-sdk isn't installed in this Python environment "
                        "(pip install databricks-sdk).")

    if client is None:
        try:
            client = WorkspaceClient(host=host)
        except Exception as e:
            return False, f"Could not configure a Databricks client for {host}: {e}"

    try:
        me = client.current_user.me()
    except Exception as e:
        return False, (f"Reached {host} but authentication failed: {e}\n"
                        f"See https://docs.databricks.com/en/dev-tools/auth.html to "
                        f"configure credentials for your preferred auth method.")

    lines = [f"OK  authenticated to {host} as {me.user_name!r}"]

    if secret_scope:
        try:
            keys = [s.key for s in client.secrets.list_secrets(secret_scope)]
        except Exception as e:
            lines.append(f"!!  could not read secret scope {secret_scope!r}: {e}")
            return False, "\n".join(lines)
        lines.append(f"OK  secret scope {secret_scope!r}: {len(keys)} key(s) present "
                      f"({', '.join(sorted(keys)) or '(none)'})")

    return True, "\n".join(lines)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("--host", default=os.environ.get("DATABRICKS_HOST", DEFAULT_HOST),
                   help=f"workspace URL (default: env DATABRICKS_HOST, else {DEFAULT_HOST!r})")
    p.add_argument("--secret-scope",
                   default=os.environ.get("COMPLIANCE_DATABRICKS_SECRET_SCOPE"),
                   help="also list keys in this secret scope (default: "
                        "COMPLIANCE_DATABRICKS_SECRET_SCOPE if set; skipped if neither given)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    ok, message = check_connection(args.host, args.secret_scope)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
