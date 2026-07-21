# Compliance Automation

Builds a per-recipient non-compliance worklist from the CrowdStrike/Purview/
Zapp/DLP reports and CMDB/AD_Users exports, and sends the resulting
notifications via Microsoft Graph (`consolidate_noncompliant.py` for the
worklist/preview, `send_email.py` for actually sending - see the docstring
at the top of each for details and flags).

## Dev setup

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sh scripts/install-hooks.sh   # one-time: installs the pre-commit test hook
```

The pre-commit hook runs the full `pytest` suite before every commit and
blocks the commit if anything fails. Bypass a single commit intentionally
with `git commit --no-verify`.

## Running on Databricks

Databricks (workspace: `adb-go05-eas-d-genai-gen01`) is the intended run
location, replacing the Azure Function App plan from earlier - see the
Project Brief. What that means concretely today:

- **Compute only, for now.** The scripts are unchanged plain Python
  entry points, runnable as a Databricks Job "Python script" task (e.g. a
  Git-repo-backed Job pointing at `consolidate_noncompliant.py` /
  `send_email.py`) - no bundle/job definition is checked into this repo yet,
  since that depends on how the workspace is actually set up on your end.
- **Inputs/outputs are still local disk**, via the existing
  `COMPLIANCE_DATA_DIR`/`COMPLIANCE_OUTPUT_DIR` env vars. Reading reports
  directly from cloud storage is still pending (not implemented) - per the
  access granted so far, that part isn't ready yet. If/when the report files
  land in a Unity Catalog Volume, pointing `COMPLIANCE_DATA_DIR` at its
  `/Volumes/...` path should work as-is, since Volumes are exposed as a
  normal filesystem path on cluster compute and `LocalDataSource` just reads
  bytes off disk - no code change anticipated, but unverified until that
  Volume actually exists.
- **Secrets**: `send_email.py` can read `GRAPH_*`/`COMPLIANCE_*` credentials
  from a Databricks secret scope instead of `.env`, auto-selected whenever
  `DATABRICKS_RUNTIME_VERSION` is set (i.e. running on a cluster/job) -
  override with `COMPLIANCE_SECRETS_BACKEND=env|databricks`. See the "Auth"
  section of `send_email.py`'s docstring. Requires
  `pip install -r requirements-databricks.txt` and an actual secret scope
  (default name `compliance-automation`, override via
  `COMPLIANCE_DATABRICKS_SECRET_SCOPE`) - neither exists yet.
- **Verify connectivity/auth actually works** before relying on any of the
  above: `python check_databricks_connection.py` (add `--secret-scope
  compliance-automation` once that scope exists). This needs real network
  access and Databricks auth already configured - per the access granted so
  far, that's expected to only work from the company laptop, not from an
  arbitrary dev machine.
