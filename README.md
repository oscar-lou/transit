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
