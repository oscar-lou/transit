# Pytest bootstrap: makes the project's flat modules (consolidate_noncompliant,
# send_email) importable from tests/ regardless of cwd or how pytest is
# invoked - same rationale as the sys.path fix in send_email.py itself.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))