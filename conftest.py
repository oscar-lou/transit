# Pytest bootstrap: makes the project's flat modules (consolidate_noncompliant,
# send_email) importable from tests/ regardless of cwd or how pytest is
# invoked - same rationale as the sys.path fix in send_email.py itself.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

import consolidate_noncompliant as cnc


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Redirects consolidate_noncompliant.DATA_DIR at a scratch directory for
    the duration of one test. Shared across test files that only need input
    files, not output writing - see data_and_output_dir for tests that need
    both."""
    monkeypatch.setattr(cnc, "DATA_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def data_and_output_dir(tmp_path, monkeypatch):
    """Redirects both DATA_DIR and OUTPUT_DIR at scratch subdirectories -
    for tests that run the full pipeline (which also writes worklist/
    preview output files)."""
    monkeypatch.setattr(cnc, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(cnc, "OUTPUT_DIR", str(tmp_path / "output"))
    return tmp_path