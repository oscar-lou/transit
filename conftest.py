# Pytest bootstrap: makes the project's flat modules (consolidate_noncompliant,
# send_email) importable from tests/ regardless of cwd or how pytest is
# invoked - same rationale as the sys.path fix in send_email.py itself.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

import consolidate_noncompliant as cnc


@pytest.fixture(autouse=True)
def _clear_xlsx_workbook_cache():
    """Every test starts and ends with an empty xlsx workbook cache (see
    consolidate_noncompliant._get_cached_workbook()/_clear_xlsx_cache()) -
    without this, a workbook cached by one test could leak an open file
    handle past that test's tmp_path teardown (Windows can't delete a
    directory with an open handle into it), or - if two tests ever reused
    the exact same DATA_DIR+filename pair - serve one test's content to
    another."""
    cnc._clear_xlsx_cache()
    yield
    cnc._clear_xlsx_cache()


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