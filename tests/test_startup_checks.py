"""Tests for _warn_if_thresholds_stale() - CS_LATEST/PURVIEW_LATEST are
hardcoded reference versions with no way to auto-refresh; this is the only
thing standing between them going stale and nobody noticing.
"""
from datetime import date, timedelta

import consolidate_noncompliant as cnc


def test_warns_when_thresholds_are_old(monkeypatch, capsys):
    monkeypatch.setattr(cnc, "THRESHOLDS_VERIFIED",
                         date.today() - timedelta(days=cnc.THRESHOLDS_STALE_AFTER_DAYS + 1))
    stale = cnc._warn_if_thresholds_stale()
    out = capsys.readouterr().out
    assert stale is True
    assert "CS_LATEST/PURVIEW_LATEST" in out
    assert "verified" in out.lower()
    assert "update" in out.lower()


def test_no_warning_when_thresholds_are_recent(monkeypatch, capsys):
    monkeypatch.setattr(cnc, "THRESHOLDS_VERIFIED", date.today())
    stale = cnc._warn_if_thresholds_stale()
    out = capsys.readouterr().out
    assert stale is False
    assert out == ""


def test_boundary_exactly_at_threshold_is_not_yet_stale(monkeypatch, capsys):
    """Off-by-one guard: exactly THRESHOLDS_STALE_AFTER_DAYS old should not
    warn yet - only strictly older than that."""
    monkeypatch.setattr(cnc, "THRESHOLDS_VERIFIED",
                         date.today() - timedelta(days=cnc.THRESHOLDS_STALE_AFTER_DAYS))
    assert cnc._warn_if_thresholds_stale() is False
