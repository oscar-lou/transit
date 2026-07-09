"""Wraps send_email.py's existing --selftest (no network calls, no real
credentials) so `pytest` is the single command that verifies everything in
this project, instead of needing a separate manual invocation.
"""
import send_email as se


def test_send_email_selftest_passes():
    assert se.selftest() == 0


def test_max_send_defaults_to_25_when_unset(monkeypatch):
    monkeypatch.delenv("COMPLIANCE_MAX_SEND", raising=False)
    assert se._load_max_send() == 25


def test_max_send_overridable_via_env_var(monkeypatch):
    monkeypatch.setenv("COMPLIANCE_MAX_SEND", "100")
    assert se._load_max_send() == 100


def test_max_send_falls_back_to_default_on_invalid_value(monkeypatch, capsys):
    monkeypatch.setenv("COMPLIANCE_MAX_SEND", "not-a-number")
    assert se._load_max_send() == 25
    assert "not-a-number" in capsys.readouterr().out


def test_max_send_falls_back_to_default_on_non_positive_value(monkeypatch):
    monkeypatch.setenv("COMPLIANCE_MAX_SEND", "0")
    assert se._load_max_send() == 25
