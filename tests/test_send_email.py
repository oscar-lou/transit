"""Wraps send_email.py's existing --selftest (no network calls, no real
credentials) so `pytest` is the single command that verifies everything in
this project, instead of needing a separate manual invocation.
"""
import send_email as se


def test_send_email_selftest_passes():
    assert se.selftest() == 0
