"""Wraps send_email.py's existing --selftest (no network calls, no real
credentials) so `pytest` is the single command that verifies everything in
this project, instead of needing a separate manual invocation.
"""
import csv
import io
import urllib.error

import send_email as se


def test_send_email_selftest_passes():
    assert se.selftest() == 0


# ===========================================================================
# send_one() failure path - the self-test above only ever exercises the
# success path (fake_send always returns 202); these pin what happens when
# Graph actually fails, which is otherwise completely unverified.
# ===========================================================================

def test_send_one_returns_failed_on_http_error(monkeypatch):
    def fake_send(token, sender_upn, to_email, subject, body_html):
        raise urllib.error.HTTPError(
            url="https://graph.microsoft.com/v1.0/users/x/sendMail", code=403,
            msg="Forbidden", hdrs=None,
            fp=io.BytesIO(b'{"error": {"message": "Access is denied"}}'))

    monkeypatch.setattr(se, "_graph_send_mail", fake_send)
    result, error = se.send_one("token", "sender@example.com", "to@example.com",
                                 "subj", "<p>body</p>")
    assert result == "failed"
    assert "403" in error
    assert "Access is denied" in error


def test_send_one_truncates_long_http_error_body(monkeypatch):
    # A unique marker placed just past the 300-char truncation point, so the
    # assertion actually proves truncation happened rather than relying on a
    # repeated-character body where any suffix is trivially a substring of
    # the (equally repetitive) truncated prefix.
    long_detail = ("a" * 300) + "UNIQUE_TAIL_MARKER_BEYOND_TRUNCATION"

    def fake_send(token, sender_upn, to_email, subject, body_html):
        raise urllib.error.HTTPError(
            url="https://graph.microsoft.com/v1.0/users/x/sendMail", code=429,
            msg="Too Many Requests", hdrs=None, fp=io.BytesIO(long_detail.encode()))

    monkeypatch.setattr(se, "_graph_send_mail", fake_send)
    result, error = se.send_one("token", "sender@example.com", "to@example.com",
                                 "subj", "<p>body</p>")
    assert result == "failed"
    assert error.startswith("HTTP 429: ")
    assert long_detail[:300] in error
    assert "UNIQUE_TAIL_MARKER_BEYOND_TRUNCATION" not in error, (
        "REGRESSION: HTTP error body was not truncated to 300 chars")


def test_send_one_returns_failed_on_generic_exception(monkeypatch):
    def fake_send(token, sender_upn, to_email, subject, body_html):
        raise TimeoutError("network unreachable")

    monkeypatch.setattr(se, "_graph_send_mail", fake_send)
    result, error = se.send_one("token", "sender@example.com", "to@example.com",
                                 "subj", "<p>body</p>")
    assert result == "failed"
    assert "network unreachable" in error


def test_run_with_groups_continues_after_one_recipient_fails(monkeypatch, tmp_path):
    """The module docstring states 'one recipient failing never aborts the
    run' - pin that directly rather than trusting the comment."""
    groups = {
        "fail@example.com": {"how": "test", "rows": [
            {"hostname": "WS-FAIL-01", "source": "CrowdStrike", "issue": "x", "action": "y"}]},
        "ok@example.com": {"how": "test", "rows": [
            {"hostname": "WS-OK-01", "source": "CrowdStrike", "issue": "x", "action": "y"}]},
    }
    attempted = []

    def fake_send(token, sender_upn, to_email, subject, body_html):
        attempted.append(to_email)
        if to_email == "fail@example.com":
            raise urllib.error.HTTPError(
                url="https://graph.microsoft.com/v1.0/users/x/sendMail", code=500,
                msg="Internal Server Error", hdrs=None, fp=io.BytesIO(b"boom"))
        return 202

    monkeypatch.setattr(se, "_graph_send_mail", fake_send)
    monkeypatch.setattr(se, "_get_graph_token", lambda *a, **k: "fake-token")
    monkeypatch.setattr(se.cnc, "OUTPUT_DIR", str(tmp_path))
    for key in se.REQUIRED_GRAPH_ENV:
        monkeypatch.setenv(key, "x")

    rc = se._run_with_groups("send-live", groups, [], [], confirm_live=True)

    assert set(attempted) == {"fail@example.com", "ok@example.com"}, (
        "REGRESSION: loop must attempt every recipient, not abort after the first failure")
    assert rc == 1, "non-zero exit expected since one send failed, but the run must still complete"


def test_failed_send_is_logged_with_result_and_error(monkeypatch, tmp_path):
    groups = {
        "fail@example.com": {"how": "test", "rows": [
            {"hostname": "WS-FAIL-01", "source": "CrowdStrike", "issue": "x", "action": "y"}]},
    }

    def fake_send(token, sender_upn, to_email, subject, body_html):
        raise urllib.error.HTTPError(
            url="https://graph.microsoft.com/v1.0/users/x/sendMail", code=403,
            msg="Forbidden", hdrs=None, fp=io.BytesIO(b"Access is denied"))

    monkeypatch.setattr(se, "_graph_send_mail", fake_send)
    monkeypatch.setattr(se, "_get_graph_token", lambda *a, **k: "fake-token")
    monkeypatch.setattr(se.cnc, "OUTPUT_DIR", str(tmp_path))
    for key in se.REQUIRED_GRAPH_ENV:
        monkeypatch.setenv(key, "x")

    rc = se._run_with_groups("send-live", groups, [], [], confirm_live=True)
    assert rc == 1

    with open(tmp_path / "send_log.csv", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["result"] == "failed"
    assert rows[0]["intended_recipient"] == "fail@example.com"
    assert "403" in rows[0]["error"]
    assert "Access is denied" in rows[0]["error"]


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
