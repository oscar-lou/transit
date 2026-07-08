"""Tests for compose_email_html() - the HTML counterpart to compose_email().
Same content as the plain-text version (presentation-only change), and every
interpolated value HTML-escaped so a stray hostname containing <, &, or >
can't break rendering or inject markup.
"""
import html

import consolidate_noncompliant as cnc


def _finding(hostname, source="CrowdStrike", issue="x", action="y",
             platform="Windows", kind="Workstation", bu="AIAGO"):
    return {"hostname": hostname, "source": source, "issue": issue, "action": action,
            "platform": platform, "kind": kind, "bu": bu}


def test_html_has_same_hostnames_as_plain_text():
    findings = [_finding("HHOWKLC-TEST01"), _finding("HHOWKLC-TEST02")]
    subject, plain_body = cnc.compose_email(findings)
    html_body = cnc.compose_email_html(findings)

    for f in findings:
        assert f["hostname"] in plain_body, "test fixture sanity check"
        assert f["hostname"] in html_body, (
            f"HTML body is missing hostname {f['hostname']!r} present in the plain-text body")


def test_html_conveys_same_core_content_as_plain_text():
    """Same SLA figure, same instruction, same sign-off - no more, no less."""
    findings = [_finding("HHOWKLC-TEST01")]
    subject, plain_body = cnc.compose_email(findings)
    html_body = cnc.compose_email_html(findings)

    assert str(cnc.REMEDIATION_DAYS) in plain_body
    assert str(cnc.REMEDIATION_DAYS) in html_body

    assert cnc.USER_FACING_ACTION in plain_body
    assert cnc.USER_FACING_ACTION in html_body

    assert cnc.FROM_TEAM in plain_body
    assert cnc.FROM_TEAM in html_body

    assert "contact IT Support" in plain_body
    assert "contact IT Support" in html_body


def test_html_does_not_reintroduce_dropped_technical_detail():
    """compose_email() deliberately excludes per-finding issue/action text
    (see its docstring - simplified for end users, full detail stays in the
    Worklist for staff). The HTML version must mirror that exactly, not
    reintroduce technical detail just because HTML has room to show it."""
    findings = [_finding("HHOWKLC-TEST01", issue="UNIQUE_ISSUE_TEXT_MARKER",
                          action="UNIQUE_ACTION_TEXT_MARKER")]
    html_body = cnc.compose_email_html(findings)
    assert "UNIQUE_ISSUE_TEXT_MARKER" not in html_body
    assert "UNIQUE_ACTION_TEXT_MARKER" not in html_body


def test_html_escapes_special_characters_in_hostname():
    """Hard requirement: interpolated data must be HTML-escaped so a stray
    <, &, or > can't break rendering or inject markup."""
    dangerous_hostname = "<script>alert('x')</script> & \"quoted\""
    findings = [_finding(dangerous_hostname)]
    html_body = cnc.compose_email_html(findings)

    assert dangerous_hostname not in html_body, (
        "REGRESSION: raw unescaped hostname found in HTML output - injection risk")
    assert html.escape(dangerous_hostname) in html_body, (
        "expected the html.escape()'d hostname to appear in the output")
    assert "<script>" not in html_body, (
        "REGRESSION: a literal <script> tag survived into the HTML body")


def test_html_escapes_ampersand_in_hostname():
    """A lone '&' is the most common accidental-injection case (e.g. a
    hostname/label containing 'R&D') - must become '&amp;', not raw '&'."""
    findings = [_finding("WS-R&D-01")]
    html_body = cnc.compose_email_html(findings)
    assert "WS-R&D-01" not in html_body
    assert "WS-R&amp;D-01" in html_body
