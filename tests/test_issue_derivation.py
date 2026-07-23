"""Tests for the per-source issue/action derivation and the compliance gate
that makes the unfiltered exports (Zapp, merged DLP) safe to mix in with the
5 originally pre-filtered reports.
"""
import pytest

import consolidate_noncompliant as cnc


# --- is_compliant_text --------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("Compliant", True), ("compliant", True), ("1", True), ("true", True),
    ("TRUE", True), ("Yes", True),
    ("Non-Compliant", False), ("Non-compliant", False), ("0", False),
    ("false", False), ("", False), (None, False),
])
def test_is_compliant_text(value, expected):
    assert cnc.is_compliant_text(value) is expected


# --- cs_issue -----------------------------------------------------------------

def test_cs_issue_not_installed_flag_wins_even_with_a_reason():
    issue, action = cnc.cs_issue("Outdated", "No")
    assert issue == "CrowdStrike agent not installed"


def test_cs_issue_unknown_reason():
    issue, action = cnc.cs_issue("Unknown", "Yes")
    assert issue == "CrowdStrike agent not installed"


@pytest.mark.parametrize("agent_installed", ["0", "false", "False"])
def test_cs_issue_accepts_zero_and_false_as_not_installed(agent_installed):
    """The real Mac CrowdStrike export ("(mac)-cs" in FILE_REGISTRY) has no
    Yes/No install column - only a "0"/"1" compliant_status flag mapped
    straight into agent_installed. Must classify the same as "No", not fall
    through to a different branch just because the literal string differs."""
    issue, action = cnc.cs_issue("", agent_installed)
    assert issue == "CrowdStrike agent not installed", (
        f"REGRESSION: agent_installed={agent_installed!r} must still mean "
        f"not installed, got issue={issue!r}")


def test_cs_issue_outdated():
    issue, action = cnc.cs_issue("Outdated", "Yes")
    assert issue == "CrowdStrike agent outdated"
    assert cnc.CS_LATEST["windows"] in action


def test_cs_issue_latest_but_not_reporting():
    issue, action = cnc.cs_issue("Latest", "Yes")
    assert issue == "Agent current but NOT reporting"


def test_cs_issue_blank_reason_but_installed():
    issue, action = cnc.cs_issue("", "Yes")
    assert issue == "CrowdStrike status not reported"


def test_cs_issue_blank_reason_and_not_installed():
    """Pins the exact pair some real files (e.g. Workstation) actually send:
    a blank reason cell AND proc_agent_installed='No' (they leave the reason
    blank for agent-less hosts instead of writing 'Unknown'). Must still
    report 'not installed', not fall through to the blank-reason 'status not
    reported' branch - existing tests only cover blank+Yes or non-blank+No,
    never both blank and not-installed together."""
    issue, action = cnc.cs_issue("", "No")
    assert issue == "CrowdStrike agent not installed", (
        f"REGRESSION: blank reason + not-installed must report "
        f"'CrowdStrike agent not installed', got {issue!r}")


def test_cs_issue_unrecognized_status_falls_through():
    issue, action = cnc.cs_issue("SomeNewStatus", "Yes")
    assert "SomeNewStatus" in issue


# --- purview_issue --------------------------------------------------------

def test_purview_issue_not_updated():
    issue, action, detail = cnc.purview_issue("NotUpdated", "NotUpdated", "Windows", "1.0", "2.0")
    assert "not updated" in issue.lower()
    assert cnc.PURVIEW_LATEST["windows"]["mocamp"] in action


def test_purview_issue_blank_means_not_enrolled():
    issue, action, detail = cnc.purview_issue("", "", "Windows")
    assert "not enrolled" in issue.lower()


def test_purview_issue_other_status_falls_through():
    issue, action, detail = cnc.purview_issue("Updated", "Applied", "Windows")
    assert "Updated" in issue and "Applied" in issue


def test_purview_issue_uses_mac_reference_versions_on_mac():
    issue, action, detail = cnc.purview_issue("NotUpdated", "NotUpdated", "Mac")
    assert cnc.PURVIEW_LATEST["macos"]["mocamp"] in action


# --- zapp_issue -----------------------------------------------------------

def test_zapp_issue_missing_client():
    issue, action = cnc.zapp_issue("0", "1")
    assert "not installed" in issue.lower()


def test_zapp_issue_not_installed_flag():
    issue, action = cnc.zapp_issue("0", "0")
    assert "not installed" in issue.lower()


def test_zapp_issue_other_noncompliance():
    issue, action = cnc.zapp_issue("1", "0")
    assert issue == "Zapp reporting non-compliant"


# --- bitlocker_issue --------------------------------------------------------
# Shapes pinned directly from the real file's actual non-compliant rows
# (data/*Hard Disk Encryption Compliance*.csv) - see bitlocker_issue()'s
# docstring for the full breakdown of which shape is how common.

def test_bitlocker_issue_not_encrypted():
    """The clearest real shape (4/33 non-compliant rows): reports in, drive
    explicitly not encrypted."""
    issue, action = cnc.bitlocker_issue("notEncrypted", "compliant")
    assert issue == "BitLocker drive encryption not enabled"


def test_bitlocker_issue_no_telemetry_reported():
    """The majority real shape (28/33 non-compliant rows): no BitLocker/Intune
    telemetry at all - blank encryption_status regardless of setting_state_summary."""
    issue, action = cnc.bitlocker_issue("", "")
    assert issue == "BitLocker status not reported"


def test_bitlocker_issue_encrypted_but_policy_not_assigned():
    """The one real row shaped this way: encrypted, but the compliance
    policy itself was never assigned to the device."""
    issue, action = cnc.bitlocker_issue("encrypted", "notAssigned")
    assert issue == "BitLocker encrypted but compliance policy not applied"


def test_bitlocker_issue_unrecognized_status_falls_through():
    issue, action = cnc.bitlocker_issue("SomeNewStatus", "SomeNewSetting")
    assert "SomeNewStatus" in issue


# --- _platform_from_os ------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Windows 11 24H2", "Windows"),
    ("macOS 14.5", "Mac"),
    ("Mac OS X", "Mac"),
    ("Ubuntu 22.04", "Linux"),
    ("RHEL 8", "Linux"),
    ("Citrix VDI", "Unknown"),
    ("", "Unknown"),
    (None, "Unknown"),
])
def test_platform_from_os(text, expected):
    assert cnc._platform_from_os(text) == expected
