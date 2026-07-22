"""Tests for SharePointDataSource - mock-tested only, per its own docstring:
there is no live Sites.Selected/Files.Read.All grant yet, so every test here
replaces _graph_list_children/_graph_download_content/urllib.request.urlopen
with fakes. No test in this file makes a real HTTP call.

The discovery tests are deliberately adversarial: folder listings are
returned in scrambled (non-sorted) order, and month/day values are chosen so
that a plain string/alphabetical comparison - or just taking the first or
last element of whatever order the fake "server" happens to return - would
pick the WRONG folder. Only genuine max-by-parsed-integer gets these right,
which is the whole point of the exercise (see the confirmed constraint:
folders are unpredictable, not a fixed cadence, so nothing here may assume
"latest" means "most recent by string sort" or "last one listed").
"""
import json

import consolidate_noncompliant as cnc

BASE_PATH_CS = ("Documents/Reports-Prod/AIAGO/Weekly Dashboard/"
                "17. Workstation Security Agent Deployment")
BASE_PATH_BITLOCKER = ("Documents/Reports-Prod/AIAGO/Weekly Dashboard/"
                       "19. Hard Disk Encryption Compliance")


def _folder(name):
    return {"name": name, "folder": {"childCount": 1}}


def _file(name):
    return {"name": name, "file": {"mimeType": "text/csv"}}


def _responses_source(responses, calls=None):
    """-> a fake _graph_list_children(drive_id, path, token) that serves
    canned responses keyed by path, and (if `calls` is given) records every
    path actually requested - so tests can assert not just the final answer
    but how many real lookups it took to get there (see the caching test)."""
    def fake(drive_id, path, token):
        if calls is not None:
            calls.append(path)
        if path not in responses:
            raise AssertionError(f"unexpected path requested: {path!r}")
        return responses[path]
    return fake


# ===========================================================================
# Multi-level "pick the latest" discovery - the core of this feature.
# ===========================================================================

def test_resolve_latest_dated_folder_picks_chronologically_latest_not_alphabetical(monkeypatch):
    """Years, months, and days are all returned scrambled and chosen so
    string/alphabetical comparison gives a different (wrong) answer at every
    level:
      - months ['9','12','3'] -> alphabetically last is '9' (since '9' > '3'
        > '12' as strings); correct answer is '12'.
      - days ['2','15','9'] -> alphabetically last is '9'; correct answer
        is '15'.
    Also mixes in a non-numeric folder and a stray file at each level, which
    must be ignored rather than crashing or being mistaken for a candidate.
    """
    responses = {
        BASE_PATH_CS: [_folder("2025"), _folder("2024"), _folder("2026"), _file("notes.txt")],
        f"{BASE_PATH_CS}/2026": [_folder("9"), _folder("12"), _folder("3"), _folder("Archive")],
        f"{BASE_PATH_CS}/2026/12": [_folder("2"), _folder("15"), _folder("9")],
    }
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))

    source = cnc.SharePointDataSource("drive-1", BASE_PATH_CS, get_token=lambda: "fake-token")
    resolved = source._resolve_latest_dated_folder()

    assert resolved == f"{BASE_PATH_CS}/2026/12/15", (
        f"REGRESSION: expected the chronologically latest folder, got {resolved!r}")


def test_latest_numeric_subfolder_uses_integer_not_string_comparison(monkeypatch):
    """The exact unpadded-single-digit case called out as a known risk:
    string-max(['9', '10']) is '9' (since '9' > '1' as the first character),
    but the numerically latest is '10'."""
    responses = {"some/path": [_folder("9"), _folder("10")]}
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))
    source = cnc.SharePointDataSource("drive-1", "irrelevant", get_token=lambda: "tok")

    assert source._latest_numeric_subfolder("some/path") == "10"


def test_latest_numeric_subfolder_ignores_files_and_non_numeric_folders(monkeypatch):
    responses = {"some/path": [_file("2026"), _folder("Archive"), _folder("07")]}
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))
    source = cnc.SharePointDataSource("drive-1", "irrelevant", get_token=lambda: "tok")

    # "2026" is a FILE here (deliberately, to prove folder-ness is checked,
    # not just the name), so the only real numeric FOLDER is "07".
    assert source._latest_numeric_subfolder("some/path") == "07"


def test_latest_numeric_subfolder_raises_clear_error_when_none_found(monkeypatch):
    responses = {"some/path": [_folder("Archive"), _file("readme.txt")]}
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))
    source = cnc.SharePointDataSource("drive-1", "irrelevant", get_token=lambda: "tok")

    try:
        source._latest_numeric_subfolder("some/path")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "some/path" in str(e)


def test_resolved_folder_is_cached_across_calls(monkeypatch):
    """Discovery (year -> month -> day, 3 real lookups) must happen once per
    instance, not once per list_files()/read_file() call."""
    responses = {
        BASE_PATH_CS: [_folder("2026")],
        f"{BASE_PATH_CS}/2026": [_folder("7")],
        f"{BASE_PATH_CS}/2026/7": [_folder("15")],
        f"{BASE_PATH_CS}/2026/7/15": [_file("a.csv"), _file("b.csv")],
    }
    calls = []
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses, calls))

    source = cnc.SharePointDataSource("drive-1", BASE_PATH_CS, get_token=lambda: "tok")
    source.list_files()
    calls_after_first = list(calls)
    source.list_files()

    assert calls_after_first == [BASE_PATH_CS, f"{BASE_PATH_CS}/2026", f"{BASE_PATH_CS}/2026/7",
                                  f"{BASE_PATH_CS}/2026/7/15"], (
        "expected exactly one discovery pass (3 lookups) plus the file listing itself")
    assert calls == calls_after_first + [f"{BASE_PATH_CS}/2026/7/15"], (
        "REGRESSION: second list_files() call re-ran folder discovery instead of using the cached path")


def test_get_token_not_called_until_first_real_use(monkeypatch):
    monkeypatch.setattr(cnc, "_graph_list_children", lambda *a, **k: [])
    calls = []
    source = cnc.SharePointDataSource("drive-1", BASE_PATH_CS, get_token=lambda: calls.append(1) or "tok")
    assert calls == [], "get_token must not be called at construction time"


# ===========================================================================
# exists() / list_files() / read_file() - the DataSource interface itself.
# ===========================================================================

def test_exists_true_when_folder_resolves(monkeypatch):
    responses = {
        BASE_PATH_CS: [_folder("2026")],
        f"{BASE_PATH_CS}/2026": [_folder("7")],
        f"{BASE_PATH_CS}/2026/7": [_folder("15")],
    }
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))
    source = cnc.SharePointDataSource("drive-1", BASE_PATH_CS, get_token=lambda: "tok")
    assert source.exists() is True


def test_exists_false_when_no_dated_folder_present(monkeypatch):
    responses = {BASE_PATH_CS: [_folder("Archive")]}
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))
    source = cnc.SharePointDataSource("drive-1", BASE_PATH_CS, get_token=lambda: "tok")
    assert source.exists() is False


def test_list_files_returns_sorted_file_names_from_resolved_folder(monkeypatch):
    responses = {
        BASE_PATH_BITLOCKER: [_folder("2026")],
        f"{BASE_PATH_BITLOCKER}/2026": [_folder("7")],
        f"{BASE_PATH_BITLOCKER}/2026/7": [_folder("15")],
        f"{BASE_PATH_BITLOCKER}/2026/7/15": [
            _file("Zeta_Report.csv"), _folder("Superseded"), _file("Alpha_Report.csv")],
    }
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))
    source = cnc.SharePointDataSource("drive-1", BASE_PATH_BITLOCKER, get_token=lambda: "tok")

    assert source.list_files() == ["Alpha_Report.csv", "Zeta_Report.csv"], (
        "expected only files (not the 'Superseded' folder), sorted")


def test_read_file_downloads_from_the_resolved_folder_path(monkeypatch):
    responses = {
        BASE_PATH_CS: [_folder("2026")],
        f"{BASE_PATH_CS}/2026": [_folder("7")],
        f"{BASE_PATH_CS}/2026/7": [_folder("15")],
    }
    monkeypatch.setattr(cnc, "_graph_list_children", _responses_source(responses))

    captured = {}

    def fake_download(drive_id, path, token):
        captured["drive_id"], captured["path"], captured["token"] = drive_id, path, token
        return b"file bytes"

    monkeypatch.setattr(cnc, "_graph_download_content", fake_download)

    source = cnc.SharePointDataSource("drive-1", BASE_PATH_CS, get_token=lambda: "tok-abc")
    content = source.read_file("Crowdstrike.csv")

    assert content == b"file bytes"
    assert captured == {
        "drive_id": "drive-1",
        "path": f"{BASE_PATH_CS}/2026/7/15/Crowdstrike.csv",
        "token": "tok-abc",
    }


# ===========================================================================
# Graph HTTP helpers - URL construction and the parameterized-scope token
# fetch (get_graph_token_for_scope), each mocked at the urllib boundary.
# ===========================================================================

class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_graph_list_children_builds_url_with_drive_id_and_encoded_path(monkeypatch):
    captured = {}

    def fake_get_bytes(url, token):
        captured["url"], captured["token"] = url, token
        return json.dumps({"value": [{"name": "2026", "folder": {}}]}).encode()

    monkeypatch.setattr(cnc, "_graph_get_bytes", fake_get_bytes)
    result = cnc._graph_list_children("drive-xyz", "Weekly Dashboard/17. Workstation", "tok-1")

    assert result == [{"name": "2026", "folder": {}}]
    assert captured["token"] == "tok-1"
    assert "drive-xyz" in captured["url"]
    assert captured["url"].endswith(":/children")
    assert "Weekly%20Dashboard" in captured["url"], "spaces in the path must be URL-encoded"
    assert "/" in captured["url"].split(":/children")[0], "the '/' path separators must survive encoding"


def test_graph_download_content_builds_content_url(monkeypatch):
    captured = {}

    def fake_get_bytes(url, token):
        captured["url"] = url
        return b"raw bytes"

    monkeypatch.setattr(cnc, "_graph_get_bytes", fake_get_bytes)
    result = cnc._graph_download_content("drive-xyz", "some/path/file.csv", "tok-1")

    assert result == b"raw bytes"
    assert captured["url"].endswith(":/content")
    assert "drive-xyz" in captured["url"]


def test_get_graph_token_for_scope_sends_the_given_scope_not_a_hardcoded_one(monkeypatch):
    """The whole point of taking `scope` as a parameter: prove a caller
    asking for a DIFFERENT scope than Mail.Send's '.default' actually gets
    that scope sent to Azure AD, not something hardcoded."""
    captured = {}

    def fake_urlopen(req, timeout=30):
        captured["data"] = req.data
        captured["url"] = req.full_url
        return _FakeHTTPResponse({"access_token": "tok-123"})

    monkeypatch.setattr(cnc.urllib.request, "urlopen", fake_urlopen)

    token = cnc.get_graph_token_for_scope(
        "tenant-1", "client-1", "secret-1",
        scope="https://graph.microsoft.com/Sites.Selected")

    assert token == "tok-123"
    assert b"Sites.Selected" in captured["data"]
    assert b"client-1" in captured["data"]
    assert "tenant-1" in captured["url"]


def test_get_graph_token_for_scope_defaults_to_dot_default(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=30):
        captured["data"] = req.data
        return _FakeHTTPResponse({"access_token": "tok-456"})

    monkeypatch.setattr(cnc.urllib.request, "urlopen", fake_urlopen)
    cnc.get_graph_token_for_scope("tenant-1", "client-1", "secret-1")

    assert b".default" in captured["data"]
