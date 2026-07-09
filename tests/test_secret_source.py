"""Tests for the SecretSource abstraction (credential/config seam) -
verifies LocalEnvSecretSource behaves identically to the pre-refactor direct
os.environ reads, so the abstraction itself is verified, not just trusted.
"""
import send_email as se


def test_get_returns_value_when_set(monkeypatch):
    monkeypatch.setenv("SOME_TEST_KEY", "some-value")
    assert se.LocalEnvSecretSource().get("SOME_TEST_KEY") == "some-value"


def test_get_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("SOME_UNSET_KEY", raising=False)
    assert se.LocalEnvSecretSource().get("SOME_UNSET_KEY") is None


def test_get_secret_source_reflects_current_environ_not_cached(monkeypatch):
    """Not cached - reflects os.environ at call time, since real env vars,
    _load_dotenv(), and tests all mutate the environment at runtime."""
    monkeypatch.setenv("SOME_TEST_KEY", "value-one")
    assert se._get_secret_source().get("SOME_TEST_KEY") == "value-one"
    monkeypatch.setenv("SOME_TEST_KEY", "value-two")
    assert se._get_secret_source().get("SOME_TEST_KEY") == "value-two"


def test_load_graph_credentials_goes_through_secret_source(monkeypatch):
    """End-to-end: setting values via plain os.environ (what a real env var,
    or _load_dotenv(), does) must be picked up by _load_graph_credentials()
    through the new seam, identical to the pre-refactor direct os.environ
    reads."""
    monkeypatch.setenv("GRAPH_TENANT_ID", "t")
    monkeypatch.setenv("GRAPH_CLIENT_ID", "c")
    monkeypatch.setenv("GRAPH_CLIENT_SECRET", "s")
    monkeypatch.setenv("GRAPH_SENDER_UPN", "sender@example.com")
    creds = se._load_graph_credentials()
    assert creds == {
        "GRAPH_TENANT_ID": "t",
        "GRAPH_CLIENT_ID": "c",
        "GRAPH_CLIENT_SECRET": "s",
        "GRAPH_SENDER_UPN": "sender@example.com",
    }


def test_load_graph_credentials_none_when_missing(monkeypatch):
    for key in se.REQUIRED_GRAPH_ENV:
        monkeypatch.delenv(key, raising=False)
    assert se._load_graph_credentials() is None
