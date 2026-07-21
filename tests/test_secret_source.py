"""Tests for the SecretSource abstraction (credential/config seam) -
verifies LocalEnvSecretSource behaves identically to the pre-refactor direct
os.environ reads, so the abstraction itself is verified, not just trusted.
Also covers DatabricksSecretSource and _get_secret_source()'s backend
selection, added when Databricks became this project's run location.
"""
import types

import send_email as se


def _clear_backend_env(monkeypatch):
    """Backend auto-detection keys off these two env vars - tests that mean
    to pin LocalEnvSecretSource must not be at the mercy of whatever
    happens to be set in the real environment they run in."""
    monkeypatch.delenv("DATABRICKS_RUNTIME_VERSION", raising=False)
    monkeypatch.delenv("COMPLIANCE_SECRETS_BACKEND", raising=False)


def test_get_returns_value_when_set(monkeypatch):
    monkeypatch.setenv("SOME_TEST_KEY", "some-value")
    assert se.LocalEnvSecretSource().get("SOME_TEST_KEY") == "some-value"


def test_get_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("SOME_UNSET_KEY", raising=False)
    assert se.LocalEnvSecretSource().get("SOME_UNSET_KEY") is None


def test_get_secret_source_reflects_current_environ_not_cached(monkeypatch):
    """Not cached - reflects os.environ at call time, since real env vars,
    _load_dotenv(), and tests all mutate the environment at runtime."""
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("SOME_TEST_KEY", "value-one")
    assert se._get_secret_source().get("SOME_TEST_KEY") == "value-one"
    monkeypatch.setenv("SOME_TEST_KEY", "value-two")
    assert se._get_secret_source().get("SOME_TEST_KEY") == "value-two"


def test_load_graph_credentials_goes_through_secret_source(monkeypatch):
    """End-to-end: setting values via plain os.environ (what a real env var,
    or _load_dotenv(), does) must be picked up by _load_graph_credentials()
    through the new seam, identical to the pre-refactor direct os.environ
    reads."""
    _clear_backend_env(monkeypatch)
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


# ===========================================================================
# Backend selection - _get_secret_source() picks LocalEnvSecretSource vs
# DatabricksSecretSource based on DATABRICKS_RUNTIME_VERSION (a fact
# Databricks itself sets on every cluster, not a guess) or the explicit
# COMPLIANCE_SECRETS_BACKEND override.
# ===========================================================================

def test_backend_defaults_to_env_outside_databricks(monkeypatch):
    _clear_backend_env(monkeypatch)
    assert isinstance(se._get_secret_source(), se.LocalEnvSecretSource)


def test_backend_switches_to_databricks_when_runtime_version_is_set(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("DATABRICKS_RUNTIME_VERSION", "15.4")
    monkeypatch.setattr(se, "HAVE_DATABRICKS_SDK", True)
    assert isinstance(se._get_secret_source(), se.DatabricksSecretSource)


def test_backend_override_forces_env_even_inside_databricks(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("DATABRICKS_RUNTIME_VERSION", "15.4")
    monkeypatch.setenv("COMPLIANCE_SECRETS_BACKEND", "env")
    assert isinstance(se._get_secret_source(), se.LocalEnvSecretSource)


def test_backend_override_forces_databricks_outside_databricks(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("COMPLIANCE_SECRETS_BACKEND", "databricks")
    monkeypatch.setattr(se, "HAVE_DATABRICKS_SDK", True)
    assert isinstance(se._get_secret_source(), se.DatabricksSecretSource)


def test_backend_falls_back_to_env_when_sdk_missing(monkeypatch, capsys):
    """Selecting the Databricks backend without the optional dependency
    installed must degrade to LocalEnvSecretSource with a clear explanation,
    not crash the whole run over a missing optional package."""
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("COMPLIANCE_SECRETS_BACKEND", "databricks")
    monkeypatch.setattr(se, "HAVE_DATABRICKS_SDK", False)
    source = se._get_secret_source()
    assert isinstance(source, se.LocalEnvSecretSource)
    assert "databricks-sdk" in capsys.readouterr().out


def test_databricks_secret_scope_defaults_and_is_overridable(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("COMPLIANCE_SECRETS_BACKEND", "databricks")
    monkeypatch.setattr(se, "HAVE_DATABRICKS_SDK", True)

    monkeypatch.delenv("COMPLIANCE_DATABRICKS_SECRET_SCOPE", raising=False)
    assert se._get_secret_source().scope == "compliance-automation"

    monkeypatch.setenv("COMPLIANCE_DATABRICKS_SECRET_SCOPE", "my-custom-scope")
    assert se._get_secret_source().scope == "my-custom-scope"


# ===========================================================================
# DatabricksSecretSource.get() - a fake WorkspaceClient stands in for the SDK
# (via monkeypatch.setattr(..., raising=False), so these pass whether or not
# the optional databricks-sdk package happens to be installed).
# ===========================================================================

class _FakeSecretsAPI:
    def __init__(self, values):
        self._values = values  # {(scope, key): base64-encoded str}

    def get_secret(self, scope, key):
        value = self._values.get((scope, key))
        if value is None:
            raise Exception(f"Secret does not exist with scope: {scope} key: {key}")
        return types.SimpleNamespace(key=key, value=value)


def _fake_workspace_client_factory(values):
    def factory(*a, **k):
        return types.SimpleNamespace(secrets=_FakeSecretsAPI(values))
    return factory


def test_databricks_secret_source_decodes_base64_value(monkeypatch):
    import base64
    encoded = base64.b64encode(b"super-secret-value").decode()
    monkeypatch.setattr(se, "WorkspaceClient",
                         _fake_workspace_client_factory({("myscope", "GRAPH_CLIENT_SECRET"): encoded}),
                         raising=False)
    source = se.DatabricksSecretSource("myscope")
    assert source.get("GRAPH_CLIENT_SECRET") == "super-secret-value"


def test_databricks_secret_source_returns_none_when_secret_missing(monkeypatch, capsys):
    monkeypatch.setattr(se, "WorkspaceClient", _fake_workspace_client_factory({}), raising=False)
    source = se.DatabricksSecretSource("myscope")
    assert source.get("NOT_THERE") is None
    assert "myscope" in capsys.readouterr().out


def test_databricks_secret_source_caches_client_across_get_calls(monkeypatch):
    calls = []

    def counting_factory(*a, **k):
        calls.append(1)
        return types.SimpleNamespace(secrets=_FakeSecretsAPI({}))

    monkeypatch.setattr(se, "WorkspaceClient", counting_factory, raising=False)
    source = se.DatabricksSecretSource("myscope")
    source.get("A")
    source.get("B")
    assert len(calls) == 1, "REGRESSION: WorkspaceClient must be constructed once, not per get() call"
