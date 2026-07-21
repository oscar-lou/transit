"""Tests for check_databricks_connection.py's check_connection() - the
testable core, isolated from the real SDK/network via the `client`
injection point main() never uses in production. Mirrors send_email.py's
own style: mock what talks to the network, pin what the code does with the
result.
"""
import types

import check_databricks_connection as dbc


class _FakeCurrentUserAPI:
    def __init__(self, user_name=None, error=None):
        self._user_name = user_name
        self._error = error

    def me(self):
        if self._error:
            raise self._error
        return types.SimpleNamespace(user_name=self._user_name)


class _FakeSecretsAPI:
    def __init__(self, keys=None, error=None):
        self._keys = keys or []
        self._error = error

    def list_secrets(self, scope):
        if self._error:
            raise self._error
        return [types.SimpleNamespace(key=k) for k in self._keys]


def _fake_client(user_name=None, auth_error=None, keys=None, secrets_error=None):
    return types.SimpleNamespace(
        current_user=_FakeCurrentUserAPI(user_name, auth_error),
        secrets=_FakeSecretsAPI(keys, secrets_error),
    )


def test_check_connection_reports_success_with_username():
    client = _fake_client(user_name="oscar@example.com")
    ok, message = dbc.check_connection("https://example.databricks.net", client=client)
    assert ok is True
    assert "oscar@example.com" in message


def test_check_connection_reports_auth_failure_clearly():
    client = _fake_client(auth_error=ValueError("cannot configure default credentials"))
    ok, message = dbc.check_connection("https://example.databricks.net", client=client)
    assert ok is False
    assert "cannot configure default credentials" in message


def test_check_connection_lists_secret_scope_keys():
    client = _fake_client(user_name="oscar@example.com",
                          keys=["GRAPH_TENANT_ID", "GRAPH_CLIENT_ID"])
    ok, message = dbc.check_connection("https://example.databricks.net",
                                        secret_scope="compliance-automation", client=client)
    assert ok is True
    assert "GRAPH_TENANT_ID" in message
    assert "GRAPH_CLIENT_ID" in message


def test_check_connection_skips_secret_scope_when_not_requested():
    client = _fake_client(user_name="oscar@example.com")
    ok, message = dbc.check_connection("https://example.databricks.net", client=client)
    assert ok is True
    assert "secret scope" not in message


def test_check_connection_reports_secret_scope_failure():
    client = _fake_client(user_name="oscar@example.com",
                          secrets_error=Exception("scope does not exist"))
    ok, message = dbc.check_connection("https://example.databricks.net",
                                        secret_scope="nonexistent", client=client)
    assert ok is False
    assert "scope does not exist" in message


def test_check_connection_reports_missing_sdk_clearly(monkeypatch):
    monkeypatch.setattr(dbc, "HAVE_DATABRICKS_SDK", False)
    ok, message = dbc.check_connection("https://example.databricks.net")
    assert ok is False
    assert "pip install databricks-sdk" in message


def test_parse_args_defaults_to_this_projects_workspace():
    args = dbc.parse_args([])
    assert args.host == dbc.DEFAULT_HOST
    assert args.secret_scope is None


def test_parse_args_host_override():
    args = dbc.parse_args(["--host", "https://custom.azuredatabricks.net"])
    assert args.host == "https://custom.azuredatabricks.net"


def test_main_returns_zero_on_success(monkeypatch):
    monkeypatch.setattr(dbc, "WorkspaceClient",
                         lambda host: _fake_client(user_name="oscar@example.com"),
                         raising=False)
    assert dbc.main([]) == 0


def test_main_returns_nonzero_on_auth_failure(monkeypatch):
    monkeypatch.setattr(
        dbc, "WorkspaceClient",
        lambda host: _fake_client(auth_error=ValueError("no credentials")),
        raising=False)
    assert dbc.main([]) == 1
