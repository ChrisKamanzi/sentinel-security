"""ANTHROPIC_API_KEY configuration and Anthropic client initialization.

Only fake keys are used; no test reads the real .env or contacts the API
(constructing an SDK client makes no network calls).
"""

import logging

import anthropic
import pytest
from pydantic import SecretStr

from app.core.config import Settings, settings
from app.services import ai_analyst

# Captured at import time, before conftest's autouse fixture replaces it.
REAL_GET_CLIENT = ai_analyst.get_client

FAKE_KEY = "sk-ant-test-0000000000000000000000000000"
API = "/api/v1"


def _settings_from(tmp_path, monkeypatch, env_text: str) -> Settings:
    """Settings built from a throwaway .env file with no competing env var."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(env_text, encoding="utf-8")
    return Settings(_env_file=env_file)


# --- Settings -----------------------------------------------------------------------------------


def test_key_loaded_from_env_file(tmp_path, monkeypatch):
    s = _settings_from(tmp_path, monkeypatch, f"ANTHROPIC_API_KEY={FAKE_KEY}\n")
    assert isinstance(s.anthropic_api_key, SecretStr)
    assert s.anthropic_api_key.get_secret_value() == FAKE_KEY


def test_environment_variable_overrides_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-environment")
    assert Settings(_env_file=env_file).anthropic_api_key.get_secret_value() == "from-environment"


@pytest.mark.parametrize("env_text", ["", "ANTHROPIC_API_KEY=\n", "ANTHROPIC_API_KEY=   \n"],
                         ids=["absent", "empty", "whitespace"])
def test_missing_or_blank_key_is_unset(tmp_path, monkeypatch, env_text):
    assert _settings_from(tmp_path, monkeypatch, env_text).anthropic_api_key is None


def test_surrounding_whitespace_is_stripped(tmp_path, monkeypatch):
    s = _settings_from(tmp_path, monkeypatch, f"ANTHROPIC_API_KEY=  {FAKE_KEY}  \n")
    assert s.anthropic_api_key.get_secret_value() == FAKE_KEY


def test_key_is_masked_in_repr_and_dumps(tmp_path, monkeypatch):
    s = _settings_from(tmp_path, monkeypatch, f"ANTHROPIC_API_KEY={FAKE_KEY}\n")
    for rendered in (repr(s), str(s), str(s.anthropic_api_key), s.model_dump_json(), str(s.model_dump())):
        assert FAKE_KEY not in rendered


def test_test_process_never_sees_the_real_key():
    # conftest blanks ANTHROPIC_API_KEY before the app is imported
    assert settings.anthropic_api_key is None


# --- get_client -----------------------------------------------------------------------------------


@pytest.fixture
def oauth_environment(monkeypatch, tmp_path):
    """Simulate a machine with competing non-API-key credentials available."""
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "oauth-token-should-be-ignored")
    monkeypatch.setenv("ANTHROPIC_PROFILE", "profile-should-be-ignored")
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path / "no-such-config"))


def test_client_uses_configured_key_explicitly(monkeypatch, oauth_environment):
    monkeypatch.setattr(settings, "anthropic_api_key", SecretStr(FAKE_KEY))
    client = REAL_GET_CLIENT()
    assert client.api_key == FAKE_KEY
    # Nothing from the OAuth / profile / auth-token chain was picked up
    assert client.auth_token is None
    assert client.credentials is None
    assert client.auth_headers == {"Authorization": f"Bearer {FAKE_KEY}"}


def test_client_keeps_configured_timeout_and_retries(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", SecretStr(FAKE_KEY))
    client = REAL_GET_CLIENT()
    assert client.timeout == settings.anthropic_timeout_seconds
    assert client.max_retries == 2


def test_missing_key_fails_closed_without_building_a_client(monkeypatch, oauth_environment):
    monkeypatch.setattr(settings, "anthropic_api_key", None)

    def _must_not_be_called(*args, **kwargs):
        raise AssertionError("SDK client must not be created without an API key")

    monkeypatch.setattr(ai_analyst.anthropic, "Anthropic", _must_not_be_called)
    with pytest.raises(ai_analyst.MissingAPIKeyError, match="ANTHROPIC_API_KEY is not configured"):
        REAL_GET_CLIENT()


def test_get_client_does_not_log_the_key(monkeypatch, caplog):
    monkeypatch.setattr(settings, "anthropic_api_key", SecretStr(FAKE_KEY))
    with caplog.at_level(logging.DEBUG):
        REAL_GET_CLIENT()
    assert FAKE_KEY not in caplog.text


# --- end to end through the API ---------------------------------------------------------------------


@pytest.fixture
def scan_with_a_finding(client, make_scan):
    scan = make_scan()
    resp = client.post(f"{API}/scans/{scan['id']}/findings", json={
        "title": "Missing header", "severity": "low", "location": "http://example.com"})
    assert resp.status_code == 201, resp.text
    return scan


def test_analysis_without_key_is_recorded_as_failed(client, scan_with_a_finding, monkeypatch, caplog):
    monkeypatch.setattr(ai_analyst, "get_client", REAL_GET_CLIENT)
    monkeypatch.setattr(settings, "anthropic_api_key", None)
    client.post(f"{API}/scans/{scan_with_a_finding['id']}/analysis")
    a = client.get(f"{API}/scans/{scan_with_a_finding['id']}/analysis").json()
    assert a["status"] == "failed"
    assert a["error_message"].startswith("ANTHROPIC_API_KEY is not configured")
    assert "Traceback" not in caplog.text  # handled cleanly, not via the generic handler


def test_auth_error_message_does_not_mention_oauth_fallback(client, scan_with_a_finding, monkeypatch):
    import httpx

    class RejectingClient:
        class beta:
            class messages:
                @staticmethod
                def stream(**kwargs):
                    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
                    raise anthropic.AuthenticationError(
                        "invalid x-api-key", response=httpx.Response(401, request=req), body=None)

    monkeypatch.setattr(ai_analyst, "get_client", lambda: RejectingClient)
    client.post(f"{API}/scans/{scan_with_a_finding['id']}/analysis")
    a = client.get(f"{API}/scans/{scan_with_a_finding['id']}/analysis").json()
    assert a["status"] == "failed"
    assert "check ANTHROPIC_API_KEY" in a["error_message"]
    assert "ant auth login" not in a["error_message"]
