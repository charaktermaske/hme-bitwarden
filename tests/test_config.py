from pathlib import Path

import pytest

from hme_bitwarden.config import AdminAuth, ConfigError, load_settings

TOKEN = "a" * 64


def env(tmp_path: Path, **values: str) -> dict[str, str]:
    base = {"HME_API_TOKEN": TOKEN, "HME_ADMIN_PASSWORD": "long enough password", "HME_DATA_DIR": str(tmp_path)}
    base.update(values)
    return {k: v for k, v in base.items() if v is not None}


def test_defaults(tmp_path):
    settings = load_settings(env(tmp_path))
    assert settings.admin_auth is AdminAuth.PASSWORD
    assert settings.cookie_secure is True
    assert settings.access_log is False
    assert settings.session_dir == tmp_path / "session"


def test_short_api_token_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="HME_API_TOKEN"):
        load_settings(env(tmp_path, HME_API_TOKEN="short"))


def test_password_mode_requires_strong_password(tmp_path):
    with pytest.raises(ConfigError, match="HME_ADMIN_PASSWORD"):
        load_settings(env(tmp_path, HME_ADMIN_PASSWORD="short"))


def test_admin_password_must_differ_from_token(tmp_path):
    with pytest.raises(ConfigError, match="differ"):
        load_settings(env(tmp_path, HME_ADMIN_PASSWORD=TOKEN))


def test_proxy_mode_needs_no_password(tmp_path):
    values = env(tmp_path, HME_ADMIN_AUTH="proxy")
    del values["HME_ADMIN_PASSWORD"]
    assert load_settings(values).admin_auth is AdminAuth.PROXY


def test_invalid_admin_auth(tmp_path):
    with pytest.raises(ConfigError, match="HME_ADMIN_AUTH"):
        load_settings(env(tmp_path, HME_ADMIN_AUTH="none"))


def test_secrets_from_files(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text(f"{'b' * 40}\n")
    values = env(tmp_path, HME_API_TOKEN_FILE=str(token_file))
    del values["HME_API_TOKEN"]
    assert load_settings(values).api_token == "b" * 40


def test_unreadable_secret_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(env(tmp_path, HME_API_TOKEN_FILE=str(tmp_path / "missing")))


def test_session_secret_is_generated_once(tmp_path):
    first = load_settings(env(tmp_path)).session_secret
    second = load_settings(env(tmp_path)).session_secret
    assert first == second
    assert len(first) >= 48


@pytest.mark.parametrize(("name", "value"), [("HME_PORT", "x"), ("HME_KEEPALIVE_INTERVAL", "10")])
def test_invalid_numbers(tmp_path, name, value):
    with pytest.raises(ConfigError, match=name):
        load_settings(env(tmp_path, **{name: value}))


def test_invalid_boolean(tmp_path):
    with pytest.raises(ConfigError, match="HME_COOKIE_SECURE"):
        load_settings(env(tmp_path, HME_COOKIE_SECURE="maybe"))
