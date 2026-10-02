"""Settings loaded from environment variables.

Every secret can also be read from a file by appending ``_FILE`` to the variable name
(e.g. ``HME_API_TOKEN_FILE=/run/secrets/hme_token``), which works well with Docker secrets.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

MIN_API_TOKEN_LENGTH = 32
MIN_ADMIN_PASSWORD_LENGTH = 12


class ConfigError(ValueError):
    """Raised when the configuration is missing or invalid."""


class AdminAuth(StrEnum):
    """How the admin UI is protected."""

    PASSWORD = "password"  # noqa: S105 - built-in login with HME_ADMIN_PASSWORD
    PROXY = "proxy"  # an authenticating reverse proxy (Authelia, Authentik, ...) guards everything but /api


@dataclass(frozen=True)
class Settings:
    api_token: str
    data_dir: Path
    admin_auth: AdminAuth
    admin_password: str | None
    session_secret: str
    public_url: str = ""
    cookie_secure: bool = True
    keepalive_interval: int = 6 * 3600
    max_aliases_per_hour: int = 10
    ntfy_url: str = ""
    ntfy_topic: str = ""
    ntfy_token: str = ""
    webhook_url: str = ""
    log_level: str = "INFO"
    host: str = "0.0.0.0"  # noqa: S104 - listening on all interfaces is intended inside a container
    port: int = 8000
    trusted_proxies: str = "127.0.0.1"
    access_log: bool = False

    @property
    def session_dir(self) -> Path:
        """Where pyicloud keeps cookies and the trust token."""
        return self.data_dir / "session"


def _read(env: Mapping[str, str], name: str, default: str = "") -> str:
    """Return ``name`` from the environment, or the contents of the file named by ``name_FILE``."""
    file_name = env.get(f"{name}_FILE")
    if file_name:
        try:
            return Path(file_name).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ConfigError(f"{name}_FILE: cannot read {file_name}: {error.strerror}") from error
    return env.get(name, default).strip()


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
    raw = _read(env, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from error
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = _read(env, name).lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _session_secret(env: Mapping[str, str], data_dir: Path) -> str:
    """Use HME_SESSION_SECRET, or create a random one once and keep it in the data directory."""
    configured = _read(env, "HME_SESSION_SECRET")
    if configured:
        return configured
    path = data_dir / "session_secret"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return value


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build and validate the settings; creates the data directory if needed."""
    env = os.environ if env is None else env

    api_token = _read(env, "HME_API_TOKEN")
    if len(api_token) < MIN_API_TOKEN_LENGTH:
        raise ConfigError(
            f"HME_API_TOKEN must be at least {MIN_API_TOKEN_LENGTH} characters "
            "(generate one with: openssl rand -hex 32)"
        )

    try:
        admin_auth = AdminAuth(_read(env, "HME_ADMIN_AUTH", AdminAuth.PASSWORD).lower())
    except ValueError as error:
        raise ConfigError("HME_ADMIN_AUTH must be 'password' or 'proxy'") from error

    admin_password = _read(env, "HME_ADMIN_PASSWORD") or None
    if admin_auth is AdminAuth.PASSWORD:
        if not admin_password or len(admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
            raise ConfigError(
                f"HME_ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters, "
                "or set HME_ADMIN_AUTH=proxy if a reverse proxy authenticates the admin UI"
            )
        if admin_password == api_token:
            raise ConfigError("HME_ADMIN_PASSWORD must differ from HME_API_TOKEN")

    data_dir = Path(_read(env, "HME_DATA_DIR", "/data"))
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    return Settings(
        api_token=api_token,
        data_dir=data_dir,
        admin_auth=admin_auth,
        admin_password=admin_password,
        session_secret=_session_secret(env, data_dir),
        public_url=_read(env, "HME_PUBLIC_URL").rstrip("/"),
        cookie_secure=_bool(env, "HME_COOKIE_SECURE", True),
        keepalive_interval=_int(env, "HME_KEEPALIVE_INTERVAL", 6 * 3600, minimum=300),
        max_aliases_per_hour=_int(env, "HME_MAX_ALIASES_PER_HOUR", 10, minimum=1),
        ntfy_url=_read(env, "HME_NTFY_URL").rstrip("/"),
        ntfy_topic=_read(env, "HME_NTFY_TOPIC"),
        ntfy_token=_read(env, "HME_NTFY_TOKEN"),
        webhook_url=_read(env, "HME_WEBHOOK_URL"),
        log_level=_read(env, "HME_LOG_LEVEL", "INFO").upper(),
        host=_read(env, "HME_HOST", "0.0.0.0"),  # noqa: S104
        port=_int(env, "HME_PORT", 8000, minimum=1),
        trusted_proxies=_read(env, "HME_TRUSTED_PROXIES", "127.0.0.1"),
        access_log=_bool(env, "HME_ACCESS_LOG", False),
    )
