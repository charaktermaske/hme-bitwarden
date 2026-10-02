"""iCloud account handling: sign-in with 2FA, session reuse and Hide My Email calls.

Apple has no public Hide My Email API. This module uses the private web API that icloud.com itself uses,
through the pyicloud library. All pyicloud usage is contained here so that an upstream change only
affects this file.

The Apple ID password is never written to disk. pyicloud keeps it in memory for the lifetime of the
sign-in so that an expired session token can be renewed without 2FA while the trust token is valid.
Only cookies and the trust token are persisted (in ``Settings.session_dir``).
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import requests
from pyicloud import PyiCloudService
from pyicloud.exceptions import PyiCloudException, PyiCloudFailedLoginException

log = logging.getLogger(__name__)

_NETWORK_ERRORS = (PyiCloudException, requests.RequestException)


class AccountState(StrEnum):
    SIGNED_OUT = "signed_out"
    AWAITING_CODE = "awaiting_code"
    READY = "ready"


@dataclass(frozen=True)
class AccountStatus:
    state: AccountState
    apple_id: str | None = None
    problem: str | None = None
    code_delivery: str | None = None  # "sms" or "trusted_device" while AWAITING_CODE


class ICloudError(Exception):
    """Base class for errors reported to the user."""


class SignInRequired(ICloudError):
    """There is no usable iCloud session; someone has to sign in through the admin UI."""


class SignInFailed(ICloudError):
    """Sign-in or 2FA verification did not succeed."""


class AppleApiError(ICloudError):
    """Apple rejected a Hide My Email request (e.g. rate limit) or could not be reached."""


class AliasBackend(Protocol):
    """What the rest of the application needs from an iCloud account."""

    def status(self) -> AccountStatus: ...
    def refresh(self) -> AccountStatus: ...
    def start_sign_in(self, apple_id: str, password: str) -> AccountStatus: ...
    def verify_code(self, code: str) -> AccountStatus: ...
    def cancel_sign_in(self) -> None: ...
    def sign_out(self) -> None: ...
    def create_alias(self, label: str, note: str) -> str: ...


ServiceFactory = Callable[..., PyiCloudService]


class ICloudAccount:
    """A single iCloud account backed by pyicloud. Thread-safe; calls are serialized."""

    def __init__(
        self,
        session_dir: Path,
        on_session_lost: Callable[[str], None] | None = None,
        service_factory: ServiceFactory = PyiCloudService,
    ) -> None:
        self._session_dir = session_dir
        self._account_file = session_dir / "account.json"
        self._on_session_lost = on_session_lost or (lambda _reason: None)
        self._factory = service_factory
        self._lock = threading.RLock()
        self._api: PyiCloudService | None = None
        self._pending: PyiCloudService | None = None
        self._problem: str | None = "Not signed in yet"
        self._lost_reported = False

    # --- status --------------------------------------------------------------------------------------------

    def status(self) -> AccountStatus:
        with self._lock:
            if self._pending is not None:
                return AccountStatus(
                    AccountState.AWAITING_CODE,
                    apple_id=self._pending.account_name,
                    code_delivery=self._pending.two_factor_delivery_method,
                )
            if self._api is not None:
                return AccountStatus(AccountState.READY, apple_id=self._api.account_name)
            return AccountStatus(AccountState.SIGNED_OUT, apple_id=self._stored_apple_id(), problem=self._problem)

    def refresh(self) -> AccountStatus:
        """Resume the stored session, or keep the current one alive. Never prompts for 2FA."""
        with self._lock:
            if self._pending is None:
                self._resume()
            return self.status()

    # --- sign-in -------------------------------------------------------------------------------------------

    def start_sign_in(self, apple_id: str, password: str) -> AccountStatus:
        apple_id = apple_id.strip()
        if not apple_id or not password:
            raise SignInFailed("Apple ID and password are required.")
        with self._lock:
            self._pending = None
            self._prepare_session_dir()
            try:
                api = self._factory(apple_id, password, cookie_directory=str(self._session_dir))
            except PyiCloudFailedLoginException as error:
                raise SignInFailed("Apple ID or password is incorrect.") from error
            except _NETWORK_ERRORS as error:
                raise SignInFailed(f"Sign-in failed: {_describe(error)}") from error

            self._store_apple_id(apple_id)
            if _is_ready(api):
                self._set_ready(api)
                return self.status()
            if api.security_key_names:
                raise SignInFailed("This Apple ID requires a hardware security key, which is not supported.")
            try:
                api.request_2fa_code()
            except _NETWORK_ERRORS as error:
                raise SignInFailed(f"Could not request a verification code: {_describe(error)}") from error
            self._pending = api
            return self.status()

    def verify_code(self, code: str) -> AccountStatus:
        code = code.strip()
        if not (len(code) == 6 and code.isdigit()):
            raise SignInFailed("The verification code has six digits.")
        with self._lock:
            api = self._pending
            if api is None:
                raise SignInFailed("No sign-in in progress. Please start again.")
            try:
                accepted = api.validate_2fa_code(code)
            except _NETWORK_ERRORS as error:
                self._pending = None
                raise SignInFailed(f"Verification failed: {_describe(error)}") from error
            if not accepted:
                raise SignInFailed("The verification code is incorrect.")
            self._pending = None
            if not _is_ready(api):
                raise SignInFailed("Apple did not trust this session. Please sign in again.")
            self._set_ready(api)
            log.info("Signed in to iCloud")
            return self.status()

    def cancel_sign_in(self) -> None:
        with self._lock:
            self._pending = None

    def sign_out(self) -> None:
        with self._lock:
            if self._api is not None:
                try:
                    self._api.logout()
                except (*_NETWORK_ERRORS, TypeError):
                    log.debug("Logout request failed; removing the local session anyway", exc_info=True)
            self._api = None
            self._pending = None
            self._problem = "Signed out"
            self._lost_reported = True  # an intentional sign-out is not worth a notification
            shutil.rmtree(self._session_dir, ignore_errors=True)
            log.info("Signed out of iCloud and removed the stored session")

    # --- Hide My Email -------------------------------------------------------------------------------------

    def create_alias(self, label: str, note: str) -> str:
        """Generate a new address and reserve it with the given label and note."""
        with self._lock:
            if self._api is None and self._pending is None:
                self._resume()
            if self._api is None:
                raise SignInRequired(self._problem or "Not signed in")
            try:
                return self._generate_and_reserve(self._api, label, note)
            except _NETWORK_ERRORS as error:
                # Usually an expired token: renew once, then give up.
                log.info("Hide My Email request failed (%s); renewing the session", _describe(error))
                self._resume()
                if self._api is None:
                    raise SignInRequired(self._problem or "Session expired") from error
                try:
                    return self._generate_and_reserve(self._api, label, note)
                except _NETWORK_ERRORS as retry_error:
                    raise AppleApiError(f"iCloud is not reachable: {_describe(retry_error)}") from retry_error

    def _generate_and_reserve(self, api: PyiCloudService, label: str, note: str) -> str:
        email = _hme_call(api, "generate", {"langCode": "en-us"}).get("hme")
        if not isinstance(email, str) or "@" not in email:
            raise AppleApiError("Apple did not return an address")
        _hme_call(api, "reserve", {"hme": email, "label": label, "note": note})
        return email

    # --- internals (caller holds the lock) -----------------------------------------------------------------

    def _resume(self) -> None:
        api = self._api
        if api is None:
            apple_id = self._stored_apple_id()
            if not apple_id:
                self._problem = "Not signed in yet"
                return
            api = self._factory(apple_id, cookie_directory=str(self._session_dir), authenticate=False)
        try:
            # Valid session: a single /validate call. Otherwise token login, then password (memory only).
            api.authenticate()
        except _NETWORK_ERRORS as error:
            self._lose_session(f"The iCloud session expired ({_describe(error)})")
            return
        if not _is_ready(api):
            self._lose_session("Apple requires a new sign-in with two-factor authentication")
            return
        self._set_ready(api)

    def _set_ready(self, api: PyiCloudService) -> None:
        self._api = api
        self._problem = None
        self._lost_reported = False

    def _lose_session(self, reason: str) -> None:
        self._api = None
        self._problem = reason
        log.warning("iCloud session lost: %s", reason)
        if not self._lost_reported:
            self._lost_reported = True
            self._on_session_lost(reason)

    def _prepare_session_dir(self) -> None:
        self._session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._session_dir.chmod(0o700)

    def _stored_apple_id(self) -> str | None:
        try:
            return json.loads(self._account_file.read_text(encoding="utf-8")).get("apple_id") or None
        except (OSError, ValueError, AttributeError):
            return None

    def _store_apple_id(self, apple_id: str) -> None:
        self._account_file.write_text(json.dumps({"apple_id": apple_id}), encoding="utf-8")
        self._account_file.chmod(0o600)


def _is_ready(api: PyiCloudService) -> bool:
    return bool(api.is_trusted_session) and not api.requires_2fa and not api.requires_2sa


def _hme_call(api: PyiCloudService, action: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST to the Hide My Email web service and return its ``result`` object."""
    root = api.get_webservice_url("premiummailsettings")
    response = api.session.post(f"{root}/v1/hme/{action}", params=api.params, json=body)
    try:
        data = response.json()
    except ValueError as error:
        raise AppleApiError(f"Unexpected response from Apple ({action})") from error
    if not isinstance(data, dict):
        raise AppleApiError(f"Unexpected response from Apple ({action})")
    if not data.get("success"):
        raise AppleApiError(_apple_error_message(data) or f"Apple rejected the {action} request")
    result = data.get("result")
    return result if isinstance(result, dict) else {}


def _apple_error_message(data: dict[str, Any]) -> str | None:
    error = data.get("error")
    if isinstance(error, dict):
        for key in ("errorMessage", "reason", "errorCode"):
            if error.get(key):
                return str(error[key])
    elif error:
        return str(error)
    return str(data["reason"]) if data.get("reason") else None


def _describe(error: Exception) -> str:
    text = str(error).strip()
    return f"{error.__class__.__name__}: {text}" if text else error.__class__.__name__
