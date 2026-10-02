"""ICloudAccount against a fake pyicloud service (no network)."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
from pyicloud.exceptions import PyiCloudAPIResponseException, PyiCloudFailedLoginException

from hme_bitwarden.icloud import AccountState, AppleApiError, ICloudAccount, SignInFailed, SignInRequired

HME_ROOT = "https://p00-maildomainws.icloud.com"


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, service: FakeService) -> None:
        self.service = service
        self.calls: list[tuple[str, dict]] = []

    def post(self, url, params=None, json=None):
        self.calls.append((url, json))
        if self.service.expired:
            raise PyiCloudAPIResponseException("Authentication required", 421)
        if url.endswith("/generate"):
            if self.service.generate_error:
                return FakeResponse({"success": False, "error": {"errorMessage": self.service.generate_error}})
            return FakeResponse({"success": True, "result": {"hme": "new-alias@icloud.com"}})
        if url.endswith("/reserve"):
            return FakeResponse({"success": True, "result": {"hme": {"hme": json["hme"]}}})
        raise AssertionError(url)


class FakeService:
    """Mimics the parts of PyiCloudService that ICloudAccount uses."""

    instances: ClassVar[list[FakeService]] = []
    # behaviour switches, set by tests before the service is created
    wrong_password = False
    needs_2fa = True
    session_valid = True

    def __init__(self, apple_id, password=None, cookie_directory=None, authenticate=True):
        self.account_name = apple_id
        self.password = password
        self.cookie_directory = cookie_directory
        self.trusted = False
        self.code_requested = False
        self.expired = False
        self.generate_error: str | None = None
        self.params = {"clientId": "test"}
        self.session = FakeSession(self)
        self.security_key_names = None
        self.two_factor_delivery_method = "trusted_device"
        FakeService.instances.append(self)
        if authenticate:
            if FakeService.wrong_password:
                raise PyiCloudFailedLoginException("Invalid email/password combination.")
            self.trusted = not FakeService.needs_2fa

    # pyicloud API surface
    @property
    def is_trusted_session(self):
        return self.trusted

    @property
    def requires_2fa(self):
        return not self.trusted

    requires_2sa = False

    def authenticate(self):
        if not FakeService.session_valid:
            raise PyiCloudFailedLoginException("No password set")
        self.trusted = True
        self.expired = False

    def request_2fa_code(self):
        self.code_requested = True
        return True

    def validate_2fa_code(self, code):
        if code != "123456":
            return False
        self.trusted = True
        return True

    def get_webservice_url(self, key):
        assert key == "premiummailsettings"
        return HME_ROOT

    def logout(self):
        pass


@pytest.fixture(autouse=True)
def reset_fake():
    FakeService.instances = []
    FakeService.wrong_password = False
    FakeService.needs_2fa = True
    FakeService.session_valid = True


@pytest.fixture
def lost() -> list[str]:
    return []


@pytest.fixture
def account(tmp_path: Path, lost) -> ICloudAccount:
    return ICloudAccount(tmp_path / "session", on_session_lost=lost.append, service_factory=FakeService)


def sign_in(account: ICloudAccount) -> None:
    status = account.start_sign_in("me@icloud.com", "pw")
    assert status.state is AccountState.AWAITING_CODE
    assert account.verify_code("123456").state is AccountState.READY


def test_sign_in_with_2fa(account, tmp_path):
    status = account.start_sign_in(" me@icloud.com ", "pw")
    assert status.state is AccountState.AWAITING_CODE
    assert status.code_delivery == "trusted_device"
    assert FakeService.instances[0].code_requested

    status = account.verify_code("123456")
    assert status.state is AccountState.READY
    assert status.apple_id == "me@icloud.com"
    # The password is never written to disk.
    for file in (tmp_path / "session").rglob("*"):
        assert "pw" not in file.read_text()


def test_sign_in_without_2fa_when_session_is_trusted(account):
    FakeService.needs_2fa = False
    assert account.start_sign_in("me@icloud.com", "pw").state is AccountState.READY


def test_wrong_password(account):
    FakeService.wrong_password = True
    with pytest.raises(SignInFailed, match="incorrect"):
        account.start_sign_in("me@icloud.com", "pw")
    assert account.status().state is AccountState.SIGNED_OUT


def test_wrong_code_keeps_sign_in_pending(account):
    account.start_sign_in("me@icloud.com", "pw")
    with pytest.raises(SignInFailed, match="incorrect"):
        account.verify_code("654321")
    assert account.status().state is AccountState.AWAITING_CODE


@pytest.mark.parametrize("code", ["12345", "abcdef", "1234567", ""])
def test_malformed_code_is_rejected_locally(account, code):
    account.start_sign_in("me@icloud.com", "pw")
    with pytest.raises(SignInFailed, match="six digits"):
        account.verify_code(code)


def test_create_alias_generates_and_reserves(account):
    sign_in(account)
    assert account.create_alias("example.com", "note") == "new-alias@icloud.com"
    calls = FakeService.instances[0].session.calls
    assert [url.rsplit("/", 1)[1] for url, _ in calls] == ["generate", "reserve"]
    assert calls[1][1] == {"hme": "new-alias@icloud.com", "label": "example.com", "note": "note"}


def test_create_alias_requires_sign_in(account):
    with pytest.raises(SignInRequired):
        account.create_alias("example.com", "note")


def test_apple_error_message_is_reported(account):
    sign_in(account)
    FakeService.instances[0].generate_error = "Rate limit reached"
    with pytest.raises(AppleApiError, match="Rate limit reached"):
        account.create_alias("example.com", "note")


def test_expired_token_is_renewed_once(account):
    sign_in(account)
    FakeService.instances[0].expired = True
    assert account.create_alias("example.com", "note") == "new-alias@icloud.com"


def test_session_lost_is_reported_once(account, lost):
    sign_in(account)
    FakeService.instances[0].expired = True
    FakeService.session_valid = False
    with pytest.raises(SignInRequired):
        account.create_alias("example.com", "note")
    account.refresh()
    assert account.status().state is AccountState.SIGNED_OUT
    assert len(lost) == 1


def test_stored_session_is_resumed_after_restart(tmp_path, lost):
    first = ICloudAccount(tmp_path / "session", on_session_lost=lost.append, service_factory=FakeService)
    sign_in(first)

    restarted = ICloudAccount(tmp_path / "session", on_session_lost=lost.append, service_factory=FakeService)
    assert restarted.refresh().state is AccountState.READY
    resumed = FakeService.instances[-1]
    assert resumed.password is None  # resumed from cookies, no password involved
    assert lost == []


def test_sign_out_removes_session(account, tmp_path, lost):
    sign_in(account)
    account.sign_out()
    assert not (tmp_path / "session").exists()
    assert account.status().state is AccountState.SIGNED_OUT
    assert lost == []  # intentional sign-out is not reported
