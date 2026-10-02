from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hme_bitwarden.app import create_app
from hme_bitwarden.config import AdminAuth, Settings
from hme_bitwarden.icloud import AccountState, AccountStatus, SignInFailed, SignInRequired
from hme_bitwarden.notify import Notifier

API_TOKEN = "t" * 64
ADMIN_PASSWORD = "correct horse battery"


class FakeBackend:
    """In-memory stand-in for ICloudAccount."""

    def __init__(self) -> None:
        self.state = AccountState.SIGNED_OUT
        self.apple_id: str | None = None
        self.created: list[tuple[str, str]] = []
        self.error: Exception | None = None
        self.counter = 0

    def status(self) -> AccountStatus:
        problem = "Not signed in yet" if self.state is AccountState.SIGNED_OUT else None
        return AccountStatus(self.state, apple_id=self.apple_id, problem=problem, code_delivery="trusted_device")

    def refresh(self) -> AccountStatus:
        return self.status()

    def start_sign_in(self, apple_id: str, password: str) -> AccountStatus:
        if password != "apple-pass":
            raise SignInFailed("Apple ID or password is incorrect.")
        self.apple_id = apple_id
        self.state = AccountState.AWAITING_CODE
        return self.status()

    def verify_code(self, code: str) -> AccountStatus:
        if code != "123456":
            raise SignInFailed("The verification code is incorrect.")
        self.state = AccountState.READY
        return self.status()

    def cancel_sign_in(self) -> None:
        self.state = AccountState.SIGNED_OUT

    def sign_out(self) -> None:
        self.state = AccountState.SIGNED_OUT

    def create_alias(self, label: str, note: str) -> str:
        if self.error is not None:
            raise self.error
        if self.state is not AccountState.READY:
            raise SignInRequired("Not signed in yet")
        self.counter += 1
        self.created.append((label, note))
        return f"alias{self.counter}@icloud.com"


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "api_token": API_TOKEN,
        "data_dir": tmp_path,
        "admin_auth": AdminAuth.PASSWORD,
        "admin_password": ADMIN_PASSWORD,
        "session_secret": "s" * 48,
        "public_url": "https://hme.example.com",
        "cookie_secure": False,
        "max_aliases_per_hour": 5,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def client_factory(tmp_path: Path, backend: FakeBackend):
    clients: list[TestClient] = []

    def build(**overrides) -> TestClient:
        app = create_app(make_settings(tmp_path, **overrides), backend=backend, notifier=Notifier([]))
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield build
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(client_factory) -> TestClient:
    return client_factory()
