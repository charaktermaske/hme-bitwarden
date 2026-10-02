import re

from hme_bitwarden.config import AdminAuth
from hme_bitwarden.icloud import AccountState

from .conftest import ADMIN_PASSWORD, API_TOKEN

CSRF = re.compile(r'name="csrf" value="([^"]+)"')


def csrf_from(response) -> str:
    match = CSRF.search(response.text)
    assert match, "page has no CSRF token"
    return match.group(1)


def log_in(client) -> str:
    page = client.get("/login")
    response = client.post("/login", data={"password": ADMIN_PASSWORD, "csrf": csrf_from(page)}, follow_redirects=False)
    assert response.status_code == 303
    return csrf_from(client.get("/"))


def test_dashboard_requires_admin_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_wrong_admin_password(client):
    page = client.get("/login")
    response = client.post("/login", data={"password": "nope", "csrf": csrf_from(page)})
    assert response.status_code == 401
    assert "Wrong password" in response.text


def test_admin_login_requires_csrf_token(client):
    client.get("/login")
    response = client.post("/login", data={"password": ADMIN_PASSWORD, "csrf": "forged"})
    assert response.status_code == 400


def test_admin_login_is_rate_limited(client):
    page = client.get("/login")
    token = csrf_from(page)
    for _ in range(10):
        client.post("/login", data={"password": "nope", "csrf": token})
    response = client.post("/login", data={"password": ADMIN_PASSWORD, "csrf": token})
    assert response.status_code == 429


def test_dashboard_shows_setup_after_login(client):
    log_in(client)
    page = client.get("/")
    assert page.status_code == 200
    assert "https://hme.example.com" in page.text
    assert API_TOKEN in page.text
    assert "Not signed in yet" in page.text


def test_full_icloud_sign_in_flow(client, backend):
    csrf = log_in(client)
    response = client.post(
        "/icloud/sign-in", data={"apple_id": "me@icloud.com", "password": "apple-pass", "csrf": csrf}
    )
    assert response.status_code == 200  # redirect followed
    assert "verification code" in response.text
    assert backend.state is AccountState.AWAITING_CODE

    wrong = client.post("/icloud/verify", data={"code": "000000", "csrf": csrf})
    assert wrong.status_code == 400
    assert "incorrect" in wrong.text

    done = client.post("/icloud/verify", data={"code": "123456", "csrf": csrf})
    assert "Signed in as me@icloud.com" in done.text
    assert backend.state is AccountState.READY

    client.post("/icloud/sign-out", data={"csrf": csrf})
    assert backend.state is AccountState.SIGNED_OUT


def test_icloud_actions_require_csrf_token(client, backend):
    log_in(client)
    response = client.post(
        "/icloud/sign-in", data={"apple_id": "me@icloud.com", "password": "apple-pass", "csrf": "forged"}
    )
    assert response.status_code == 400
    assert backend.state is AccountState.SIGNED_OUT


def test_icloud_actions_require_admin(client, backend):
    response = client.post(
        "/icloud/sign-in",
        data={"apple_id": "me@icloud.com", "password": "apple-pass", "csrf": "x"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert backend.state is AccountState.SIGNED_OUT


def test_logout_ends_admin_session(client):
    csrf = log_in(client)
    client.post("/logout", data={"csrf": csrf})
    assert client.get("/", follow_redirects=False).status_code == 303


def test_proxy_mode_has_no_login(client_factory):
    client = client_factory(admin_auth=AdminAuth.PROXY, admin_password=None)
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 200
    assert "Set up Bitwarden" in page.text
    assert "Log out" not in page.text


def test_security_headers_on_ui(client):
    response = client.get("/login")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "script-src" not in response.headers["content-security-policy"]  # default-src 'none' covers scripts
    assert response.headers["x-frame-options"] == "DENY"
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    assert "httponly" in response.headers["set-cookie"].lower()


def test_output_is_escaped(client, backend):
    backend.apple_id = '<script>alert("x")</script>'
    log_in(client)
    page = client.get("/")
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text
