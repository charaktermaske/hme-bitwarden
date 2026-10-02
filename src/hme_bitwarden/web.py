"""Admin UI: protect access, sign in to iCloud (with 2FA) and show how to configure Bitwarden."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .aliases import AliasService
from .config import AdminAuth, Settings
from .icloud import AliasBackend, SignInFailed
from .security import (
    ADMIN_SESSION_KEY,
    FailureLimiter,
    client_key,
    csrf_token,
    csrf_valid,
    tokens_match,
)

log = logging.getLogger(__name__)

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def create_router(
    settings: Settings,
    backend: AliasBackend,
    aliases: AliasService,
    failures: FailureLimiter,
) -> APIRouter:
    router = APIRouter()
    password_mode = settings.admin_auth is AdminAuth.PASSWORD

    def is_admin(request: Request) -> bool:
        return not password_mode or request.session.get(ADMIN_SESSION_KEY) is True

    def render(request: Request, template: str, status: int = 200, **context) -> HTMLResponse:
        context.update(csrf=csrf_token(request), password_mode=password_mode)
        return templates.TemplateResponse(request, template, context, status_code=status)

    def dashboard(request: Request, error: str | None = None, status: int = 200) -> HTMLResponse:
        base_url = settings.public_url or str(request.base_url).rstrip("/")
        return render(
            request,
            "dashboard.html",
            status=status,
            account=backend.status(),
            error=error,
            base_url=base_url,
            api_token=settings.api_token,
            recent=aliases.recent,
        )

    def guard(request: Request, csrf: str | None = None) -> Response | None:
        """Return a response that stops the request, or None if it may proceed."""
        if not is_admin(request):
            return redirect("/login")
        if csrf is not None and not csrf_valid(request, csrf):
            return dashboard(request, error="Your form expired. Please try again.", status=400)
        return None

    # --- admin login (only with HME_ADMIN_AUTH=password) ---------------------------------------------------

    @router.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> Response:
        if is_admin(request):
            return redirect("/")
        return render(request, "login.html")

    @router.post("/login", response_class=HTMLResponse)
    def login(request: Request, password: str = Form(""), csrf: str = Form("")) -> Response:
        if not password_mode:
            return redirect("/")
        client = client_key(request)
        if failures.is_blocked(client):
            return render(request, "login.html", status=429, error="Too many failed attempts. Try again later.")
        if not csrf_valid(request, csrf):
            return render(request, "login.html", status=400, error="Your form expired. Please try again.")
        if not tokens_match(password, settings.admin_password or ""):
            failures.record_failure(client)
            log.warning("Failed admin login from %s", client)
            return render(request, "login.html", status=401, error="Wrong password.")
        failures.reset(client)
        request.session.clear()  # new session on privilege change
        request.session[ADMIN_SESSION_KEY] = True
        return redirect("/")

    @router.post("/logout")
    def logout(request: Request, csrf: str = Form("")) -> Response:
        if csrf_valid(request, csrf):
            request.session.clear()
        return redirect("/login" if password_mode else "/")

    # --- dashboard and iCloud sign-in ----------------------------------------------------------------------

    @router.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        if (stop := guard(request)) is not None:
            return stop
        backend.refresh()
        return dashboard(request)

    @router.post("/icloud/sign-in")
    def icloud_sign_in(
        request: Request, apple_id: str = Form(""), password: str = Form(""), csrf: str = Form("")
    ) -> Response:
        if (stop := guard(request, csrf)) is not None:
            return stop
        try:
            backend.start_sign_in(apple_id, password)
        except SignInFailed as exc:
            return dashboard(request, error=str(exc), status=400)
        return redirect("/")

    @router.post("/icloud/verify")
    def icloud_verify(request: Request, code: str = Form(""), csrf: str = Form("")) -> Response:
        if (stop := guard(request, csrf)) is not None:
            return stop
        try:
            backend.verify_code(code)
        except SignInFailed as exc:
            return dashboard(request, error=str(exc), status=400)
        return redirect("/")

    @router.post("/icloud/cancel")
    def icloud_cancel(request: Request, csrf: str = Form("")) -> Response:
        if (stop := guard(request, csrf)) is not None:
            return stop
        backend.cancel_sign_in()
        return redirect("/")

    @router.post("/icloud/sign-out")
    def icloud_sign_out(request: Request, csrf: str = Form("")) -> Response:
        if (stop := guard(request, csrf)) is not None:
            return stop
        backend.sign_out()
        return redirect("/")

    return router
