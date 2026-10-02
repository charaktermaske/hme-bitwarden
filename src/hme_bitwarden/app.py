"""Application factory: wires settings, iCloud backend, alias service, API and admin UI together."""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__, bitwarden, web
from .aliases import AliasService
from .config import AdminAuth, Settings
from .icloud import AliasBackend, ICloudAccount
from .notify import Notifier
from .security import API_PREFIX, FailureLimiter, SecurityHeadersMiddleware

log = logging.getLogger(__name__)

SESSION_MAX_AGE = 12 * 3600


class ApiOnlyCORS:
    """CORS for the Bitwarden API only (web vault and desktop app call it cross-origin); never the admin UI."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app
        self._cors = CORSMiddleware(
            app,
            allow_origins=["*"],
            allow_methods=["POST"],
            allow_headers=["Authentication", "Authorization", "Content-Type", "X-Requested-With"],
            max_age=600,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith(API_PREFIX):
            await self._cors(scope, receive, send)
        else:
            await self._app(scope, receive, send)


def _keepalive(backend: AliasBackend, interval: int, stop: threading.Event) -> None:
    while not stop.wait(interval):
        try:
            backend.refresh()
        except Exception:
            log.exception("Session keep-alive failed")


def create_app(
    settings: Settings,
    backend: AliasBackend | None = None,
    notifier: Notifier | None = None,
) -> FastAPI:
    notifier = notifier or Notifier.from_settings(settings)

    def on_session_lost(reason: str) -> None:
        where = f" at {settings.public_url}" if settings.public_url else ""
        notifier.send(
            "Hide My Email: sign-in required",
            f"{reason}. Bitwarden cannot create iCloud addresses until you sign in again{where}.",
            settings.public_url,
        )

    backend = backend or ICloudAccount(settings.session_dir, on_session_lost=on_session_lost)
    aliases = AliasService(backend, settings.max_aliases_per_hour)
    failures = FailureLimiter()
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if settings.admin_auth is AdminAuth.PROXY:
            log.warning("HME_ADMIN_AUTH=proxy: the admin UI has no login of its own; protect it with your proxy")
        await run_in_threadpool(backend.refresh)
        threading.Thread(
            target=_keepalive,
            args=(backend, settings.keepalive_interval, stop),
            name="icloud-keepalive",
            daemon=True,
        ).start()
        yield
        stop.set()

    app = FastAPI(
        title="hme-bitwarden",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="hme_session",
        max_age=SESSION_MAX_AGE,
        same_site="strict",
        https_only=settings.cookie_secure,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ApiOnlyCORS)

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    app.include_router(bitwarden.create_router(settings, aliases, failures))
    app.include_router(web.create_router(settings, backend, aliases, failures))

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
