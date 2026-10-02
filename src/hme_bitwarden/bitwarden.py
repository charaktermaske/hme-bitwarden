"""Endpoints that Bitwarden's username generator calls, mimicking self-hosted SimpleLogin and addy.io.

Bitwarden shows the ``error`` field of a JSON error response to the user, so every failure returns one.

  POST /api/alias/random/new?hostname=…  SimpleLogin  header "Authentication: <token>"         → {"alias": …}
  POST /api/v1/aliases                   addy.io      header "Authorization: Bearer <token>"  → {"data": {"email": …}}
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .aliases import AliasService, CreatedAlias, RateLimited
from .config import Settings
from .icloud import AppleApiError, SignInRequired
from .security import FailureLimiter, api_token_from, client_key, tokens_match

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 16 * 1024


def error(message: str, status: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


async def read_json(request: Request) -> dict[str, Any]:
    body = await request.body()
    if not body or len(body) > MAX_BODY_BYTES:
        return {}
    try:
        data = await request.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def create_router(settings: Settings, aliases: AliasService, failures: FailureLimiter) -> APIRouter:
    router = APIRouter(prefix="/api")

    def create(request: Request, hostname: str, description: str) -> CreatedAlias | JSONResponse:
        """Blocking (talks to Apple), so the endpoints run it in the thread pool."""
        client = client_key(request)
        if failures.is_blocked(client):
            return error("Too many failed attempts; try again later", 429)
        if not tokens_match(api_token_from(request), settings.api_token):
            failures.record_failure(client)
            log.warning("Rejected API request with an invalid token from %s", client)
            return error("Invalid API key", 401)
        try:
            return aliases.create(hostname=hostname, description=description)
        except SignInRequired as exc:
            where = f" Sign in again at {settings.public_url}" if settings.public_url else ""
            return error(f"iCloud: {exc}.{where}", 503)
        except RateLimited as exc:
            return error(str(exc), 429)
        except AppleApiError as exc:
            return error(f"iCloud: {exc}", 502)

    @router.post("/alias/random/new")
    async def simplelogin(request: Request, hostname: str = "") -> JSONResponse:
        note = str((await read_json(request)).get("note", ""))
        result = await run_in_threadpool(create, request, hostname, note)
        if isinstance(result, JSONResponse):
            return result
        return JSONResponse({"alias": result.email}, status_code=201)

    @router.post("/v1/aliases")
    async def addy_io(request: Request) -> JSONResponse:
        description = str((await read_json(request)).get("description", ""))
        result = await run_in_threadpool(create, request, "", description)
        if isinstance(result, JSONResponse):
            return result
        return JSONResponse({"data": {"email": result.email}}, status_code=201)

    return router
