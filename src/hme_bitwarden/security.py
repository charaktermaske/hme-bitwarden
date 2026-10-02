"""Authentication helpers: API token, admin session, CSRF protection, brute-force limiting, headers."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

API_PREFIX = "/api/"
CSRF_SESSION_KEY = "csrf"
ADMIN_SESSION_KEY = "admin"

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)


def tokens_match(given: str, expected: str) -> bool:
    """Constant-time comparison that also works for strings of different length."""
    return hmac.compare_digest(given.encode(), expected.encode())


def api_token_from(request: Request) -> str:
    """Bitwarden sends ``Authentication: <token>`` (SimpleLogin) or ``Authorization: Bearer <token>`` (addy.io)."""
    token = request.headers.get("Authentication", "").strip()
    if token:
        return token
    scheme, _, value = request.headers.get("Authorization", "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


def client_key(request: Request) -> str:
    """The client address as seen after trusted proxy headers were applied by uvicorn."""
    return request.client.host if request.client else "unknown"


class FailureLimiter:
    """Blocks a client after too many failed attempts within a time window."""

    def __init__(self, max_failures: int = 10, window: float = 900, clock=time.monotonic) -> None:
        self._max = max_failures
        self._window = window
        self._clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        events = self._failures[key]
        while events and now - events[0] >= self._window:
            events.popleft()
        if not events:
            del self._failures[key]
            return deque()
        return events

    def is_blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, self._clock())) >= self._max

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            self._prune(key, now)
            self._failures[key].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def csrf_valid(request: Request, submitted: str) -> bool:
    expected = request.session.get(CSRF_SESSION_KEY, "")
    return bool(expected) and bool(submitted) and tokens_match(submitted, expected)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Cache-Control", "no-store")
        if not request.url.path.startswith(API_PREFIX):
            headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
            headers.setdefault("X-Frame-Options", "DENY")
        return response
