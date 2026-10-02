"""Alias creation on top of the iCloud backend: labels, rate limiting and a short in-memory history."""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

from .icloud import AliasBackend, ICloudError

log = logging.getLogger(__name__)

MAX_LABEL_LENGTH = 60
MAX_NOTE_LENGTH = 200
DEFAULT_LABEL = "Bitwarden"
DEFAULT_NOTE = "Created by Bitwarden"
HISTORY_SIZE = 10

_HOSTNAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.IGNORECASE)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class RateLimited(ICloudError):
    """This service's own hourly limit was reached (protects the Apple account if the token leaks)."""


@dataclass(frozen=True)
class CreatedAlias:
    email: str
    label: str
    created_at: datetime


def clean(text: str, max_length: int) -> str:
    return _CONTROL_CHARS.sub(" ", text).strip()[:max_length]


def derive_label(hostname: str, description: str) -> str:
    """Use the website as the label: Bitwarden sends it as a hostname or inside a free-text description."""
    for candidate in (hostname, description):
        match = _HOSTNAME.search(candidate or "")
        if match:
            return match.group(0).lower()[:MAX_LABEL_LENGTH]
    return DEFAULT_LABEL


class SlidingWindowLimiter:
    """Allows at most ``limit`` events per ``window`` seconds."""

    def __init__(self, limit: int, window: float, clock=time.monotonic) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self._clock()
            while self._events and now - self._events[0] >= self._window:
                self._events.popleft()
            if len(self._events) >= self._limit:
                return False
            self._events.append(now)
            return True

    def refund(self) -> None:
        """Give back the most recent event (the attempt did not produce anything)."""
        with self._lock:
            if self._events:
                self._events.pop()


class AliasService:
    def __init__(self, backend: AliasBackend, max_per_hour: int) -> None:
        self._backend = backend
        self._limiter = SlidingWindowLimiter(max_per_hour, 3600)
        self._history: deque[CreatedAlias] = deque(maxlen=HISTORY_SIZE)

    @property
    def recent(self) -> list[CreatedAlias]:
        return list(reversed(self._history))

    def create(self, hostname: str = "", description: str = "") -> CreatedAlias:
        if not self._limiter.try_acquire():
            raise RateLimited("Hourly alias limit reached; try again later")
        label = derive_label(hostname, description)
        note = clean(description, MAX_NOTE_LENGTH) or DEFAULT_NOTE
        try:
            email = self._backend.create_alias(label, note)
        except Exception:
            self._limiter.refund()
            raise
        alias = CreatedAlias(email=email, label=label, created_at=datetime.now(UTC))
        self._history.append(alias)
        log.info("Created a Hide My Email address for %s", label)
        return alias
