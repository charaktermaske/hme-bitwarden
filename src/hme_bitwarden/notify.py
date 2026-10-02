"""Notifications when the iCloud session needs attention (ntfy and/or a generic JSON webhook)."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

import requests

from .config import Settings

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 15

Sender = Callable[[str, str, str], None]


class Notifier:
    """Sends a title and message to every configured channel, in a background thread."""

    def __init__(self, senders: list[Sender]) -> None:
        self._senders = senders

    @classmethod
    def from_settings(cls, settings: Settings) -> Notifier:
        senders: list[Sender] = []
        if settings.ntfy_url and settings.ntfy_topic:
            senders.append(_ntfy_sender(settings.ntfy_url, settings.ntfy_topic, settings.ntfy_token))
        if settings.webhook_url:
            senders.append(_webhook_sender(settings.webhook_url))
        return cls(senders)

    @property
    def enabled(self) -> bool:
        return bool(self._senders)

    def send(self, title: str, message: str, link: str = "") -> None:
        if not self._senders:
            log.warning("%s: %s", title, message)
            return
        threading.Thread(target=self._send_all, args=(title, message, link), daemon=True).start()

    def _send_all(self, title: str, message: str, link: str) -> None:
        for sender in self._senders:
            try:
                sender(title, message, link)
            except requests.RequestException as error:
                log.warning("Notification failed: %s", error.__class__.__name__)


def _ntfy_sender(url: str, topic: str, token: str) -> Sender:
    def send(title: str, message: str, link: str) -> None:
        headers = {"Title": title, "Priority": "high", "Tags": "warning"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if link:
            headers["Click"] = link
        response = requests.post(f"{url}/{topic}", data=message.encode(), headers=headers, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()

    return send


def _webhook_sender(url: str) -> Sender:
    def send(title: str, message: str, link: str) -> None:
        payload = {"title": title, "message": message, "url": link or None}
        response = requests.post(url, json=payload, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()

    return send
