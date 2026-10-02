"""Entry point: ``python -m hme_bitwarden`` or ``hme-bitwarden``."""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .app import create_app
from .config import ConfigError, load_settings


def main() -> None:
    os.umask(0o077)  # session files and secrets are private to the service user
    try:
        settings = load_settings()
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(2)

    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("pyicloud").setLevel(max(logging.WARNING, logging.getLogger().level))

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips=settings.trusted_proxies,
        server_header=False,
        # Off by default: request URLs contain the website an address is created for.
        access_log=settings.access_log,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
