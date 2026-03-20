"""Application settings resolved from environment variables at import time."""

from __future__ import annotations

import os


class Settings:
    """Central config object. Override any value via environment variables."""

    app_title: str = "NetSure Scanner API"
    app_version: str = "1.0.0"
    log_level: str = os.environ.get("LOG_LEVEL", "INFO").upper()
    default_scan_timeout: int = int(os.environ.get("SCAN_TIMEOUT", "20"))
    default_scan_mode: str = os.environ.get("SCAN_MODE", "full")
    # SQLite by default; swap to postgresql+asyncpg://... for production
    database_url: str = os.environ.get(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./netsure.db",
    )


settings = Settings()
