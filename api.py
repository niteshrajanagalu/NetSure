"""FastAPI application factory.

Run with:
    uvicorn api:app --reload
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from db import init_db
from exceptions import register_exception_handlers
from routers.health import router as health_router
from routers.scan import router as scan_router

_mw_logger = logging.getLogger("netsure.access")
_BASE_DIR = Path(__file__).resolve().parent
_FRONTEND_DIR = _BASE_DIR / "frontend"
_FRONTEND_INDEX = _FRONTEND_DIR / "index.html"


class _RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request with method, path, status code, and elapsed time."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        _mw_logger.info(
            "%s %s %d %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=__import__("sys").stderr,
    )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    _configure_logging()
    log = logging.getLogger(__name__)
    log.info("NetSure API starting — version=%s", settings.app_version)

    # Models must be imported before init_db() so their metadata is registered.
    import models  # noqa: F401

    await init_db()
    log.info("Database ready — %s", settings.database_url)

    yield

    log.info("NetSure API shut down")


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application.

    Returns:
        A fully wired FastAPI instance ready for serving.
    """
    application = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        description="HTTP API for running network scans and computing device risk.",
        lifespan=_lifespan,
    )

    application.add_middleware(_RequestLoggingMiddleware)
    register_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(scan_router)

    if _FRONTEND_DIR.exists():
        application.mount("/static", StaticFiles(directory=_FRONTEND_DIR), name="frontend-static")

        @application.get("/", include_in_schema=False)
        async def serve_frontend() -> FileResponse:
            return FileResponse(_FRONTEND_INDEX)

    return application


app = create_app()
