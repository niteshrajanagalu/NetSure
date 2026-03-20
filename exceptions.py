"""Custom exception types and centralised FastAPI exception handler registration."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class ScanTimeoutError(Exception):
    """Raised when the nmap scan exceeds its configured timeout."""


class ScanError(Exception):
    """Raised for nmap or underlying scanner infrastructure failures."""


class NotFoundError(Exception):
    """Raised by the service layer when a requested resource does not exist."""


def register_exception_handlers(app: FastAPI) -> None:
    """Attach all exception handlers to the given FastAPI application.

    Args:
        app: The FastAPI instance to register handlers on.
    """

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        logger.warning("Validation error on %s: %s", request.url.path, exc.errors())
        return JSONResponse(
            status_code=400,
            content={"detail": jsonable_encoder(exc.errors())},
        )
