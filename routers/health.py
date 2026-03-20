"""Health-check router."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])


@router.get("/health", include_in_schema=False)
async def health() -> JSONResponse:
    """Liveness probe — returns 200 when the process is up."""
    return JSONResponse({"status": "ok"})
