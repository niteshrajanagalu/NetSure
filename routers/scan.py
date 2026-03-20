"""Scan router — thin HTTP layer that delegates all logic to the service layer."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_db
from exceptions import NotFoundError
from schemas import ScanRequest, ScanResponse, ScanSummary
from services import get_scan_by_id, list_scans, run_scan

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scanner"])

# Reusable dependency annotation — keeps route signatures concise.
DB = Annotated[AsyncSession, Depends(get_db)]


@router.post("/scan", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanRequest, db: DB) -> ScanResponse:
    """Run a network scan, persist the results, and return them with a scan ID.

    Args:
        payload: Validated scan parameters (cidr, timeout, mode).
        db: Injected async database session.

    Returns:
        ScanResponse containing scan_id, metadata, and per-host results.

    Raises:
        HTTPException 400: Invalid CIDR or request parameters.
        HTTPException 500: Unexpected persistence failure (scanner errors return partial results).
    """
    try:
        return await run_scan(payload.cidr, payload.timeout, payload.mode, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unhandled failure for %s", payload.cidr)
        raise HTTPException(status_code=500, detail="Internal error") from exc


@router.get("/scans", response_model=list[ScanSummary])
async def get_scans(
    db: DB,
    limit: Annotated[int, Query(ge=1, le=100, description="Page size (1–100)")] = 20,
    offset: Annotated[int, Query(ge=0, description="Number of records to skip")] = 0,
) -> list[ScanSummary]:
    """List past scans ordered by newest first with cursor-style pagination.

    Args:
        db: Injected async database session.
        limit: Maximum results to return (default 20, max 100).
        offset: Records to skip before returning results (default 0).

    Returns:
        List of ScanSummary objects — no device detail included.
    """
    return await list_scans(db, limit=limit, offset=offset)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: DB) -> ScanResponse:
    """Retrieve the full results of a single scan by its ID.

    Args:
        scan_id: UUID of the scan to retrieve.
        db: Injected async database session.

    Returns:
        ScanResponse with all device records for the scan.

    Raises:
        HTTPException 404: When no scan with the given ID exists.
    """
    try:
        return await get_scan_by_id(scan_id, db)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
