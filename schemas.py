"""Pydantic request and response schemas for the NetSure API."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from config import settings

# Canonical type alias — used in requests, responses, and the service layer.
# Pydantic rejects any value outside this set with a clear validation error.
ScanMode = Literal["fast", "full"]


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Validated payload for a scan request."""

    cidr: str = Field(..., examples=["192.168.1.0/24"])
    timeout: int = Field(
        default=settings.default_scan_timeout,
        gt=0,
        le=300,
        examples=[20],
    )
    mode: ScanMode = Field(
        default=settings.default_scan_mode,  # type: ignore[assignment]
        examples=["full"],
    )

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        """Reject malformed CIDR strings before the scan runs."""
        normalized = value.strip()
        try:
            ipaddress.ip_network(normalized, strict=False)
        except ValueError as exc:
            raise ValueError("cidr must be a valid CIDR network") from exc
        return normalized


# ---------------------------------------------------------------------------
# Intelligence sub-schemas
# ---------------------------------------------------------------------------


class SecurityIssue(BaseModel):
    """A single actionable security finding attached to a device."""

    title: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    description: str
    recommendation: str


# ---------------------------------------------------------------------------
# Shared device schema
# ---------------------------------------------------------------------------


class ScanResult(BaseModel):
    """Per-host device result including security intelligence."""

    ip: str
    ports: list[int]
    services: list[str]
    risk: str
    device_type: str = "Unknown Device"
    role: str = "UNKNOWN"
    confidence: float = 0.2
    exposure: str = "LOW"
    configuration: str = ""
    issues: list[SecurityIssue] = Field(default_factory=list)
    primary_issue: SecurityIssue | None = None
    known_exploits: list[dict] = Field(default_factory=list)
    exploit_risk_level: str = "LOW"
    primary_exploit: dict | None = None
    probes: list[dict] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    router_brand: str | None = None
    router_model: str | None = None
    router_confidence: float = 0.0
    reasoning: str = ""
    lateral_movement: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class ScanResponse(BaseModel):
    """Full scan result — returned by POST /scan and GET /scans/{id}."""

    scan_id: str
    cidr: str
    mode: ScanMode
    timestamp: datetime
    device_count: int
    duration_ms: int | None = None
    """Wall-clock time of the nmap scan in milliseconds.
    Present on POST /scan (live run). None on GET /scans/{id} (not stored)."""

    # ── User-facing decision layer (plain English, no jargon) ────────────────
    answer:          dict = Field(default_factory=dict)
    priority:        str  = ""
    confidence:      str  = ""
    why:             str  = ""
    impact:          str  = ""
    business_impact: str  = ""
    attack_path:     str  = ""
    fix_now:         dict = Field(default_factory=dict)
    proof:           list = Field(default_factory=list)
    upgrade_prompt:  str  = ""

    # ── Scan completeness ────────────────────────────────────────────────────
    scan_status: Literal["complete", "partial"] = "complete"

    # ── Internet exposure layer ───────────────────────────────────────────────
    internet_exposure: dict = Field(default_factory=dict)
    """Result of the external exposure check.
    Keys: public_ip, external_open_ports, exposed_devices, upnp, summary, has_exposure."""

    # ── Technical detail layer ───────────────────────────────────────────────
    details: dict = Field(default_factory=dict)


class ScanSummary(BaseModel):
    """Lightweight scan record — one entry in the GET /scans list."""

    scan_id: str
    cidr: str
    mode: ScanMode
    timestamp: datetime
    device_count: int
