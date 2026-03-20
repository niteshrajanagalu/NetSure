"""SQLAlchemy ORM models for persisted scan results.

Design notes
------------
* UUIDs are stored as VARCHAR(36) strings — compatible with both SQLite and
  PostgreSQL (use sqlalchemy.Uuid for native PG uuid type when migrating).
* ports / services use the JSON column type, which SQLAlchemy maps to TEXT
  on SQLite and to native JSON/JSONB on PostgreSQL.
* Scan.devices uses lazy="raise" — any accidental implicit load raises
  immediately rather than silently firing a query.  All callers that need
  devices must use an explicit selectinload() option.
* Device.scan_id carries index=True for fast FK lookups and joins.
* IDs are generated eagerly in __init__ (not deferred to INSERT time) so
  that scan.id is available immediately after construction.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db import Base


class Scan(Base):
    """One row per POST /scan invocation."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    cidr: Mapped[str] = mapped_column(String(50), nullable=False)
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    devices: Mapped[list[Device]] = relationship(
        "Device",
        back_populates="scan",
        cascade="all, delete-orphan",
        # "raise" prevents silent lazy loads in async context.
        # Use selectinload(Scan.devices) explicitly where devices are needed.
        lazy="raise",
    )

    def __init__(self, cidr: str, mode: str, **kwargs: Any) -> None:
        super().__init__(
            id=kwargs.pop("id", str(uuid.uuid4())),
            cidr=cidr,
            mode=mode,
            timestamp=kwargs.pop("timestamp", datetime.now(timezone.utc)),
            **kwargs,
        )


class Device(Base):
    """One row per reachable host discovered during a scan."""

    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,  # accelerates JOIN in list_scans aggregation and FK lookups
    )
    ip: Mapped[str] = mapped_column(String(50), nullable=False)
    ports: Mapped[list] = mapped_column(JSON, nullable=False)
    services: Mapped[list] = mapped_column(JSON, nullable=False)
    risk: Mapped[str] = mapped_column(String(10), nullable=False)

    scan: Mapped[Scan] = relationship(
        "Scan",
        back_populates="devices",
        lazy="raise",  # never traverse Device → Scan; prevents accidental N+1
    )

    def __init__(
        self,
        scan_id: str,
        ip: str,
        ports: list,
        services: list,
        risk: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            id=kwargs.pop("id", str(uuid.uuid4())),
            scan_id=scan_id,
            ip=ip,
            ports=ports,
            services=services,
            risk=risk,
            **kwargs,
        )
