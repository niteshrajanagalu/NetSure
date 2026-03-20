"""Database engine, session factory, and FastAPI dependency.

Swap SQLite → PostgreSQL by setting DATABASE_URL to:
    postgresql+asyncpg://user:pass@host:5432/dbname
No other code changes are required.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    # Keeps stale connections from surfacing as errors after a DB restart.
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base — every ORM model inherits from this."""


async def init_db() -> None:
    """Create all tables that do not yet exist.

    Must be called at startup *after* all model modules have been imported
    so that their metadata is registered with Base.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields a scoped async session per request.

    Rolls back automatically on any unhandled exception so the connection
    is always returned to the pool in a clean state.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
