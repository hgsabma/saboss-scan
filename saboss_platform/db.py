"""Database setup (SQLAlchemy 2.0).

SQLite is the default for local development. Any database supported by
SQLAlchemy can be used through SABOSS_DATABASE_URL; PostgreSQL is
recommended in production (see docs/DEPLOYMENT.md).

All queries go through the SQLAlchemy ORM or bound parameters, never string
formatting, which prevents SQL injection.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Current UTC time without tzinfo (stored the same way in every database)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite:///"):
        path = database_url.removeprefix("sqlite:///")
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(database_url, connect_args={"check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - trivial
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        return engine
    return create_engine(database_url, pool_pre_ping=True)


class Database:
    """Holds the engine and session factory for one application instance."""

    def __init__(self, database_url: str):
        self.url = database_url
        self.engine = make_engine(database_url)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    def session(self) -> Session:
        return self.session_factory()

    def sessions(self) -> Iterator[Session]:
        """FastAPI dependency: one session per request, always closed."""
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()


def run_migrations(database_url: str) -> None:
    """Bring the database schema up to date with Alembic."""
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parent.parent
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    config.attributes["explicit_url"] = True
    command.upgrade(config, "head")
