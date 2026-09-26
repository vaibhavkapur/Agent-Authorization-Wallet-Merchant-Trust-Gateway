"""Database engine / session management.

``DATABASE_URL`` selects PostgreSQL (docker-compose) or SQLite (local dev and
tests). SQLite connections enable WAL and a busy timeout so concurrent claim
tests exercise real write contention.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base


def make_engine(url: Optional[str] = None) -> Engine:
    url = url or os.environ.get("DATABASE_URL", "sqlite:///./aaw.db")
    if url.startswith("sqlite"):
        if url in ("sqlite://", "sqlite:///:memory:"):
            engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
        else:
            engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}, future=True)

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - trivial
            cur = dbapi_connection.cursor()
            try:
                cur.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass
            cur.execute("PRAGMA busy_timeout=30000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine
    return create_engine(url, pool_pre_ping=True, future=True)


class Database:
    def __init__(self, url: Optional[str] = None, engine: Optional[Engine] = None):
        self.engine = engine or make_engine(url)
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False, future=True)

    def create_all(self) -> None:
        """Idempotent schema creation. Several services start concurrently against the
        same database, so a lost race on CREATE TABLE ("already exists") is retried."""
        import time

        from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

        # SQLite reports the race as "table already exists" (OperationalError); PostgreSQL as
        # "duplicate key value violates unique constraint pg_type_typname_nsp_index"
        # (IntegrityError) or "relation already exists" (ProgrammingError).
        for attempt in range(8):
            try:
                Base.metadata.create_all(self.engine, checkfirst=True)
                return
            except (OperationalError, ProgrammingError, IntegrityError) as exc:
                msg = str(exc).lower()
                if ("already exists" in msg or "duplicate key" in msg) and attempt < 7:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise

    def drop_all(self) -> None:
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self.SessionLocal()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def new_session(self) -> Session:
        return self.SessionLocal()
