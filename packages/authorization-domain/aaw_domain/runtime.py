"""Shared process runtime: database, dev key store, clock, fault flags."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from sqlalchemy.orm import Session

from aaw_signer import DevKeyStore

from .clock import Clock, SystemClock
from .db import Database
from .trust import TrustStore


class Runtime:
    def __init__(self, database_url: Optional[str] = None, keys_dir: Optional[str] = None, clock: Optional[Clock] = None):
        self.db = Database(database_url or os.environ.get("DATABASE_URL", "sqlite:///./aaw.db"))
        kd = keys_dir if keys_dir is not None else os.environ.get("AAW_KEYS_DIR", ".keys")
        self.keys = DevKeyStore(None if kd in ("", "memory") else kd)
        self.clock = clock or SystemClock()
        self.faults: Dict[str, Any] = {}  # demo failure-injection flags (process local)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.db.session() as s:
            yield s

    def trust(self, session: Session) -> TrustStore:
        return TrustStore(session, self.clock)

    def now(self) -> int:
        return self.clock.now_ts()
