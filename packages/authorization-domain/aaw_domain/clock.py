"""Injectable clock so expiry boundaries are testable."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional


class Clock:
    def now(self) -> datetime:  # pragma: no cover - interface
        raise NotImplementedError

    def now_ts(self) -> int:
        return int(self.now().timestamp())


class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def now_ts(self) -> int:
        return int(time.time())


class FixedClock(Clock):
    def __init__(self, at: Optional[datetime] = None):
        self._at = at or datetime.now(timezone.utc)

    def now(self) -> datetime:
        return self._at

    def set(self, at: datetime) -> None:
        self._at = at

    def advance(self, seconds: int) -> None:
        from datetime import timedelta

        self._at = self._at + timedelta(seconds=seconds)


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are rejected (time zone required)."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a time zone offset")
    return dt


def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
