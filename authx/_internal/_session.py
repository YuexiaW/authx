"""Session management utilities for AuthX."""

import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from authx._internal._utils import get_now, get_uuid


class SessionInfo(BaseModel):
    """Represents an active authentication session.

    Usable as a FastAPI ``response_model`` for session listing endpoints.
    """

    session_id: str = Field(default_factory=get_uuid)
    uid: str
    created_at: datetime.datetime = Field(default_factory=get_now)
    last_active: datetime.datetime = Field(default_factory=get_now)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[dict[str, Any]] = None
    is_active: bool = True


class InMemorySessionStore:
    """In-memory session store for development and single-process deployments.

    Supports optional TTL expiry (lazy cleanup on read) and a maximum
    session count to prevent unbounded memory growth.

    For production multi-worker setups, implement the ``SessionStoreProtocol``
    from ``authx.types`` with Redis or a database backend.
    """

    def __init__(
        self,
        session_ttl: Optional[datetime.timedelta] = None,
        max_sessions: int = 0,
    ) -> None:
        """Initialize InMemorySessionStore.

        Args:
            session_ttl: Optional TTL duration. Sessions whose ``last_active``
                timestamp exceeds this duration are considered expired and
                removed lazily on access. ``None`` (default) means no TTL.
            max_sessions: Maximum number of sessions to store. When exceeded,
                the oldest session (by ``last_active``) is evicted on the
                next ``create`` call. ``0`` (default) means unlimited.
        """
        self._sessions: dict[str, SessionInfo] = {}
        self._session_ttl = session_ttl
        self._max_sessions = max_sessions

    def _is_expired(self, session: SessionInfo) -> bool:
        if self._session_ttl is None:
            return False
        return get_now() - session.last_active > self._session_ttl

    def _evict_if_needed(self) -> None:
        if self._max_sessions <= 0:
            return
        if len(self._sessions) < self._max_sessions:
            return
        # Evict the oldest session by last_active
        oldest_sid = min(self._sessions, key=lambda sid: self._sessions[sid].last_active)
        del self._sessions[oldest_sid]

    def _purge_expired(self) -> None:
        if self._session_ttl is None:
            return
        now = get_now()
        to_remove = [
            sid
            for sid, s in self._sessions.items()
            if now - s.last_active > self._session_ttl
        ]
        for sid in to_remove:
            del self._sessions[sid]

    async def create(self, session: SessionInfo) -> None:
        self._purge_expired()
        self._evict_if_needed()
        self._sessions[session.session_id] = session

    async def get(self, session_id: str) -> Optional[SessionInfo]:
        self._purge_expired()
        session = self._sessions.get(session_id)
        if session is not None and self._is_expired(session):
            del self._sessions[session_id]
            return None
        return session

    async def update(self, session_id: str, **kwargs: Any) -> None:
        session = self._sessions.get(session_id)
        if session is not None:
            for key, value in kwargs.items():
                if hasattr(session, key):
                    object.__setattr__(session, key, value)

    async def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def list_by_user(self, uid: str) -> list[SessionInfo]:
        self._purge_expired()
        return [s for s in self._sessions.values() if s.uid == uid and s.is_active and not self._is_expired(s)]

    async def delete_all_by_user(self, uid: str) -> None:
        to_remove = [sid for sid, s in self._sessions.items() if s.uid == uid]
        for sid in to_remove:
            del self._sessions[sid]

    async def cleanup(self) -> int:
        """Remove all expired sessions and return the count removed."""
        count = len(self._sessions)
        self._purge_expired()
        return count - len(self._sessions)
