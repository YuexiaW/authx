"""Session service for AuthX - handles session lifecycle management."""

from typing import Any, Optional

from fastapi import Request

from authx._internal._session import SessionInfo
from authx.types import SessionStoreProtocol


class SessionService:
    """Service responsible for managing authentication sessions.

    Encapsulates all session-related operations that were previously
    inlined in the AuthX main class.
    """

    def __init__(self, session_store: Optional[SessionStoreProtocol] = None) -> None:
        self._session_store = session_store

    @property
    def session_store(self) -> Optional[SessionStoreProtocol]:
        return self._session_store

    def set_session_store(self, store: Optional[SessionStoreProtocol] = None) -> None:
        self._session_store = store

    async def create_session(
        self,
        uid: str,
        request: Optional[Request] = None,
        device_info: Optional[dict[str, Any]] = None,
    ) -> SessionInfo:
        ip_address: Optional[str] = None
        user_agent: Optional[str] = None
        if request is not None:
            if request.client is not None:
                ip_address = request.client.host
            user_agent = request.headers.get("user-agent")

        session = SessionInfo(
            uid=uid,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )

        if self._session_store is not None:
            await self._session_store.create(session)

        return session

    async def list_sessions(self, uid: str) -> list[SessionInfo]:
        if self._session_store is None:
            return []
        return await self._session_store.list_by_user(uid)

    async def revoke_session(self, session_id: str) -> None:
        if self._session_store is not None:
            await self._session_store.delete(session_id)

    async def revoke_all_sessions(self, uid: str) -> None:
        if self._session_store is not None:
            await self._session_store.delete_all_by_user(uid)

    async def get_session(self, session_id: str) -> Optional[SessionInfo]:
        if self._session_store is None:
            return None
        return await self._session_store.get(session_id)