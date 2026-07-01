"""Tests for session management support."""

import datetime
from unittest.mock import Mock

import pytest

from authx import AuthX, AuthXConfig, SessionInfo
from authx._internal._session import InMemorySessionStore


class TestSessionInfo:
    """Tests for the SessionInfo model."""

    def test_default_fields(self):
        s = SessionInfo(uid="user1")
        assert s.uid == "user1"
        assert s.session_id is not None
        assert s.is_active is True
        assert s.ip_address is None
        assert s.user_agent is None
        assert s.device_info is None

    def test_custom_fields(self):
        s = SessionInfo(
            uid="user1",
            ip_address="1.2.3.4",
            user_agent="TestBot/1.0",
            device_info={"os": "Linux"},
        )
        assert s.ip_address == "1.2.3.4"
        assert s.user_agent == "TestBot/1.0"
        assert s.device_info == {"os": "Linux"}

    def test_serialization(self):
        s = SessionInfo(uid="user1")
        data = s.model_dump()
        assert "session_id" in data
        assert "uid" in data
        assert "created_at" in data
        assert "last_active" in data
        assert data["is_active"] is True


class TestInMemorySessionStore:
    """Tests for the in-memory session store."""

    @pytest.mark.asyncio
    async def test_create_and_get(self):
        store = InMemorySessionStore()
        s = SessionInfo(uid="user1")
        await store.create(s)
        retrieved = await store.get(s.session_id)
        assert retrieved is not None
        assert retrieved.uid == "user1"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self):
        store = InMemorySessionStore()
        assert await store.get("nonexistent") is None

    @pytest.mark.asyncio
    async def test_update(self):
        store = InMemorySessionStore()
        s = SessionInfo(uid="user1", ip_address="1.1.1.1")
        await store.create(s)
        await store.update(s.session_id, ip_address="2.2.2.2")
        updated = await store.get(s.session_id)
        assert updated is not None
        assert updated.ip_address == "2.2.2.2"

    @pytest.mark.asyncio
    async def test_update_nonexistent(self):
        store = InMemorySessionStore()
        await store.update("nonexistent", ip_address="1.1.1.1")

    @pytest.mark.asyncio
    async def test_delete(self):
        store = InMemorySessionStore()
        s = SessionInfo(uid="user1")
        await store.create(s)
        await store.delete(s.session_id)
        assert await store.get(s.session_id) is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self):
        store = InMemorySessionStore()
        await store.delete("nonexistent")

    @pytest.mark.asyncio
    async def test_list_by_user(self):
        store = InMemorySessionStore()
        await store.create(SessionInfo(uid="user1"))
        await store.create(SessionInfo(uid="user1"))
        await store.create(SessionInfo(uid="user2"))

        user1_sessions = await store.list_by_user("user1")
        assert len(user1_sessions) == 2
        assert all(s.uid == "user1" for s in user1_sessions)

    @pytest.mark.asyncio
    async def test_list_by_user_excludes_inactive(self):
        store = InMemorySessionStore()
        active = SessionInfo(uid="user1")
        inactive = SessionInfo(uid="user1", is_active=False)
        await store.create(active)
        await store.create(inactive)

        sessions = await store.list_by_user("user1")
        assert len(sessions) == 1
        assert sessions[0].session_id == active.session_id

    @pytest.mark.asyncio
    async def test_delete_all_by_user(self):
        store = InMemorySessionStore()
        await store.create(SessionInfo(uid="user1"))
        await store.create(SessionInfo(uid="user1"))
        await store.create(SessionInfo(uid="user2"))

        await store.delete_all_by_user("user1")
        assert len(await store.list_by_user("user1")) == 0
        assert len(await store.list_by_user("user2")) == 1


class TestInMemorySessionStoreTTL:
    """Tests for TTL expiry and max_sessions in InMemorySessionStore."""

    @pytest.mark.asyncio
    async def test_ttl_expired_session_returns_none(self):
        store = InMemorySessionStore(session_ttl=datetime.timedelta(minutes=30))
        s = SessionInfo(uid="user1")
        await store.create(s)

        # Manually set last_active to 31 minutes ago
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=31)
        object.__setattr__(s, "last_active", past)

        assert await store.get(s.session_id) is None

    @pytest.mark.asyncio
    async def test_ttl_active_session_returns_session(self):
        store = InMemorySessionStore(session_ttl=datetime.timedelta(minutes=30))
        s = SessionInfo(uid="user1")
        await store.create(s)

        assert await store.get(s.session_id) is not None

    @pytest.mark.asyncio
    async def test_ttl_expired_session_excluded_from_list_by_user(self):
        store = InMemorySessionStore(session_ttl=datetime.timedelta(minutes=30))
        s = SessionInfo(uid="user1")
        await store.create(s)

        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=31)
        object.__setattr__(s, "last_active", past)

        sessions = await store.list_by_user("user1")
        assert len(sessions) == 0

    @pytest.mark.asyncio
    async def test_no_ttl_never_expires(self):
        store = InMemorySessionStore()
        s = SessionInfo(uid="user1")
        await store.create(s)

        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
        object.__setattr__(s, "last_active", past)

        assert await store.get(s.session_id) is not None

    @pytest.mark.asyncio
    async def test_max_sessions_evicts_oldest(self):
        store = InMemorySessionStore(max_sessions=3)
        s1 = SessionInfo(uid="user1")
        s2 = SessionInfo(uid="user2")
        s3 = SessionInfo(uid="user3")

        await store.create(s1)
        await store.create(s2)
        await store.create(s3)

        # s4 should evict the oldest (s1 if all have same last_active)
        s4 = SessionInfo(uid="user4")
        await store.create(s4)

        assert await store.get(s1.session_id) is None
        assert await store.get(s2.session_id) is not None
        assert await store.get(s3.session_id) is not None
        assert await store.get(s4.session_id) is not None
        assert len(store._sessions) == 3

    @pytest.mark.asyncio
    async def test_max_sessions_zero_is_unlimited(self):
        store = InMemorySessionStore(max_sessions=0)
        for i in range(100):
            await store.create(SessionInfo(uid=f"user{i}"))
        assert len(store._sessions) == 100

    @pytest.mark.asyncio
    async def test_cleanup_removes_expired(self):
        store = InMemorySessionStore(session_ttl=datetime.timedelta(minutes=30))
        s1 = SessionInfo(uid="user1")
        s2 = SessionInfo(uid="user2")
        await store.create(s1)
        await store.create(s2)

        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=31)
        object.__setattr__(s1, "last_active", past)

        removed = await store.cleanup()
        assert removed == 1
        assert await store.get(s2.session_id) is not None


class TestAuthXSessionManagement:
    """Tests for AuthX session methods."""

    def _make_auth(self) -> AuthX:
        auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="a]V&F*jk2s$5ghT!qR@pN8xLm3wY+bZ"))
        auth.set_session_store(InMemorySessionStore())
        return auth

    @pytest.mark.asyncio
    async def test_create_session_basic(self):
        auth = self._make_auth()
        session = await auth.create_session(uid="user1")
        assert session.uid == "user1"
        assert session.session_id is not None

    @pytest.mark.asyncio
    async def test_create_session_with_request(self):
        auth = self._make_auth()
        request = Mock()
        request.client = Mock(host="10.0.0.1")
        request.headers = {"user-agent": "Mozilla/5.0"}

        session = await auth.create_session(uid="user1", request=request)
        assert session.ip_address == "10.0.0.1"
        assert session.user_agent == "Mozilla/5.0"

    @pytest.mark.asyncio
    async def test_create_session_with_device_info(self):
        auth = self._make_auth()
        session = await auth.create_session(uid="user1", device_info={"os": "iOS", "app": "v2.1"})
        assert session.device_info == {"os": "iOS", "app": "v2.1"}

    @pytest.mark.asyncio
    async def test_create_session_no_client(self):
        auth = self._make_auth()
        request = Mock()
        request.client = None
        request.headers = {}

        session = await auth.create_session(uid="user1", request=request)
        assert session.ip_address is None

    @pytest.mark.asyncio
    async def test_list_sessions(self):
        auth = self._make_auth()
        await auth.create_session(uid="user1")
        await auth.create_session(uid="user1")
        await auth.create_session(uid="user2")

        sessions = await auth.list_sessions("user1")
        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_revoke_session(self):
        auth = self._make_auth()
        session = await auth.create_session(uid="user1")
        await auth.revoke_session(session.session_id)

        retrieved = await auth.get_session(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_revoke_all_sessions(self):
        auth = self._make_auth()
        await auth.create_session(uid="user1")
        await auth.create_session(uid="user1")
        await auth.create_session(uid="user2")

        await auth.revoke_all_sessions("user1")
        assert len(await auth.list_sessions("user1")) == 0
        assert len(await auth.list_sessions("user2")) == 1

    @pytest.mark.asyncio
    async def test_get_session(self):
        auth = self._make_auth()
        session = await auth.create_session(uid="user1")
        retrieved = await auth.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == session.session_id

    @pytest.mark.asyncio
    async def test_get_session_nonexistent(self):
        auth = self._make_auth()
        assert await auth.get_session("nonexistent") is None

    @pytest.mark.asyncio
    async def test_no_store_returns_empty(self):
        auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="a]V&F*jk2s$5ghT!qR@pN8xLm3wY+bZ"))
        sessions = await auth.list_sessions("user1")
        assert sessions == []

    @pytest.mark.asyncio
    async def test_no_store_get_returns_none(self):
        auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="a]V&F*jk2s$5ghT!qR@pN8xLm3wY+bZ"))
        assert await auth.get_session("any") is None

    @pytest.mark.asyncio
    async def test_no_store_create_still_returns_session(self):
        auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="a]V&F*jk2s$5ghT!qR@pN8xLm3wY+bZ"))
        session = await auth.create_session(uid="user1")
        assert session.uid == "user1"

    @pytest.mark.asyncio
    async def test_no_store_revoke_does_not_error(self):
        auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="a]V&F*jk2s$5ghT!qR@pN8xLm3wY+bZ"))
        await auth.revoke_session("any")
        await auth.revoke_all_sessions("any")
