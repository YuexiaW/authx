"""Tests for rate limiting support."""

import asyncio
from unittest.mock import Mock

import pytest

from authx import AuthX, AuthXConfig, RateLimiter, RateLimitExceeded
from authx._internal._ratelimit import InMemoryBackend, _default_key_func


class TestInMemoryBackend:
    """Tests for the in-memory rate limit backend."""

    @pytest.mark.asyncio
    async def test_increment_first_request(self):
        backend = InMemoryBackend()
        count = await backend.increment("key1", window=60)
        assert count == 1

    @pytest.mark.asyncio
    async def test_increment_multiple_requests(self):
        backend = InMemoryBackend()
        for _i in range(5):
            count = await backend.increment("key1", window=60)
        assert count == 5

    @pytest.mark.asyncio
    async def test_increment_separate_keys(self):
        backend = InMemoryBackend()
        await backend.increment("key1", window=60)
        await backend.increment("key1", window=60)
        count_key2 = await backend.increment("key2", window=60)
        assert count_key2 == 1

    @pytest.mark.asyncio
    async def test_window_expiry(self):
        backend = InMemoryBackend()
        await backend.increment("key1", window=0)
        await asyncio.sleep(0.05)
        count = await backend.increment("key1", window=0)
        assert count == 1

    @pytest.mark.asyncio
    async def test_reset(self):
        backend = InMemoryBackend()
        await backend.increment("key1", window=60)
        await backend.increment("key1", window=60)
        await backend.reset("key1")
        count = await backend.increment("key1", window=60)
        assert count == 1

    @pytest.mark.asyncio
    async def test_reset_nonexistent_key(self):
        backend = InMemoryBackend()
        await backend.reset("nonexistent")

    def test_cleanup(self):
        backend = InMemoryBackend()
        backend._store["old"] = (5, 0.0)
        backend._store["new"] = (1, float("inf"))
        backend._cleanup(window=1)
        assert "old" not in backend._store
        assert "new" in backend._store

    @pytest.mark.asyncio
    async def test_max_entries_evicts_oldest(self):
        backend = InMemoryBackend(max_entries=2)
        await backend.increment("key1", window=60)
        await backend.increment("key2", window=60)
        # key3 should evict the oldest (key1)
        await backend.increment("key3", window=60)
        assert "key1" not in backend._store
        assert "key2" in backend._store
        assert "key3" in backend._store

    @pytest.mark.asyncio
    async def test_max_entries_preserves_current_key(self):
        """The key being incremented is never chosen as the eviction victim."""
        backend = InMemoryBackend(max_entries=1)
        # With max_entries=1, each new key forces eviction of the existing one.
        # The current key being incremented always survives.
        await backend.increment("key1", window=60)
        await backend.increment("key2", window=60)  # evicts key1
        await backend.increment("key1", window=60)  # evicts key2, keeps key1
        assert "key1" in backend._store
        assert "key2" not in backend._store

    @pytest.mark.asyncio
    async def test_max_entries_none_allows_unlimited(self):
        backend = InMemoryBackend(max_entries=None)
        for i in range(1000):
            await backend.increment(f"key{i}", window=60)
        assert len(backend._store) == 1000

    @pytest.mark.asyncio
    async def test_lazy_cleanup_removes_expired_entries(self):
        """After 100 increments with expired windows, stale keys are swept."""
        backend = InMemoryBackend()
        # Insert entries with expired timestamps
        for i in range(50):
            backend._store[f"stale_{i}"] = (1, 0.0)
        backend._store["active"] = (1, float("inf"))

        # Trigger lazy cleanup by running 100 increment ops
        for _ in range(100):
            await backend.increment("trigger", window=1)

        # Stale keys should be gone
        for i in range(50):
            assert f"stale_{i}" not in backend._store
        assert "active" in backend._store


class TestDefaultKeyFunc:
    """Tests for the default key extraction function."""

    def test_with_client(self):
        request = Mock()
        request.client = Mock(host="192.168.1.1")
        assert _default_key_func(request) == "ratelimit:192.168.1.1"

    def test_without_client(self):
        request = Mock()
        request.client = None
        assert _default_key_func(request) == "ratelimit:unknown"


class TestRateLimiter:
    """Tests for the RateLimiter dependency."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        limiter = RateLimiter(max_requests=3, window=60)
        request = Mock()
        request.client = Mock(host="10.0.0.1")
        for _ in range(3):
            await limiter(request)

    @pytest.mark.asyncio
    async def test_raises_on_exceeded(self):
        limiter = RateLimiter(max_requests=2, window=60)
        request = Mock()
        request.client = Mock(host="10.0.0.1")
        await limiter(request)
        await limiter(request)
        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter(request)
        assert exc_info.value.retry_after == 60

    @pytest.mark.asyncio
    async def test_different_clients_independent(self):
        limiter = RateLimiter(max_requests=1, window=60)
        req1 = Mock(client=Mock(host="10.0.0.1"))
        req2 = Mock(client=Mock(host="10.0.0.2"))
        await limiter(req1)
        await limiter(req2)

    @pytest.mark.asyncio
    async def test_custom_key_func(self):
        def by_user_agent(request: Mock) -> str:
            return f"ua:{request.headers.get('user-agent', 'unknown')}"

        limiter = RateLimiter(max_requests=1, window=60, key_func=by_user_agent)
        request = Mock()
        request.headers = {"user-agent": "TestBot"}
        await limiter(request)
        with pytest.raises(RateLimitExceeded):
            await limiter(request)

    @pytest.mark.asyncio
    async def test_custom_backend(self):
        class CountingBackend:
            def __init__(self) -> None:
                self.calls = 0

            async def increment(self, key: str, window: int) -> int:
                self.calls += 1
                return self.calls

            async def reset(self, key: str) -> None:
                self.calls = 0

        backend = CountingBackend()
        limiter = RateLimiter(max_requests=5, window=60, backend=backend)
        request = Mock(client=Mock(host="10.0.0.1"))
        await limiter(request)
        assert backend.calls == 1

    def test_default_values(self):
        limiter = RateLimiter()
        assert limiter.max_requests == 10
        assert limiter.window == 60
        assert isinstance(limiter.backend, InMemoryBackend)


class TestRateLimitExceededException:
    """Tests for the RateLimitExceeded exception."""

    def test_default_message(self):
        exc = RateLimitExceeded(retry_after=30)
        assert exc.retry_after == 30
        assert "30 seconds" in str(exc)

    def test_custom_message(self):
        exc = RateLimitExceeded(retry_after=60, message="Too fast")
        assert str(exc) == "Too fast"
        assert exc.retry_after == 60


class TestAuthXRateLimited:
    """Tests for AuthX.rate_limited() integration."""

    def test_returns_callable(self):
        auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="a]V&F*jk2s$5ghT!qR@pN8xLm3wY+bZ"))
        dep = auth.rate_limited(max_requests=5, window=30)
        assert callable(dep)
