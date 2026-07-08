"""Runtime permission/role provider protocol for AuthX.

Similar to Sa-Token's ``StpInterface`` — implement this protocol to provide
dynamic permissions that are checked at runtime on every request, rather
than relying solely on static scopes embedded in the token at creation time.

Typical usage::

    from authx import AuthX, PermissionProvider

    class MyPermissionProvider:
        async def get_permissions(self, uid: str, login_type: str | None = None) -> list[str]:
            # Query your database or external service
            return await db.fetch_permissions(uid)

        async def get_roles(self, uid: str, login_type: str | None = None) -> list[str]:
            return await db.fetch_roles(uid)

    auth = AuthX()
    auth.set_permission_provider(MyPermissionProvider())

    @app.get("/admin/users")
    async def admin_users(
        _=Depends(auth.permissions_required("admin:users")),
    ):
        ...
"""

from collections.abc import Awaitable
from typing import Optional, Protocol, Union


class PermissionProvider(Protocol):
    """Protocol for runtime permission/role retrieval.

    Implement this interface to decouple permission storage from token
   签发.  When attached via ``AuthX.set_permission_provider()`` or
    ``AuthManager.set_permission_provider()``, the
    :meth:`AuthX.permissions_required` and :meth:`AuthX.role_required`
    dependencies query this provider on **every request**, meaning
    permission changes take effect immediately without re-issuing tokens.

    Both methods are async-aware — they accept sync and async callables.
    """

    async def get_permissions(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> list[str]:
        """Return all permission identifiers for a user.

        This is called on every request where ``permissions_required()``
        is used.  Return an empty list when the user has no permissions.

        Args:
            uid: User identifier (typically ``token.sub``).
            login_type: Optional login type for multi-account systems.

        Returns:
            A list of permission strings (e.g. ``["user:read", "admin:*"]``).
        """
        ...

    async def get_roles(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> list[str]:
        """Return all role identifiers for a user.

        This is called on every request where ``role_required()`` is used.
        Return an empty list when the user has no roles.

        Args:
            uid: User identifier (typically ``token.sub``).
            login_type: Optional login type for multi-account systems.

        Returns:
            A list of role strings (e.g. ``["admin", "moderator"]``).
        """
        ...

    async def is_superuser(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> bool:
        """Return True if the user is a superuser and should bypass
        all permission and role checks.

        When this returns ``True``, :meth:`AuthX.permissions_required`
        and :meth:`AuthX.role_required` dependencies grant access without
        checking the user's actual permissions or roles.

        The default implementation returns ``False``, so existing providers
        that do not implement this method continue to work unchanged.

        Args:
            uid: User identifier (typically ``token.sub``).
            login_type: Optional login type for multi-account systems.

        Returns:
            ``True`` if the user should bypass all permission checks.
        """
        return False


class _PermissionProviderHandler:
    """Internal handler that wraps a PermissionProvider and caches its async state.

    Handles the sync/async duality internally so that AuthX does not need
    to branch on provider method signatures.
    """

    def __init__(self, provider: PermissionProvider) -> None:
        self._provider = provider

    async def get_permissions(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> list[str]:
        return await self._provider.get_permissions(uid=uid, login_type=login_type)

    async def get_roles(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> list[str]:
        return await self._provider.get_roles(uid=uid, login_type=login_type)

    async def is_superuser(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> bool:
        return await self._provider.is_superuser(uid=uid, login_type=login_type)


class StaticPermissionProvider:
    """A simple concrete provider backed by in-memory dicts.

    Useful for testing, demos, and simple deployments where permissions
    are configured in code rather than loaded from a database.

    Example::

        provider = StaticPermissionProvider(
            permissions={
                "alice": ["admin:*", "users:read", "users:write"],
                "bob":   ["users:read"],
            },
            roles={
                "alice": ["admin"],
                "bob":   ["user"],
            },
            superusers={"root"},
        )
        auth.set_permission_provider(provider)

    Users listed in ``superusers`` bypass all permission and role checks.
    When a uid is not found in the dict, an empty list is returned.
    """

    def __init__(
        self,
        permissions: Optional[dict[str, list[str]]] = None,
        roles: Optional[dict[str, list[str]]] = None,
        superusers: Optional[set[str]] = None,
    ) -> None:
        self._permissions = permissions or {}
        self._roles = roles or {}
        self._superusers = superusers or set()

    async def get_permissions(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> list[str]:
        return list(self._permissions.get(uid, []))

    async def get_roles(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> list[str]:
        return list(self._roles.get(uid, []))

    async def is_superuser(
        self,
        uid: str,
        login_type: Optional[str] = None,
    ) -> bool:
        return uid in self._superusers
