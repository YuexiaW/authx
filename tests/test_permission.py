"""Tests for runtime PermissionProvider integration."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from authx import AuthX, AuthXConfig, InsufficientScopeError
from authx.permission import StaticPermissionProvider


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def permission_app():
    """FastAPI app with a StaticPermissionProvider attached."""
    config = AuthXConfig(
        JWT_SECRET_KEY="perm-secret",
        JWT_TOKEN_LOCATION=["headers"],
    )
    auth = AuthX(config=config)
    auth.set_permission_provider(
        StaticPermissionProvider(
            permissions={
                "alice": ["admin:*", "users:read", "users:write"],
                "bob": ["users:read"],
                "charlie": [],
            },
            roles={
                "alice": ["admin", "moderator"],
                "bob": ["user"],
            },
        )
    )

    app = FastAPI()
    auth.handle_errors(app)

    # Token endpoints
    @app.get("/token/alice")
    def token_alice():
        return {"access_token": auth.create_access_token(uid="alice", scopes=["dummy"])}

    @app.get("/token/bob")
    def token_bob():
        return {"access_token": auth.create_access_token(uid="bob", scopes=["dummy"])}

    @app.get("/token/charlie")
    def token_charlie():
        return {"access_token": auth.create_access_token(uid="charlie", scopes=["dummy"])}

    # Permission-protected endpoints
    @app.get("/perm/admin", dependencies=[Depends(auth.permissions_required("admin:*"))])
    def perm_admin():
        return {"ok": True}

    @app.get("/perm/users-read", dependencies=[Depends(auth.permissions_required("users:read"))])
    def perm_users_read():
        return {"ok": True}

    @app.get("/perm/admin-and-users", dependencies=[Depends(auth.permissions_required("admin:*", "users:read"))])
    def perm_admin_and_users():
        return {"ok": True}

    @app.get("/perm/admin-or-users", dependencies=[Depends(auth.permissions_required("admin:*", "users:read", all_required=False))])
    def perm_admin_or_users():
        return {"ok": True}

    # Role-protected endpoints
    @app.get("/role/admin", dependencies=[Depends(auth.role_required("admin"))])
    def role_admin():
        return {"ok": True}

    @app.get("/role/admin-or-user", dependencies=[Depends(auth.role_required("admin", "user", all_required=False))])
    def role_admin_or_user():
        return {"ok": True}

    return app, auth


@pytest.fixture(scope="function")
def client(permission_app):
    app, _ = permission_app
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _auth_header(client, url):
    """Return Authorization header with a token obtained from the given URL."""
    resp = client.get(url)
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# AuthX — permissions_required
# ---------------------------------------------------------------------------


def test_permissions_required_allows_when_user_has_permission(client):
    """User with 'users:read' can access a route requiring 'users:read'."""
    headers = _auth_header(client, "/token/alice")
    resp = client.get("/perm/users-read", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_permissions_required_denies_when_user_lacks_permission(client):
    """User without 'admin:*' cannot access a route requiring 'admin:*'."""
    headers = _auth_header(client, "/token/bob")
    resp = client.get("/perm/admin", headers=headers)
    assert resp.status_code == 403


def test_permissions_required_denies_when_user_has_empty_permissions(client):
    """User with empty permission list cannot access any protected route."""
    headers = _auth_header(client, "/token/charlie")
    resp = client.get("/perm/users-read", headers=headers)
    assert resp.status_code == 403


def test_permissions_required_and_logic_missing_one(client):
    """AND logic: user with 'users:read' but not 'admin:*' fails combined check."""
    headers = _auth_header(client, "/token/bob")
    resp = client.get("/perm/admin-and-users", headers=headers)
    assert resp.status_code == 403


def test_permissions_required_and_logic_all_present(client):
    """AND logic: user with both permissions passes."""
    headers = _auth_header(client, "/token/alice")
    resp = client.get("/perm/admin-and-users", headers=headers)
    assert resp.status_code == 200


def test_permissions_required_or_logic_one_present(client):
    """OR logic: user with only one of the required permissions passes."""
    headers = _auth_header(client, "/token/bob")
    resp = client.get("/perm/admin-or-users", headers=headers)
    assert resp.status_code == 200


def test_permissions_required_wildcard_match(client):
    """Wildcard 'admin:*' matches 'admin:read', 'admin:users', etc."""
    headers = _auth_header(client, "/token/alice")
    resp = client.get("/perm/admin", headers=headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AuthX — role_required
# ---------------------------------------------------------------------------


def test_role_required_allows_user_with_role(client):
    """User with 'admin' role can access a route requiring 'admin'."""
    headers = _auth_header(client, "/token/alice")
    resp = client.get("/role/admin", headers=headers)
    assert resp.status_code == 200


def test_role_required_denies_user_without_role(client):
    """User without 'admin' role is denied."""
    headers = _auth_header(client, "/token/bob")
    resp = client.get("/role/admin", headers=headers)
    assert resp.status_code == 403


def test_role_required_or_logic(client):
    """OR logic: user with 'user' role passes 'admin or user'."""
    headers = _auth_header(client, "/token/bob")
    resp = client.get("/role/admin-or-user", headers=headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# No provider configured
# ---------------------------------------------------------------------------


def test_permissions_required_raises_without_provider():
    """Using permissions_required without a provider raises RuntimeError."""
    auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="test", JWT_TOKEN_LOCATION=["headers"]))
    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/no-provider", dependencies=[Depends(auth.permissions_required("anything"))])
    def no_provider():
        return {"ok": True}

    client = TestClient(app)
    token = auth.create_access_token(uid="test")
    with pytest.raises(RuntimeError, match="No PermissionProvider configured"):
        client.get("/no-provider", headers={"Authorization": f"Bearer {token}"})


def test_role_required_raises_without_provider():
    """Using role_required without a provider raises RuntimeError."""
    auth = AuthX(config=AuthXConfig(JWT_SECRET_KEY="test", JWT_TOKEN_LOCATION=["headers"]))
    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/no-provider-role", dependencies=[Depends(auth.role_required("admin"))])
    def no_provider_role():
        return {"ok": True}

    client = TestClient(app)
    token = auth.create_access_token(uid="test")
    with pytest.raises(RuntimeError, match="No PermissionProvider configured"):
        client.get("/no-provider-role", headers={"Authorization": f"Bearer {token}"})


# ---------------------------------------------------------------------------
# AuthManager delegation
# ---------------------------------------------------------------------------


def test_manager_permissions_required():
    """AuthManager.permissions_required delegates to the registered AuthX."""
    config = AuthXConfig(JWT_SECRET_KEY="admin-secret", JWT_TOKEN_LOCATION=["headers"])
    from authx import AuthManager

    manager = AuthManager()
    auth = AuthX(config=config, login_type="admin")
    auth.set_permission_provider(
        StaticPermissionProvider(
            permissions={"root": ["admin:*"]},
            roles={"root": ["admin"]},
        )
    )
    manager.register(auth)

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/admin-only", dependencies=[Depends(manager.permissions_required("admin", "admin:*"))])
    def admin_only():
        return {"ok": True}

    client = TestClient(app)
    token = manager.create_access_token("admin", uid="root")
    resp = client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_manager_role_required():
    """AuthManager.role_required delegates to the registered AuthX."""
    from authx import AuthManager

    config = AuthXConfig(JWT_SECRET_KEY="admin-secret", JWT_TOKEN_LOCATION=["headers"])
    manager = AuthManager()
    auth = AuthX(config=config, login_type="admin")
    auth.set_permission_provider(
        StaticPermissionProvider(
            roles={"root": ["admin"]},
        )
    )
    manager.register(auth)

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/role-check", dependencies=[Depends(manager.role_required("admin", "admin"))])
    def role_check():
        return {"ok": True}

    client = TestClient(app)
    token = manager.create_access_token("admin", uid="root")
    resp = client.get("/role-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_manager_set_permission_provider_on_all():
    """Manager.set_permission_provider sets provider on all registered without one."""
    from authx import AuthManager

    config = AuthXConfig(JWT_SECRET_KEY="s", JWT_TOKEN_LOCATION=["headers"])
    manager = AuthManager()
    auth1 = AuthX(config=config, login_type="type1")
    auth2 = AuthX(config=config, login_type="type2")
    manager.register(auth1)
    manager.register(auth2)

    provider = StaticPermissionProvider(
        permissions={"u": ["perm1"]},
    )
    manager.set_permission_provider(provider)

    # Both instances should have the provider now
    assert auth1._permission_handler is not None
    assert auth2._permission_handler is not None


# ---------------------------------------------------------------------------
# StaticPermissionProvider behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_provider_missing_uid_returns_empty():
    """StaticPermissionProvider returns empty lists for unknown uids."""
    provider = StaticPermissionProvider(
        permissions={"known": ["x"]},
        roles={"known": ["y"]},
    )
    perms = await provider.get_permissions(uid="unknown")
    roles = await provider.get_roles(uid="unknown")
    assert perms == []
    assert roles == []


# ---------------------------------------------------------------------------
# JWT_SUPER_ROLE bypass tests
# ---------------------------------------------------------------------------


def test_super_role_bypasses_permissions_required():
    """User with JWT_SUPER_ROLE can access a permissions-protected route."""
    config = AuthXConfig(
        JWT_SECRET_KEY="super-secret",
        JWT_TOKEN_LOCATION=["headers"],
        JWT_SUPER_ROLE="super_admin",
    )
    auth = AuthX(config=config)
    auth.set_permission_provider(
        StaticPermissionProvider(
            permissions={"alice": ["users:read"]},
            roles={"root": ["super_admin"], "alice": ["editor"]},
        )
    )

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/admin", dependencies=[Depends(auth.permissions_required("admin:*"))])
    def admin():
        return {"ok": True}

    client = TestClient(app)

    # root has "super_admin" role → bypasses even without "admin:*" permission
    token = auth.create_access_token(uid="root")
    resp = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    # alice has "users:read" but NOT "admin:*" → denied
    token = auth.create_access_token(uid="alice")
    resp = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_super_role_bypasses_role_required():
    """User with JWT_SUPER_ROLE can access a role-protected route."""
    config = AuthXConfig(
        JWT_SECRET_KEY="super-secret",
        JWT_TOKEN_LOCATION=["headers"],
        JWT_SUPER_ROLE="super_admin",
    )
    auth = AuthX(config=config)
    auth.set_permission_provider(
        StaticPermissionProvider(
            roles={"root": ["super_admin"], "alice": ["editor"]},
        )
    )

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/admin-role", dependencies=[Depends(auth.role_required("admin"))])
    def admin_role():
        return {"ok": True}

    client = TestClient(app)

    # root has "super_admin" → bypasses role check
    token = auth.create_access_token(uid="root")
    resp = client.get("/admin-role", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    # alice has "editor" but NOT "admin" → denied
    token = auth.create_access_token(uid="alice")
    resp = client.get("/admin-role", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_super_role_no_provider_no_bypass():
    """Without a PermissionProvider, JWT_SUPER_ROLE has no effect."""
    config = AuthXConfig(
        JWT_SECRET_KEY="super-secret",
        JWT_TOKEN_LOCATION=["headers"],
        JWT_SUPER_ROLE="super_admin",
    )
    auth = AuthX(config=config)

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/no-provider", dependencies=[Depends(auth.permissions_required("anything"))])
    def no_provider():
        return {"ok": True}

    client = TestClient(app)
    token = auth.create_access_token(uid="root")
    with pytest.raises(RuntimeError, match="No PermissionProvider configured"):
        client.get("/no-provider", headers={"Authorization": f"Bearer {token}"})


def test_super_role_bypass_with_authmanager():
    """AuthManager delegates JWT_SUPER_ROLE bypass correctly."""
    config = AuthXConfig(
        JWT_SECRET_KEY="admin-secret",
        JWT_TOKEN_LOCATION=["headers"],
        JWT_SUPER_ROLE="super_admin",
    )
    from authx import AuthManager

    manager = AuthManager()
    auth = AuthX(config=config, login_type="admin")
    manager.register(auth)

    auth.set_permission_provider(
        StaticPermissionProvider(
            permissions={"user1": ["users:read"]},
            roles={"root": ["super_admin"]},
        )
    )

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/super-only", dependencies=[Depends(manager.permissions_required("admin", "super:*"))])
    def super_only():
        return {"ok": True}

    client = TestClient(app)

    # root has "super_admin" role → bypasses
    token = manager.create_access_token("admin", uid="root")
    resp = client.get("/super-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    # user1 has only "users:read" → denied
    token = manager.create_access_token("admin", uid="user1")
    resp = client.get("/super-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
