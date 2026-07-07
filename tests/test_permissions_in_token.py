"""Tests for JWT_PERMISSIONS_IN_TOKEN feature."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from authx import AuthX, AuthXConfig
from authx.permission import StaticPermissionProvider


def make_auth_with_permissions(perms: dict[str, list[str]], roles: dict[str, list[str]], jwt_secret: str = "secret") -> AuthX:
    """Create an AuthX instance with JWT_PERMISSIONS_IN_TOKEN enabled."""
    config = AuthXConfig(
        JWT_SECRET_KEY=jwt_secret,
        JWT_TOKEN_LOCATION=["headers"],
        JWT_PERMISSIONS_IN_TOKEN=True,
    )
    auth = AuthX(config=config)
    provider = StaticPermissionProvider(permissions=perms, roles=roles)
    auth.set_permission_provider(provider)
    return auth


# ------------------------------------------------------------------
# Token creation — permissions/roles embedded in JWT payload
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_create_access_token_embeds_permissions():
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read", "admin:*"]},
        roles={"alice": ["admin"]},
    )
    token = await auth.async_create_access_token("alice")
    payload = auth._decode_token(token)
    assert payload.sub == "alice"
    assert getattr(payload, "permissions", None) == ["users:read", "admin:*"]
    assert getattr(payload, "roles", None) == ["admin"]


@pytest.mark.asyncio
async def test_async_create_access_token_embeds_empty_permissions():
    auth = make_auth_with_permissions(perms={"alice": []}, roles={"alice": []})
    token = await auth.async_create_access_token("alice")
    payload = auth._decode_token(token)
    assert getattr(payload, "permissions", None) is None
    assert getattr(payload, "roles", None) is None


@pytest.mark.asyncio
async def test_async_create_refresh_token_re_fetches_permissions():
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read"]},
        roles={"alice": ["user"]},
    )
    token = await auth.async_create_refresh_token("alice")
    payload = auth._decode_token(token)
    assert getattr(payload, "permissions", None) == ["users:read"]
    assert getattr(payload, "roles", None) == ["user"]


@pytest.mark.asyncio
async def test_sync_create_access_token_does_not_embed():
    """Sync create_access_token should NOT auto-embed (it's sync, can't await provider)."""
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read"]},
        roles={"alice": ["user"]},
    )
    token = auth.create_access_token("alice")
    payload = auth._decode_token(token)
    assert getattr(payload, "permissions", None) is None
    assert getattr(payload, "roles", None) is None


def test_flag_off_does_not_embed_permissions():
    config = AuthXConfig(JWT_SECRET_KEY="secret", JWT_TOKEN_LOCATION=["headers"], JWT_PERMISSIONS_IN_TOKEN=False)
    auth = AuthX(config=config)
    provider = StaticPermissionProvider(permissions={"alice": ["admin:*"]}, roles={"alice": ["admin"]})
    auth.set_permission_provider(provider)
    token = auth.create_access_token("alice")
    payload = auth._decode_token(token)
    assert getattr(payload, "permissions", None) is None


# ------------------------------------------------------------------
# permissions_required / role_required — read from token payload
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_permissions_required_reads_from_token_when_flag_on():
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read", "users:write"]},
        roles={},
    )
    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/perm-check", dependencies=[Depends(auth.permissions_required("users:read"))])
    async def perm_check():
        return {"ok": True}

    client = TestClient(app)
    token = await auth.async_create_access_token("alice")
    resp = client.get("/perm-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_permissions_required_denies_when_missing_from_token():
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read"]},
        roles={},
    )
    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/perm-check", dependencies=[Depends(auth.permissions_required("admin:*"))])
    async def perm_check():
        return {"ok": True}

    client = TestClient(app)
    token = await auth.async_create_access_token("alice")
    resp = client.get("/perm-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_role_required_reads_from_token_when_flag_on():
    auth = make_auth_with_permissions(
        perms={},
        roles={"alice": ["admin"]},
    )
    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/role-check", dependencies=[Depends(auth.role_required("admin"))])
    async def role_check():
        return {"ok": True}

    client = TestClient(app)
    token = await auth.async_create_access_token("alice")
    resp = client.get("/role-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_role_required_denies_when_missing_from_token():
    auth = make_auth_with_permissions(
        perms={},
        roles={"alice": ["user"]},
    )
    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/role-check", dependencies=[Depends(auth.role_required("admin"))])
    async def role_check():
        return {"ok": True}

    client = TestClient(app)
    token = await auth.async_create_access_token("alice")
    resp = client.get("/role-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# ------------------------------------------------------------------
# Old-token fallback — token without permissions claim
# ------------------------------------------------------------------


def test_permissions_required_fallback_when_no_permissions_in_token():
    """Token created before JWT_PERMISSIONS_IN_TOKEN was enabled should get empty perms."""
    config = AuthXConfig(JWT_SECRET_KEY="secret", JWT_TOKEN_LOCATION=["headers"], JWT_PERMISSIONS_IN_TOKEN=True)
    auth = AuthX(config=config)
    # No provider set — token won't have permissions claim
    token = auth.create_access_token("alice")

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/perm-check", dependencies=[Depends(auth.permissions_required("users:read"))])
    async def perm_check():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/perm-check", headers={"Authorization": f"Bearer {token}"})
    # No permissions in token → denied
    assert resp.status_code == 403


# ------------------------------------------------------------------
# Provider still works when flag is off (default)
# ------------------------------------------------------------------


def test_permissions_required_uses_provider_when_flag_off():
    config = AuthXConfig(JWT_SECRET_KEY="secret", JWT_TOKEN_LOCATION=["headers"], JWT_PERMISSIONS_IN_TOKEN=False)
    auth = AuthX(config=config)
    provider = StaticPermissionProvider(permissions={"alice": ["users:read"]}, roles={})
    auth.set_permission_provider(provider)

    app = FastAPI()
    auth.handle_errors(app)

    @app.get("/perm-check", dependencies=[Depends(auth.permissions_required("users:read"))])
    async def perm_check():
        return {"ok": True}

    client = TestClient(app)
    token = auth.create_access_token("alice")
    resp = client.get("/perm-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


# ------------------------------------------------------------------
# Manager delegation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manager_async_create_access_token_embeds_permissions():
    from authx import AuthManager

    manager = AuthManager()
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read"]},
        roles={"alice": ["admin"]},
    )
    auth.login_type = "admin"
    manager.register(auth)

    token = await manager.async_create_access_token("admin", uid="alice")
    payload = auth._decode_token(token)
    assert getattr(payload, "permissions", None) == ["users:read"]
    assert getattr(payload, "roles", None) == ["admin"]


@pytest.mark.asyncio
async def test_manager_permissions_required_from_token():
    from authx import AuthManager

    manager = AuthManager()
    auth = make_auth_with_permissions(
        perms={"alice": ["admin:*"]},
        roles={},
    )
    auth.login_type = "admin"
    manager.register(auth)
    auth.handle_errors(FastAPI())

    app = FastAPI()

    @app.get("/perm-check", dependencies=[Depends(manager.permissions_required("admin", "admin:read"))])
    async def perm_check():
        return {"ok": True}

    client = TestClient(app)
    token = await manager.async_create_access_token("admin", uid="alice")
    resp = client.get("/perm-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


# ------------------------------------------------------------------
# Carry-over via data preserves extra payload fields
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_create_with_data_preserves_extra_fields():
    auth = make_auth_with_permissions(
        perms={"alice": ["users:read"]},
        roles={"alice": ["user"]},
    )
    token = await auth.async_create_access_token("alice", data={"tenant": "acme"})
    payload = auth._decode_token(token)
    # Permissions and roles from provider are embedded
    assert getattr(payload, "permissions", None) == ["users:read"]
    assert getattr(payload, "roles", None) == ["user"]
    # Extra data is preserved
    assert getattr(payload, "tenant", None) == "acme"
