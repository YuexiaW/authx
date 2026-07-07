"""
AuthX 全功能演示脚本
=====================
展示 AuthX 框架的所有核心能力，包括：
  - JWT token 创建与验证
  - FastAPI 依赖注入
  - Scope (作用域) 校验
  - Policy Engine (策略引擎)
  - PermissionProvider (运行时权限/角色)
  - Rate Limiting (速率限制)
  - Session 管理
  - AuthManager 多登录类型
  - Cookie 管理 / CSRF 保护
  - 回调钩子 (subject 获取 / token 黑名单)

运行方式:
    pip install "authx[all]" uvicorn
    python demo.py

然后访问 http://localhost:8000/docs 查看 OpenAPI 交互文档。
"""

from __future__ import annotations

import os
import typing
from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.responses import JSONResponse

from authx import AuthX, AuthXConfig, AuthManager
from authx.permission import StaticPermissionProvider
from authx._internal._ratelimit import InMemoryBackend, RateLimiter
from authx._internal._session import InMemorySessionStore
from authx.exceptions import (
    AuthXException,
    InsufficientScopeError,
    MissingTokenError,
)
from authx.policy import PolicyCondition, PolicyContext, PolicyEngine, PolicyRule
from authx.schema import RequestToken, TokenPayload, TokenResponse

# =============================================================================
# 1. 基础配置
# =============================================================================
#
# AuthXConfig 通过 Pydantic BaseSettings 管理所有 JWT / Cookie / CSRF 配置。
# 也可以从环境变量读取（不传参则必须提供环境变量）。

SECRET_KEY = os.getenv("AUTHX_SECRET_KEY", "super-secret-key-change-in-production")

config = AuthXConfig(
    JWT_SECRET_KEY=SECRET_KEY,
    JWT_TOKEN_LOCATION=["headers"],  # 从 Authorization header 读取 token
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=15),
    JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=1),
    JWT_HEADER_TYPE="Bearer",
    # 若启用 Cookie:
    #   JWT_TOKEN_LOCATION=["cookies"],
    #   JWT_COOKIE_CSRF_PROTECT=True,
    #   JWT_ACCESS_COOKIE_NAME="access_token",
)

# =============================================================================
# 2. 创建 AuthX 实例
# =============================================================================
#
# AuthX 是核心类，支持 Generic[T] 泛型——T 为 get_current_subject 的返回类型。

auth = AuthX[dict](config=config)

# =============================================================================
# 3. 回调钩子: Subject 获取 & Token 黑名单
# =============================================================================
#
# 用于 get_current_subject 依赖和 token 即时撤销校验。

# 模拟用户数据库
_fake_users: dict[str, dict] = {
    "alice": {"uid": "alice", "name": "Alice", "role": "admin"},
    "bob": {"uid": "bob", "name": "Bob", "role": "user"},
}
_fake_blocklist: set[str] = set()


@auth.set_callback_get_model_instance
async def get_user(uid: str) -> dict | None:
    """根据 uid 获取用户对象。"""
    return _fake_users.get(uid)


@auth.set_callback_token_blocklist
async def check_blocklist(token: str) -> bool:
    """检查 token 是否已被撤销。"""
    return token in _fake_blocklist


# =============================================================================
# 4. 策略引擎 (Policy Engine)
# =============================================================================
#
# PolicyRule 定义了一条规则: 匹配 action + resource + scope + 自定义条件。
# 支持 AND / OR scope 逻辑、通配符 scope（如 "admin:*"）。

policy_engine = PolicyEngine(
    rules=[
        # 管理员可以执行所有操作 (action="*")
        PolicyRule(
            effect="allow",
            actions=["*"],
            resources=["*"],
            scopes=["admin:*"],
        ),
        # 普通用户只能读取自己的文档
        PolicyRule(
            effect="allow",
            actions=["read"],
            resources=["document"],
            scopes=["user:read"],
            conditions=[
                PolicyCondition(
                    source="subject",
                    key="uid",
                    operator="equals",
                    value="subject_uid",
                ),
            ],
        ),
        # 非工作时间禁止写操作
        PolicyRule(
            effect="deny",
            actions=["write"],
            resources=["*"],
            conditions=[
                PolicyCondition(
                    source="environment",
                    key="hour",
                    operator="gte",
                    value=22,
                ),
            ],
            reason="Write operations are not allowed after 10 PM",
        ),
        PolicyRule(
            effect="deny",
            actions=["write"],
            resources=["*"],
            conditions=[
                PolicyCondition(
                    source="environment",
                    key="hour",
                    operator="lt",
                    value=8,
                ),
            ],
            reason="Write operations are not allowed before 8 AM",
        ),
    ],
)

# =============================================================================
# 5. FastAPI 应用
# =============================================================================

app = FastAPI(title="AuthX Demo")

# 注册 AuthX 异常处理器 —— 将 AuthXException 转为 JSON 响应
auth.handle_errors(app)


@app.exception_handler(InsufficientScopeError)
async def scope_error_handler(
    request: Request, exc: InsufficientScopeError
) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "detail": str(exc),
            "required": exc.required,
            "provided": exc.provided,
        },
    )


# =============================================================================
# 6. 认证路由
# =============================================================================


@app.post("/auth/login", response_model=TokenResponse, summary="登录并获取 token 对")
async def login(username: str = "alice", password: str = ""):
    """用用户名密码登录，返回 access + refresh token 对。"""
    if username not in _fake_users:
        raise HTTPException(401, "Invalid credentials")

    user = _fake_users[username]
    # 根据角色注入 scope
    if user["role"] == "admin":
        scopes = ["admin:*", "admin:users", "admin:settings"]
    else:
        scopes = ["user:read"]

    return auth.create_token_pair(
        uid=username,
        fresh=True,
        data={"role": user["role"]},
        access_scopes=scopes,
    )


@app.post(
    "/auth/refresh", response_model=TokenResponse, summary="用 refresh token 刷新 access token"
)
async def refresh(request: Request):
    """使用 refresh token 换取新的 access token。"""
    refresh_token = await auth.get_token_from_request(
        request, token_type="refresh", optional=False
    )
    payload = auth.verify_token(refresh_token, verify_type=True)

    new_access = auth.create_access_token(
        uid=payload.sub,
        fresh=False,
        data=payload.extra_dict,
        scopes=payload.scopes,
    )
    return TokenResponse(access_token=new_access, refresh_token=refresh_token.token)


@app.post("/auth/logout", summary="登出并撤销 token")
async def logout(
    request: Request,
    token_payload: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
):
    """将当前 token 加入黑名单，之后同一 token 将无法使用。"""
    raw_token = await auth.get_token_from_request(request, optional=False)
    _fake_blocklist.add(raw_token.token)
    return {"msg": "Token revoked"}


# =============================================================================
# 7. 使用 @cached_property 依赖保护路由
# =============================================================================
#
# ACCESS_REQUIRED / REFRESH_REQUIRED / FRESH_REQUIRED / CURRENT_SUBJECT
# 都是 @cached_property，返回 Depends(...)，可直接在 Depends() 中使用。


@app.get("/me", summary="获取当前用户信息 (access token)")
async def read_current_user(
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
    subject: typing.Annotated[dict, auth.CURRENT_SUBJECT],
):
    """需要有效的 access token。"""
    return {
        "token_uid": token.sub,
        "token_scopes": token.scopes,
        "token_type": token.type,
        "token_fresh": token.fresh,
        "token_jti": token.jti,
        "token_expires_in_seconds": token.time_until_expiry.total_seconds(),
        "user": subject,
    }


@app.get("/fresh", summary="需要 fresh token（如修改密码前）")
async def fresh_only(
    token: typing.Annotated[TokenPayload, auth.FRESH_REQUIRED],
):
    """如果 token 不是 fresh 状态 (fresh=False)，则抛出 FreshTokenRequiredError。"""
    return {"msg": "Fresh token confirmed", "fresh": token.fresh}


@app.get("/refresh-test", summary="需要有效的 refresh token")
async def refresh_only(
    token: typing.Annotated[TokenPayload, auth.REFRESH_REQUIRED],
):
    """路由等级使用 refresh token 保护。"""
    return {"msg": "Refresh token is valid", "sub": token.sub}


# =============================================================================
# 8. Scope 校验
# =============================================================================
#
# scopes_required() 支持:
#   - AND: 所有 scope 必须存在 (all_required=True, 默认)
#   - OR:  至少一个 scope 存在  (all_required=False)
#   - 通配符: "admin:*" 可以匹配 "admin:users"


@app.get("/admin/users", summary="需要 admin:users scope (AND 模式)")
async def admin_users(
    token: typing.Annotated[TokenPayload, Depends(auth.scopes_required("admin:users"))],
):
    return {"users": list(_fake_users.keys())}


@app.get("/admin/settings", summary="需要 admin:settings scope (AND 模式)")
async def admin_settings(
    token: typing.Annotated[TokenPayload, Depends(auth.scopes_required("admin:settings"))],
):
    return {"settings": {"theme": "dark", "lang": "en"}}


# =============================================================================
# 9. Policy Engine (策略引擎) 集成
# =============================================================================


@app.post("/policy/check", summary="使用 PolicyEngine 做细粒度权限校验")
async def policy_check(
    request: Request,
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
    action: str = "read",
    resource: str = "document",
):
    """手动调用 PolicyEngine 校验 action + resource 权限。"""
    uid = token.sub
    user = _fake_users.get(uid, {})

    context = PolicyContext(
        login_type="default",
        action=action,
        resource=resource,
        payload=token,
        request=request,
        subject=user,
        resource_attrs={"owner": uid},
        environment={},
    )
    decision = await policy_engine.evaluate(context)
    if not decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={"reason": decision.reason, "rule": str(decision.rule)},
        )
    return {
        "allowed": True,
        "reason": decision.reason,
        "action": action,
        "resource": resource,
    }


# =============================================================================
# 10. 更灵活的 token 获取
# =============================================================================
#
# ACCESS_TOKEN 返回 RequestToken（取不到返回 None），不抛出异常。


@app.get("/token-info", summary="手动提取并检查 token")
async def token_info(
    token: typing.Annotated[RequestToken, auth.ACCESS_TOKEN],
):
    """ACCESS_TOKEN 返回 RequestToken（取不到返回 None），不抛出异常。"""
    if token is None:
        return {"token": None}
    return {
        "token_preview": token.token[:20] + "...",
        "location": token.location,
        "type": token.type,
    }


# =============================================================================
# 11. Cookie 管理
# =============================================================================
#
# 需在 config 中启用 cookie 支持。


@app.post("/auth/cookie-login", summary="Cookie 模式登录")
async def cookie_login(response: Response):
    """将 token 作为 httpOnly cookie 写入。"""
    access_token = auth.create_access_token(uid="alice", fresh=True)
    refresh_token = auth.create_refresh_token(uid="alice")

    auth.set_access_cookies(access_token, response)
    auth.set_refresh_cookies(refresh_token, response)

    return {"msg": "Cookies set"}


@app.post("/auth/cookie-logout", summary="清除认证 cookie")
async def cookie_logout(response: Response):
    """清除 access 和 refresh cookie。"""
    auth.unset_access_cookies(response)
    auth.unset_refresh_cookies(response)
    return {"msg": "Cookies cleared"}


# =============================================================================
# 12. Rate Limiting (速率限制)
# =============================================================================

rate_limiter = RateLimiter(
    max_requests=5,
    window=30,
    backend=InMemoryBackend(max_entries=100),
)


@app.get("/rate-limited", summary="测试速率限制 (5 次 / 30 秒)")
async def rate_limited(
    _: typing.Annotated[None, Depends(rate_limiter)],
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
):
    return {"msg": "Rate limited endpoint OK"}


@app.get("/rate-limited-v2", summary="内置的速率限制 + 认证")
async def rate_limited_v2(
    _: typing.Annotated[
        TokenPayload, Depends(auth.rate_limited(max_requests=3, window=15))
    ],
):
    """3 次 / 15 秒。"""
    return {"msg": "Rate limited + auth OK"}


# =============================================================================
# 13. Session 管理
# =============================================================================

session_store = InMemorySessionStore(session_ttl=timedelta(hours=1))
auth.set_session_store(session_store)


@app.post("/session/create", summary="创建用户会话")
async def create_session(
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
    request: Request,
):
    session = await auth.create_session(
        uid=token.sub,
        request=request,
        device_info={"browser": "Chrome", "platform": "demo"},
    )
    return {"session_id": session.session_id, "uid": session.uid}


@app.get("/session/list", summary="列出用户的所有活跃会话")
async def list_sessions(
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
):
    sessions = await auth.list_sessions(uid=token.sub)
    return [
        {
            "session_id": s.session_id,
            "created_at": s.created_at.isoformat(),
            "last_active": s.last_active.isoformat(),
            "device_info": s.device_info,
        }
        for s in sessions
    ]


@app.post("/session/revoke/{session_id}", summary="撤销指定会话")
async def revoke_session(
    session_id: str,
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
):
    await auth.revoke_session(session_id=session_id)
    return {"msg": f"Session {session_id} revoked"}


@app.post("/session/revoke-all", summary="撤销用户的所有会话")
async def revoke_all_sessions(
    token: typing.Annotated[TokenPayload, auth.ACCESS_REQUIRED],
):
    await auth.revoke_all_sessions(uid=token.sub)
    return {"msg": "All sessions revoked"}


# =============================================================================
# 14. AuthManager — 多登录类型隔离
# =============================================================================
#
# 当系统需要区分不同用户群体（如 "user" / "admin" / "api") 时使用。

admin_config = AuthXConfig(
    JWT_SECRET_KEY="admin-secret-key",
    JWT_TOKEN_LOCATION=["headers"],
    JWT_ACCESS_TOKEN_EXPIRES=typing.cast(typing.Any, 5),
)
api_config = AuthXConfig(
    JWT_SECRET_KEY="api-secret-key",
    JWT_TOKEN_LOCATION=["headers"],
    JWT_ACCESS_TOKEN_EXPIRES=typing.cast(typing.Any, 60),
)

admin_auth = AuthX[dict](config=admin_config, login_type="admin")
api_auth = AuthX[dict](config=api_config, login_type="api")

manager = AuthManager(policy_engine=policy_engine)
manager.register(admin_auth)
manager.register(api_auth)
manager.handle_errors(app)


@app.post("/manager/login/{login_type}", summary="AuthManager: 多类型登录")
async def manager_login(login_type: str):
    """测试用: 用 manager 创建 token。"""
    if login_type == "admin":
        token = manager.create_access_token(
            login_type="admin", uid="admin_user", scopes=["admin:*"]
        )
        return {"access_token": token, "login_type": "admin"}
    elif login_type == "api":
        token = manager.create_access_token(
            login_type="api", uid="api_client", scopes=["api:read"]
        )
        return {"access_token": token, "login_type": "api"}
    raise HTTPException(400, f"Unknown login_type: {login_type}")


@app.get(
    "/manager/admin-only",
    summary="AuthManager: 仅限 admin login_type",
)
async def manager_admin_only(
    token: typing.Annotated[
        TokenPayload, Depends(manager.access_token_required(login_type="admin"))
    ],
):
    """仅接受 login_type="admin" 的 token。"""
    return {
        "msg": "Admin endpoint",
        "login_type": token.login_type,
        "sub": token.sub,
    }


@app.get(
    "/manager/api-only",
    summary="AuthManager: 仅限 api login_type",
)
async def manager_api_only(
    token: typing.Annotated[
        TokenPayload, Depends(manager.access_token_required(login_type="api"))
    ],
):
    """仅接受 login_type="api" 的 token。"""
    return {
        "msg": "API endpoint",
        "login_type": token.login_type,
        "sub": token.sub,
    }


@app.get(
    "/manager/authorize",
    summary="AuthManager: 策略授权",
)
async def manager_authorize(
    token: typing.Annotated[
        TokenPayload,
        Depends(
            manager.policy_required(
                login_type="admin", action="read", resource="document"
            )
        ),
    ],
):
    """组合了 token 校验 + login_type 校验 + policy 校验。"""
    return {"msg": "Policy authorized", "sub": token.sub}


# =============================================================================
# 15. PermissionProvider — 运行时权限/角色校验
# =============================================================================
#
# PermissionProvider 是动态权限/角色的抽象层（类似 Sa-Token 的 StpInterface），
# 每次请求都会查询 provider 获取用户最新的权限/角色，
# 变更即时生效，无需重新签发 token。
#
# StaticPermissionProvider 是内存版简单实现，适合测试与演示。
# 生产环境应实现自己的 PermissionProvider protocol，从数据库查询。

perm_provider = StaticPermissionProvider(
    permissions={
        "alice": ["admin:*", "users:read", "users:write"],
        "bob":   ["users:read"],
    },
    roles={
        "alice": ["admin", "moderator"],
        "bob":   ["user"],
    },
)
auth.set_permission_provider(perm_provider)


@app.get(
    "/perm/admin",
    summary="PermissionProvider: 需要 admin:* 权限",
)
async def perm_admin(
    _: typing.Annotated[
        TokenPayload, Depends(auth.permissions_required("admin:*"))
    ],
):
    """Alice 有 admin:* → 可通过；Bob 没有 → 403。"""
    return {"msg": "Admin permission granted"}


@app.get(
    "/perm/users-read",
    summary="PermissionProvider: 需要 users:read 权限",
)
async def perm_users_read(
    _: typing.Annotated[
        TokenPayload, Depends(auth.permissions_required("users:read"))
    ],
):
    """Alice 和 Bob 都有 users:read → 两人均可通过。"""
    return {"msg": "users:read permission granted"}


@app.get(
    "/perm/admin-with-role",
    summary="PermissionProvider: 需要 admin 角色",
)
async def perm_admin_role(
    _: typing.Annotated[
        TokenPayload, Depends(auth.role_required("admin"))
    ],
):
    """Alice 有 admin 角色 → 可通过；Bob 没有 → 403。"""
    return {"msg": "Admin role granted"}


# =============================================================================
# 16. WebSocket 认证
# =============================================================================

# @app.websocket("/ws")
# async def websocket_endpoint(websocket: WebSocket):
#     """通过 query parameter ?token=... 或 Authorization header 认证。"""
#     await websocket.accept()
#     try:
#         await auth.WS_AUTH_REQUIRED(websocket)
#     except (MissingTokenError, AuthXException) as e:
#         await websocket.send_json({"error": str(e)})
#         await websocket.close()
#         return
#
#     await websocket.send_json({"msg": "Authenticated WebSocket connection"})
#     try:
#         while True:
#             data = await websocket.receive_text()
#             await websocket.send_text(f"Echo: {data}")
#     except Exception:
#         await websocket.close()


# =============================================================================
# 17. 低层级 API: TokenPayload 直接 encode / decode
# =============================================================================
#
# 不需要 FastAPI 请求上下文，可直接操作 token。


@app.get("/token-playground", summary="手动编解码 JWT")
async def token_playground():
    """演示 TokenPayload.encode() 和 TokenPayload.decode() 的用法。"""

    payload = TokenPayload(
        sub="demo_user",
        type="access",
        fresh=True,
        exp=timedelta(hours=1),
        scopes=["demo:read", "demo:write"],
        data={"custom_field": "hello"},  # type: ignore[arg-type]
    )

    # encode → JWT 字符串
    encoded = payload.encode(key=SECRET_KEY, algorithm="HS256")

    # decode → TokenPayload
    decoded = TokenPayload.decode(
        token=encoded, key=SECRET_KEY, algorithms=["HS256"]
    )

    return {
        "original_scopes": payload.scopes,
        "encoded_token": encoded[:30] + "...",
        "decoded_sub": decoded.sub,
        "decoded_type": decoded.type,
        "decoded_fresh": decoded.fresh,
        "decoded_scopes": decoded.scopes,
        "has_scope_demo_read": decoded.has_scopes("demo:read"),
        "jti": decoded.jti,
        "issued_at": decoded.issued_at.isoformat(),
        "time_until_expiry_seconds": decoded.time_until_expiry.total_seconds(),
    }


# =============================================================================
# 18. token_required() 自定义参数
# =============================================================================


@app.get(
    "/custom-token-check",
    summary="用 token_required() 自定义校验参数",
)
async def custom_token_check(
    token: typing.Annotated[
        TokenPayload,
        Depends(
            auth.token_required(
                token_type="access", verify_fresh=True, verify_csrf=None
            )
        ),
    ],
):
    """等价于 FRESH_REQUIRED，但显式展示了参数定制能力。"""
    return {
        "sub": token.sub,
        "type": token.type,
        "fresh": token.fresh,
    }


# =============================================================================
# 19. health check
# =============================================================================


@app.get("/health", summary="健康检查")
async def health():
    return {
        "status": "ok",
        "authx_version": "1.7.1",
        "features": [
            "JWT access/refresh tokens",
            "Scope-based authorization",
            "Policy Engine (RBAC + conditions)",
            "PermissionProvider (runtime permissions/roles)",
            "Rate Limiting",
            "Session Management",
            "AuthManager (multi-login-type)",
            "Cookie support with CSRF protection",
            "WebSocket authentication",
            "Token blocklist/revocation",
            "Subject callback",
        ],
    }


# =============================================================================
# 20. 启动
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    print("  -> Demo API running at http://localhost:8000")
    print("  -> OpenAPI docs at http://localhost:8000/docs")
    print()
    print("Quick test:")
    print('  curl -s -X POST "http://localhost:8000/auth/login?username=alice&password="')
    print()
    uvicorn.run(app, host="0.0.0.0", port=8000)
