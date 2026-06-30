# AuthXException 的 login_type 属性

`AuthXException` 及其所有子类现在支持 `login_type` 属性，用于标识引发该异常的 `AuthX` 实例的登录类型。这一特性使得在有多套认证体系（如管理员和普通用户使用不同的 `AuthX` 实例）的场景下，异常处理器能够区分异常来源并做出差异化响应。

## 概述

当项目中使用多个 `AuthX` 实例时（通常通过 `AuthManager` 管理），每个实例都有一个唯一的 `login_type`：

```python
from authx import AuthX, AuthXConfig

admin_auth = AuthX(
    config=AuthXConfig(JWT_SECRET_KEY="admin-secret"),
    login_type="admin",
)

user_auth = AuthX(
    config=AuthXConfig(JWT_SECRET_KEY="user-secret"),
    login_type="user",
)
```

之前，从这些实例抛出的异常（如 `MissingTokenError`、`JWTDecodeError`、`RevokedTokenError` 等）**没有携带** `login_type`，导致全局异常处理器无法区分异常来自哪个认证体系。

现在所有经过 `AuthX` 或 `AuthManager` 抛出的异常都会自动携带对应的 `login_type`。

## 用法示例

### 1. 全局异常处理器中区分 login_type

```python
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from authx import AuthXException

app = FastAPI()

@app.exception_handler(AuthXException)
async def authx_exception_handler(request, exc: AuthXException):
    if exc.login_type == "admin":
        return JSONResponse(
            {"error": "管理员认证失败", "code": "ADMIN_AUTH_FAILED"},
            status_code=401,
        )
    elif exc.login_type == "user":
        return JSONResponse(
            {"error": "用户认证失败", "code": "USER_AUTH_FAILED"},
            status_code=401,
        )
    # fallback
    return JSONResponse(
        {"error": "认证失败"},
        status_code=401,
    )
```

### 2. 结合 AuthManager 使用

`AuthManager` 管理多个 `AuthX` 实例，异常中的 `login_type` 会自动填入对应的登录类型：

```python
from authx import AuthManager

manager = AuthManager()
manager.register(admin_auth)
manager.register(user_auth)

# 当 manager.decode_token(login_type="admin", ...) 抛出异常时，
# exc.login_type == "admin"
```

### 3. 自定义异常处理器中检查 login_type

```python
@app.exception_handler(RevokedTokenError)
async def revoked_token_handler(request, exc: RevokedTokenError):
    if exc.login_type == "admin":
        # 管理员 token 被撤销 → 可能需要通知安全团队
        await notify_security_team(request)
        return JSONResponse({"error": "管理员会话已过期"}, status_code=401)

    # 普通用户 → 引导重新登录
    return JSONResponse({"error": "会话已过期，请重新登录"}, status_code=401)
```

### 4. 中间件中统一记录认证失败

```python
import logging

logger = logging.getLogger("auth")

@app.middleware("http")
async def log_auth_failures(request, call_next):
    try:
        return await call_next(request)
    except AuthXException as exc:
        logger.warning(
            "认证失败 | login_type=%s | path=%s | error=%s",
            exc.login_type,
            request.url.path,
            str(exc),
        )
        raise
```

## 传播链路

`login_type` 在以下链路中自动传播：

```
token.verify() → JWTDecodeError (login_type=None)
  → AuthX.verify_token() → 注入 login_type=self.login_type
    → AuthX._auth_required() → 异常已携带 login_type
      → AuthManager.decode_token() → 异常已携带 login_type
```

- `AuthX.verify_token()` 和 `AuthX._decode_token()` 使用外层 `except AuthXException` 拦截底层异常，注入 `self.login_type`。
- `AuthX._auth_required()`、WebSocket handler、`scopes_required()` 等直接构造异常时显式传入 `login_type=self.login_type`。
- `AuthManager` 的 `decode_token()`、`_verify_login_type()`、`authorize()` 方法同理。

## 涉及的异常类

所有 `AuthXException` 的子类均支持 `login_type`：

| 异常类 | 说明 |
|---|---|
| `MissingTokenError` | 缺少 token |
| `MissingCSRFTokenError` | 缺少 CSRF token |
| `JWTDecodeError` | Token 解码失败 |
| `TokenExpiredError` | Token 已过期 |
| `TokenInvalidSignatureError` | 签名无效 |
| `TokenInvalidAudienceError` | audience 无效 |
| `TokenInvalidIssuerError` | issuer 无效 |
| `RevokedTokenError` | Token 已被撤销 |
| `FreshTokenRequiredError` | 需要 fresh token |
| `AccessTokenRequiredError` | 需要 access token |
| `RefreshTokenRequiredError` | 需要 refresh token |
| `LoginTypeMismatchError` | login_type 不匹配（含 `expected_type` / `actual_type`） |
| `InsufficientScopeError` | 权限不足（含 `required` / `provided` scopes） |
| `PolicyDeniedError` | 策略拒绝（含 `reason`） |
| `RateLimitExceeded` | 限流（含 `retry_after`） |
| `CSRFError` | CSRF 校验失败 |
| `BadConfigurationError` | 配置错误 |
| 等 | ... |

## 注意事项

- 如果 `login_type` 未被设置（例如直接从 `schema.py` 或 `token.py` 手动构造异常抛出），其值默认为 `None`。
- `login_type` 只在通过 `AuthX` 实例或 `AuthManager` 的方法调用时自动填充。直接 `raise MissingTokenError("msg")` 不会自动获得 `login_type`。
