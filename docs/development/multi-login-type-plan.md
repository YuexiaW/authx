# 多账号体系（StpLogic 风格）改造方案

> 参考 Sa-Token 的 StpLogic 多账号体系架构，对 AuthX 现有的 `AuthManager` + `AuthX` 模式进行增强。
> 
> 分析日期：2026-07-01

---

## 背景

AuthX 已有 `AuthManager` 作为多 `AuthX` 实例的注册表，每个实例通过 `login_type` 隔离。这与 Sa-Token 的 `SaManager` + `StpLogic` 架构**同构**，但在开发者体验上存在差距：

- 没有懒创建模式（必须手动 `register()`）
- 不同 `login_type` 的 token 名称空间不自动隔离
- `login_type` 在装饰器/依赖中透传不够流畅
- 缺少按 `login_type` 路由的中间件支持

---

## 设计目标

1. **最小侵入** — 不改动 AuthX 现有公共 API，只增强 AuthManager
2. **FastAPI 原生** — 不仿 Java 静态 Facade 模式，保持依赖注入风格
3. **渐进可用** — 每个阶段独立可交付，不阻塞现有功能

---

## 第一阶段：AuthManager 懒创建与自动隔离

### 1.1 `get_or_create` — 懒创建模式

```python
class AuthManager:
    # 现有 register / get 不变，新增：

    def get_or_create(
        self,
        login_type: str,
        config: Optional[AuthXConfig] = None,
        **auth_kwargs: Any,
    ) -> AuthX[Any]:
        """获取或创建指定 login_type 的 AuthX 实例。

        类似 SaManager.getStpLogic(type, isCreate=true) 的懒创建模式。
        首次调用时自动创建一个默认配置的 AuthX 实例。
        """
        try:
            return self.get(login_type)
        except BadConfigurationError:
            auth = AuthX(config=config or AuthXConfig(), **auth_kwargs)
            auth.login_type = login_type
            self.register(auth)
            return auth
```

**涉及文件：**
- `authx/manager.py` — 新增 `get_or_create` 方法

### 1.2 自动 Token 名称隔离

当前问题：两个 `AuthX` 实例使用相同配置时，token 会放在同名的 cookie/header 中，造成冲突。

```python
class AuthXConfig:
    # 新增：自动隔离开关，默认关闭（向后兼容）
    AUTO_ISOLATE_BY_LOGIN_TYPE: bool = False
```

当启用时，`AuthX.__init__` 或 `AuthManager.register` 自动将 `login_type` 注入 token 名称后缀：

```python
# 伪代码逻辑
if config.AUTO_ISOLATE_BY_LOGIN_TYPE and login_type:
    config.JWT_HEADER_NAME = f"x-auth-{login_type}"
    config.JWT_COOKIE_NAME = f"{login_type}_token"
```

**涉及文件：**
- `authx/config.py` — 新增 `AUTO_ISOLATE_BY_LOGIN_TYPE` 配置项
- `authx/manager.py` — `register()` 中执行自动隔离逻辑

### 1.3 影响范围

| 项目 | 说明 |
|------|------|
| 向后兼容 | ✅ 全部可选特性，默认关闭 |
| 测试新增 | `test_manager_lazy.py` 或扩充现有 `test_manager.py` |
| 文档更新 | 更新 `AuthManager` 章节 |

---

## 第二阶段：login_type 透传与装饰器增强

### 2.1 AuthManager 直接暴露 `token_required` / `scopes_required`

当前用法：
```python
auth = manager.get("admin")
Depends(auth.token_required())
```

期望用法：
```python
Depends(manager.token_required(login_type="admin"))
```

当前 `AuthManager.token_required(login_type, ...)` 已经存在此签名，但需要验证以下是否到位：

```python
# manager.py 现有代码（确认并补齐）
def token_required(
    self,
    login_type: str,
    type: str = "access",
    verify_type: bool = True,
    verify_fresh: bool = False,
    verify_csrf: Optional[bool] = None,
    locations: Optional[TokenLocations] = None,
) -> Callable[[Request], Awaitable[TokenPayload]]:
    auth = self.get(login_type)
    return auth.token_required(
        type=type,
        verify_type=verify_type,
        verify_fresh=verify_fresh,
        verify_csrf=verify_csrf,
        locations=locations,
    )
```

**需要补齐的缺失方法：**
- `AuthManager.scopes_required(login_type, *scopes, ...)` — 当前不存在
- `AuthManager.fresh_token_required(login_type)` — 当前不存在
- `AuthManager.access_token_required(login_type)` — 当前不存在
- `AuthManager.refresh_token_required(login_type)` — 当前不存在
- `AuthManager.policy_required(login_type, action, resource, ...)` — 已存在

### 2.2 FastAPI 装饰器风格封装

```python
# 可选：提供装饰器风格的重载
manager = AuthManager()

@manager.login_required(login_type="admin")
@app.get("/admin/dashboard")
async def admin_dashboard(payload: TokenPayload = Depends()):
    ...
```

实际上这只是一个返回 `Depends(...)` 的工厂函数，与 FastAPI 风格完全兼容。

**涉及文件：**
- `authx/manager.py` — 补齐缺失的依赖工厂方法

### 2.3 影响范围

| 项目 | 说明 |
|------|------|
| 向后兼容 | ✅ 新增方法，不影响现有 |
| 测试新增 | 对应每个新增方法的测试 |
| 文档更新 | AuthManager API 参考 |

---

## 第三阶段：按 login_type 路由中间件（远期）

### 3.1 请求级 login_type 自动识别

```python
class AuthManager:
    def request_middleware(
        self,
        login_type_resolver: Optional[Callable[[Request], Optional[str]]] = None,
    ) -> Callable:
        """中间件：根据请求自动识别 login_type 并注入 request.state。"""
```

当请求进入时，通过自定义 resolver 函数（例如检查路径前缀 `/admin/*` → `"admin"`）自动选择对应的 `AuthX` 实例做鉴权。

### 3.2 多账号路由守卫

```python
router_admin = APIRouter(
    prefix="/admin",
    dependencies=[Depends(manager.token_required(login_type="admin"))],
)
router_user = APIRouter(
    prefix="/api",
    dependencies=[Depends(manager.access_token_required(login_type="user"))],
)
```

这实际上在第二阶段补齐后就能做到——不需要额外的中间件支持。

### 3.3 影响范围

| 项目 | 说明 |
|------|------|
| 优先级 | 低于前两阶段 |
| 向后兼容 | ✅ |
| 测试 | 中间件集成测试 |

---

## 实施路线图

```
Phase 1 ──────────────► Phase 2 ──────────────► Phase 3
                        │
  AuthManager           │  AuthManager 补齐     按 login_type 路由
  懒创建                │  依赖工厂方法           中间件
  Token 自动隔离         │  login_type 透传       请求级自动识别
                        │
◄──── 几天 ──────────► ◄──── 几天 ──────────► ◄──── 可选 ────►
```

---

## 不纳入范围

以下明确不在此方案中：

1. **静态 Facade 模式**（`StpUtil` 风格）— 与 FastAPI 依赖注入文化冲突，不做
2. **继承式 StpLogic 子类**（`StpLogicJwtForSimple` 风格）— Python 偏好组合，当前服务组合模式更优
3. **注解式鉴权**（`@SaCheckPermission` 风格）— Python 无原生注解，FastAPI 的 `Depends` 已是等价方案
4. **事件监听器**（`SaTokenEventCenter` 风格）— 与当前回调系统重复，暂不引入

---

## 参考

- [Sa-Token 多账号认证文档](https://sa-token.cc/doc.html#/fun/multi-account)
- AuthX 现有设计缺陷清单：`docs/framework-design-flaws.md`
