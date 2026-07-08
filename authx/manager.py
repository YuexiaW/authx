"""AuthManager for multiple isolated AuthX contexts."""

import contextlib
import inspect
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from typing import Any, Optional

from fastapi import Depends, Request, Response
from fastapi.security import HTTPBearer

from authx._internal._error import _ErrorHandler
from authx.config import AuthXConfig
from authx.exceptions import (
    AuthXException,
    BadConfigurationError,
    JWTDecodeError,
    LoginTypeMismatchError,
    PolicyDeniedError,
    RevokedTokenError,
)
from authx.main import _OPENAPI_BEARER_DESCRIPTION, AuthX, _noop_openapi_security
from authx.permission import PermissionProvider
from authx.policy import (
    PolicyContext,
    PolicyEngine,
    PolicyEvaluator,
    PolicyRule,
    build_policy_environment,
    default_subject_from_payload,
)
from authx.schema import RequestToken, TokenPayload, TokenResponse
from authx.types import DateTimeExpression, StringOrSequence, TokenLocations


class AuthManager(_ErrorHandler):
    """Manage multiple isolated AuthX instances by login type."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        policy_rules: Optional[Sequence[PolicyRule]] = None,
    ) -> None:
        """Initialize AuthManager.

        Args:
            policy_engine: Optional policy engine instance.
            policy_rules: Optional rules used when creating the default policy engine.
        """
        self._auth_by_type: dict[str, AuthX[Any]] = {}
        self.policy_engine = policy_engine or PolicyEngine(rules=policy_rules)

    @property
    def login_types(self) -> tuple[str, ...]:
        """Return registered login types."""
        return tuple(self._auth_by_type)

    def register(self, auth: AuthX[Any]) -> None:
        """Register an AuthX instance with a unique login type."""
        if auth.login_type is None:
            raise BadConfigurationError("AuthX instances registered with AuthManager require a login_type")
        if auth.login_type in self._auth_by_type:
            raise BadConfigurationError(f"AuthX login_type '{auth.login_type}' is already registered")
        self._auth_by_type[auth.login_type] = auth

    def get(self, login_type: str) -> AuthX[Any]:
        """Return the AuthX instance for a login type."""
        try:
            return self._auth_by_type[login_type]
        except KeyError as e:
            raise BadConfigurationError(f"Unknown login_type '{login_type}'") from e

    def get_or_create(
        self,
        login_type: str,
        config: Optional[AuthXConfig] = None,
        **auth_kwargs: Any,
    ) -> AuthX[Any]:
        """Get or create an AuthX instance for the given login_type.

        Lazily creates a new AuthX (with an optional custom config) if one
        hasn't been registered yet — similar to SaManager.getStpLogic(type, isCreate=true).

        Args:
            login_type: The login type identifier.
            config: Optional config to use when creating a new instance.
                    Defaults to ``AuthXConfig()`` when omitted.
            **auth_kwargs: Additional keyword arguments forwarded to the
                           :class:`AuthX` constructor (e.g. ``model``,
                           ``model_callback``, ``token_callback``).

        Returns:
            The existing or newly created :class:`AuthX` instance.
        """
        try:
            return self.get(login_type)
        except BadConfigurationError:
            auth = AuthX(
                config=config or AuthXConfig(),
                login_type=login_type,
                **auth_kwargs,
            )
            self.register(auth)
            return auth

    def add_policy_rule(self, rule: PolicyRule) -> None:
        """Register a policy rule."""
        self.policy_engine.add_rule(rule)

    def add_policy_evaluator(self, evaluator: PolicyEvaluator) -> None:
        """Register a global policy evaluator."""
        self.policy_engine.add_evaluator(evaluator)

    def create_access_token(
        self,
        login_type: str,
        uid: str,
        fresh: bool = False,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Create an access token for a registered login type."""
        auth = self.get(login_type)
        return auth.create_access_token(uid, fresh, headers, expiry, data, audience, scopes, *args, **kwargs)

    async def async_create_access_token(
        self,
        login_type: str,
        uid: str,
        fresh: bool = False,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Async variant of :meth:`create_access_token` for a registered login type.

        Currently delegates to the sync implementation. This async surface
        exists so that subclasses or future versions can perform async work
        without breaking callers that already ``await`` the method.
        """
        auth = self.get(login_type)
        return await auth.async_create_access_token(uid, fresh, headers, expiry, data, audience, scopes, *args, **kwargs)

    def create_refresh_token(
        self,
        login_type: str,
        uid: str,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Create a refresh token for a registered login type."""
        auth = self.get(login_type)
        return auth.create_refresh_token(uid, headers, expiry, data, audience, scopes, *args, **kwargs)

    async def async_create_refresh_token(
        self,
        login_type: str,
        uid: str,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Async variant of :meth:`create_refresh_token` for a registered login type.

        Currently delegates to the sync implementation. This async surface
        exists so that subclasses or future versions can perform async work
        without breaking callers that already ``await`` the method.
        """
        auth = self.get(login_type)
        return await auth.async_create_refresh_token(uid, headers, expiry, data, audience, scopes, *args, **kwargs)

    def create_token_pair(
        self,
        login_type: str,
        uid: str,
        fresh: bool = False,
        headers: Optional[dict[str, Any]] = None,
        access_expiry: Optional[DateTimeExpression] = None,
        refresh_expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        access_scopes: Optional[list[str]] = None,
        refresh_scopes: Optional[list[str]] = None,
    ) -> TokenResponse:
        """Create access and refresh tokens for a registered login type."""
        return self.get(login_type).create_token_pair(
            uid=uid,
            fresh=fresh,
            headers=headers,
            access_expiry=access_expiry,
            refresh_expiry=refresh_expiry,
            data=data,
            audience=audience,
            access_scopes=access_scopes,
            refresh_scopes=refresh_scopes,
        )

    def _build_openapi_params(
        self,
        login_type: str,
        token_type: str = "access",
        locations: Optional[TokenLocations] = None,
    ) -> dict[str, inspect.Parameter]:
        """Build OpenAPI signature params for enabled token locations only.

        Delegates to the registered ``AuthX`` instance for the given login
        type.  Falls back to a bare HTTPBearer scheme when the login type
        hasn't been registered yet (``BadConfigurationError``).
        """
        try:
            return self.get(login_type)._build_openapi_params(token_type=token_type, locations=locations)
        except BadConfigurationError:
            dep = Depends(HTTPBearer(
                scheme_name="AuthXBearer",
                bearerFormat="JWT",
                description=_OPENAPI_BEARER_DESCRIPTION,
                auto_error=False,
            ))
            return {
                "_authx_openapi_header": inspect.Parameter(
                    "_authx_openapi_header", inspect.Parameter.KEYWORD_ONLY,
                    default=dep, annotation=Any,
                ),
            }

    def token_required(
        self,
        login_type: str,
        token_type: str = "access",
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
        token_name: Optional[str] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory requiring a token for a specific login type."""
        openapi_params = self._build_openapi_params(
            login_type=login_type,
            token_type=token_type,
            locations=locations,
        )

        async def _auth_required(
            request: Request,
            **extra: Any,
        ) -> TokenPayload:
            self.ensure_request_exception_handlers(request)
            return await self._auth_required(
                login_type=login_type,
                request=request,
                token_type=token_type,
                verify_type=verify_type,
                verify_fresh=verify_fresh,
                verify_csrf=verify_csrf,
                locations=locations,
                token_name=token_name,
            )

        # Inject signature so FastAPI discovers Depends only for active locations
        sig_params = [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            *openapi_params.values(),
        ]
        _auth_required.__signature__ = inspect.Signature(sig_params)
        return _auth_required

    def _openapi_security_dependencies(
        self,
        login_type: str,
        token_type: str = "access",
        locations: Optional[TokenLocations] = None,
    ) -> tuple[Callable[..., Any], Callable[..., Any], Callable[..., Any]]:
        try:
            return self.get(login_type)._openapi_security_dependencies(token_type=token_type, locations=locations)
        except BadConfigurationError:
            return (
                HTTPBearer(
                    scheme_name="AuthXBearer",
                    bearerFormat="JWT",
                    description=_OPENAPI_BEARER_DESCRIPTION,
                    auto_error=False,
                ),
                _noop_openapi_security,
                _noop_openapi_security,
            )

    def access_token_required(
        self,
        login_type: str,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
        token_name: Optional[str] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory requiring an access token for a login type.

        Args:
            login_type: The registered login type to authenticate against.
            verify_fresh: Require token freshness. Defaults to False.
            verify_csrf: Apply CSRF verification. Defaults to the config value.
            locations: Token locations to search (e.g. ``["headers"]``,
                       ``["cookies"]``, ``["query"]``, ``["json"]``).
                       Defaults to the AuthX instance's configured locations.
            token_name: Override the token key name for the active location.
        """
        return self.token_required(
            login_type=login_type,
            token_type="access",
            verify_type=True,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
            locations=locations,
            token_name=token_name,
        )

    def refresh_token_required(
        self,
        login_type: str,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
        token_name: Optional[str] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory requiring a refresh token for a login type.

        Note:
            Refresh tokens do not carry a ``fresh`` claim, so unlike
            :meth:`access_token_required` there is no ``verify_fresh`` parameter.

        Args:
            login_type: The registered login type to authenticate against.
            verify_csrf: Apply CSRF verification. Defaults to the config value.
            locations: Token locations to search (e.g. ``["headers"]``,
                       ``["cookies"]``, ``["query"]``, ``["json"]``).
                       Defaults to the AuthX instance's configured locations.
            token_name: Override the token key name for the active location.
        """
        return self.token_required(
            login_type=login_type,
            token_type="refresh",
            verify_type=True,
            verify_csrf=verify_csrf,
            locations=locations,
            token_name=token_name,
        )

    def fresh_token_required(
        self,
        login_type: str,
        verify_fresh: bool = True,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
        token_name: Optional[str] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory requiring a fresh access token for a login type.

        Args:
            login_type: The registered login type to authenticate against.
            verify_fresh: Require token freshness. Defaults to True.
            verify_csrf: Apply CSRF verification. Defaults to the config value.
            locations: Token locations to search (e.g. ``["headers"]``,
                       ``["cookies"]``, ``["query"]``, ``["json"]``).
                       Defaults to the AuthX instance's configured locations.
            token_name: Override the token key name for the active location.
        """
        return self.token_required(
            login_type=login_type,
            token_type="access",
            verify_type=True,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
            locations=locations,
            token_name=token_name,
        )

    def scopes_required(
        self,
        login_type: str,
        *scopes: str,
        all_required: bool = True,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory that checks token scopes for a login type.

        Delegates to the registered :class:`AuthX` instance's
        :meth:`~AuthX.scopes_required`.

        Unlike :meth:`permissions_required` which queries the runtime
        :class:`PermissionProvider`, this validates scopes **embedded in the
        JWT token** at creation time.

        Args:
            login_type: The registered login type to authenticate against.
            *scopes: Variable number of scope strings required.
            all_required: If True (default), ALL scopes must be present (AND logic).
                         If False, at least ONE scope must be present (OR logic).
            verify_type: Apply token type verification. Defaults to True.
            verify_fresh: Require token freshness. Defaults to False.
            verify_csrf: Enable CSRF verification. Defaults to None (uses config).
            locations: Locations to retrieve token from. Defaults to None.

        Returns:
            A FastAPI dependency callable.
        """
        auth = self.get(login_type)
        return auth.scopes_required(
            *scopes,
            all_required=all_required,
            verify_type=verify_type,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
            locations=locations,
        )

    async def _auth_required(
        self,
        login_type: str,
        request: Request,
        token_type: str = "access",
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
        token_name: Optional[str] = None,
    ) -> TokenPayload:
        auth = self.get(login_type)
        try:
            payload = await auth._auth_required(
                request=request,
                token_type=token_type,
                verify_type=verify_type,
                verify_fresh=verify_fresh,
                verify_csrf=verify_csrf,
                locations=locations,
                token_name=token_name,
            )
        except JWTDecodeError:
            mismatch = await self._decode_mismatched_login_type(
                expected_login_type=login_type,
                request=request,
                token_type=token_type,
                locations=locations,
                token_name=token_name,
            )
            if mismatch is not None:
                raise LoginTypeMismatchError(
                    expected_type=login_type, actual_type=mismatch, login_type=login_type
                ) from None
            raise

        self._verify_login_type(payload, login_type)
        return payload

    async def _decode_mismatched_login_type(
        self,
        expected_login_type: str,
        request: Request,
        token_type: str,
        locations: Optional[TokenLocations],
        token_name: Optional[str] = None,
    ) -> Optional[str]:
        expected_auth = self.get(expected_login_type)
        request_token = await expected_auth.get_token_from_request(
            request=request,
            token_type="refresh" if token_type == "refresh" else "access",
            optional=False,
            locations=locations,
            token_name=token_name,
        )
        for registered_type, auth in self._auth_by_type.items():
            if registered_type == expected_login_type:
                continue
            payload = self._try_verify_with_auth(auth, request_token)
            if payload is not None:
                return self._payload_login_type(payload)
        return None

    def _try_verify_with_auth(self, auth: AuthX[Any], request_token: RequestToken) -> Optional[TokenPayload]:
        try:
            return auth.verify_token(request_token, verify_csrf=False)
        except (JWTDecodeError, RevokedTokenError):
            return None

    def _verify_login_type(self, payload: TokenPayload, expected_login_type: str) -> None:
        actual_login_type = self._payload_login_type(payload)
        if actual_login_type != expected_login_type:
            raise LoginTypeMismatchError(
                expected_type=expected_login_type,
                actual_type=actual_login_type,
                login_type=expected_login_type,
            )

    def _payload_login_type(self, payload: TokenPayload) -> Optional[str]:
        login_type = payload.login_type
        return str(login_type) if login_type is not None else None

    async def authorize(
        self,
        login_type: str,
        action: str,
        resource: str,
        *,
        payload: Optional[TokenPayload] = None,
        request: Optional[Request] = None,
        subject: Any = None,
        resource_attrs: Any = None,
        env: Optional[Mapping[str, Any]] = None,
    ) -> TokenPayload:
        """Authorize a token payload against the policy engine."""
        if payload is None:
            if request is None:
                raise PolicyDeniedError(
                    "A request or token payload is required for policy authorization",
                    login_type=login_type,
                )
            payload = await self._auth_required(login_type=login_type, request=request)
        else:
            self._verify_login_type(payload, login_type)

        context = PolicyContext(
            login_type=login_type,
            action=action,
            resource=resource,
            payload=payload,
            request=request,
            subject=subject if subject is not None else default_subject_from_payload(payload),
            resource_attrs=resource_attrs or {},
            environment=build_policy_environment(request=request, environment=env),
        )
        decision = await self.policy_engine.evaluate(context)
        if not decision.allowed:
            raise PolicyDeniedError(decision.reason, login_type=login_type)
        return payload

    def policy_required(
        self,
        login_type: str,
        action: str,
        resource: str,
        *,
        subject: Any = None,
        resource_attrs: Any = None,
        env: Optional[Mapping[str, Any]] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory requiring policy authorization."""
        openapi_params = self._build_openapi_params(login_type=login_type)

        async def _policy_required(
            request: Request,
            **extra: Any,
        ) -> TokenPayload:
            self.ensure_request_exception_handlers(request)
            return await self.authorize(
                login_type=login_type,
                action=action,
                resource=resource,
                request=request,
                subject=subject,
                resource_attrs=resource_attrs,
                env=env,
            )

        # Inject signature so FastAPI discovers Depends only for active locations
        sig_params = [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            *openapi_params.values(),
        ]
        _policy_required.__signature__ = inspect.Signature(sig_params)
        return _policy_required

    # ------------------------------------------------------------------
    # Permission Provider (delegates to registered AuthX instances)
    # ------------------------------------------------------------------

    def set_permission_provider(
        self,
        provider: PermissionProvider,
        login_type: Optional[str] = None,
    ) -> None:
        """Attach a runtime permission/role provider to one or all AuthX instances.

        Args:
            provider: An object implementing the :class:`PermissionProvider` protocol.
            login_type: If provided, set the provider only on the AuthX instance
                for that login type.  If ``None``, set it on **all** registered
                AuthX instances that do not already have a provider.
        """
        if login_type is not None:
            self.get(login_type).set_permission_provider(provider)
        else:
            for auth in self._auth_by_type.values():
                if auth._permission_handler is None:
                    auth.set_permission_provider(provider)

    def permissions_required(
        self,
        login_type: str,
        *permissions: str,
        all_required: bool = True,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory that checks runtime permissions for a login type.

        Delegates to the registered :class:`AuthX` instance's
        :meth:`~AuthX.permissions_required`.

        A provider **must** have been set on the underlying AuthX instance
        (via :meth:`set_permission_provider`) before this dependency can be used.
        """
        auth = self.get(login_type)
        return auth.permissions_required(
            *permissions,
            all_required=all_required,
            verify_type=verify_type,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
            locations=locations,
        )

    def role_required(
        self,
        login_type: str,
        *roles: str,
        all_required: bool = True,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency factory that checks runtime roles for a login type.

        Delegates to the registered :class:`AuthX` instance's
        :meth:`~AuthX.role_required`.

        A provider **must** have been set on the underlying AuthX instance
        (via :meth:`set_permission_provider`) before this dependency can be used.
        """
        auth = self.get(login_type)
        return auth.role_required(
            *roles,
            all_required=all_required,
            verify_type=verify_type,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
            locations=locations,
        )

    async def implicit_refresh_middleware(
        self,
        request: Request,
        call_next: Callable[[Request], Coroutine[Any, Any, Response]],
    ) -> Response:
        """FastAPI Middleware that applies implicit token refresh for the authenticated login type.

        After the endpoint runs, reads ``request.state.login_type`` (set by
        :meth:`AuthX._auth_required` during token verification) and performs
        an implicit refresh only for the :class:`AuthX` instance that handled
        the request — no iteration over unrelated login types.

        Usage::

            manager = AuthManager()
            manager.get_or_create("admin")
            manager.get_or_create("user")

            app.middleware("http")(manager.implicit_refresh_middleware)

        The middleware is a no-op when no token was verified on the request
        (public endpoints, missing tokens, etc.).

        Returns:
            Response: Response with an updated access token cookie if the
                      token was nearing expiry.
        """
        response = await call_next(request)

        login_type: Optional[str] = getattr(request.state, "login_type", None)
        if login_type is None:
            return response

        try:
            auth = self.get(login_type)
        except BadConfigurationError:
            return response

        config = auth.config
        if not config.has_location("cookies") or not auth._implicit_refresh_enabled_for_request(request):
            return response

        with contextlib.suppress(AuthXException):
            token = await auth._get_token_from_request(
                request=request,
                locations=["cookies"],
                refresh=False,
                optional=False,
            )
            payload = auth.verify_token(token, verify_fresh=False, verify_csrf=False)
            if payload.time_until_expiry < config.JWT_IMPLICIT_REFRESH_DELTATIME:
                new_token = await auth.async_create_access_token(
                    uid=payload.sub, fresh=False, data=payload.extra_dict,
                )
                auth.set_access_cookies(new_token, response=response)
        return response
