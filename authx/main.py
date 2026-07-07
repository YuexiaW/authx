"""Main module for AuthX."""

import contextlib
import inspect
from collections.abc import Awaitable, Coroutine
from functools import cached_property

from makefun import with_signature
from typing import (
    Any,
    Callable,
    Generic,
    Literal,
    Optional,
    Union,
    overload,
)

from fastapi import Depends, Request, Response, WebSocket
from fastapi.security import APIKeyCookie, APIKeyHeader, APIKeyQuery, HTTPBearer

from authx._internal._callback import _CallbackHandler
from authx._internal._cookie_service import CookieService
from authx._internal._error import _ErrorHandler
from authx._internal._ratelimit import RateLimiter
from authx._internal._scopes import has_required_scopes
from authx._internal._session import SessionInfo
from authx._internal._session_service import SessionService
from authx._internal._token_service import TokenService
from authx.config import AuthXConfig
from authx.core import TOKEN_GETTERS
from authx.exceptions import (
    AuthXException,
    InsufficientScopeError,
    MissingTokenError,
    RevokedTokenError,
)
from authx.permission import PermissionProvider, _PermissionProviderHandler
from authx.schema import RequestToken, TokenPayload, TokenResponse
from authx.types import (
    DateTimeExpression,
    ModelCallback,
    SessionStoreProtocol,
    StringOrSequence,
    T,
    TokenCallback,
    TokenLocations,
    TokenType,
)


def _noop_openapi_security() -> None:
    """Placeholder dependency for token locations that OpenAPI cannot represent."""
    return None


_OPENAPI_BEARER_DESCRIPTION = (
    "Paste an AuthX JWT from create_access_token/create_refresh_token, not JWT_SECRET_KEY. "
    "The Bearer prefix is optional in Swagger UI."
)
_OPENAPI_HEADER_DESCRIPTION = "Provide an AuthX JWT in this header, not JWT_SECRET_KEY."
_OPENAPI_ACCESS_COOKIE_DESCRIPTION = "Provide an AuthX access token in this cookie."
_OPENAPI_REFRESH_COOKIE_DESCRIPTION = "Provide an AuthX refresh token in this cookie."
_OPENAPI_QUERY_DESCRIPTION = "Provide an AuthX JWT in this query parameter."


class AuthX(Generic[T]):
    """The base class for AuthX.

    AuthX enables JWT management within a FastAPI application.
    Its main purpose is to provide a reusable & simple syntax to protect API
    with JSON Web Token authentication.

    Args:
        config (AuthXConfig, optional): Configuration instance to use. Defaults to AuthXConfig().
        model (Optional[T], optional): Model type hint. Defaults to dict[str, Any].

    Note:
        AuthX is a Generic python object.
        Its TypeVar is not mandatory but helps type hinting furing development

    """

    def __init__(
        self,
        config: AuthXConfig = AuthXConfig(),
        model: Optional[T] = None,
        login_type: Optional[str] = None,
        model_callback: Optional[ModelCallback[T]] = None,
        token_callback: Optional[TokenCallback] = None,
    ) -> None:
        """AuthX base object.

        Args:
            config: Configuration instance to use. Defaults to AuthXConfig().
            model: Model type hint. Defaults to dict[str, Any].
            login_type: Explicit login type for manager-based auth contexts.
            model_callback: Optional callback for model/subject retrieval
                (constructor injection, avoids a separate ``set_callback_*`` call).
            token_callback: Optional callback for token blocklist validation
                (constructor injection, avoids a separate ``set_callback_*`` call).
        """
        self.model: Union[T, dict[str, Any]] = model if model is not None else {}
        self._callbacks = _CallbackHandler[T](model=model, model_callback=model_callback, token_callback=token_callback)
        self._error_handler = _ErrorHandler()
        self._config = config
        self.login_type = login_type

        # Auto-isolate token names by login_type when configured
        if config.AUTO_ISOLATE_BY_LOGIN_TYPE and login_type:
            config.JWT_HEADER_NAME = f"x-auth-{login_type}"
            config.JWT_ACCESS_COOKIE_NAME = f"{login_type}_access_token"
            config.JWT_REFRESH_COOKIE_NAME = f"{login_type}_refresh_token"
            config.JWT_ACCESS_CSRF_COOKIE_NAME = f"{login_type}_csrf_access"
            config.JWT_REFRESH_CSRF_COOKIE_NAME = f"{login_type}_csrf_refresh"
            config.JWT_QUERY_STRING_NAME = f"{login_type}_token"

        self._token_service = TokenService(config=self._config, login_type=self.login_type)
        self._cookie_service = CookieService(config=self._config, token_service=self._token_service)
        self._session_service = SessionService()
        self._permission_handler: Optional[_PermissionProviderHandler] = None

    def __setattr__(self, name: str, value: Any) -> None:
        # Forward MSG_* attribute sets to _error_handler for backward
        # compatibility after the composition refactor (P0-3).
        if name.startswith("MSG_") and "_error_handler" in self.__dict__:
            object.__setattr__(self._error_handler, name, value)
        else:
            object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        # Forward MSG_* attribute reads to _error_handler for backward
        # compatibility after the composition refactor (P0-3).
        if name.startswith("MSG_"):
            return getattr(self._error_handler, name)
        msg = f"'{type(self).__name__}' object has no attribute '{name}'"
        raise AttributeError(msg)

    def load_config(self, config: AuthXConfig) -> None:
        """Load and store the configuration for the authentication system.

        Sets the internal configuration object with the provided authentication configuration.

        Args:
            config: The configuration settings for the AuthX authentication system.

        Returns:
            None
        """
        self._config = config
        self._token_service = TokenService(config=self._config, login_type=self.login_type)
        self._cookie_service = CookieService(config=self._config, token_service=self._token_service)

    # --- Callback forwarding (delegated to _callbacks) ---

    def set_callback_get_model_instance(self, callback: Any) -> None:
        """Set the callback for model/subject retrieval.

        Args:
            callback: A callable (sync or async) that accepts a uid and returns the subject/model.
        """
        self._callbacks.set_callback_get_model_instance(callback)

    def set_callback_token_blocklist(self, callback: Any) -> None:
        """Set the callback for token blocklist validation.

        Args:
            callback: A callable (sync or async) that accepts a token string
                      and returns a boolean indicating if the token is revoked.
        """
        self._callbacks.set_callback_token_blocklist(callback)

    def set_subject_getter(self, callback: Any) -> None:
        """Set the callback to run for subject retrieval and serialization.

        Args:
            callback: A callable (sync or async) that accepts a uid and returns the subject/model.
        """
        self._callbacks.set_subject_getter(callback)

    def set_token_blocklist(self, callback: Any) -> None:
        """Set the callback to run for validation of revoked tokens.

        Args:
            callback: A callable (sync or async) that accepts a token string
                      and returns a boolean indicating if the token is revoked.
        """
        self._callbacks.set_token_blocklist(callback)

    # --- Error handler forwarding (delegated to _error_handler) ---

    def handle_errors(self, app: Any) -> None:
        """Register AuthX exception handlers on a FastAPI application.

        Args:
            app: The FastAPI application to attach exception handlers to.
        """
        self._error_handler.handle_errors(app)

    @property
    def config(self) -> AuthXConfig:
        """AuthX Configuration getter.

        Returns:
            AuthXConfig: Configuration BaseSettings
        """
        return self._config

    def _create_payload(
        self,
        uid: str,
        token_type: str,
        fresh: bool = False,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> TokenPayload:
        return self._token_service.create_payload(
            uid=uid,
            token_type=token_type,
            fresh=fresh,
            expiry=expiry,
            data=data,
            audience=audience,
            scopes=scopes,
            **kwargs,
        )

    def _create_token(
        self,
        uid: str,
        token_type: str,
        fresh: bool = False,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> str:
        return self._token_service.create_token(
            uid=uid,
            token_type=token_type,
            fresh=fresh,
            headers=headers,
            expiry=expiry,
            data=data,
            audience=audience,
            scopes=scopes,
            **kwargs,
        )

    def _decode_token(
        self,
        token: str,
        verify: bool = True,
        audience: Optional[StringOrSequence] = None,
        issuer: Optional[str] = None,
    ) -> TokenPayload:
        return self._token_service.decode_token(
            token=token,
            verify=verify,
            audience=audience,
            issuer=issuer,
        )

    def _set_cookies(
        self,
        token: str,
        token_type: str,
        response: Response,
        max_age: Optional[int] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self._cookie_service.set_cookies(token=token, token_type=token_type, response=response, max_age=max_age)

    def _unset_cookies(
        self,
        token_type: str,
        response: Response,
    ) -> None:
        self._cookie_service.unset_cookies(token_type=token_type, response=response)

    @overload
    async def _get_token_from_request(
        self,
        request: Request,
        locations: Optional[TokenLocations] = None,
        refresh: bool = False,
        optional: Literal[False] = False,
    ) -> RequestToken: ...

    @overload
    async def _get_token_from_request(
        self,
        request: Request,
        locations: Optional[TokenLocations] = None,
        refresh: bool = False,
        optional: Literal[True] = True,
    ) -> Optional[RequestToken]: ...

    async def _get_token_from_request(
        self,
        request: Request,
        locations: Optional[TokenLocations] = None,
        refresh: bool = False,
        optional: bool = False,
    ) -> Optional[RequestToken]:
        if locations is None:
            locations = list(self.config.JWT_TOKEN_LOCATION)
        errors: list[MissingTokenError] = []
        try:
            for location in locations:
                try:
                    getter = TOKEN_GETTERS[location]
                    token = await getter(request, self.config, refresh)
                    if token is not None:
                        return token
                except MissingTokenError as e:
                    errors.append(e)
            if errors:
                raise MissingTokenError(*(str(err) for err in errors))
            raise MissingTokenError(f"No token found in request from '{locations}'")
        except MissingTokenError:
            if optional:
                return None
            raise

    async def get_access_token_from_request(
        self, request: Request, locations: Optional[TokenLocations] = None
    ) -> RequestToken:
        """Dependency to retrieve access token from request.

        Args:
            request (Request): Request to retrieve access token from
            locations (Optional[TokenLocations], optional): Locations to retrieve token from. Defaults to None.

        Raises:
            MissingTokenError: When no `access` token is available in request

        Returns:
            RequestToken: Request Token instance for `access` token type
        """
        return await self._get_token_from_request(request, optional=False, locations=locations)

    async def get_refresh_token_from_request(
        self, request: Request, locations: Optional[TokenLocations] = None
    ) -> RequestToken:
        """Dependency to retrieve refresh token from request.

        Args:
            request (Request): Request to retrieve refresh token from
            locations (Optional[TokenLocations], optional): Locations to retrieve token from. Defaults to None.

        Raises:
            MissingTokenError: When no `refresh` token is available in request

        Returns:
            RequestToken: Request Token instance for `refresh` token type
        """
        return await self._get_token_from_request(request, refresh=True, optional=False, locations=locations)

    async def _auth_required(
        self,
        request: Request,
        token_type: str = "access",
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> TokenPayload:
        if token_type == "access":
            method = self.get_access_token_from_request
        elif token_type == "refresh":
            method = self.get_refresh_token_from_request
        else:
            ...  # pragma: no cover
        if verify_csrf is None:
            verify_csrf = self.config.JWT_COOKIE_CSRF_PROTECT and (
                request.method.upper() in self.config.JWT_CSRF_METHODS
            )

        request_token = await method(
            request=request,
            locations=locations,
        )

        if await self._callbacks.is_token_in_blocklist(request_token.token):
            raise RevokedTokenError("Token has been revoked", login_type=self.login_type)

        return self.verify_token(
            request_token,
            verify_type=verify_type,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
        )

    def verify_token(
        self,
        token: RequestToken,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: bool = True,
    ) -> TokenPayload:
        """Verify a request token.

        Attempts verification with the current key first, then falls back
        to the previous key if key rotation is configured.

        Args:
            token (RequestToken): RequestToken instance
            verify_type (bool, optional): Apply token type verification. Defaults to True.
            verify_fresh (bool, optional): Apply token freshness verification. Defaults to False.
            verify_csrf (bool, optional): Apply token CSRF verification. Defaults to True.

        Returns:
            TokenPayload: Verified token payload
        """
        return self._token_service.verify_token(
            token=token,
            verify_type=verify_type,
            verify_fresh=verify_fresh,
            verify_csrf=verify_csrf,
        )

    def create_access_token(
        self,
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
        """Generate an Access Token.

        Args:
            uid (str): Unique identifier to generate token for
            fresh (bool, optional): Generate fresh token. Defaults to False.
            headers (Optional[dict[str, Any]], optional): Custom JWT headers. Defaults to None.
            expiry (Optional[DateTimeExpression], optional): Use a user defined expiry claim. Defaults to None.
            data (Optional[dict[str, Any]], optional): Additional data to store in token. Defaults to None.
            audience (Optional[StringOrSequence], optional): Audience claim. Defaults to None.
            scopes (Optional[list[str]], optional): List of scopes to include in the token. Defaults to None.

        Returns:
            str: Access Token

        Example:
            ```python
            # Token with scopes
            token = auth.create_access_token(
                uid="user123",
                scopes=["users:read", "posts:write"]
            )
            ```
        """
        return self._create_token(
            uid=uid,
            token_type="access",
            fresh=fresh,
            headers=headers,
            expiry=expiry,
            data=data,
            audience=audience,
            scopes=scopes,
        )

    async def async_create_access_token(
        self,
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
        """Async variant of :meth:`create_access_token`.

        When :attr:`AuthXConfig.JWT_PERMISSIONS_IN_TOKEN` is ``True`` and a
        :class:`PermissionProvider` has been set, this method fetches the
        latest permissions and roles for the user from the provider and
        embeds them in the token payload — so that downstream
        ``permissions_required`` and ``role_required`` dependencies can read
        them directly from the JWT without calling the provider on every
        request.

        The returned token is functionally identical to
        :meth:`create_access_token`; callers that do not need the
        auto-embedding behaviour can continue to call the sync version.
        """
        if self._config.JWT_PERMISSIONS_IN_TOKEN and self._permission_handler is not None:
            perms = await self._permission_handler.get_permissions(uid=uid, login_type=self.login_type)
            roles = await self._permission_handler.get_roles(uid=uid, login_type=self.login_type)
            data = dict(data) if data is not None else {}
            if perms:
                data["permissions"] = perms
            if roles:
                data["roles"] = roles
        return self.create_access_token(uid, fresh, headers, expiry, data, audience, scopes, *args, **kwargs)

    def create_refresh_token(
        self,
        uid: str,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Generate a Refresh Token.

        Args:
            uid (str): Unique identifier to generate token for
            headers (Optional[dict[str, Any]], optional): Custom JWT headers. Defaults to None.
            expiry (Optional[DateTimeExpression], optional): Use a user defined expiry claim. Defaults to None.
            data (Optional[dict[str, Any]], optional): Additional data to store in token. Defaults to None.
            audience (Optional[StringOrSequence], optional): Audience claim. Defaults to None.
            scopes (Optional[list[str]], optional): List of scopes to include in the token. Defaults to None.

        Returns:
            str: Refresh Token
        """
        return self._create_token(
            uid=uid,
            token_type="refresh",
            headers=headers,
            expiry=expiry,
            data=data,
            audience=audience,
            scopes=scopes,
        )

    async def async_create_refresh_token(
        self,
        uid: str,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """Async variant of :meth:`create_refresh_token`.

        When :attr:`AuthXConfig.JWT_PERMISSIONS_IN_TOKEN` is ``True`` and a
        :class:`PermissionProvider` has been set, this method re-fetches the
        latest permissions and roles from the provider and embeds them in
        the new token — ensuring refreshed tokens carry up-to-date
        authorisation data.
        """
        if self._config.JWT_PERMISSIONS_IN_TOKEN and self._permission_handler is not None:
            perms = await self._permission_handler.get_permissions(uid=uid, login_type=self.login_type)
            roles = await self._permission_handler.get_roles(uid=uid, login_type=self.login_type)
            data = dict(data) if data is not None else {}
            if perms:
                data["permissions"] = perms
            if roles:
                data["roles"] = roles
        return self.create_refresh_token(uid, headers, expiry, data, audience, scopes, *args, **kwargs)

    def create_token_pair(
        self,
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
        """Generate an access and refresh token pair.

        Convenience method that creates both tokens at once and returns them
        in a standardized ``TokenResponse`` model.

        Args:
            uid: Unique identifier of the user.
            fresh: Whether the access token should be marked as fresh. Defaults to False.
            headers: Optional custom JWT headers applied to both tokens.
            access_expiry: Optional expiry override for the access token.
            refresh_expiry: Optional expiry override for the refresh token.
            data: Optional additional data stored in both tokens.
            audience: Optional audience claim for both tokens.
            access_scopes: Optional scopes for the access token.
            refresh_scopes: Optional scopes for the refresh token.

        Returns:
            TokenResponse: A model containing ``access_token``, ``refresh_token``, and ``token_type``.

        Example:
            ```python
            tokens = auth.create_token_pair(uid="user123", fresh=True)
            return tokens  # {"access_token": "...", "refresh_token": "...", "token_type": "bearer"}
            ```
        """
        access_token = self.create_access_token(
            uid=uid,
            fresh=fresh,
            headers=headers,
            expiry=access_expiry,
            data=data,
            audience=audience,
            scopes=access_scopes,
        )
        refresh_token = self.create_refresh_token(
            uid=uid,
            headers=headers,
            expiry=refresh_expiry,
            data=data,
            audience=audience,
            scopes=refresh_scopes,
        )
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    def set_access_cookies(
        self,
        token: str,
        response: Response,
        max_age: Optional[int] = None,
    ) -> None:
        """Add 'Set-Cookie' for access token in response header.

        Args:
            token (str): Access token
            response (Response): response to set cookie on
            max_age (Optional[int], optional): Max Age cookie parameter. Defaults to None.
        """
        self._cookie_service.set_access_cookies(token=token, response=response, max_age=max_age)

    def set_refresh_cookies(
        self,
        token: str,
        response: Response,
        max_age: Optional[int] = None,
    ) -> None:
        """Add 'Set-Cookie' for refresh token in response header.

        Args:
            token (str): Refresh token
            response (Response): response to set cookie on
            max_age (Optional[int], optional): Max Age cookie parameter. Defaults to None.
        """
        self._cookie_service.set_refresh_cookies(token=token, response=response, max_age=max_age)

    def unset_access_cookies(
        self,
        response: Response,
    ) -> None:
        """Remove 'Set-Cookie' for access token in response header.

        Args:
            response (Response): response to remove cooke from
        """
        self._cookie_service.unset_access_cookies(response=response)

    def unset_refresh_cookies(
        self,
        response: Response,
    ) -> None:
        """Remove 'Set-Cookie' for refresh token in response header.

        Args:
            response (Response): response to remove cooke from
        """
        self._cookie_service.unset_refresh_cookies(response=response)

    def unset_cookies(
        self,
        response: Response,
    ) -> None:
        """Remove 'Set-Cookie' for tokens from response headers.

        Args:
            response (Response): response to remove token cookies from
        """
        self._cookie_service.unset_cookies_all(response=response)

    # --- Standard FastAPI dependency properties ---

    @cached_property
    def FRESH_REQUIRED(self) -> TokenPayload:
        """FastAPI Dependency to enforce valid token availability in request."""
        return Depends(self.fresh_token_required)

    @cached_property
    def ACCESS_REQUIRED(self) -> TokenPayload:
        """FastAPI Dependency to enforce presence of an `access` token in request."""
        return Depends(self.access_token_required)

    @cached_property
    def REFRESH_REQUIRED(self) -> TokenPayload:
        """FastAPI Dependency to enforce presence of a `refresh` token in request."""
        return Depends(self.refresh_token_required)

    @cached_property
    def ACCESS_TOKEN(self) -> RequestToken:
        """FastAPI Dependency to retrieve access token from request."""

        async def _get_access_token(request: Request) -> Optional[RequestToken]:
            return await self._get_token_from_request(request, refresh=False, optional=True)

        return Depends(_get_access_token)

    @cached_property
    def REFRESH_TOKEN(self) -> RequestToken:
        """FastAPI Dependency to retrieve refresh token from request."""

        async def _get_refresh_token(request: Request) -> Optional[RequestToken]:
            return await self._get_token_from_request(request, refresh=True, optional=True)

        return Depends(_get_refresh_token)

    @cached_property
    def CURRENT_SUBJECT(self) -> T:
        """FastAPI Dependency to retrieve the current subject from request."""
        return Depends(self.get_current_subject)

    @cached_property
    def WS_AUTH_REQUIRED(self) -> TokenPayload:
        """FastAPI Dependency to enforce valid access token on a WebSocket connection.

        Extracts the token from the ``token`` query parameter or the ``Authorization``
        header of the WebSocket handshake request.
        """
        return Depends(self._ws_auth_required)

    async def _ws_auth_required(self, websocket: WebSocket) -> TokenPayload:
        """Verify an access token from a WebSocket connection.

        Looks for the token in the query string (``?token=...``) first,
        then falls back to the ``Authorization`` header.

        Raises:
            MissingTokenError: When no token is found.
            JWTDecodeError: When the token is invalid.
        """
        token_str: Optional[str] = websocket.query_params.get(self.config.JWT_QUERY_STRING_NAME)
        if token_str is None:
            auth_header = websocket.headers.get(self.config.JWT_HEADER_NAME)
            if auth_header is not None and self.config.JWT_HEADER_TYPE:
                token_str = auth_header.removeprefix(f"{self.config.JWT_HEADER_TYPE} ")
            elif auth_header is not None:
                token_str = auth_header

        if token_str is None:
            raise MissingTokenError(
                f"Missing token in WebSocket query parameter '{self.config.JWT_QUERY_STRING_NAME}' "
                f"or '{self.config.JWT_HEADER_NAME}' header",
                login_type=self.login_type,
            )

        request_token = RequestToken(token=token_str, csrf=None, type="access", location="query")
        if await self._callbacks.is_token_in_blocklist(request_token.token):
            raise RevokedTokenError("Token has been revoked", login_type=self.login_type)
        return self.verify_token(request_token, verify_type=True, verify_fresh=False, verify_csrf=False)

    def _openapi_header_security_scheme(self) -> Callable[..., Any]:
        if self.config.JWT_HEADER_NAME.lower() == "authorization" and self.config.JWT_HEADER_TYPE.lower() == "bearer":
            return HTTPBearer(
                scheme_name="AuthXBearer",
                bearerFormat="JWT",
                description=_OPENAPI_BEARER_DESCRIPTION,
                auto_error=False,
            )
        return APIKeyHeader(
            name=self.config.JWT_HEADER_NAME,
            scheme_name="AuthXHeader",
            description=_OPENAPI_HEADER_DESCRIPTION,
            auto_error=False,
        )

    def _openapi_cookie_security_scheme(self, token_type: str) -> Callable[..., Any]:
        if token_type == "refresh":
            return APIKeyCookie(
                name=self.config.JWT_REFRESH_COOKIE_NAME,
                scheme_name="AuthXRefreshCookie",
                description=_OPENAPI_REFRESH_COOKIE_DESCRIPTION,
                auto_error=False,
            )
        return APIKeyCookie(
            name=self.config.JWT_ACCESS_COOKIE_NAME,
            scheme_name="AuthXAccessCookie",
            description=_OPENAPI_ACCESS_COOKIE_DESCRIPTION,
            auto_error=False,
        )

    def _openapi_query_security_scheme(self) -> Callable[..., Any]:
        return APIKeyQuery(
            name=self.config.JWT_QUERY_STRING_NAME,
            scheme_name="AuthXQuery",
            description=_OPENAPI_QUERY_DESCRIPTION,
            auto_error=False,
        )

    def _openapi_security_dependencies(
        self,
        token_type: str = "access",
        locations: Optional[TokenLocations] = None,
    ) -> tuple[Callable[..., Any], Callable[..., Any], Callable[..., Any]]:
        effective_locations = locations if locations is not None else self.config.JWT_TOKEN_LOCATION
        return (
            self._openapi_header_security_scheme() if "headers" in effective_locations else _noop_openapi_security,
            self._openapi_cookie_security_scheme(token_type) if "cookies" in effective_locations else _noop_openapi_security,
            self._openapi_query_security_scheme() if "query" in effective_locations else _noop_openapi_security,
        )

    def _build_openapi_params(
        self,
        token_type: str = "access",
        locations: Optional[TokenLocations] = None,
    ) -> dict[str, inspect.Parameter]:
        """Build OpenAPI signature params for enabled token locations only.

        Returns a dict of ``inspect.Parameter`` objects keyed by parameter name,
        containing ``Depends(...)`` defaults for the security schemes of
        token locations that are actually enabled in the config.  The caller
        applies these to the dependency function's ``__signature__`` so that
        FastAPI only discovers security schemes for truly active locations.
        """
        effective = locations if locations is not None else self.config.JWT_TOKEN_LOCATION
        result: dict[str, inspect.Parameter] = {}
        if "headers" in effective:
            dep = Depends(self._openapi_header_security_scheme())
            result["_authx_openapi_header"] = inspect.Parameter(
                "_authx_openapi_header", inspect.Parameter.KEYWORD_ONLY,
                default=dep, annotation=Any,
            )
        if "cookies" in effective:
            dep = Depends(self._openapi_cookie_security_scheme(token_type))
            result["_authx_openapi_cookie"] = inspect.Parameter(
                "_authx_openapi_cookie", inspect.Parameter.KEYWORD_ONLY,
                default=dep, annotation=Any,
            )
        if "query" in effective:
            dep = Depends(self._openapi_query_security_scheme())
            result["_authx_openapi_query"] = inspect.Parameter(
                "_authx_openapi_query", inspect.Parameter.KEYWORD_ONLY,
                default=dep, annotation=Any,
            )
        return result

    def token_required(
        self,
        token_type: str = "access",
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency to enforce valid token availability in request.

        Args:
            token_type (str, optional): Require a given token type. Defaults to "access".
            verify_type (bool, optional): Apply type verification. Defaults to True.
            verify_fresh (bool, optional): Require token freshness. Defaults to False.
            verify_csrf (Optional[bool], optional): Enable CSRF verification. Defaults to None.
            locations (Optional[TokenLocations], optional): Locations to retrieve token from. Defaults to None.

        Returns:
            Callable[[Request], TokenPayload]: Dependency for Valid token Payload retrieval
        """
        openapi_params = self._build_openapi_params(token_type=token_type, locations=locations)
        sig = inspect.Signature([
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            *openapi_params.values(),
        ])

        @with_signature(sig)
        async def _auth_required(
            request: Request,
            **extra: Any,
        ) -> Any:
            self._error_handler.ensure_request_exception_handlers(request)
            return await self._auth_required(
                request=request,
                token_type=token_type,
                verify_csrf=verify_csrf,
                verify_type=verify_type,
                verify_fresh=verify_fresh,
                locations=locations,
            )

        return _auth_required

    @cached_property
    def fresh_token_required(self) -> Callable[[Request], Awaitable[TokenPayload]]:
        """FastAPI Dependency to enforce presence of a `fresh` `access` token in request."""
        return self.token_required(
            token_type="access",
            verify_csrf=None,
            verify_fresh=True,
            verify_type=True,
        )

    @cached_property
    def access_token_required(self) -> Callable[[Request], Awaitable[TokenPayload]]:
        """FastAPI Dependency to enforce presence of an `access` token in request."""
        return self.token_required(
            token_type="access",
            verify_csrf=None,
            verify_fresh=False,
            verify_type=True,
        )

    @cached_property
    def refresh_token_required(self) -> Callable[[Request], Awaitable[TokenPayload]]:
        """FastAPI Dependency to enforce presence of a `refresh` token in request."""
        return self.token_required(
            token_type="refresh",
            verify_csrf=None,
            verify_fresh=False,
            verify_type=True,
        )

    def scopes_required(
        self,
        *scopes: str,
        all_required: bool = True,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency to enforce required scopes in token.

        Creates a FastAPI dependency that validates that the token contains
        the required scopes. Supports both simple and hierarchical scopes
        with wildcard matching (e.g., "admin:*" matches "admin:users").

        Args:
            *scopes: Variable number of scope strings required.
            all_required: If True (default), ALL scopes must be present (AND logic).
                         If False, at least ONE scope must be present (OR logic).
            verify_type: Apply token type verification. Defaults to True.
            verify_fresh: Require token freshness. Defaults to False.
            verify_csrf: Enable CSRF verification. Defaults to None (uses config).
            locations: Locations to retrieve token from. Defaults to None.

        Returns:
            Callable[[Request], Awaitable[TokenPayload]]: Dependency for scope validation.

        Raises:
            InsufficientScopeError: When token lacks required scopes.

        Example:
            ```python
            # Require single scope
            @app.get("/users", dependencies=[Depends(auth.scopes_required("users:read"))])
            async def list_users(): ...

            # Require multiple scopes (AND)
            @app.delete("/users/{id}", dependencies=[Depends(auth.scopes_required("users:read", "users:delete"))])
            async def delete_user(id: int): ...

            # Require any of the scopes (OR)
            @app.get("/admin", dependencies=[Depends(auth.scopes_required("admin", "superuser", all_required=False))])
            async def admin_panel(): ...

            # Wildcard scope
            @app.get("/admin/users", dependencies=[Depends(auth.scopes_required("admin:*"))])
            async def admin_users(): ...
            ```
        """
        required_scopes = list(scopes)
        openapi_params = self._build_openapi_params(token_type="access", locations=locations)
        sig = inspect.Signature([
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            *openapi_params.values(),
        ])

        @with_signature(sig)
        async def _scopes_required(
            request: Request,
            **extra: Any,
        ) -> TokenPayload:
            self._error_handler.ensure_request_exception_handlers(request)
            payload = await self._auth_required(
                request=request,
                token_type="access",
                verify_type=verify_type,
                verify_fresh=verify_fresh,
                verify_csrf=verify_csrf,
                locations=locations,
            )

            if not has_required_scopes(required_scopes, payload.scopes, all_required=all_required):
                raise InsufficientScopeError(
                    required=required_scopes,
                    provided=payload.scopes,
                    login_type=self.login_type,
                )

            return payload

        return _scopes_required

    # ------------------------------------------------------------------
    # Permission Provider
    # ------------------------------------------------------------------

    def set_permission_provider(
        self,
        provider: PermissionProvider,
    ) -> None:
        """Attach a runtime permission/role provider to this AuthX instance.

        Once attached, the :meth:`permissions_required` and
        :meth:`role_required` dependencies query the provider on every
        request so that permission changes take effect immediately
        without re-issuing tokens.

        Args:
            provider: An object implementing the :class:`PermissionProvider`
                protocol (i.e. with ``get_permissions(uid, login_type)``
                and ``get_roles(uid, login_type)`` async methods).
        """
        self._permission_handler = _PermissionProviderHandler(provider)

    def permissions_required(
        self,
        *permissions: str,
        all_required: bool = True,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency that checks runtime permissions via the
        :class:`PermissionProvider`.

        Unlike :meth:`scopes_required` which validates scopes **embedded
        in the JWT token at creation time**, this dependency queries the
        configured :class:`PermissionProvider` on **every request** so
        that permission changes take effect immediately.

        A provider **must** have been set via
        :meth:`set_permission_provider` before this dependency can be
        used.

        Args:
            *permissions: Required permission strings.
            all_required: If True (default), ALL permissions must be
                present (AND).  If False, at least ONE is enough (OR).
            verify_type: Apply token type verification.  Defaults to True.
            verify_fresh: Require token freshness.  Defaults to False.
            verify_csrf: CSRF verification override.  Defaults to None.
            locations: Token locations.  Defaults to None.

        Returns:
            A FastAPI dependency callable.

        Raises:
            RuntimeError: If no :class:`PermissionProvider` has been set.
        """
        required_permissions = list(permissions)
        openapi_params = self._build_openapi_params(token_type="access", locations=locations)
        sig = inspect.Signature([
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            *openapi_params.values(),
        ])

        @with_signature(sig)
        async def _permissions_required(
            request: Request,
            **extra: Any,
        ) -> TokenPayload:
            self._error_handler.ensure_request_exception_handlers(request)

            payload = await self._auth_required(
                request=request,
                token_type="access",
                verify_type=verify_type,
                verify_fresh=verify_fresh,
                verify_csrf=verify_csrf,
                locations=locations,
            )

            if self._config.JWT_PERMISSIONS_IN_TOKEN:
                # Read permissions embedded in the JWT payload at token creation time.
                # Tokens that pre-date this feature simply lack the claim → empty list.
                user_permissions = getattr(payload, "permissions", None) or []
            else:
                handler = self._permission_handler
                if handler is None:
                    raise RuntimeError(
                        "No PermissionProvider configured. "
                        "Call auth.set_permission_provider(provider) first."
                    )
                user_permissions = await handler.get_permissions(
                    uid=payload.sub,
                    login_type=self.login_type,
                )

            if not has_required_scopes(required_permissions, user_permissions, all_required=all_required):
                raise InsufficientScopeError(
                    required=required_permissions,
                    provided=user_permissions,
                    login_type=self.login_type,
                )

            return payload

        return _permissions_required

    def role_required(
        self,
        *roles: str,
        all_required: bool = True,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: Optional[bool] = None,
        locations: Optional[TokenLocations] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency that checks runtime roles via the
        :class:`PermissionProvider`.

        Similar to :meth:`permissions_required` but for role checks.

        A provider **must** have been set via
        :meth:`set_permission_provider` before this dependency can be
        used.

        Args:
            *roles: Required role strings.
            all_required: If True (default), ALL roles must be present
                (AND).  If False, at least ONE is enough (OR).
            verify_type: Apply token type verification.  Defaults to True.
            verify_fresh: Require token freshness.  Defaults to False.
            verify_csrf: CSRF verification override.  Defaults to None.
            locations: Token locations.  Defaults to None.

        Returns:
            A FastAPI dependency callable.

        Raises:
            RuntimeError: If no :class:`PermissionProvider` has been set.
        """
        required_roles = list(roles)
        openapi_params = self._build_openapi_params(token_type="access", locations=locations)
        sig = inspect.Signature([
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            *openapi_params.values(),
        ])

        @with_signature(sig)
        async def _role_required(
            request: Request,
            **extra: Any,
        ) -> TokenPayload:
            self._error_handler.ensure_request_exception_handlers(request)

            payload = await self._auth_required(
                request=request,
                token_type="access",
                verify_type=verify_type,
                verify_fresh=verify_fresh,
                verify_csrf=verify_csrf,
                locations=locations,
            )

            if self._config.JWT_PERMISSIONS_IN_TOKEN:
                # Read roles embedded in the JWT payload at token creation time.
                user_roles = getattr(payload, "roles", None) or []
            else:
                handler = self._permission_handler
                if handler is None:
                    raise RuntimeError(
                        "No PermissionProvider configured. "
                        "Call auth.set_permission_provider(provider) first."
                    )
                user_roles = await handler.get_roles(
                    uid=payload.sub,
                    login_type=self.login_type,
                )

            if not has_required_scopes(required_roles, user_roles, all_required=all_required):
                raise InsufficientScopeError(
                    required=required_roles,
                    provided=user_roles,
                    login_type=self.login_type,
                )

            return payload

        return _role_required

    async def get_current_subject(self, request: Request) -> Optional[T]:
        """Retrieve the currently authenticated subject from the request.

        Validates the request token and fetches the corresponding subject based on the user identifier.

        Args:
            request: The HTTP request containing authentication credentials.

        Returns:
            The authenticated subject if present, otherwise None.
        """
        self._error_handler.ensure_request_exception_handlers(request)
        token: TokenPayload = await self._auth_required(request=request)
        uid = token.sub
        return await self._callbacks._get_current_subject(uid=uid)

    @overload
    async def get_token_from_request(
        self,
        request: Request,
        token_type: TokenType = "access",
        optional: Literal[True] = True,
        locations: Optional[TokenLocations] = None,
    ) -> Optional[RequestToken]: ...

    @overload
    async def get_token_from_request(
        self,
        request: Request,
        token_type: TokenType = "access",
        optional: Literal[False] = False,
        locations: Optional[TokenLocations] = None,
    ) -> RequestToken: ...

    async def get_token_from_request(
        self,
        request: Request,
        token_type: TokenType = "access",
        optional: bool = True,
        locations: Optional[TokenLocations] = None,
    ) -> Optional[RequestToken]:
        """Retrieve token from request.

        Args:
            request (Request): The FastAPI request object.
            token_type (TokenType, optional): The type of token to retrieve from request.
                Defaults to "access".
            optional (bool, optional): Whether or not to enforce token presence in request.
                Defaults to True.
            locations (Optional[TokenLocations], optional): Locations to retrieve token from.
                Defaults to None (uses configured JWT_TOKEN_LOCATION).

        Note:
            When `optional=True`, the return value might be `None`
            if no token is available in request.

            When `optional=False`, raises a MissingTokenError.

        Returns:
            Optional[RequestToken]: The RequestToken if available, None if optional and not found.

        Example:
            ```python
            token = await auth.get_token_from_request(request)
            token = await auth.get_token_from_request(request, token_type="refresh")
            token = await auth.get_token_from_request(request, optional=False)
            ```
        """
        if optional:
            return await self._get_token_from_request(
                request,
                locations=locations,
                refresh=(token_type == "refresh"),
                optional=True,
            )
        else:
            return await self._get_token_from_request(
                request,
                locations=locations,
                refresh=(token_type == "refresh"),
                optional=False,
            )

    def _implicit_refresh_enabled_for_request(self, request: Request) -> bool:
        """Check if a request should implement implicit token refresh.

        Args:
            request (Request): Request to check

        Returns:
            bool: True if request allows for refreshing access token
        """
        if request.url.components.path in self.config.JWT_IMPLICIT_REFRESH_ROUTE_EXCLUDE:
            return False
        elif request.url.components.path in self.config.JWT_IMPLICIT_REFRESH_ROUTE_INCLUDE:
            return True
        elif request.method in self.config.JWT_IMPLICIT_REFRESH_METHOD_EXCLUDE:
            return False
        elif request.method in self.config.JWT_IMPLICIT_REFRESH_METHOD_INCLUDE:
            return False
        else:
            return True

    async def implicit_refresh_middleware(
        self,
        request: Request,
        call_next: Callable[[Request], Coroutine[Any, Any, Response]],
    ) -> Response:
        """FastAPI Middleware to enable token refresh for an APIRouter.

        Args:
            request (Request): Incoming request
            call_next (Coroutine): Endpoint logic to be called

        Note:
            This middleware is only based on `access` tokens.
            Using implicit refresh mechanism makes use of `refresh`
            tokens unnecessary.

        Note:
            The refreshed `access` token will not be considered as
            `fresh`

        Note:
            The implicit refresh mechanism is only enabled
            for authorization through cookies.

        Returns:
            Response: Response with update access token cookie if relevant
        """
        response = await call_next(request)

        if self.config.has_location("cookies") and self._implicit_refresh_enabled_for_request(request):
            with contextlib.suppress(AuthXException):
                # Refresh mechanism
                token = await self._get_token_from_request(
                    request=request,
                    locations=["cookies"],
                    refresh=False,
                    optional=False,
                )
                payload = self.verify_token(token, verify_fresh=False, verify_csrf=False)
                if payload.time_until_expiry < self.config.JWT_IMPLICIT_REFRESH_DELTATIME:
                    new_token = await self.async_create_access_token(
                        uid=payload.sub, fresh=False, data=payload.extra_dict,
                    )
                    self.set_access_cookies(new_token, response=response)
        return response

    def rate_limited(
        self,
        max_requests: int = 10,
        window: int = 60,
        key_func: Optional[Callable[[Request], str]] = None,
    ) -> Callable[[Request], Awaitable[TokenPayload]]:
        """Dependency combining rate limiting with access token verification.

        Args:
            max_requests: Maximum requests allowed within the window.
            window: Time window in seconds.
            key_func: Callable to extract rate limit key from request. Defaults to client IP.

        Returns:
            A FastAPI dependency that enforces both rate limiting and token auth.

        Example:
            ```python
            @app.get("/api", dependencies=[Depends(auth.rate_limited(max_requests=5, window=60))])
            async def api_route(): ...
            ```
        """
        limiter = RateLimiter(max_requests=max_requests, window=window, key_func=key_func)

        async def _rate_limited_auth(request: Request) -> TokenPayload:
            await limiter(request)
            return await self._auth_required(request=request)

        return _rate_limited_auth

    # --- Session Management ---

    def set_session_store(self, store: Optional[SessionStoreProtocol] = None) -> None:
        """Register a session storage backend.

        Args:
            store: An object implementing the ``SessionStoreProtocol``.
        """
        self._session_service.set_session_store(store)

    async def create_session(
        self,
        uid: str,
        request: Optional[Request] = None,
        device_info: Optional[dict[str, Any]] = None,
    ) -> SessionInfo:
        """Create a new session and persist it via the session store.

        Args:
            uid: User identifier.
            request: Optional HTTP request for IP/User-Agent extraction.
            device_info: Optional additional device metadata.

        Returns:
            The created ``SessionInfo`` instance.
        """
        return await self._session_service.create_session(uid=uid, request=request, device_info=device_info)

    async def list_sessions(self, uid: str) -> list[SessionInfo]:
        """List all active sessions for a user.

        Args:
            uid: User identifier.

        Returns:
            List of active ``SessionInfo`` objects.
        """
        return await self._session_service.list_sessions(uid=uid)

    async def revoke_session(self, session_id: str) -> None:
        """Revoke a single session by ID.

        Args:
            session_id: The session to revoke.
        """
        await self._session_service.revoke_session(session_id=session_id)

    async def revoke_all_sessions(self, uid: str) -> None:
        """Revoke all sessions for a user.

        Args:
            uid: User identifier.
        """
        await self._session_service.revoke_all_sessions(uid=uid)

    async def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """Retrieve a session by ID.

        Args:
            session_id: The session to look up.

        Returns:
            The ``SessionInfo`` if found and active, otherwise None.
        """
        return await self._session_service.get_session(session_id=session_id)
