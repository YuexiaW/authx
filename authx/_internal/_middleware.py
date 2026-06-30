"""Middleware for AuthX - implicit token refresh middleware."""

import contextlib
from collections.abc import Coroutine
from typing import Any, Callable

from fastapi import Request, Response

from authx.config import AuthXConfig
from authx.exceptions import AuthXException


class ImplicitRefreshMiddleware:
    """Middleware responsible for implicit token refresh.

    Encapsulates the implicit refresh logic that was previously
    inlined in the AuthX main class.
    """

    def __init__(self, config: AuthXConfig, authx_ref: Any) -> None:
        self._config = config
        self._authx = authx_ref

    @property
    def config(self) -> AuthXConfig:
        return self._config

    def _implicit_refresh_enabled_for_request(self, request: Request) -> bool:
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

    async def __call__(
        self,
        request: Request,
        call_next: Callable[[Request], Coroutine[Any, Any, Response]],
    ) -> Response:
        response = await call_next(request)

        if self.config.has_location("cookies") and self._implicit_refresh_enabled_for_request(request):
            with contextlib.suppress(AuthXException):
                token = await self._authx._get_token_from_request(
                    request=request,
                    locations=["cookies"],
                    refresh=False,
                    optional=False,
                )
                payload = self._authx.verify_token(token, verify_fresh=False, verify_csrf=False)
                if payload.time_until_expiry < self.config.JWT_IMPLICIT_REFRESH_DELTATIME:
                    new_token = self._authx.create_access_token(uid=payload.sub, fresh=False, data=payload.extra_dict)
                    self._authx.set_access_cookies(new_token, response=response)
        return response