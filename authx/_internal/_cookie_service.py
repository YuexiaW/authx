"""Cookie service for AuthX - handles setting and unsetting authentication cookies."""

from typing import Any, Optional

from fastapi import Response

from authx.config import AuthXConfig


_COOKIE_KEYS = {
    "access": {
        "token_key": "JWT_ACCESS_COOKIE_NAME",
        "token_path": "JWT_ACCESS_COOKIE_PATH",
        "csrf_key": "JWT_ACCESS_CSRF_COOKIE_NAME",
        "csrf_path": "JWT_ACCESS_CSRF_COOKIE_PATH",
    },
    "refresh": {
        "token_key": "JWT_REFRESH_COOKIE_NAME",
        "token_path": "JWT_REFRESH_COOKIE_PATH",
        "csrf_key": "JWT_REFRESH_CSRF_COOKIE_NAME",
        "csrf_path": "JWT_REFRESH_CSRF_COOKIE_PATH",
    },
}


class CookieService:
    """Service responsible for managing authentication cookies.

    Encapsulates all cookie-related operations that were previously
    inlined in the AuthX main class.
    """

    def __init__(self, config: AuthXConfig, token_service: Any = None) -> None:
        self._config = config
        self._token_service = token_service

    @property
    def config(self) -> AuthXConfig:
        return self._config

    def _get_cookie_meta(self, token_type: str) -> dict[str, str]:
        if token_type not in _COOKIE_KEYS:
            raise ValueError("Token type must be 'access' | 'refresh'")
        mapping = _COOKIE_KEYS[token_type]
        return {
            "token_key": getattr(self.config, mapping["token_key"]),
            "token_path": getattr(self.config, mapping["token_path"]),
            "csrf_key": getattr(self.config, mapping["csrf_key"]),
            "csrf_path": getattr(self.config, mapping["csrf_path"]),
        }

    def set_cookies(
        self,
        token: str,
        token_type: str,
        response: Response,
        max_age: Optional[int] = None,
    ) -> None:
        meta = self._get_cookie_meta(token_type)

        response.set_cookie(
            key=meta["token_key"],
            value=token,
            path=meta["token_path"],
            domain=self.config.JWT_COOKIE_DOMAIN,
            samesite=self.config.JWT_COOKIE_SAMESITE,
            secure=self.config.JWT_COOKIE_SECURE,
            httponly=self.config.JWT_COOKIE_HTTP_ONLY,
            max_age=max_age or self.config.JWT_COOKIE_MAX_AGE,
        )

        if self.config.JWT_COOKIE_CSRF_PROTECT and self.config.JWT_CSRF_IN_COOKIES:
            csrf = self._token_service.decode_token(token=token, verify=True).csrf
            str_csrf = csrf if csrf is not None else ""
            response.set_cookie(
                key=meta["csrf_key"],
                value=str_csrf,
                path=meta["csrf_path"],
                domain=self.config.JWT_COOKIE_DOMAIN,
                samesite=self.config.JWT_COOKIE_SAMESITE,
                secure=self.config.JWT_COOKIE_SECURE,
                httponly=False,
                max_age=max_age or self.config.JWT_COOKIE_MAX_AGE,
            )

    def unset_cookies(
        self,
        token_type: str,
        response: Response,
    ) -> None:
        meta = self._get_cookie_meta(token_type)

        response.delete_cookie(
            key=meta["token_key"],
            path=meta["token_path"],
            domain=self.config.JWT_COOKIE_DOMAIN,
        )

        if self.config.JWT_COOKIE_CSRF_PROTECT and self.config.JWT_CSRF_IN_COOKIES:
            response.delete_cookie(
                key=meta["csrf_key"],
                path=meta["csrf_path"],
                domain=self.config.JWT_COOKIE_DOMAIN,
            )

    def set_access_cookies(
        self,
        token: str,
        response: Response,
        max_age: Optional[int] = None,
    ) -> None:
        self.set_cookies(token=token, token_type="access", response=response, max_age=max_age)

    def set_refresh_cookies(
        self,
        token: str,
        response: Response,
        max_age: Optional[int] = None,
    ) -> None:
        self.set_cookies(token=token, token_type="refresh", response=response, max_age=max_age)

    def unset_access_cookies(self, response: Response) -> None:
        self.unset_cookies("access", response=response)

    def unset_refresh_cookies(self, response: Response) -> None:
        self.unset_cookies("refresh", response=response)

    def unset_cookies_all(self, response: Response) -> None:
        self.unset_access_cookies(response)
        self.unset_refresh_cookies(response)