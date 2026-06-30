"""Token service for AuthX - handles token creation, verification and decoding."""

from typing import Any, Optional

from authx._internal._utils import get_uuid
from authx.config import AuthXConfig
from authx.exceptions import JWTDecodeError
from authx.schema import RequestToken, TokenPayload
from authx.types import (
    DateTimeExpression,
    StringOrSequence,
)


class TokenService:
    """Service responsible for JWT token creation, verification and decoding.

    This service encapsulates all token-related operations that were previously
    inlined in the AuthX main class.
    """

    def __init__(self, config: AuthXConfig, login_type: Optional[str] = None) -> None:
        self._config = config
        self.login_type = login_type

    @property
    def config(self) -> AuthXConfig:
        return self._config

    def create_payload(
        self,
        uid: str,
        type: str,
        fresh: bool = False,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> TokenPayload:
        if data is None:
            data = {}
        else:
            data = data.copy()

        if self.login_type is not None:
            data["login_type"] = self.login_type

        exp = expiry
        if exp is None:
            exp = self.config.JWT_ACCESS_TOKEN_EXPIRES if type == "access" else self.config.JWT_REFRESH_TOKEN_EXPIRES

        csrf = ""
        if self.config.has_location("cookies") and self.config.JWT_COOKIE_CSRF_PROTECT:
            csrf = get_uuid()

        aud = audience
        if aud is None:
            aud = self.config.JWT_ENCODE_AUDIENCE

        return TokenPayload(
            sub=uid,
            fresh=fresh,
            exp=exp,
            type=type,
            iss=self.config.JWT_ENCODE_ISSUER,
            aud=aud,
            csrf=csrf,
            scopes=scopes,
            nbf=None,
            **data,
        )

    def create_token(
        self,
        uid: str,
        type: str,
        fresh: bool = False,
        headers: Optional[dict[str, Any]] = None,
        expiry: Optional[DateTimeExpression] = None,
        data: Optional[dict[str, Any]] = None,
        audience: Optional[StringOrSequence] = None,
        scopes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> str:
        encode_data = data.copy() if data is not None else {}
        if self.login_type is not None:
            encode_data["login_type"] = self.login_type

        payload = self.create_payload(
            uid=uid,
            type=type,
            fresh=fresh,
            expiry=expiry,
            data=data,
            audience=audience,
            scopes=scopes,
            **kwargs,
        )
        return payload.encode(
            key=self.config.private_key,
            algorithm=self.config.JWT_ALGORITHM,
            headers=headers,
            data=encode_data if encode_data else None,
        )

    def decode_token(
        self,
        token: str,
        verify: bool = True,
        audience: Optional[StringOrSequence] = None,
        issuer: Optional[str] = None,
    ) -> TokenPayload:
        try:
            return TokenPayload.decode(
                token=token,
                key=self.config.public_key,
                algorithms=[self.config.JWT_ALGORITHM],
                verify=verify,
                audience=audience or self.config.JWT_DECODE_AUDIENCE,
                issuer=issuer or self.config.JWT_DECODE_ISSUER,
            )
        except JWTDecodeError:
            previous_key = self.config.previous_public_key
            if previous_key is None:
                raise
            return TokenPayload.decode(
                token=token,
                key=previous_key,
                algorithms=[self.config.JWT_ALGORITHM],
                verify=verify,
                audience=audience or self.config.JWT_DECODE_AUDIENCE,
                issuer=issuer or self.config.JWT_DECODE_ISSUER,
            )

    def verify_token(
        self,
        token: RequestToken,
        verify_type: bool = True,
        verify_fresh: bool = False,
        verify_csrf: bool = True,
    ) -> TokenPayload:
        try:
            return token.verify(
                key=self.config.public_key,
                algorithms=[self.config.JWT_ALGORITHM],
                verify_fresh=verify_fresh,
                verify_type=verify_type,
                verify_csrf=verify_csrf,
                audience=self.config.JWT_DECODE_AUDIENCE,
                issuer=self.config.JWT_DECODE_ISSUER,
            )
        except JWTDecodeError:
            previous_key = self.config.previous_public_key
            if previous_key is None:
                raise
            return token.verify(
                key=previous_key,
                algorithms=[self.config.JWT_ALGORITHM],
                verify_fresh=verify_fresh,
                verify_type=verify_type,
                verify_csrf=verify_csrf,
                audience=self.config.JWT_DECODE_AUDIENCE,
                issuer=self.config.JWT_DECODE_ISSUER,
            )