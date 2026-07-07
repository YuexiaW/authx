from inspect import iscoroutinefunction
from typing import Generic, Optional, cast
from typing_extensions import ParamSpecKwargs

from authx.types import ModelCallback, T, TokenCallback


class _CallbackHandler(Generic[T]):
    """Base class for callback handlers in AuthX.

    Args:
        Generic (T): Model type

    Raises:
        AttributeError: If callback is not set
    """

    def __init__(
        self,
        model: Optional[T] = None,
        model_callback: Optional[ModelCallback[T]] = None,
        token_callback: Optional[TokenCallback] = None,
    ) -> None:
        """Base class for callback handlers in AuthX.

        Args:
            model: Model instance for type context.
            model_callback: Optional callback for model/subject retrieval
                (injected at construction, avoiding a separate setter call).
            token_callback: Optional callback for token blocklist validation
                (injected at construction, avoiding a separate setter call).
        """
        self._model: Optional[T] = model
        self.callback_get_model_instance: Optional[ModelCallback[T]] = model_callback
        self.callback_is_token_in_blocklist: Optional[TokenCallback] = token_callback

    @property
    def is_model_callback_set(self) -> bool:
        """Check if callback is set for model instance."""
        return self.callback_get_model_instance is not None

    @property
    def is_token_callback_set(self) -> bool:
        """Check if callback is set for token."""
        return self.callback_is_token_in_blocklist is not None

    def _check_model_callback_is_set(self, ignore_errors: bool = False) -> bool:
        """Check if callback is set for model instance and raise exception if not set."""
        if self.is_model_callback_set:
            return True
        if not ignore_errors:
            name = self._model.__class__.__name__ if self._model is not None else "NoneType"
            raise AttributeError(f"Model callback not set for {name} instance")
        return False

    def _check_token_callback_is_set(self, ignore_errors: bool = False) -> bool:
        """Check if callback is set for token and raise exception if not set."""
        if self.is_token_callback_set:
            return True
        if not ignore_errors:
            name = self._model.__class__.__name__ if self._model is not None else "NoneType"
            raise AttributeError(f"Token callback not set for {name} instance")
        return False

    def set_callback_get_model_instance(self, callback: ModelCallback[T]) -> None:
        """Set callback for model instance."""
        self.callback_get_model_instance = callback

    def set_callback_token_blocklist(self, callback: TokenCallback) -> None:
        """Set callback for token."""
        self.callback_is_token_in_blocklist = callback

    def set_subject_getter(self, callback: ModelCallback[T]) -> None:
        """Set the callback to run for subject retrieval and serialization."""
        self.set_callback_get_model_instance(callback)

    def set_token_blocklist(self, callback: TokenCallback) -> None:
        """Set the callback to run for validation of revoked tokens."""
        self.set_callback_token_blocklist(callback)

    async def _get_current_subject(self, uid: str, **kwargs: ParamSpecKwargs) -> Optional[T]:
        """Get current model instance from callback."""
        self._check_model_callback_is_set()
        callback: Optional[ModelCallback[T]] = self.callback_get_model_instance
        if callback is None:
            return None
        if iscoroutinefunction(callback):
            return await callback(uid, **kwargs)
        return cast(Optional[T], callback(uid, **kwargs))

    async def is_token_in_blocklist(self, token: Optional[str], **kwargs: ParamSpecKwargs) -> bool:
        """Check if token is in blocklist."""
        if self._check_token_callback_is_set(ignore_errors=True):
            callback: Optional[TokenCallback] = self.callback_is_token_in_blocklist
            if callback is not None and token is not None:
                if iscoroutinefunction(callback):
                    return await callback(token, **kwargs)
                return cast(bool, callback(token, **kwargs))
        return False
