"""Spize SDK exception hierarchy."""


class SpizeError(Exception):
    """Root class for SDK errors."""


class SpizeHTTPError(SpizeError):
    """Raised when the control plane returns a non-2xx response."""

    def __init__(self, status_code: int, code: str | None, message: str) -> None:
        super().__init__(f"[{status_code}] {code or 'error'}: {message}")
        self.status_code = status_code
        self.code = code
        self.message = message


class IdentityError(SpizeError):
    """Raised for identity-file corruption or mismatched keys."""
