"""Exception hierarchy for the filescan.io client."""

import reprlib


class FileScanError(Exception):
    """Base error for the filescanio package."""


class ConfigError(FileScanError):
    """Raised when no API key can be resolved."""


class TransportError(FileScanError):
    """Raised when the API cannot be reached (network or protocol failure)."""


class RequestTimeout(TransportError):
    """Raised when the API did not answer within the configured timeout."""


class ApiError(FileScanError):
    """Raised when the API responds with an error status."""

    def __init__(
        self, status_code: int, detail: str, retry_after: str | None = None
    ) -> None:
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail
        self.retry_after = retry_after

    def __reduce__(self) -> tuple[type[ApiError], tuple[int, str, str | None]]:
        return (ApiError, (self.status_code, self.detail, self.retry_after))


DESCRIBE_LIMIT = 200


# Bounded on purpose: a plain repr of a deeply nested payload exhausts the C
# stack, and the depth that takes differs between platforms, so the failure it
# used to guard against could never be reproduced reliably. This walks a few
# levels and never recurses far enough to raise.
_describer = reprlib.Repr()
_describer.maxlevel = 6
_describer.maxstring = DESCRIBE_LIMIT
_describer.maxother = DESCRIBE_LIMIT
_describer.maxlist = 12
_describer.maxdict = 12
_describer.maxtuple = 12
_describer.maxset = 12


def describe(value: object) -> str:
    """Render a server payload for an error message without ever failing."""
    return _describer.repr(value)
