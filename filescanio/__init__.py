"""Library and CLI for the filescan.io API.

The client pulls in httpx, which costs more to import than everything else
here put together. Commands that never reach the network — ``--help``,
``--version``, ``config`` — should not pay for it, so the name is resolved
on first use (PEP 562) instead of at import time.
"""

from typing import TYPE_CHECKING, Any

from filescanio.errors import (
    ApiError,
    ConfigError,
    FileScanError,
    RequestTimeout,
    TransportError,
)

if TYPE_CHECKING:
    from filescanio.client import FileScanClient

__version__ = "0.1.0"

__all__ = [
    "ApiError",
    "ConfigError",
    "FileScanClient",
    "FileScanError",
    "RequestTimeout",
    "TransportError",
    "__version__",
]


def __getattr__(name: str) -> Any:
    """Import the client on first use so a bare import stays cheap."""
    if name == "FileScanClient":
        from filescanio.client import FileScanClient

        return FileScanClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
