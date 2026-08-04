"""Library and CLI for the filescan.io API."""

from filescanio.client import FileScanClient
from filescanio.errors import (
    ApiError,
    ConfigError,
    FileScanError,
    RequestTimeout,
    TransportError,
)

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
