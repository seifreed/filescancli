"""Transport contract that endpoint groups depend on."""

import math
from collections.abc import Mapping
from typing import Any, Protocol

DEFAULT_TIMEOUT = 60.0

QueryValue = str | int | float | bool | list[str] | None

BAD_TIMEOUT = "timeout must be a positive finite number"
BAD_BASE_URL = "must not contain a query string or fragment"


def is_usable_timeout(seconds: float) -> bool:
    """Report whether a timeout can be handed to the HTTP client."""
    return math.isfinite(seconds) and seconds > 0


def is_usable_base_url(url: str) -> bool:
    """Report whether a base URL can anchor the API's relative paths."""
    return "?" not in url and "#" not in url


class ApiTransport(Protocol):
    """Abstraction over the HTTP layer used by the endpoint groups."""

    def request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json_body: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
    ) -> Any:
        """Perform a request and return the decoded JSON body."""

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
    ) -> bytes:
        """Perform a request and return the raw response body."""

    def request_text(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
    ) -> str:
        """Perform a request and return the response body as text."""
