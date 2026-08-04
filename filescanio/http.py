"""Thin HTTP transport around httpx with auth and error mapping."""

from collections.abc import Mapping
from contextlib import suppress
from typing import Any

import httpx

from filescanio.errors import (
    ApiError,
    ConfigError,
    RequestTimeout,
    TransportError,
)
from filescanio.transport import (
    BAD_BASE_URL,
    BAD_TIMEOUT,
    DEFAULT_TIMEOUT,
    QueryValue,
    is_usable_base_url,
    is_usable_timeout,
)

MAX_REDIRECTS = 5


def clean_params(params: Mapping[str, QueryValue]) -> dict[str, Any]:
    """Drop parameters whose value is None."""
    return {key: value for key, value in params.items() if value is not None}


class Transport:
    """Authenticated HTTP client for the filescan.io API."""

    def __init__(
        self,
        api_key: str,
        base_url: str | httpx.URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not is_usable_timeout(timeout):
            raise ConfigError(BAD_TIMEOUT)
        if not api_key.strip():
            raise ConfigError("API key is empty")
        if not api_key.isascii():
            raise ConfigError("API key contains non-ASCII characters")
        try:
            origin = httpx.URL(base_url)
        except (httpx.InvalidURL, TypeError) as exc:
            raise ConfigError(f"Invalid base URL {base_url!r}: {exc}") from exc
        if not is_usable_base_url(str(base_url)):
            raise ConfigError(f"Base URL {base_url!r} {BAD_BASE_URL}")
        self._origin = (origin.scheme, origin.netloc)
        try:
            self._client = httpx.Client(
                base_url=base_url,
                headers={"X-Api-Key": api_key},
                timeout=timeout,
                follow_redirects=False,
            )
        except (ImportError, ValueError) as exc:
            raise ConfigError(f"Cannot create the HTTP client: {exc}") from exc
        self._closed = False

    def _same_origin(self, url: httpx.URL) -> bool:
        return (url.scheme, url.netloc) == self._origin

    def _follow_redirects(self, response: httpx.Response) -> httpx.Response:
        """Follow redirects only within the API origin, so the key never leaks."""
        redirects = 0
        while (next_request := response.next_request) is not None:
            if redirects >= MAX_REDIRECTS:
                raise TransportError("Too many redirects")
            if not self._same_origin(next_request.url):
                raise TransportError(
                    f"Refusing cross-origin redirect to {next_request.url}"
                )
            response = self._client.send(next_request)
            redirects += 1
        return response

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json_body: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        if self._closed:
            raise TransportError("Transport is closed")
        try:
            response = self._follow_redirects(
                self._client.request(
                    method,
                    path,
                    params=(clean_params(params) if params else None) or None,
                    json=json_body,
                    data=dict(data) if data else None,
                    files=files,
                )
            )
        except (
            httpx.HTTPError,
            httpx.StreamError,
            httpx.InvalidURL,
            OSError,
            UnicodeEncodeError,
        ) as exc:
            if isinstance(exc, httpx.TimeoutException):
                raise RequestTimeout(f"Request timed out: {exc}") from exc
            raise TransportError(f"Network error: {exc}") from exc
        except (TypeError, ValueError) as exc:
            # httpx encodes the body with allow_nan=False, so a payload the
            # JSON module happily parsed can still be unsendable.
            raise TransportError(f"Cannot encode the request body: {exc}") from exc
        if response.status_code >= 400:
            raise ApiError(
                response.status_code,
                _error_detail(response),
                response.headers.get("Retry-After"),
            )
        if response.is_redirect or response.status_code >= 300:
            raise TransportError(
                f"Unusable redirect response: HTTP {response.status_code} "
                "without a usable Location header"
            )
        return response

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
        response = self._request(
            method, path, params=params, json_body=json_body, data=data, files=files
        )
        try:
            return response.json()
        except (ValueError, RecursionError) as exc:
            raise TransportError(f"Response is not valid JSON: {exc}") from exc

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
    ) -> bytes:
        return self._request(method, path, params=params).content

    def request_text(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
    ) -> str:
        return _decode_text(self._request(method, path, params=params))

    def close(self) -> None:
        self._closed = True
        self._client.close()

    def __enter__(self) -> Transport:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            self.close()


def _decode_text(response: httpx.Response) -> str:
    """Decode a body without trusting the charset the server declares."""
    charset = response.charset_encoding or "utf-8"
    try:
        decoded = response.content.decode(charset, errors="replace")
    except LookupError, ValueError:
        decoded = response.content.decode("utf-8", errors="replace")
    return decoded.encode("utf-8", "replace").decode("utf-8")


def _error_detail(response: httpx.Response) -> str:
    """Prefer the server's own detail, falling back to the raw body.

    Decoding a deeply nested body and rendering the detail out of it can each
    exhaust the stack, and which gives way first differs between platforms, so
    both answer the same way.
    """
    with suppress(ValueError, RecursionError):
        payload = response.json()
        if isinstance(payload, dict) and "detail" in payload:
            return str(payload["detail"])
    return _decode_text(response)
