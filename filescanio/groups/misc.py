"""Miscellaneous endpoints: API docs and OAuth callback."""

from typing import Any

from filescanio.groups._base import ApiGroup
from filescanio.transport import QueryValue


class MiscGroup(ApiGroup):
    """Documentation, sitemap, and OAuth callback endpoints."""

    def openapi(self) -> Any:
        """Return the OpenAPI specification document."""
        return self._transport.request_json("GET", "/openapi.json")

    def sitemap(self) -> str:
        """Return the sitemap (XML document)."""
        return self._transport.request_text("GET", "/api/docs/sitemap")

    def oauth_callback(
        self,
        *,
        state: str | None = None,
        code: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ) -> Any:
        """Forward an OAuth provider response to the scan-source callback."""
        params: dict[str, QueryValue] = {
            "state": state,
            "code": code,
            "error": error,
            "error_description": error_description,
        }
        return self._transport.request_json(
            "GET", "/api/admin/scan-sources/oauth/callback", params=params
        )
