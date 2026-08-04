"""User endpoints: avatars, statistics, and tag insights."""

from typing import Any

from filescanio.groups._base import ApiGroup, segment


class UsersGroup(ApiGroup):
    """User account data: avatars, IOC statistics, and tag insights."""

    def avatar(self, account_id: str) -> bytes:
        """Return the account's avatar image (raw bytes)."""
        return self._transport.request_bytes(
            "GET", f"/api/users/{segment(account_id)}/avatar"
        )

    def uploads(self) -> Any:
        """Return the account's own submissions.

        Absent from openapi.json, which defines UserUploadsResponse but
        references it from no path. The official client uses this endpoint.
        """
        return self._transport.request_json("GET", "/api/users/uploads")

    def ioc_stats(self) -> Any:
        """Return the user's IOC statistics."""
        return self._transport.request_json("GET", "/api/users/stat/iocs")

    def frequent_tags(self) -> Any:
        """Return the user's most frequently used tags."""
        return self._transport.request_json("GET", "/api/users/get-frequent-tags")

    def most_interesting(self) -> Any:
        """Return the user's most interesting reports."""
        return self._transport.request_json("GET", "/api/users/most-interesting")
