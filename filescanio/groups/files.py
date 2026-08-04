"""File endpoints: check availability of files by hash, download samples."""

from typing import Any

from filescanio.groups._base import ApiGroup, segment


class FilesGroup(ApiGroup):
    """Query file availability on the platform."""

    def availability(self, hashes: list[str]) -> Any:
        """Check which of the given file hashes are available on the platform."""
        return self._transport.request_json(
            "POST", "/api/files/availability", json_body=hashes
        )

    def download(self, file_hash: str, *, password: str | None = None) -> bytes:
        """Return the sample itself, zipped under the password when one is set.

        Absent from openapi.json: the official client uses it, so the
        endpoint is real but undocumented. Do not delete it as unreachable.
        """
        return self._transport.request_bytes(
            "GET",
            f"/api/files/{segment(file_hash)}",
            params={"type": "raw", "password": password},
        )
