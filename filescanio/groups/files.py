"""File endpoints: check availability of files by hash."""

from typing import Any

from filescanio.groups._base import ApiGroup


class FilesGroup(ApiGroup):
    """Query file availability on the platform."""

    def availability(self, hashes: list[str]) -> Any:
        """Check which of the given file hashes are available on the platform."""
        return self._transport.request_json(
            "POST", "/api/files/availability", json_body=hashes
        )
