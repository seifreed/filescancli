"""Reputation endpoints: hash and IOC lookups."""

from typing import Any

from filescanio.groups._base import ApiGroup, segment


class ReputationGroup(ApiGroup):
    """Reputation lookups for file hashes and network IOCs."""

    def file_hash(self, sha256: str) -> Any:
        """Return the reputation of a file by its SHA-256 hash."""
        return self._transport.request_json(
            "GET", "/api/reputation/hash", params={"sha256": sha256}
        )

    def file_hash_bulk(self, hashes: list[str]) -> Any:
        """Return reputations for multiple file hashes in one request."""
        return self._transport.request_json(
            "POST", "/api/reputation/hash", json_body=hashes
        )

    def ioc(self, ioc_type: str, ioc_value: str) -> Any:
        """Return the reputation of a single IOC of the given type."""
        return self._transport.request_json(
            "GET",
            f"/api/reputation/{segment(ioc_type)}",
            params={"ioc_value": ioc_value},
        )

    def ioc_bulk(self, ioc_type: str, values: list[str]) -> Any:
        """Return reputations for multiple IOCs of the given type."""
        return self._transport.request_json(
            "POST", f"/api/reputation/{segment(ioc_type)}", json_body=values
        )
