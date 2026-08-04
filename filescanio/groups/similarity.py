"""Similarity search endpoints."""

from typing import Any

from filescanio.groups._base import ApiGroup


class SimilarityGroup(ApiGroup):
    """Find reports similar to a given file hash."""

    def similar(
        self,
        file_hash: str,
        *,
        min_similarity: int | None = None,
        verdict: str | None = None,
        tags: list[str] | None = None,
    ) -> Any:
        """Return reports similar to the given SHA-256 hash."""
        return self._transport.request_json(
            "GET",
            "/api/similarity-search/similarity",
            params={
                "hash": file_hash,
                "min_similarity": min_similarity,
                "verdict": verdict,
                "tags": tags,
            },
        )
