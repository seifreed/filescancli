"""Tests for SimilarityGroup against the echo server."""

from filescanio.client import FileScanClient


def test_similar_with_options(client: FileScanClient) -> None:
    echo = client.similarity.similar(
        "deadbeef",
        min_similarity=80,
        verdict="malicious",
        tags=["stealer", "packed"],
    )
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/similarity-search/similarity"
    assert echo["query"] == {
        "hash": ["deadbeef"],
        "min_similarity": ["80"],
        "verdict": ["malicious"],
        "tags": ["stealer", "packed"],
    }


def test_similar_defaults(client: FileScanClient) -> None:
    echo = client.similarity.similar("cafebabe")
    assert echo["query"] == {"hash": ["cafebabe"]}
