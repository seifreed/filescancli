"""Tests for FilesGroup against the echo server."""

import json

from filescanio.client import FileScanClient


def test_availability(client: FileScanClient) -> None:
    echo = client.files.availability(["hash-a", "hash-b"])
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/files/availability"
    assert echo["query"] == {}
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == ["hash-a", "hash-b"]
