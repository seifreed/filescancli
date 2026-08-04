"""Tests for FilesGroup against the echo server."""

import json

from filescanio.client import FileScanClient
from tests.conftest import assert_get


def test_availability(client: FileScanClient) -> None:
    echo = client.files.availability(["hash-a", "hash-b"])
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/files/availability"
    assert echo["query"] == {}
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == ["hash-a", "hash-b"]


def test_download_asks_for_the_raw_sample(client: FileScanClient) -> None:
    echo = json.loads(client.files.download("a" * 64))
    assert_get(echo, f"/api/files/{'a' * 64}", {"type": ["raw"]})


def test_download_passes_the_zip_password(client: FileScanClient) -> None:
    echo = json.loads(client.files.download("a" * 64, password="infected"))
    assert_get(
        echo, f"/api/files/{'a' * 64}", {"type": ["raw"], "password": ["infected"]}
    )
