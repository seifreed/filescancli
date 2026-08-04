import json
from collections.abc import Callable
from typing import Any

import pytest

from filescanio.client import FileScanClient


def test_file_hash(client: FileScanClient) -> None:
    echo = client.reputation.file_hash("a" * 64)
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/reputation/hash"
    assert echo["query"] == {"sha256": ["a" * 64]}
    assert echo["api_key"] == "k"


def test_ioc(client: FileScanClient) -> None:
    echo = client.reputation.ioc("domain", "evil.example")
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/reputation/domain"
    assert echo["query"] == {"ioc_value": ["evil.example"]}


@pytest.mark.parametrize(
    ("call", "path"),
    [
        pytest.param(
            lambda client, values: client.reputation.file_hash_bulk(values),
            "/api/reputation/hash",
            id="hash",
        ),
        pytest.param(
            lambda client, values: client.reputation.ioc_bulk("ip", values),
            "/api/reputation/ip",
            id="ioc",
        ),
    ],
)
def test_bulk_lookups_post_the_values_as_json(
    client: FileScanClient,
    call: Callable[[FileScanClient, list[str]], Any],
    path: str,
) -> None:
    values = ["v1", "v2"]
    echo = call(client, values)
    assert echo["method"] == "POST"
    assert echo["path"] == path
    assert echo["query"] == {}
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == values
