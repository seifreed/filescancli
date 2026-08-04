"""Tests for the UsersGroup endpoints against the echo server."""

import json

from filescanio.client import FileScanClient


def test_avatar(client: FileScanClient) -> None:
    echo = json.loads(client.users.avatar("acc-1"))
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/users/acc-1/avatar"
    assert echo["api_key"] == "k"
