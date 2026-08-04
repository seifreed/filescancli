"""Tests for the MiscGroup endpoints against the echo server."""

from filescanio.client import FileScanClient


def test_oauth_callback_without_params(client: FileScanClient) -> None:
    echo = client.misc.oauth_callback()
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/admin/scan-sources/oauth/callback"
    assert echo["query"] == {}


def test_oauth_callback_with_params(client: FileScanClient) -> None:
    echo = client.misc.oauth_callback(
        state="s1", code="c1", error="denied", error_description="user denied"
    )
    assert echo["path"] == "/api/admin/scan-sources/oauth/callback"
    assert echo["query"] == {
        "state": ["s1"],
        "code": ["c1"],
        "error": ["denied"],
        "error_description": ["user denied"],
    }
