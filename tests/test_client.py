from pathlib import Path

from filescanio import FileScanClient
from filescanio.config import ENV_API_KEY, ENV_BASE_URL
from tests.conftest import no_credentials, set_env


def test_explicit_credentials(api_server: str) -> None:
    with FileScanClient(api_key="k", base_url=api_server) as client:
        echo = client._transport.request_json("GET", "/api/ping")
    assert echo["api_key"] == "k"


def test_credentials_from_environment(api_server: str, tmp_path: Path) -> None:
    with (
        set_env(
            HOME=str(tmp_path), **{ENV_API_KEY: "env-key", ENV_BASE_URL: api_server}
        ),
        FileScanClient() as client,
    ):
        echo = client._transport.request_json("GET", "/api/ping")
    assert echo["api_key"] == "env-key"


def test_default_base_url_when_key_explicit(tmp_path: Path) -> None:
    with (
        no_credentials(tmp_path),
        FileScanClient(api_key="k") as client,
    ):
        assert client._transport._origin == ("https", b"www.filescan.io")
