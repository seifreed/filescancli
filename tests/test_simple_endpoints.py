"""Every no-argument endpoint reaches the path its CLI command advertises."""

import json
from typing import Any

import pytest

from filescanio.cli import SIMPLE_COMMANDS
from filescanio.client import FileScanClient
from tests.conftest import SIMPLE_CASES


@pytest.mark.parametrize(("argv", "expected_path"), SIMPLE_CASES)
def test_no_argument_endpoints(
    client: FileScanClient, argv: tuple[str, str], expected_path: str
) -> None:
    call, _ = SIMPLE_COMMANDS[argv]
    payload: Any = call(client)
    echo = json.loads(payload) if isinstance(payload, str) else payload
    assert echo["method"] == "GET"
    assert echo["path"] == expected_path
    assert echo["api_key"] == "k"
