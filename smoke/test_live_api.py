"""Smoke checks against the real filescan.io API.

These need a real API key, so they cannot run in the automated suite and are
kept out of ``testpaths``. Run them on demand with ``pytest smoke``.
"""

import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from filescanio import FileScanClient

REPO = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    not os.environ.get("FILESCANIO"), reason="FILESCANIO env var not set"
)


@pytest.fixture(scope="module")
def live_client() -> Iterator[FileScanClient]:
    with FileScanClient() as client:
        yield client


def test_system_version(live_client: FileScanClient) -> None:
    assert "release_version" in live_client.system.version()


def test_search(live_client: FileScanClient) -> None:
    assert "items" in live_client.reports.search("mirai", page_size=5)


def test_reputation_hash(live_client: FileScanClient) -> None:
    empty_file_sha256 = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert isinstance(live_client.reputation.file_hash(empty_file_sha256), dict)


def _normalize(path: str) -> str:
    """Reduce a path to its literal parts, ignoring how segments are named."""
    return re.sub(r"\{[^}]*\}", "{}", path)


def _implemented() -> set[str]:
    """Every request path the endpoint groups build, segments blanked out."""
    return {
        _normalize(literal or interpolated)
        for source in (REPO / "filescanio" / "groups").glob("*.py")
        for literal, interpolated in re.findall(
            r'"(/[^"]*)"|f"(/[^"]*)"', source.read_text(encoding="utf-8")
        )
    }


def test_every_published_endpoint_is_implemented(live_client: FileScanClient) -> None:
    """Fetches the specification, so the repository ships no copy of it."""
    published = live_client.misc.openapi()["paths"]
    implemented = _implemented()
    assert [path for path in published if _normalize(path) not in implemented] == []
