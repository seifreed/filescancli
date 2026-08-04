"""Tests for ReportsGroup against the echo server."""

import json
from collections.abc import Callable
from typing import Any

import pytest

from filescanio.client import FileScanClient
from tests.conftest import assert_get


@pytest.mark.parametrize(
    ("call", "path", "query"),
    [
        pytest.param(
            lambda client: client.reports.get("report-2", "def456"),
            "/api/reports/report-2/def456",
            {},
            id="get without a view",
        ),
        pytest.param(
            lambda client: client.reports.get(
                "report-1", "abc123", filters=["general"], sorting=["date"], other=["x"]
            ),
            "/api/reports/report-1/abc123",
            {"filter": ["general"], "sorting": ["date"], "other": ["x"]},
            id="get with a view",
        ),
        pytest.param(
            lambda client: client.reports.search(),
            "/api/reports/search",
            {},
            id="search defaults",
        ),
        pytest.param(
            lambda client: client.reports.search("evil.exe", page=2, page_size=10),
            "/api/reports/search",
            {"query": ["evil.exe"], "page": ["2"], "page_size": ["10"]},
            id="search with pagination",
        ),
        pytest.param(
            lambda client: client.reports.public(),
            "/api/reports",
            {},
            id="public defaults",
        ),
        pytest.param(
            lambda client: client.reports.public(page=3, page_size=25),
            "/api/reports",
            {"page": ["3"], "page_size": ["25"]},
            id="public with paging",
        ),
    ],
)
def test_only_the_supplied_options_become_query_parameters(
    client: FileScanClient,
    call: Callable[[FileScanClient], Any],
    path: str,
    query: dict[str, list[str]],
) -> None:
    assert_get(call(client), path, query)


def test_search_matches(client: FileScanClient) -> None:
    echo = client.reports.search_matches(
        ["r1", "r2"],
        unique_files=True,
        method="or",
        filters={"sha256": "abc"},
    )
    assert echo["method"] == "POST"
    assert echo["path"] == "/api/reports/search/matches"
    assert echo["query"] == {
        "unique_files": ["true"],
        "method": ["or"],
        "sha256": ["abc"],
    }
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == {"reports_ids": ["r1", "r2"]}


def test_search_matches_defaults(client: FileScanClient) -> None:
    echo = client.reports.search_matches(["r3"])
    assert echo["query"] == {}
    assert json.loads(echo["body"]) == {"reports_ids": ["r3"]}


def test_matches_filters_override_named_parameters(client: FileScanClient) -> None:
    echo = client.reports.search_matches(["r1"], method="or", filters={"method": "and"})
    assert echo["query"]["method"] == ["and"]
