"""Tests for ReportsGroup against the echo server."""

import itertools
import json
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any

import pytest

from filescanio.client import FileScanClient
from filescanio.groups._base import PAGE_CEILING
from filescanio.groups.reports import ReportsGroup
from filescanio.http import Transport
from tests.conftest import assert_get, json_server


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
            lambda client: json.loads(client.reports.download("r9")),
            "/api/reports/r9/download",
            {},
            id="download default serialisation",
        ),
        pytest.param(
            lambda client: json.loads(
                client.reports.download("r9", export_format="misp")
            ),
            "/api/reports/r9/download",
            {"format": ["misp"]},
            id="download as misp",
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


def paged_server(*pages: list[dict[str, int]]) -> AbstractContextManager[str]:
    """Serve one page of items per request, then an empty page forever."""
    hits = itertools.count()
    return json_server(
        lambda _: (
            200,
            json.dumps(
                {
                    "items": pages[i] if (i := next(hits)) < len(pages) else [],
                    "count": 0,
                }
            ).encode(),
        )
    )


@contextmanager
def paging(server: AbstractContextManager[str]) -> Iterator[ReportsGroup]:
    with server as base_url, Transport(api_key="k", base_url=base_url) as transport:
        yield ReportsGroup(transport)


def test_search_pages_walks_until_a_short_page() -> None:
    with paging(paged_server([{"id": 1}, {"id": 2}], [{"id": 3}])) as reports:
        assert [item["id"] for item in reports.search_pages("x", page_size=2)] == [
            1,
            2,
            3,
        ]


def test_public_pages_stops_on_an_empty_page() -> None:
    with paging(paged_server([{"id": 1}, {"id": 2}])) as reports:
        assert [item["id"] for item in reports.public_pages(page_size=2)] == [1, 2]


def test_pages_stop_when_the_server_answers_with_no_items() -> None:
    with paging(json_server(lambda _: (200, b'{"count": 0}'))) as reports:
        assert list(reports.search_pages(page_size=5)) == []


def test_pages_stop_when_the_server_answers_with_a_list() -> None:
    with paging(json_server(lambda _: (200, b"[1, 2]"))) as reports:
        assert list(reports.search_pages(page_size=5)) == []


def test_the_page_ceiling_stops_a_server_that_never_runs_out() -> None:
    """Every page is full, so only the ceiling ends the walk."""
    endless = json_server(lambda _: (200, b'{"items": [{"id": 1}]}'))
    with paging(endless) as reports:
        assert len(list(reports.search_pages(page_size=1))) == PAGE_CEILING
