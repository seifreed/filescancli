"""Tests for the SystemGroup endpoints against the echo server."""

import json
from collections.abc import Callable
from typing import Any

import pytest

from filescanio.client import FileScanClient
from tests.conftest import assert_get


def test_terms(client: FileScanClient) -> None:
    echo = client.system.terms("privacy-policy")
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/system/get-terms/privacy-policy"


def test_translations(client: FileScanClient) -> None:
    echo = client.system.translations("en")
    assert echo["method"] == "GET"
    assert echo["path"] == "/api/system/translations/en"


def test_remove_news(client: FileScanClient) -> None:
    echo = client.system.remove_news("news-1")
    assert echo["method"] == "DELETE"
    assert echo["path"] == "/api/system/news"
    assert echo["query"] == {"news_id": ["news-1"]}


@pytest.mark.parametrize(
    ("call", "path"),
    [
        pytest.param(
            lambda client, payload: client.system.log_error(payload),
            "/api/system/errors/log",
            id="log-error",
        ),
        pytest.param(
            lambda client, payload: client.system.save_news(payload),
            "/api/system/news",
            id="save-news",
        ),
    ],
)
def test_documents_are_posted_as_json(
    client: FileScanClient,
    call: Callable[[FileScanClient, dict[str, str]], Any],
    path: str,
) -> None:
    payload = {"message": "boom"}
    echo = call(client, payload)
    assert echo["method"] == "POST"
    assert echo["path"] == path
    assert echo["content_type"] == "application/json"
    assert json.loads(echo["body"]) == payload


@pytest.mark.parametrize(
    ("call", "path", "query"),
    [
        pytest.param(
            lambda client: client.system.yara(),
            "/api/system/yara",
            {},
            id="yara without names",
        ),
        pytest.param(
            lambda client: client.system.yara(names=["rule_a", "rule_b"]),
            "/api/system/yara",
            {"name": ["rule_a", "rule_b"]},
            id="yara with names",
        ),
        pytest.param(
            lambda client: json.loads(client.system.logo()),
            "/api/system/logo",
            {},
            id="logo without filters",
        ),
        pytest.param(
            lambda client: json.loads(
                client.system.logo(logo_type="full", theme="dark", name="main")
            ),
            "/api/system/logo",
            {"type": ["full"], "theme": ["dark"], "name": ["main"]},
            id="logo with filters",
        ),
        pytest.param(
            lambda client: client.system.query_healthcheck(),
            "/api/system/query-healthcheck",
            {},
            id="healthcheck without a range",
        ),
        pytest.param(
            lambda client: client.system.query_healthcheck(days=7, days_from=1),
            "/api/system/query-healthcheck",
            {"days": ["7"], "days_from": ["1"]},
            id="healthcheck with a range",
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
