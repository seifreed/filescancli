"""Path segments must not escape their position in the URL."""

import json
from collections.abc import Callable
from typing import Any

import pytest

from filescanio.client import FileScanClient
from filescanio.errors import FileScanError

Position = tuple[Callable[[FileScanClient, str], Any], str]

INTERPOLATED_POSITIONS: list[Position] = [
    (lambda c, value: c.reports.get(value, "x"), "/api/reports/{}/x"),
    (lambda c, value: c.scan.report(value), "/api/scan/{}/report"),
    (lambda c, value: c.system.terms(value), "/api/system/get-terms/{}"),
    (lambda c, value: c.system.translations(value), "/api/system/translations/{}"),
    (lambda c, value: c.reputation.ioc(value, "v"), "/api/reputation/{}"),
    (lambda c, value: c.reputation.ioc_bulk(value, ["a"]), "/api/reputation/{}"),
    (lambda c, value: json.loads(c.users.avatar(value)), "/api/users/{}/avatar"),
]

HOSTILE_IDENTIFIERS = [
    ("../x", "..%2Fx"),
    ("../../admin/secret", "..%2F..%2Fadmin%2Fsecret"),
    ("id?admin=1", "id%3Fadmin%3D1"),
    ("privacy#frag", "privacy%23frag"),
    ("..", "%2E%2E"),
]


@pytest.mark.parametrize(("call", "template"), INTERPOLATED_POSITIONS)
@pytest.mark.parametrize(("value", "escaped"), HOSTILE_IDENTIFIERS)
def test_every_interpolated_position_is_escaped(
    client: FileScanClient,
    call: Callable[[FileScanClient, str], Any],
    template: str,
    value: str,
    escaped: str,
) -> None:
    echo = call(client, value)
    assert echo["path"] == template.format(escaped)


def test_an_escaped_identifier_cannot_add_query_parameters(
    client: FileScanClient,
) -> None:
    echo = client.reports.get("id?admin=1", "x")
    assert echo["query"] == {}


def test_ordinary_identifiers_are_unchanged(client: FileScanClient) -> None:
    echo = client.reports.get("2ac16f60-220d-4b9c", "abc123")
    assert echo["path"] == "/api/reports/2ac16f60-220d-4b9c/abc123"


@pytest.mark.parametrize("value", ["..", ".", "...", "...."])
def test_dot_only_segments_cannot_retarget_the_request(
    client: FileScanClient, value: str
) -> None:
    echo = client.reports.get(value, "victim")
    assert echo["path"] == f"/api/reports/{'%2E' * len(value)}/victim"


def test_dots_inside_a_longer_value_are_preserved(client: FileScanClient) -> None:
    echo = client.reports.get("report.v2..final", "hash.1")
    assert echo["path"] == "/api/reports/report.v2..final/hash.1"


def test_lone_surrogate_identifier_reports_a_library_error(
    client: FileScanClient,
) -> None:
    with pytest.raises(FileScanError, match="Invalid identifier"):
        client.scan.report("abc\ud800")
