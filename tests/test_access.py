"""Tests for the safe JSON navigation helpers."""

import math
from typing import Any

import pytest

from filescanio.scanreport._access import at, mapping, numeric, records, sequence


@pytest.mark.parametrize(
    ("value", "expected"),
    [({"a": 1}, {"a": 1}), (None, {}), ([1], {}), ("x", {}), (5, {})],
)
def test_mapping(value: Any, expected: Any) -> None:
    assert mapping(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ([1, 2], [1, 2]),
        ((1,), [1]),
        ("text", []),
        (b"raw", []),
        ({"a": 1}, []),
        (None, []),
    ],
)
def test_sequence(value: Any, expected: Any) -> None:
    assert sequence(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [([{"a": 1}, 2, "x", {"b": 2}], [{"a": 1}, {"b": 2}]), (None, []), ([], [])],
)
def test_records(value: Any, expected: Any) -> None:
    assert records(value) == expected


@pytest.mark.parametrize(
    ("node", "path", "expected"),
    [
        ({"a": {"b": 3}}, ("a", "b"), 3),
        ({"a": {"b": 3}}, ("a", "missing"), None),
        ({"a": []}, ("a", "b"), None),
        (None, ("a",), None),
        ({"a": 1}, (), {"a": 1}),
    ],
)
def test_at(node: Any, path: tuple[str, ...], expected: Any) -> None:
    assert at(node, *path) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (2, 2.0),
        (0.5, 0.5),
        (0, 0.0),
        (True, None),
        ("3", None),
        (None, None),
        (math.nan, None),
        (math.inf, None),
    ],
)
def test_numeric(value: Any, expected: float | None) -> None:
    assert numeric(value) == expected
