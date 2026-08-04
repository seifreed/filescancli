"""Tests for the presentation primitives."""

from typing import Any

import pytest

from filescanio.scanreport._layout import (
    Field,
    flag,
    heading,
    human_size,
    joined,
    pairs,
    percent,
    rows,
    scalar_items,
    size,
    text,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("x", "x"),
        ("  padded  ", "padded"),
        ("", None),
        ("   ", None),
        (3, "3"),
        (0.5, "0.5"),
        (True, None),
        (None, None),
        (["x"], None),
    ],
)
def test_text(value: Any, expected: str | None) -> None:
    assert text(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0.95, "95%"), (1, "100%"), (0.25, "25%"), (0, "0%"), ("x", None), (None, None)],
)
def test_percent(value: Any, expected: str | None) -> None:
    assert percent(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, "yes"), (False, "no"), (1, None), ("yes", None), (None, None)],
)
def test_flag(value: Any, expected: str | None) -> None:
    assert flag(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (["a", "b"], "a, b"),
        (["a", None, {"x": 1}], "a"),
        ([], None),
        ("text", None),
        (None, None),
    ],
)
def test_joined(value: Any, expected: str | None) -> None:
    assert joined(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1 KiB"),
        (1536, "1.5 KiB"),
        (1024**4, "1 TiB"),
    ],
)
def test_human_size(value: int, expected: str) -> None:
    assert human_size(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(2048, "2 KiB"), (0, "0 B"), (-1, None), (True, None), ("big", None)],
)
def test_size(value: Any, expected: str | None) -> None:
    assert size(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"MD5": "x", "raw": [1]}, [("MD5", "x")]),
        ({}, []),
        ("junk", []),
    ],
)
def test_scalar_items(value: Any, expected: list[tuple[str, str]]) -> None:
    assert scalar_items(value) == expected


FIELDS = (
    Field("Name", ("file", "name")),
    Field("Missing", ("file", "gone")),
    Field("Bad", ("file", "junk")),
)


def test_rows_keeps_only_representable_values() -> None:
    node = {"file": {"name": "a.bin", "junk": ["nope"]}}
    assert rows(node, FIELDS) == [("Name", "a.bin")]


def test_rows_of_nothing_is_empty() -> None:
    assert rows(None, FIELDS) == []


def test_pairs_aligns_labels() -> None:
    assert pairs([("A", "1"), ("Long", "2")]) == ["A     1", "Long  2"]


def test_pairs_of_nothing_is_empty() -> None:
    assert pairs([]) == []


def test_heading_underlines_the_title() -> None:
    assert heading("Overview") == ["Overview", "========"]
