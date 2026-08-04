"""Tests for the presentation primitives."""

from typing import Any

import pytest

from filescanio.scanreport._layout import Field, heading, pairs, percent, rows, text


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
