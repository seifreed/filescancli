"""Presentation primitives for the readable report.

Fields are data: a section declares what it shows as `Field` rows and the
formatters collapse "missing" and "ill-typed" into the same `None`, so the
sections themselves carry almost no branches.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from filescanio.scanreport._access import at, numeric


def text(value: Any) -> str | None:
    """The value as stripped text, or None; bools and structures do not count."""
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        return None
    result = str(value).strip()
    return result or None


def percent(value: Any) -> str | None:
    """A 0..1 fraction as a whole percentage, or None."""
    number = numeric(value)
    return None if number is None else f"{round(number * 100)}%"


@dataclass(frozen=True, slots=True)
class Field:
    """One labelled row: where to read it and how to show it."""

    label: str
    path: tuple[str, ...]
    fmt: Callable[[Any], str | None] = field(default=text)


def rows(node: Any, fields: tuple[Field, ...]) -> list[tuple[str, str]]:
    """The rows whose value is present and representable."""
    return [
        (entry.label, value)
        for entry in fields
        if (value := entry.fmt(at(node, *entry.path))) is not None
    ]


def pairs(found: list[tuple[str, str]]) -> list[str]:
    """Label/value rows as aligned lines."""
    width = max((len(label) for label, _ in found), default=0)
    return [f"{label:<{width}}  {value}" for label, value in found]


def heading(title: str) -> list[str]:
    """A section title with its underline."""
    return [title, "=" * len(title)]
