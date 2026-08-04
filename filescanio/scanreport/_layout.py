"""Presentation primitives for the readable report.

Fields are data: a section declares what it shows as `Field` rows and the
formatters collapse "missing" and "ill-typed" into the same `None`, so the
sections themselves carry almost no branches.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from filescanio.scanreport._access import at, mapping, numeric, records, sequence


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


def flag(value: Any) -> str | None:
    """A boolean as yes/no, or None."""
    if not isinstance(value, bool):
        return None
    return "yes" if value else "no"


def joined(value: Any) -> str | None:
    """The scalar elements of a list, joined, or None."""
    parts = [part for item in sequence(value) if (part := text(item))]
    return ", ".join(parts) or None


def tag_names(value: Any) -> str | None:
    """The tag names in a tag list, joined, or None."""
    names = [name for item in records(value) if (name := text(at(item, "tag", "name")))]
    return ", ".join(names) or None


def human_size(value: int) -> str:
    """A byte count in the largest unit that keeps it readable."""
    amount, unit = float(value), "B"
    for larger in ("KiB", "MiB", "GiB", "TiB"):
        if amount < 1024:
            break
        amount, unit = amount / 1024, larger
    shown = f"{amount:.1f}".removesuffix(".0")
    return f"{shown} {unit}"


def size(value: Any) -> str | None:
    """A byte count as human-readable text, or None."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return human_size(value)


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


def scalar_items(node: Any) -> list[tuple[str, str]]:
    """Every representable entry of a mapping as label/value rows."""
    return [
        (str(key), shown)
        for key, item in mapping(node).items()
        if (shown := text(item)) is not None
    ]


def pairs(found: list[tuple[str, str]]) -> list[str]:
    """Label/value rows as aligned lines."""
    width = max((len(label) for label, _ in found), default=0)
    return [f"{label:<{width}}  {value}" for label, value in found]


def heading(title: str) -> list[str]:
    """A section title with its underline."""
    return [title, "=" * len(title)]


def indent(lines: list[str]) -> list[str]:
    """The lines shifted one level right."""
    return ["  " + line for line in lines]


def squeeze(value: str) -> str:
    """The text with every whitespace run collapsed to one space."""
    return " ".join(value.split())


def titled(value: str) -> str:
    """An identifier like static_analysis as words: Static Analysis."""
    return " ".join(word.capitalize() for word in value.split("_"))


def identifier(value: Any) -> str | None:
    """An identifier-style value as words, or None."""
    shown = text(value)
    return None if shown is None else titled(shown)
