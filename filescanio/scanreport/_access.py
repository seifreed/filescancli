"""Safe navigation over decoded JSON of unknown shape.

Every helper accepts anything and answers with a neutral value, so callers
never branch on missing keys or ill-typed nodes.
"""

import math
from collections.abc import Mapping, Sequence
from typing import Any


def mapping(value: Any) -> Mapping[str, Any]:
    """The value as a mapping, or an empty one."""
    return value if isinstance(value, Mapping) else {}


def sequence(value: Any) -> list[Any]:
    """The value as a list, or an empty one; text does not count."""
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return list(value)
    return []


def records(value: Any) -> list[Mapping[str, Any]]:
    """The mapping elements of the value, when it is a sequence."""
    return [item for item in sequence(value) if isinstance(item, Mapping)]


def at(node: Any, *path: str) -> Any:
    """The value reached by walking mapping keys, or None."""
    for key in path:
        node = mapping(node).get(key)
    return node


def numeric(value: Any) -> float | None:
    """The value as a finite float, or None; bools do not count."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None
