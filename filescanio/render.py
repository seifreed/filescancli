"""Render an API response as a table, JSON, TOON, or SARIF.

Presentation only: these are pure functions over already-decoded responses, so
the endpoint groups never learn how their data is displayed.
"""

import json
import math
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import StrEnum
from typing import Any
from urllib.parse import quote

from prettytable import PrettyTable

from filescanio.errors import Unrepresentable
from filescanio.scanreport.model import (
    reports_of,
    signal_groups,
    strength,
    threat_level,
    verdict_of,
)

CELL_WIDTH = 60
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "filescan.io"

# A signal group that scores at or above this counts as a finding worth an
# `error`; the API reports strength as a string, so it is parsed leniently.
STRONG_SIGNAL = 5.0

VERDICT_LEVELS = {
    "malicious": "error",
    "likely_malicious": "error",
    "suspicious": "warning",
    "informational": "note",
}
VERDICT_KINDS = {"benign": "pass", "no_threat": "pass", "unknown": "notApplicable"}


class Format(StrEnum):
    """An output format the CLI can render into."""

    TABLE = "table"
    JSON = "json"
    TOON = "toon"
    SARIF = "sarif"


def render_json(value: Any, *, compact: bool = False) -> str:
    """Render as JSON, indented unless the caller asked for one line."""
    return json.dumps(value, indent=None if compact else 2)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _cell(value: Any) -> str:
    """Render one table cell, shortening anything that would break the layout."""
    text = value if isinstance(value, str) else render_json(value, compact=True)
    if len(text) > CELL_WIDTH:
        return text[: CELL_WIDTH - 1] + "…"
    return text


def _columns(records: Sequence[Mapping[str, Any]]) -> list[str]:
    """Every key across the records, in the order they are first seen."""
    columns: dict[str, None] = {}
    for record in records:
        columns.update(dict.fromkeys(record))
    return list(columns)


def _record_table(
    records: Sequence[Mapping[str, Any]], *, key_column: str | None = None
) -> PrettyTable:
    field_names = ([key_column] if key_column else []) + _columns(records)
    if not field_names:
        raise Unrepresentable("the records carry no fields to put in columns")
    table = PrettyTable()
    table.field_names = field_names
    table.align = "l"
    return table


def _rows_of_records(value: Sequence[Any]) -> str:
    records = [item for item in value if isinstance(item, Mapping)]
    columns = _columns(records)
    table = _record_table(records)
    for record in records:
        table.add_row([_cell(record.get(name)) for name in columns])
    return table.get_string()


def _key_column(columns: Sequence[str]) -> str:
    """A name for the map-key column that no record field already claims."""
    name = "key"
    while name in columns:
        name += "_"
    return name


def _rows_of_map(value: Mapping[str, Any]) -> str:
    records = list(value.values())
    columns = _columns(records)
    table = _record_table(records, key_column=_key_column(columns))
    for key, record in value.items():
        table.add_row([key] + [_cell(record.get(name)) for name in columns])
    return table.get_string()


def _pairs(value: Mapping[str, Any]) -> str:
    table = PrettyTable()
    table.field_names = ["field", "value"]
    table.align = "l"
    for key, item in value.items():
        table.add_row([key, _cell(item)])
    return table.get_string()


def _scalars(value: Sequence[Any]) -> str:
    table = PrettyTable()
    table.field_names = ["value"]
    table.align = "l"
    for item in value:
        table.add_row([_cell(item)])
    return table.get_string()


def _all_mappings(value: Sequence[Any] | Sequence[object]) -> bool:
    return bool(value) and all(isinstance(item, Mapping) for item in value)


def render_table(value: Any) -> str:
    """Render as a table, or refuse when the shape has no sensible columns."""
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        if not value:
            raise Unrepresentable("the response is an empty list")
        if _all_mappings(value):
            return _rows_of_records(value)
        if all(_is_scalar(item) for item in value):
            return _scalars(value)
        raise Unrepresentable("the list mixes records and plain values")
    if isinstance(value, Mapping) and value:
        items = value.get("items")
        if isinstance(items, Sequence) and not isinstance(items, str) and items:
            body = render_table(items)
            # Every sibling is footered, nested ones as compact JSON: dropping
            # them would hide things like a pagination total behind one page.
            rest = {k: v for k, v in value.items() if k != "items"}
            return f"{body}\n" + _pairs(rest) if rest else body
        if _all_mappings(list(value.values())):
            return _rows_of_map(value)
        if all(_is_scalar(item) for item in value.values()):
            return _pairs(value)
    raise Unrepresentable("the response has no table-shaped rows")


def _exponent_form(value: float) -> str:
    """Exponent notation without the zero padding CPython's repr adds."""
    mantissa, _, exponent = repr(value).partition("e")
    sign = exponent[0]
    return f"{mantissa}e{sign}{exponent[1:].lstrip('0')}"


def _toon_number(value: float | int) -> str:
    """Canonical TOON number: no exponent in range, no trailing zeros, no -0."""
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise Unrepresentable("TOON has no representation for a non-finite number")
    if value == 0:
        return "0"
    if 1e-6 <= abs(value) < 1e21:
        # repr gives the shortest round-tripping digits; Decimal spells them
        # out in full, which a fixed number of decimal places cannot do.
        text = f"{Decimal(repr(value)):f}"
        return text.rstrip("0").rstrip(".") if "." in text else text
    return _exponent_form(value)


_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_BARE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_NUMERIC = re.compile(r"^-?\d+(\.\d+)?([eE][+-]?\d+)?$")


def _toon_escape(text: str) -> str:
    out = []
    for char in text:
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif char < " " or char == "\x7f":
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return "".join(out)


def _toon_string(text: str) -> str:
    needs_quotes = (
        not text
        or text != text.strip()
        or text in {"true", "false", "null"}
        or bool(_NUMERIC.match(text))
        or text[0] in "-#"
        or any(char in text for char in ',:[]{}"\\')
        or any(char < " " or char == "\x7f" for char in text)
    )
    escaped = _toon_escape(text)
    return f'"{escaped}"' if needs_quotes else escaped


def _toon_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return _toon_number(value)
    return _toon_string(str(value))


def _toon_key(key: str) -> str:
    """Keys quote on a stricter rule than values: anything not bare is quoted."""
    return key if _BARE_KEY.match(key) else f'"{_toon_escape(key)}"'


def _uniform_fields(value: Sequence[Any]) -> list[str] | None:
    """The shared field order when every element is an all-scalar record."""
    if not _all_mappings(value):
        return None
    first = list(value[0])
    if not first:
        return None
    for record in value:
        if list(record) != first or not all(_is_scalar(v) for v in record.values()):
            return None
    return first


def _toon_lines(value: Any, key: str | None, depth: int) -> list[str]:
    pad = "  " * depth
    label = f"{_toon_key(key)}: " if key is not None else ""
    bare = f"{_toon_key(key)}:" if key is not None else ""
    if _is_scalar(value):
        return [f"{pad}{label}{_toon_scalar(value)}"]
    if isinstance(value, Mapping):
        if not value:
            if key is None:
                # With no key to carry it, an empty object is a blank line:
                # unreadable at the root and undecodable as a list item.
                raise Unrepresentable("TOON cannot express an object with no fields")
            return [f"{pad}{bare}"]
        lines = [f"{pad}{bare}"] if key is not None else []
        for name, item in value.items():
            lines += _toon_lines(item, str(name), depth + (1 if key is not None else 0))
        return lines
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return _toon_array(list(value), key, depth)
    raise Unrepresentable(f"TOON cannot encode {type(value).__name__}")


def _toon_array(items: list[Any], key: str | None, depth: int) -> list[str]:
    pad = "  " * depth
    name = _toon_key(key) if key is not None else ""
    if not items:
        return [f"{pad}{name}: []" if name else f"{pad}[]"]
    if all(_is_scalar(item) for item in items):
        joined = ",".join(_toon_scalar(item) for item in items)
        return [f"{pad}{name}[{len(items)}]: {joined}"]
    fields = _uniform_fields(items)
    if fields is not None:
        header = (
            f"{pad}{name}[{len(items)}]{{{','.join(_toon_key(f) for f in fields)}}}:"
        )
        rows = [
            "  " * (depth + 1) + ",".join(_toon_scalar(record[f]) for f in fields)
            for record in items
        ]
        return [header] + rows
    lines = [f"{pad}{name}[{len(items)}]:"]
    for item in items:
        # The "- " marker shifts the first line two columns right, so the rest
        # of the item is rendered one level deeper to line up underneath it.
        rendered = _toon_lines(item, None, depth + 2)
        lines.append("  " * (depth + 1) + "- " + rendered[0].lstrip())
        lines += rendered[1:]
    return lines


def render_toon(value: Any) -> str:
    """Render as TOON (encode only, comma delimiter, two-space indent)."""
    if _is_scalar(value):
        raise Unrepresentable("TOON needs an object or an array at the root")
    return "\n".join(_toon_lines(value, None, 0))


def _flow_file_size(value: Mapping[str, Any]) -> int | None:
    """The uploaded file's size, which the API reports beside the reports."""
    size = value.get("fileSize")
    if isinstance(size, bool) or not isinstance(size, int):
        return None
    return size


def _artifact_uri(name: str) -> str:
    """Percent-encode a sample name so SARIF's uri-reference format holds.

    Sample names routinely carry spaces, backslashes, and non-ASCII, none of
    which a URI reference may contain unescaped.
    """
    return quote(name, safe="/", errors="replace")


def _artifact_of(report: Mapping[str, Any], size: int | None) -> dict[str, Any]:
    info = report.get("file")
    info = info if isinstance(info, Mapping) else {}
    artifact: dict[str, Any] = {
        "location": {"uri": _artifact_uri(str(info.get("name", "unknown")))},
        "roles": ["analysisTarget"],
    }
    if isinstance(info.get("hash"), str):
        artifact["hashes"] = {"sha-256": info["hash"]}
    if size is not None:
        artifact["length"] = size
    return artifact


def _location(index: int, uri: str) -> dict[str, Any]:
    return {"physicalLocation": {"artifactLocation": {"uri": uri, "index": index}}}


def _verdict_result(report: Mapping[str, Any], index: int, uri: str) -> dict[str, Any]:
    verdict = verdict_of(report)
    result: dict[str, Any] = {
        "message": {"text": f"filescan.io verdict: {verdict}"},
        "locations": [_location(index, uri)],
    }
    if verdict in VERDICT_LEVELS:
        result["level"] = VERDICT_LEVELS[verdict]
    else:
        # A kind other than "fail" must not carry a level (SARIF 2.1.0 3.27.9).
        result["kind"] = VERDICT_KINDS.get(verdict, "notApplicable")
    threat = threat_level(report)
    if threat is not None:
        # The threat level is a fraction, and SARIF 2.1.0 3.27.16 confines
        # rank to 0.0-100.0 however the server chose to scale it.
        result["rank"] = min(max(threat * 100, 0.0), 100.0)
    return result


def _signal_result(
    group: Mapping[str, Any], index: int, uri: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    identifier = str(group.get("id", "signal"))
    description = str(group.get("description", identifier))
    rule: dict[str, Any] = {
        "id": identifier,
        "shortDescription": {"text": description},
        "properties": {"security-severity": str(strength(group))},
    }
    techniques = str(group.get("mitre_technique_ids", "")).replace(" ", "")
    if techniques:
        rule["properties"]["tags"] = techniques.split(",")
    result = {
        "ruleId": identifier,
        "level": "error" if strength(group) >= STRONG_SIGNAL else "warning",
        "message": {"text": description},
        "locations": [_location(index, uri)],
    }
    return rule, result


def render_sarif(value: Any) -> str:
    """Render a scan report as a SARIF 2.1.0 log."""
    if not isinstance(value, Mapping):
        raise Unrepresentable("SARIF needs a scan report object")
    reports = reports_of(value)
    if not reports:
        raise Unrepresentable("the response carries no scan reports")
    artifacts: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    # fileSize describes the file that was uploaded, so it identifies an
    # artifact only when the flow did not unpack it into several reports.
    size = _flow_file_size(value) if len(reports) == 1 else None
    for report in reports:
        artifact = _artifact_of(report, size)
        index = len(artifacts)
        artifacts.append(artifact)
        uri = str(artifact["location"]["uri"])
        groups = signal_groups(report)
        for group in groups:
            rule, result = _signal_result(group, index, uri)
            rules.setdefault(rule["id"], rule)
            results.append(result)
        if not groups:
            results.append(_verdict_result(report, index, uri))
    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": "https://www.filescan.io",
    }
    if rules:
        driver["rules"] = list(rules.values())
    log = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {"tool": {"driver": driver}, "artifacts": artifacts, "results": results}
        ],
    }
    return render_json(log)


RENDERERS = {
    Format.TABLE: render_table,
    Format.TOON: render_toon,
    Format.SARIF: render_sarif,
}


def render(value: Any, fmt: Format, *, compact: bool = False) -> str:
    """Render in the requested format, or raise Unrepresentable."""
    if fmt is Format.JSON:
        return render_json(value, compact=compact)
    return RENDERERS[fmt](value)
