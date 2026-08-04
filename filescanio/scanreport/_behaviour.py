"""The behavioural sections: emulation, disassembly, interesting strings."""

from collections.abc import Mapping
from typing import Any

from filescanio.scanreport._access import at, mapping, numeric, records, sequence
from filescanio.scanreport._layout import (
    indent,
    joined,
    pairs,
    scalar_items,
    squeeze,
    text,
    titled,
)
from filescanio.scanreport.model import ScanReport


def call_counts(value: Any) -> list[tuple[str, str]]:
    """The emulated API calls as rows, most-called first."""
    counted = [
        (str(name), number)
        for name, item in mapping(value).items()
        if (number := numeric(item)) is not None
    ]
    counted.sort(key=lambda entry: entry[1], reverse=True)
    return [(name, f"{number:g}") for name, number in counted]


def emulation_overview(scan: ScanReport) -> list[str]:
    """What the emulator saw overall: call counts and summary facts."""
    overview = mapping(at(scan.resource("file"), "emulationMetaData", "Overview"))
    return pairs(call_counts(overview.get("FunctionCount")) + scalar_items(overview))


# The keys that best name what an emulated action touched, most specific first.
DESCRIPTOR_KEYS = (
    "Library",
    "Alias",
    "Address",
    "Class",
    "Url",
    "URI",
    "Command",
    "Program",
    "ProcessName",
    "Path",
    "Event",
    "Section",
    "CodeModule",
    "Dir",
    "Duration",
    "Language",
)

# Raw payload bytes: interesting to a parser, noise in a report.
SKIPPED_INFO = frozenset({"Content"})


def action_header(item: Mapping[str, Any]) -> str:
    """One action named by what it did and what it touched."""
    info = mapping(item.get("additionalInformation"))
    described = [name for key in DESCRIPTOR_KEYS if (name := text(info.get(key)))]
    mark = ["(interesting)"] if item.get("interesting") else []
    return " ".join([text(item.get("action")) or "action", *mark, *described])


def action_facts(info: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The action's scalar and list facts as rows."""
    shown = {key: value for key, value in info.items() if key not in SKIPPED_INFO}
    lists = [(str(key), row) for key, value in shown.items() if (row := joined(value))]
    return scalar_items(shown) + lists


def actions(scan: ScanReport) -> list[str]:
    """Every emulated action with its facts indented under it."""
    lines: list[str] = []
    for item in records(scan.resource("file").get("emulationData")):
        info = mapping(item.get("additionalInformation"))
        lines += [action_header(item), *indent(pairs(action_facts(info)))]
    return lines


def section_line(section: Mapping[str, Any]) -> str:
    """One disassembled region as a single summary line."""
    rva = text(section.get("fileRva")) or "?"
    descriptor = text(section.get("humanDescriptor")) or "section"
    count = len(sequence(section.get("instructions")))
    return f"RVA {rva}: {descriptor}, {count} instructions"


def disassembly(scan: ScanReport) -> list[str]:
    """Every disassembled region the analysis recorded."""
    sections = records(scan.resource("file").get("disassemblySections"))
    return [section_line(section) for section in sections]


def interesting_strings(value: Any) -> list[str]:
    """The strings a reference list marks interesting, whitespace collapsed."""
    return [
        squeeze(shown)
        for ref in records(value)
        if ref.get("interesting") and (shown := text(ref.get("str")))
    ]


def strings(scan: ScanReport) -> list[str]:
    """The interesting strings, each labelled with where it was found."""
    lines: list[str] = []
    for group in records(scan.resource("file").get("strings")):
        origin = titled(text(at(group, "origin", "type")) or "unknown")
        found = interesting_strings(group.get("references"))
        lines += [f"{item} ({origin})" for item in found]
    return lines
