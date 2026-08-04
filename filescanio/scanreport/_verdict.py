"""The verdict-centred sections of the readable report."""

from collections.abc import Mapping
from typing import Any

from filescanio.scanreport._access import at, numeric, records
from filescanio.scanreport._layout import (
    Field,
    indent,
    pairs,
    percent,
    rows,
    squeeze,
    tag_names,
    text,
    titled,
)
from filescanio.scanreport.model import (
    ScanReport,
    signal_groups,
    verdict_label,
    verdict_of,
)

REPORT_FIELDS: tuple[Field, ...] = (
    Field("Confidence", ("finalVerdict", "confidence"), percent),
    Field("Report id", ("id",)),
    Field("File name", ("file", "name")),
    Field("SHA-256", ("file", "hash")),
    Field("Submission id", ("flowId",)),
    Field("Submitted", ("created_date",)),
)

FILE_FIELDS: tuple[Field, ...] = (Field("Media type", ("mediaType", "string")),)


def overview(scan: ScanReport) -> list[str]:
    """The verdict and submission facts; never empty."""
    found = [("Verdict", verdict_of(scan.report))]
    found += rows(scan.report, REPORT_FIELDS)
    found += rows(scan.resource("file"), FILE_FIELDS)
    return pairs(found)


TAG_FIELDS: tuple[Field, ...] = (Field("Tags", ("allTags",), tag_names),)


def tags(scan: ScanReport) -> list[str]:
    """Every tag on the report, however it was sourced."""
    return pairs(rows(scan.report, TAG_FIELDS))


def technique_name(item: Mapping[str, Any]) -> str:
    """A MITRE technique with its tactic when the server related one."""
    parts = (text(at(item, "relatedTactic", "name")), text(item.get("name")))
    return " / ".join(part for part in parts if part)


def techniques(value: Any) -> str | None:
    """The MITRE techniques of a signal group, joined, or None."""
    names = [name for item in records(value) if (name := technique_name(item))]
    return ", ".join(names) or None


def signal_name(item: Mapping[str, Any]) -> str:
    """One signal with its origin, whitespace collapsed."""
    readable = squeeze(text(item.get("signalReadable")) or "")
    origin = titled(text(item.get("originType")) or "")
    return " / ".join(part for part in (readable, origin) if part)


def signal_texts(value: Any) -> str | None:
    """The signals of a signal group, joined, or None."""
    names = [name for item in records(value) if (name := signal_name(item))]
    return "; ".join(names) or None


GROUP_FIELDS: tuple[Field, ...] = (
    Field("Tags", ("allTags",), tag_names),
    Field("MITRE", ("allMitreTechniques",), techniques),
    Field("Signals", ("signals",), signal_texts),
)


def group_threat(group: Mapping[str, Any]) -> float:
    """A group's threat level for ordering; an absent level sorts last."""
    level = numeric(at(group, "verdict", "threatLevel"))
    return -1.0 if level is None else level


def group_lines(group: Mapping[str, Any]) -> list[str]:
    """One group as a verdict-labelled header with its indented facts."""
    description = text(group.get("description")) or "signal group"
    header = f"{description} [{verdict_label(group)}]"
    return [header, *indent(pairs(rows(group, GROUP_FIELDS)))]


def signals(scan: ScanReport) -> list[str]:
    """Every signal group, most threatening first."""
    ordered = sorted(signal_groups(scan.report), key=group_threat, reverse=True)
    return [row for group in ordered for row in group_lines(group)]
