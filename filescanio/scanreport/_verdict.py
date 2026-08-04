"""The verdict-centred sections of the readable report."""

from typing import Any

from filescanio.scanreport._access import at, records
from filescanio.scanreport._layout import Field, pairs, percent, rows, text
from filescanio.scanreport.model import ScanReport, verdict_of

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


def tag_names(value: Any) -> str | None:
    """The tag names in a tag list, joined, or None."""
    names = [name for item in records(value) if (name := text(at(item, "tag", "name")))]
    return ", ".join(names) or None


TAG_FIELDS: tuple[Field, ...] = (Field("Tags", ("allTags",), tag_names),)


def tags(scan: ScanReport) -> list[str]:
    """Every tag on the report, however it was sourced."""
    return pairs(rows(scan.report, TAG_FIELDS))
